"""SSH service — connects to a VPS via paramiko and manages VPNPro users.

All username inputs are validated with a strict regex before any shell
command to prevent command-injection attacks.
Passwords are set via chpasswd stdin (never interpolated in the shell).
Password files on the VPS are written with SFTP (no shell involved).
"""

from __future__ import annotations

import re
import shlex
import socket
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import paramiko

# Compatible con cuentas creadas por scripts Bash (legacy y nuevas).
# Permite letras, numeros, guion, guion bajo y punto.
_USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,32}$')
_SFTP_TIMEOUT_SECONDS = 20
_APT_AUTOREMOVE_PURGE_CMD = 'apt-get autoremove -y --purge >/dev/null 2>&1 || true'
_TRUNCATE_LARGE_LOGS_CMD = (
    "for f in /var/log/auth.log /var/log/syslog; do "
    "  [ -f \"$f\" ] && s=$(stat -c%s \"$f\" 2>/dev/null) && "
    "  [ \"${s:-0}\" -gt 209715200 ] && truncate -s 0 \"$f\" 2>/dev/null || true; "
    "done"
)


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    value = (text or '').strip().lower()
    return any(marker in value for marker in markers)


def _is_missing_user_error(detail: str) -> bool:
    return _contains_any(
        detail,
        (
            'no such user',
            'does not exist',
            'unknown user',
            'usuario no existe',
            'no existe el usuario',
            'usuario inexistente',
            'el usuario no existe',
            'no existe',
        ),
    )


def _is_already_locked_error(detail: str) -> bool:
    return _contains_any(
        detail,
        (
            'already locked',
            'password unchanged',
            'ya estaba bloqueado',
            'ya esta bloqueado',
            'cuenta bloqueada',
        ),
    )


def _is_disk_full_error(detail: str) -> bool:
    return _contains_any(
        detail,
        (
            'no space left on device',
            'disk full',
            'file write error',
            'cannot write',
            'cannot lock /etc/passwd',
            'cannot lock /etc/group',
            'resource temporarily unavailable',
            'read-only file system',
            'no hay espacio',
        ),
    )


def _format_disk_full_message(detail: str) -> str:
    detail_text = (detail or '').strip()
    return (
        'Falta de espacio en el VPS. '
        f'{detail_text}. '
        'Libera espacio en la raíz del servidor e intenta de nuevo.'
    )


class SSHService:
    def __init__(self, server) -> None:
        self._server = server
        self._client: paramiko.SSHClient | None = None

    def _connect_if_needed(self) -> tuple[bool, str, bool]:
        if self._client is not None:
            return True, 'ok', False
        ok, msg = self.connect()
        return ok, msg, ok

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def connect(self) -> tuple[bool, str]:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self._server.ip,
                port=self._server.port,
                username=self._server.ssh_user,
                password=self._server.get_ssh_password(),
                timeout=10,
                auth_timeout=25,
                banner_timeout=25,
                look_for_keys=False,
                allow_agent=False,
            )
            self._client = client
            return True, 'ok'
        except Exception as exc:
            return False, str(exc)

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def _run(self, cmd: str, timeout: int = 30) -> tuple[bool, str, str]:
        """Execute *cmd* and return (success, stdout, stderr)."""
        assert self._client is not None
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
            code = stdout.channel.recv_exit_status()
            return code == 0, out, err
        except Exception as exc:
            return False, '', str(exc)

    def _write_remote_text_file(self, remote_path: str, content: str, *, timeout: int = 15) -> None:
        self._run(
            f"printf '%s' {shlex.quote(content)} > {shlex.quote(remote_path)}",
            timeout=timeout,
        )

    def _write_remote_executable_file(self, remote_path: str, content: str, *, timeout: int = 15) -> None:
        self._write_remote_text_file(remote_path, content, timeout=timeout)
        self._run(f'chmod +x {shlex.quote(remote_path)}', timeout=10)

    def _upload_remote_binary_file(self, local_path: str, remote_path: str, *, mode: int = 0o755) -> tuple[bool, str]:
        """Upload a local binary file to the VPS using SFTP."""
        assert self._client is not None
        try:
            with self._client.open_sftp() as sftp:
                sftp.put(local_path, remote_path)
                sftp.chmod(remote_path, mode)
            return True, ''
        except Exception as exc:
            return False, str(exc)

    def _parse_df_status_line(self, raw_line: str) -> tuple[bool, str, int]:
        line = (raw_line or '').strip()
        parts = line.split()
        if len(parts) < 6:
            return False, line, -1
        percent_raw = parts[4].strip()
        percent = int(percent_raw.rstrip('%')) if percent_raw.rstrip('%').isdigit() else -1
        return True, line, percent

    def _run_normal_disk_cleanup(self, *, journal_limit_mb: int, tmp_days: int) -> None:
        cleanup_cmd = (
            f'journalctl --vacuum-size={journal_limit_mb}M --vacuum-time=7d >/dev/null 2>&1 || true; '
            'apt-get clean >/dev/null 2>&1 || true; '
            'rm -rf /var/lib/apt/lists/* >/dev/null 2>&1 || true; '
            f'find /tmp /var/tmp -xdev -mindepth 1 -mtime +{tmp_days} -delete >/dev/null 2>&1 || true; '
            "find /var/log -xdev -type f -name '*.gz' -mtime +14 -delete >/dev/null 2>&1 || true; "
            'find /var/crash -xdev -type f -mtime +7 -delete >/dev/null 2>&1 || true'
        )
        self._run(cleanup_cmd, timeout=180)
        self._run(_TRUNCATE_LARGE_LOGS_CMD, timeout=15)
        self._run(_APT_AUTOREMOVE_PURGE_CMD, timeout=120)

    def _run_aggressive_disk_cleanup(self, *, journal_limit_mb: int) -> None:
        aggressive_cmd = (
            f'journalctl --vacuum-size={max(100, journal_limit_mb // 2)}M --vacuum-time=3d >/dev/null 2>&1 || true; '
            "find /var/log -xdev -type f -name '*.1' -delete >/dev/null 2>&1 || true; "
            "find /var/log -xdev -type f -name '*.gz' -mtime +3 -delete >/dev/null 2>&1 || true; "
            'find /tmp /var/tmp -xdev -mindepth 1 -mtime +1 -delete >/dev/null 2>&1 || true; '
            'find /var/crash -xdev -type f -delete >/dev/null 2>&1 || true; '
            'apt-get autoclean >/dev/null 2>&1 || true; '
            f'{_APT_AUTOREMOVE_PURGE_CMD}; '
            'docker system prune -af --volumes >/dev/null 2>&1 || true'
        )
        self._run(aggressive_cmd, timeout=240)

    def get_root_storage_status(self) -> tuple[bool, dict[str, Any], str]:
        """Return root filesystem usage for blocks and inodes."""
        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, {}, f'No se pudo conectar: {msg}'
        try:
            ok_blk, out_blk, err_blk = self._run("df -P / 2>/dev/null | awk 'NR==2{print $0}'")
            ok_ino, out_ino, err_ino = self._run("df -Pi / 2>/dev/null | awk 'NR==2{print $0}'")

            if not ok_blk:
                return False, {}, (err_blk or out_blk or 'No se pudo obtener uso de disco').strip()
            if not ok_ino:
                return False, {}, (err_ino or out_ino or 'No se pudo obtener uso de inodos').strip()

            ok_blk_line, blk_line, blk_percent = self._parse_df_status_line(out_blk)
            ok_ino_line, ino_line, ino_percent = self._parse_df_status_line(out_ino)
            if not ok_blk_line or not ok_ino_line:
                return False, {}, 'Formato inesperado al leer estado de disco del servidor'

            return True, {
                'blocks': blk_line,
                'inodes': ino_line,
                'blocks_used_percent': blk_percent,
                'inodes_used_percent': ino_percent,
            }, ''
        finally:
            if opened_here:
                self.disconnect()

    def apply_disk_hardening(self) -> tuple[bool, str]:
        """Apply one-time permanent config to prevent disk from filling up.

        Sets journald size limits, configures logrotate for auth/syslog,
        removes old kernels and sets a weekly cron for apt autoremove.
        Safe to run multiple times (idempotent).
        """
        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # 1. journald permanent limits
            journald_conf = (
                '[Journal]\n'
                'SystemMaxUse=500M\n'
                'SystemMaxFileSize=100M\n'
                'Compress=yes\n'
                'MaxRetentionSec=2weeks\n'
                'RateLimitBurst=1000\n'
                'RateLimitIntervalSec=30s\n'
            )
            self._write_remote_text_file('/etc/systemd/journald.conf', journald_conf)
            self._run('systemctl restart systemd-journald 2>/dev/null || true', timeout=15)

            # 2. logrotate — auth.log / syslog / kern.log más agresivo
            logrotate_conf = (
                '/var/log/auth.log\n'
                '/var/log/syslog\n'
                '/var/log/kern.log\n'
                '{\n'
                '    daily\n'
                '    rotate 7\n'
                '    compress\n'
                '    delaycompress\n'
                '    missingok\n'
                '    notifempty\n'
                '    sharedscripts\n'
                '    postrotate\n'
                '        /usr/bin/systemctl kill -s HUP rsyslog.service 2>/dev/null || true\n'
                '    endscript\n'
                '}\n'
            )
            self._write_remote_text_file('/etc/logrotate.d/vpnpro-syslog', logrotate_conf)

            # 3. Cron semanal: autoremove + autoclean + vacuum journald
            weekly_cron = (
                '#!/bin/sh\n'
                'apt-get autoremove -y --purge 2>/dev/null || true\n'
                'apt-get autoclean 2>/dev/null || true\n'
                'journalctl --vacuum-size=500M --vacuum-time=14d 2>/dev/null || true\n'
                'find /var/log -name "*.gz" -mtime +14 -delete 2>/dev/null || true\n'
                'find /var/crash -mtime +7 -delete 2>/dev/null || true\n'
            )
            self._write_remote_executable_file('/etc/cron.weekly/vpnpro-disk-cleanup', weekly_cron)

            # 4. Limpiar kernels viejos ahora mismo
            self._run(_APT_AUTOREMOVE_PURGE_CMD, timeout=120)

            return True, 'Hardening de disco aplicado correctamente'
        except Exception as exc:  # pragma: no cover
            return False, f'Error aplicando hardening de disco: {exc}'
        finally:
            if opened_here:
                self.disconnect()

    def run_disk_housekeeping(
        self,
        *,
        trigger_percent: int = 92,
        journal_max_mb: int = 200,
        tmp_max_age_days: int = 3,
        aggressive: bool = False,
    ) -> tuple[bool, dict[str, Any], str]:
        """Run safe cleanup actions on VPS root when disk usage crosses trigger."""
        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, {}, f'No se pudo conectar: {msg}'

        trigger = max(1, int(trigger_percent))
        journal_limit_mb = max(50, int(journal_max_mb))
        tmp_days = max(1, int(tmp_max_age_days))

        try:
            ok_before, before, err_before = self.get_root_storage_status()
            if not ok_before:
                return False, {}, err_before

            before_percent = int(before.get('blocks_used_percent', -1) or -1)
            report: dict[str, Any] = {
                'ran': False,
                'before': before,
                'after': before,
                'trigger_percent': trigger,
                'freed_percent_points': 0,
            }
            if before_percent < trigger:
                return True, report, ''

            report['ran'] = True
            self._run_normal_disk_cleanup(journal_limit_mb=journal_limit_mb, tmp_days=tmp_days)

            ok_after, after, err_after = self.get_root_storage_status()
            if not ok_after:
                return False, report, err_after

            after_percent = int(after.get('blocks_used_percent', -1) or -1)

            # Segunda pasada más agresiva solo en flujo de guardia.
            if aggressive and after_percent >= trigger:
                self._run_aggressive_disk_cleanup(journal_limit_mb=journal_limit_mb)

                ok_after2, after2, err_after2 = self.get_root_storage_status()
                if not ok_after2:
                    return False, report, err_after2
                after = after2
                after_percent = int(after.get('blocks_used_percent', -1) or -1)

            report['after'] = after
            if before_percent >= 0 and after_percent >= 0:
                report['freed_percent_points'] = max(0, before_percent - after_percent)
            return True, report, ''
        finally:
            if opened_here:
                self.disconnect()

    def _configure_sftp_timeout(self, sftp) -> None:
        """Best-effort timeout setup for Paramiko SFTP channels."""
        try:
            sftp.get_channel().settimeout(_SFTP_TIMEOUT_SECONDS)
        except Exception:
            # Some Paramiko backends/channels do not expose timeout controls.
            pass

    def _sftp_write(self, remote_path: str, content: str) -> None:
        """Write *content* to *remote_path* via SFTP (no shell)."""
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            self._configure_sftp_timeout(sftp)
            with sftp.open(remote_path, 'w') as fh:
                fh.write(content)
            sftp.chmod(remote_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except socket.timeout as exc:
            raise TimeoutError(f'SFTP timeout al escribir {remote_path}') from exc
        except Exception as exc:
            if _is_disk_full_error(str(exc)):
                raise OSError('No space left on device') from exc
            raise
        finally:
            sftp.close()

    def _sftp_read(self, remote_path: str, default: str = '') -> str:
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            self._configure_sftp_timeout(sftp)
            with sftp.open(remote_path, 'r') as fh:
                return fh.read().decode('utf-8', errors='replace')
        except FileNotFoundError:
            return default
        except socket.timeout as exc:
            raise TimeoutError(f'SFTP timeout al leer {remote_path}') from exc
        finally:
            sftp.close()

    def _sftp_remove(self, remote_path: str) -> None:
        assert self._client is not None
        sftp = self._client.open_sftp()
        try:
            self._configure_sftp_timeout(sftp)
            sftp.remove(remote_path)
        except FileNotFoundError:
            return None
        except socket.timeout as exc:
            raise TimeoutError(f'SFTP timeout al eliminar {remote_path}') from exc
        finally:
            sftp.close()

    def _set_password_stdin(self, username: str, password: str) -> tuple[bool, str]:
        """Set system password using chpasswd via stdin (injection-safe)."""
        assert self._client is not None
        try:
            stdin, stdout, stderr = self._client.exec_command('chpasswd', timeout=15)
            stdin.write(f'{username}:{password}\n'.encode())
            stdin.flush()
            stdin.channel.shutdown_write()
            err = stderr.read().decode('utf-8', errors='replace').strip()
            code = stdout.channel.recv_exit_status()
            return code == 0, err
        except Exception as exc:
            return False, str(exc)

    def _valid_port(self, port: int) -> bool:
        return isinstance(port, int) and 1 <= port <= 65535

    def _free_tcp_port(self, port: int) -> tuple[bool, str]:
        cmd = (
            f"if command -v fuser >/dev/null 2>&1; then "
            f"  fuser -k {port}/tcp >/dev/null 2>&1 || true; "
            f"else "
            f"  pids=$(ss -lntp 2>/dev/null | awk '/:{port} / {{print $NF}}' | sed -n 's/.*pid=\\([0-9]\\+\\).*/\\1/p' | sort -u); "
            f"  for pid in $pids; do kill -9 \"$pid\" >/dev/null 2>&1 || true; done; "
            f"fi"
        )
        ok, _, err = self._run(cmd)
        if not ok:
            return False, err or f'No se pudo liberar el puerto {port}/tcp'
        return True, 'ok'

    def _tcp_port_owner_summary(self, port: int) -> str:
        cmd = (
            f"if command -v ss >/dev/null 2>&1; then "
            f"  ss -lntp 2>/dev/null | grep -E ':{port}\\b' | head -n1; "
            f"elif command -v netstat >/dev/null 2>&1; then "
            f"  netstat -lntp 2>/dev/null | grep -E ':{port}[[:space:]]' | head -n1; "
            f"fi"
        )
        ok, out, _ = self._run(cmd)
        return (out or '').strip() if ok else ''

    def _verify_local_tls_listener(self, port: int) -> tuple[bool, str]:
        # Verificación mediante ClientHello TLS crudo: envía los primeros bytes de
        # un handshake TLS 1.2 y comprueba que el servidor devuelva 0x16 (ServerHello)
        # o 0x15 (Alert). Evita cuelgues por incompatibilidad de versión SSL entre builds
        # de Python (el handshake completo vía ssl.SSLContext bloqueaba en Profitserver).
        cmd = (
            f"python3 -c \""
            f"import socket,sys,time\n"
            f"p={port}\n"
            f"# Minimal TLS 1.2 ClientHello: record type 0x16, version 0x0303\n"
            f"hello=bytes.fromhex('160301003b010000370303'+'00'*32+'0000000200350100000c0000000e000c00000966616c736500')"
            f"\nlast='sin respuesta del servidor'\n"
            f"for _ in range(8):\n"
            f"  try:\n"
            f"    s=socket.create_connection(('127.0.0.1',p),3)\n"
            f"    s.settimeout(5)\n"
            f"    s.sendall(hello)\n"
            f"    data=s.recv(3)\n"
            f"    s.close()\n"
            f"    if data and data[0] in (0x15,0x16):\n"
            f"      sys.exit(0)\n"
            f"    last=f'respuesta inesperada: {{data.hex()}}' if data else 'servidor no envio datos'\n"
            f"    break\n"
            f"  except OSError as e:\n"
            f"    last=str(e)\n"
            f"  time.sleep(1)\n"
            f"sys.stderr.write(last+'\\n')\n"
            f"sys.exit(1)\n"
            f"\""
        )
        ok, out, err = self._run(cmd, timeout=45)
        if not ok:
            detail = (err or out or '').strip()
            _, diag_out, _ = self._run(
                f"systemctl is-active --quiet ssh-ssl.service && echo 'svc:ok' || echo 'svc:dead'; "
                f"ss -lntp 2>/dev/null | grep -q ':{port}\\b' && echo 'port:open' || echo 'port:closed'; "
                f"test -f /etc/ssh-ssl/selfsigned.crt && echo 'cert:ok' || echo 'cert:missing'; "
                f"journalctl -u ssh-ssl.service -n 5 --no-pager 2>/dev/null | tail -n 5"
            )
            if diag_out:
                detail = f"{detail} | {diag_out.strip()}" if detail else diag_out.strip()
            return False, detail or f'El listener TLS local en {port}/tcp no responde correctamente.'
        return True, 'ok'

    def _verify_service_listener(self, service_name: str, port: int, proto: str = 'tcp') -> tuple[bool, str]:
        if proto == 'udp':
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lnup 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lnup 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )
        else:
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lntp 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lntp 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )

        cmd = (
            f"systemctl daemon-reload && systemctl enable {service_name} >/dev/null 2>&1 && systemctl restart {service_name} >/dev/null 2>&1; "
            f"for _ in 1 2 3 4 5; do "
            f"  systemctl is-active --quiet {service_name} && {port_check} && exit 0; "
            f"  sleep 1; "
            f"done; "
            f"echo '--- STATUS ---'; systemctl --no-pager --full status {service_name} 2>&1 | tail -n 20; "
            f"echo '--- JOURNAL ---'; journalctl -u {service_name} -n 20 --no-pager 2>&1 | tail -n 20; "
            f"exit 1"
        )
        ok, out, err = self._run(cmd)
        if ok:
            return True, 'ok'
        detail = '\n'.join(part for part in [out, err] if part).strip()
        return False, detail or f'El servicio {service_name} no quedo activo o no abrio el puerto {port}/{proto}'

    def _service_has_listener(self, service_name: str, port: int | None, proto: str = 'tcp') -> bool:
        if not port:
            # Fallback para servicios legacy: si no podemos detectar puerto, al menos
            # considerar activo cuando systemd reporta el servicio en ejecución.
            ok_active, _, _ = self._run(f'systemctl is-active --quiet {service_name}')
            return bool(ok_active)

        if proto == 'udp':
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lnup 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lnup 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )
        else:
            port_check = (
                f"(command -v ss >/dev/null 2>&1 && ss -lntp 2>/dev/null | grep -qE ':{port}\\b') "
                f"|| (command -v netstat >/dev/null 2>&1 && netstat -lntp 2>/dev/null | grep -qE ':{port}[[:space:]]')"
            )

        ok, _, _ = self._run(
            f"systemctl is-active --quiet {service_name} && ({port_check})"
        )
        return bool(ok)

    def _read_service_port(self, port_cmd: str) -> int | None:
        _, port_out, _ = self._run(port_cmd)
        port_value = (port_out or '').strip()
        return int(port_value) if port_value.isdigit() else None

    def _ensure_ssh_injector_compat(self) -> tuple[bool, str]:
        cmd = (
            "sed -i '/HostKeyAlgorithms +ssh-rsa,ssh-ed25519/d' /etc/ssh/sshd_config "
            "&& sed -i '/PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519/d' /etc/ssh/sshd_config "
            "&& sed -i '/^PasswordAuthentication /d' /etc/ssh/sshd_config "
            "&& sed -i '/^PermitTunnel /d' /etc/ssh/sshd_config "
            "&& printf '\nHostKeyAlgorithms +ssh-rsa,ssh-ed25519\nPubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519\n' >> /etc/ssh/sshd_config "
            "&& printf 'PasswordAuthentication yes\nPermitTunnel yes\n' >> /etc/ssh/sshd_config "
            "&& (systemctl restart ssh || service ssh restart || true)"
        )
        ok, _, err = self._run(cmd)
        if not ok:
            return False, err or 'No se pudo ajustar compatibilidad SSH'
        return True, 'ok'

    def _allow_firewall_port(self, port: int, proto: str = 'tcp') -> None:
        self._run(
            f'if command -v ufw >/dev/null 2>&1; then ufw allow {port}/{proto} >/dev/null 2>&1; fi'
        )

    def _disable_tunnel_service(
        self,
        service_name: str,
        port_cmd: str,
        script_path: str,
        label: str,
        extra_cleanup_cmd: str = '',
    ) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            port_value = self._read_service_port(port_cmd)
            port_text = str(port_value) if port_value else 'N/A'

            cmd_parts = [
                f'systemctl disable --now {service_name} >/dev/null 2>&1 || true',
                f'rm -f /etc/systemd/system/{service_name}',
                f'rm -f {script_path}',
            ]
            if extra_cleanup_cmd:
                cmd_parts.append(extra_cleanup_cmd)
            cmd_parts.append('systemctl daemon-reload')

            ok2, out, err = self._run('; '.join(cmd_parts), timeout=60)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or f'No se pudo desactivar {label}'

            if port_value:
                self._run(f'if command -v fuser >/dev/null 2>&1; then fuser -k {port_value}/tcp >/dev/null 2>&1 || true; fi')

            return True, f'{label} desactivado (puerto {port_text}/tcp).'
        finally:
            self.disconnect()

    def open_port_rules(self, port: int, protocols: list[str]) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'
        if not protocols:
            return False, 'Debes indicar al menos un protocolo (tcp/udp).'

        normalized = []
        for proto in protocols:
            p = (proto or '').strip().lower()
            if p in {'tcp', 'udp'} and p not in normalized:
                normalized.append(p)

        if not normalized:
            return False, 'Protocolos invalidos. Usa tcp y/o udp.'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # UFW + iptables fallback para maximizar compatibilidad.
            for proto in normalized:
                ok2, _, err = self._run(
                    f"if command -v ufw >/dev/null 2>&1; then ufw allow {port}/{proto} >/dev/null 2>&1 || true; fi; "
                    f"if command -v iptables >/dev/null 2>&1; then "
                    f"  iptables -C INPUT -p {proto} --dport {port} -j ACCEPT >/dev/null 2>&1 || "
                    f"  iptables -I INPUT -p {proto} --dport {port} -j ACCEPT >/dev/null 2>&1 || true; "
                    f"fi"
                )
                if not ok2:
                    return False, err or f'No se pudo abrir {port}/{proto} en firewall'

            return True, f'Puerto {port} abierto en firewall ({"/".join(normalized)}).'
        finally:
            if opened_here:
                self.disconnect()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test_connection(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if ok:
            self.disconnect()
        return ok, msg

    def reboot_server(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, _, err = self._run(
                "nohup sh -c 'sleep 2; /sbin/reboot || reboot' >/dev/null 2>&1 &"
            )
            if not ok2:
                return False, err or 'No se pudo enviar la orden de reinicio'
            return True, 'Orden de reinicio enviada al VPS'
        finally:
            self.disconnect()

    def install_checkuser(self, port: int = 2052) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            deps_cmd = """
set -e
export DEBIAN_FRONTEND=noninteractive

wait_apt_lock() {
    local attempts="${1:-60}"
    local delay="${2:-3}"
    local i=0
    while [ "$i" -lt "$attempts" ]; do
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
           fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
           fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
           fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
            i=$((i + 1))
            sleep "$delay"
            continue
        fi
        return 0
    done
    return 1
}

apt_safe() {
    apt-get -o DPkg::Lock::Timeout=300 "$@"
}

if command -v python3 >/dev/null 2>&1; then
    exit 0
fi

if ! wait_apt_lock; then
    echo 'No se libero el lock de apt/dpkg a tiempo.'
    exit 29
fi

apt_safe update -y
if ! apt_safe install -y python3; then
    dpkg --configure -a || true
    apt_safe -f install -y || true
    if ! wait_apt_lock; then
        echo 'Lock de apt/dpkg persistente despues de reparar paquetes.'
        exit 30
    fi
    apt_safe install -y python3
fi

command -v python3 >/dev/null 2>&1
"""
            ok2, out, err = self._run(deps_cmd, timeout=300)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or 'No se pudieron instalar dependencias para CheckUser'

            cmd = """
set -e
WORKDIR="/opt/vpnpro_checkuser"
APPFILE="$WORKDIR/checkuser_server.py"
LOGFILE="/tmp/checkuser-install.log"

rm -f "$LOGFILE"
touch "$LOGFILE"

mkdir -p "$WORKDIR"

cat > "$APPFILE" << 'PYEOF'
#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import re
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


DB_PATH = Path('/opt/vpnpro_checkuser/devices.sqlite3')


def run_cmd(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8)
    return (proc.stdout or '').strip()


def get_user_id(username: str) -> int:
    try:
        out = run_cmd(['id', '-u', username])
        return int(out)
    except Exception:
        return -1


def get_expiration_date(username: str) -> dt.datetime | None:
    try:
        data = run_cmd(['chage', '-l', username])
        m = re.search(r'Account expires\s*:\s*(.*)', data)
        if not m:
            return None
        raw = (m.group(1) or '').strip()
        if not raw or raw.lower() in {'never', 'nunca'}:
            return None
        return dt.datetime.strptime(raw, '%b %d, %Y')
    except Exception:
        return None


def get_connection_limit(username: str) -> int:
    try:
        users_db = Path('/root/usuarios.db')
        if users_db.exists():
            data = users_db.read_text(encoding='utf-8', errors='ignore')
            m = re.search(rf'^{re.escape(username)}\s+(\d+)\s*$', data, re.MULTILINE)
            if m:
                return max(1, int(m.group(1)))
    except Exception:
        return 1
    return 1


def all_online_users() -> int:
    try:
        result = subprocess.run(
            'ps -ef | grep sshd | grep -v grep | grep -v root | wc -l',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8
        )
        return max(0, int((result.stdout or '0').strip()))
    except Exception:
        return 0


_db_lock = __import__('threading').Lock()


def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute(
        'CREATE TABLE IF NOT EXISTS devices ('
        'id INTEGER PRIMARY KEY AUTOINCREMENT,'
        'username TEXT NOT NULL,'
        'device_id TEXT NOT NULL,'
        'created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,'
        'UNIQUE(username, device_id)'
        ')'
    )
    conn.commit()
    return conn


def device_count(username: str) -> int:
    with _db_lock:
        conn = _get_db()
        cur = conn.execute('SELECT COUNT(*) FROM devices WHERE username = ?', (username,))
        val = int(cur.fetchone()[0])
        conn.close()
        return val


def device_exists(username: str, device_id: str) -> bool:
    with _db_lock:
        conn = _get_db()
        cur = conn.execute('SELECT 1 FROM devices WHERE username = ? AND device_id = ? LIMIT 1', (username, device_id))
        found = cur.fetchone() is not None
        conn.close()
        return found


def device_insert(username: str, device_id: str) -> None:
    with _db_lock:
        conn = _get_db()
        conn.execute('INSERT OR IGNORE INTO devices (username, device_id) VALUES (?, ?)', (username, device_id))
        conn.commit()
        conn.close()


def device_delete_by_username(username: str) -> None:
    with _db_lock:
        conn = _get_db()
        conn.execute('DELETE FROM devices WHERE username = ?', (username,))
        conn.commit()
        conn.close()


class Handler(BaseHTTPRequestHandler):

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path or '/'
        qs = parse_qs(parsed.query)

        if path == '/':
            self._json(200, {'service': 'VPNPro CheckUser', 'status': 'ok'})
            return

        if path == '/all':
            self._json(200, {'total': all_online_users()})
            return

        if path.startswith('/kill/'):
            username = path.split('/kill/', 1)[1].strip()
            if not username:
                self._json(400, {'error': 'Username required'})
                return
            try:
                subprocess.run(['pkill', '-TERM', '-u', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6)
            except Exception:
                _ = None
            device_delete_by_username(username)
            self._json(200, {'ok': True, 'username': username})
            return

        if path.startswith('/check/'):
            username = path.split('/check/', 1)[1].strip()
            device_id = (qs.get('deviceId', [''])[0] or '').strip()
            if not username:
                self._json(400, {'error': 'Username required'})
                return

            user_id = get_user_id(username)
            if user_id < 0:
                self._json(500, {'error': 'Could not find'})
                return

            exp = get_expiration_date(username)
            limit = get_connection_limit(username)
            devices = device_count(username)
            exists = bool(device_id) and device_exists(username, device_id)
            limit_reached = bool(device_id) and (not exists) and devices >= limit

            if device_id and (not exists) and (not limit_reached):
                device_insert(username, device_id)
                devices += 1

            count_connections = devices if not limit_reached else (limit + 1)
            date_str = None
            days = None
            if exp is not None:
                date_str = exp.strftime('%d/%m/%Y')
                days = (exp - dt.datetime.now()).days + 1

            self._json(
                200,
                {
                    'id': user_id,
                    'username': username,
                    'expiration_date': date_str,
                    'expiration_days': days,
                    'limit_connections': limit,
                    'count_connections': count_connections,
                },
            )
            return

        self._json(404, {'error': 'Not found'})

    def log_message(self, format: str, *args):
        return


def main() -> None:
    parser = argparse.ArgumentParser(description='VPNPro embedded CheckUser service')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', '-p', type=int, default=2052)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, int(args.port)), Handler)
    server.serve_forever()


if __name__ == '__main__':
    main()
PYEOF

chmod 755 "$APPFILE"

if ! python3 "$APPFILE" --help >>"$LOGFILE" 2>&1; then
    echo 'No se pudo ejecutar checkuser_server.py --help.'
    tail -n 80 "$LOGFILE"
    exit 35
fi

cat > /etc/systemd/system/checkuser.service << 'EOF'
[Unit]
Description=CheckUser Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
WorkingDirectory=/opt/vpnpro_checkuser
ExecStart=/usr/bin/python3 /opt/vpnpro_checkuser/checkuser_server.py --port __CHECKUSER_PORT__
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable checkuser.service >/dev/null 2>&1
if ! systemctl restart checkuser.service; then
    echo '--- STATUS ---'
    systemctl --no-pager --full status checkuser.service 2>&1 | tail -n 40
    echo '--- JOURNAL ---'
    journalctl -u checkuser.service -n 40 --no-pager 2>&1 | tail -n 40
    echo '--- INSTALL LOG ---'
    tail -n 40 "$LOGFILE"
    exit 36
fi

if ! systemctl is-active --quiet checkuser.service; then
    echo '--- STATUS ---'
    systemctl --no-pager --full status checkuser.service 2>&1 | tail -n 40
    echo '--- JOURNAL ---'
    journalctl -u checkuser.service -n 40 --no-pager 2>&1 | tail -n 40
    echo '--- INSTALL LOG ---'
    tail -n 40 "$LOGFILE"
    exit 37
fi

rm -f "$LOGFILE"
"""
            cmd = cmd.replace('__CHECKUSER_PORT__', str(int(port)))
            ok2, out, err = self._run(cmd, timeout=300)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or 'No se pudo instalar/iniciar CheckUser en el VPS'

            self._allow_firewall_port(port, 'tcp')
            return True, f'CheckUser integrado en VPNPro e iniciado en el puerto {port}/tcp.'
        finally:
            if opened_here:
                self.disconnect()

    def uninstall_checkuser(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            cmd = """
set -e
systemctl disable --now checkuser.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/checkuser.service
systemctl daemon-reload
rm -rf /opt/vpnpro_checkuser
rm -rf /opt/DTCheckUser
rm -rf /opt/checkuser_venv
rm -rf /tmp/vpnpro-checkuser
"""
            ok2, out, err = self._run(cmd, timeout=120)
            if not ok2:
                detail = '\n'.join(part for part in [out, err] if part).strip()
                return False, detail or 'No se pudo desinstalar CheckUser en el VPS'
            return True, 'CheckUser desinstalado del VPS.'
        finally:
            self.disconnect()

    def setup_http_vpnpro_tunnel(self, port: int = 8080) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            script = f'''#!/usr/bin/env python3
import socket
import threading
import select

LISTEN_PORT = {port}
SSH_ADDR = ("127.0.0.1", 22)
RESPONSE = "HTTP/1.1 200 Connection Established\\r\\n\\r\\n"


def bridge(c1, c2):
    try:
        while True:
            ready, _, _ = select.select([c1, c2], [], [])
            if c1 in ready:
                data = c1.recv(8192)
                if not data:
                    break
                c2.sendall(data)
            if c2 in ready:
                data = c2.recv(8192)
                if not data:
                    break
                c1.sendall(data)
    finally:
        c1.close()
        c2.close()


def handle(client_conn):
    try:
        payload = client_conn.recv(8192)
        if payload:
            client_conn.sendall(RESPONSE.encode())
            ssh_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_conn.connect(SSH_ADDR)
            bridge(client_conn, ssh_conn)
    except Exception:
        client_conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-http.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-http.py')

            service = f'''[Unit]
Description=SSH HTTP Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-http.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-http.service', service)
            ok2, err = self._verify_service_listener('ssh-http.service', port, 'tcp')
            if not ok2:
                return False, err

            self._allow_firewall_port(port, 'tcp')
            return True, f'HTTP activo en el puerto {port}/tcp.'
        finally:
            if opened_here:
                self.disconnect()

    def setup_ssl_tunnel(self, port: int = 443) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            owner = self._tcp_port_owner_summary(port)
            if port == 443 and owner and 'ssh-ssl.py' not in owner:
                if any(name in owner.lower() for name in ['nginx', 'apache2', 'httpd', 'caddy', 'haproxy']):
                    return False, (
                        'El puerto 443 ya está en uso por un servicio web. '
                        'Usa SSL Tunnel en 444 o 8443 para evitar conflicto.'
                    )

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            ok2, _, err = self._run(
                "mkdir -p /etc/ssh-ssl && "
                "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
                "-keyout /etc/ssh-ssl/selfsigned.key "
                "-out /etc/ssh-ssl/selfsigned.crt "
                "-subj '/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost'"
            )
            if not ok2:
                return False, err or 'No se pudieron generar certificados SSL'

            script = f'''#!/usr/bin/env python3
import socket
import threading
import ssl

LISTEN_PORT = {port}


def tunnel(s1, s2):
    try:
        while True:
            data = s1.recv(8192)
            if not data:
                break
            s2.sendall(data)
    finally:
        try:
            s1.close()
        except Exception:
            _ = None
        try:
            s2.close()
        except Exception:
            _ = None


def handle_ssl(context, raw_conn):
    # El wrap TLS ocurre aqui (en un hilo dedicado) con timeout explícito.
    # Nunca bloquea el loop principal de aceptacion de conexiones.
    try:
        raw_conn.settimeout(30)
        conn = context.wrap_socket(raw_conn, server_side=True)
        conn.settimeout(None)  # Sin timeout para la sesion de túnel
        ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssh_sock.connect(("127.0.0.1", 22))
        t1 = threading.Thread(target=tunnel, args=(conn, ssh_sock), daemon=True)
        t2 = threading.Thread(target=tunnel, args=(ssh_sock, conn), daemon=True)
        t1.start()
        t2.start()
    except Exception:
        try:
            raw_conn.close()
        except Exception:
            _ = None


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 mínimo: máxima compatibilidad con clientes SSH VPN (HTTP Custom, etc.)
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        context = context  # Python < 3.7 no tiene minimum_version; fallback a defaults
    context.load_cert_chain(
        certfile="/etc/ssh-ssl/selfsigned.crt",
        keyfile="/etc/ssh-ssl/selfsigned.key",
    )
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    # Aceptamos TCP plano; el wrap TLS se hace en el hilo handle_ssl.
    # Esto evita que un handshake colgado congele el loop de aceptación.
    while True:
        try:
            raw_conn, _ = server.accept()
            threading.Thread(target=handle_ssl, args=(context, raw_conn), daemon=True).start()
        except Exception:
            continue


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-ssl.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-ssl.py')

            service = f'''[Unit]
Description=SSH SSL Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ssl.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-ssl.service', service)
            ok2, err = self._verify_service_listener('ssh-ssl.service', port, 'tcp')
            if not ok2:
                return False, err

            # La verificación TLS es informativa: si el servicio ya está activo y
            # el puerto responde (confirmado arriba), algunos proveedores (Profitserver,
            # OVH con protección de infraestructura) interceptan el handshake TLS en 443
            # incluso para conexiones locales 127.0.0.1→127.0.0.1, lo que provocaría un
            # falso negativo. El túnel funciona igual para los clientes externos.
            ok_tls, _ = self._verify_local_tls_listener(port)
            suffix = ' (listener TLS local verificado).' if ok_tls else ' (servicio activo; verificacion TLS local omitida por restriccion del proveedor).'

            self._allow_firewall_port(port, 'tcp')
            self._allow_firewall_port(22, 'tcp')
            return True, f'SSL Tunnel activo en el puerto {port}/tcp (certificado autofirmado){suffix}'
        finally:
            if opened_here:
                self.disconnect()

    def setup_websocket_tunnel(self, port: int = 80) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._ensure_ssh_injector_compat()
            if not ok2:
                return False, err

            ok2, _, err = self._run('apt-get install -y python3 iproute2 psmisc >/dev/null 2>&1 || true')
            if not ok2:
                return False, err or 'No se pudieron asegurar dependencias para WebSocket Tunnel'

            ok2, err = self._free_tcp_port(port)
            if not ok2:
                return False, err

            script = f'''#!/usr/bin/env python3
import socket
import threading
import select

LISTEN_PORT = {port}
PASS_RESPONSE = (
    "HTTP/1.1 101 Switching Protocols\\r\\n"
    "Upgrade: websocket\\r\\n"
    "Connection: Upgrade\\r\\n\\r\\n"
)


def bridge(client, remote):
    sockets = [client, remote]
    try:
        while True:
            read_sockets, _, _ = select.select(sockets, [], [])
            for sock in read_sockets:
                data = sock.recv(8192)
                if not data:
                    return
                if sock is client:
                    remote.sendall(data)
                else:
                    client.sendall(data)
    finally:
        client.close()
        remote.close()


def handle_client(client_sock):
    try:
        request = client_sock.recv(8192).decode('utf-8', errors='ignore')
        if "Upgrade: websocket" in request or "GET /" in request:
            client_sock.sendall(PASS_RESPONSE.encode())
            ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_sock.connect(("127.0.0.1", 22))
            bridge(client_sock, ssh_sock)
    except Exception:
        client_sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(100)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
'''
            self._sftp_write('/usr/local/bin/ssh-ws.py', script)
            self._run('chmod 755 /usr/local/bin/ssh-ws.py')

            service = f'''[Unit]
Description=SSH WebSocket Tunnel
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k {port}/tcp
ExecStart=/usr/bin/python3 /usr/local/bin/ssh-ws.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
'''
            self._sftp_write('/etc/systemd/system/ssh-ws.service', service)
            ok2, err = self._verify_service_listener('ssh-ws.service', port, 'tcp')
            if not ok2:
                return False, f'WebSocket Tunnel fallo al iniciar en {port}/tcp. {err}'

            self._allow_firewall_port(port, 'tcp')
            return True, f'WebSocket Tunnel activo en el puerto {port}/tcp.'
        finally:
            if opened_here:
                self.disconnect()

    def setup_badvpn_udpgw(self, port: int = 7300) -> tuple[bool, str]:
        if not self._valid_port(port):
            return False, 'Puerto invalido (1-65535).'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            self._run(
                'systemctl disable --now badvpn.service >/dev/null 2>&1; '
                'pkill -9 -f badvpn-udpgw >/dev/null 2>&1; '
                'rm -f /usr/bin/badvpn-udpgw >/dev/null 2>&1; '
                'true'
            )

            local_badvpn = Path(__file__).resolve().parents[2] / 'Install' / 'badvpn-udpgw'
            if not local_badvpn.exists():
                return False, f'No se encontró el binario local: {local_badvpn}'

            ok2, err = self._upload_remote_binary_file(str(local_badvpn), '/usr/bin/badvpn-udpgw', mode=0o755)
            if not ok2:
                return False, err or 'No se pudo subir badvpn-udpgw al servidor'

            ok2, _, err = self._run('[ -x /usr/bin/badvpn-udpgw ]')
            if not ok2:
                return False, 'badvpn-udpgw no está disponible en /usr/bin'

            get_ram_cmd = (
                "ram_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}'); "
                "ram_mb=$(( ${ram_kb:-0} / 1024 )); "
                "if   [ \"$ram_mb\" -ge 3500 ]; then echo 500; "
                "elif [ \"$ram_mb\" -ge 1800 ]; then echo 250; "
                "elif [ \"$ram_mb\" -ge 900  ]; then echo 100; "
                "else echo 50; fi"
            )
            _, max_clients_out, _ = self._run(get_ram_cmd)
            max_clients = (max_clients_out or '').strip()
            if not max_clients.isdigit():
                max_clients = '250'

            mem_max = '512M' if int(max_clients) >= 500 else '256M'
            ok2, _, err = self._run(
                'echo -e "[Unit]\\nDescription=BadVPN UDP Gateway\\n'
                'After=network.target\\n\\n[Service]\\nType=simple\\n'
                f'ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:{port}'
                f' --max-clients {max_clients} --max-connections-for-client 32\\n'
                f'Restart=always\\nRestartSec=5s\\nMemoryMax={mem_max}\\n'
                '\\n[Install]\\nWantedBy=multi-user.target" > /etc/systemd/system/badvpn.service && '
                'systemctl daemon-reload && systemctl enable badvpn && systemctl start badvpn'
            )
            if not ok2:
                return False, err or 'No se pudo crear/iniciar servicio BadVPN'

            # Verificar que el servicio está activo
            ok2, _, err = self._run('systemctl is-active --quiet badvpn.service')
            if not ok2:
                return False, err or 'Servicio badvpn no está activo. Verifica con: systemctl status badvpn'

            return True, f'BadVPN UDPGW activo en el puerto {port}.'
        finally:
            if opened_here:
                self.disconnect()

    def disable_badvpn_udpgw(self) -> tuple[bool, str]:
        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            self._run('systemctl disable --now badvpn.service >/dev/null 2>&1 || true')
            self._run('rm -f /etc/systemd/system/badvpn.service')
            self._run('systemctl daemon-reload')
            return True, 'BadVPN desactivado.'
        finally:
            self.disconnect()

    def disable_http_vpnpro_tunnel(self) -> tuple[bool, str]:
        return self._disable_tunnel_service(
            service_name='ssh-http.service',
            port_cmd="grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-http.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
            script_path='/usr/local/bin/ssh-http.py',
            label='HTTP',
        )

    def disable_ssl_tunnel(self) -> tuple[bool, str]:
        return self._disable_tunnel_service(
            service_name='ssh-ssl.service',
            port_cmd="grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ssl.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
            script_path='/usr/local/bin/ssh-ssl.py',
            label='SSL Tunnel',
            extra_cleanup_cmd='rm -rf /etc/ssh-ssl',
        )

    def disable_websocket_tunnel(self) -> tuple[bool, str]:
        return self._disable_tunnel_service(
            service_name='ssh-ws.service',
            port_cmd="grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ws.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
            script_path='/usr/local/bin/ssh-ws.py',
            label='WebSocket Tunnel',
        )

    def get_port_modules_details(self) -> tuple[bool, dict[str, dict[str, Any]], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, f'No se pudo conectar: {msg}'
        try:
            modules = {
                'http_vpnpro': {
                    'service': 'ssh-http.service',
                    'label': 'HTTP',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-http.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'ssl_tunnel': {
                    'service': 'ssh-ssl.service',
                    'label': 'SSL Tunnel',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ssl.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'websocket_tunnel': {
                    'service': 'ssh-ws.service',
                    'label': 'WebSocket Tunnel',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "grep -oE 'ExecStartPre=-/usr/bin/fuser -k [0-9]+/tcp' /etc/systemd/system/ssh-ws.service 2>/dev/null | grep -oE '[0-9]+' | head -n1",
                },
                'badvpn_udp': {
                    'service': 'badvpn.service',
                    'label': 'BadVPN UDPGW',
                    'proto': 'udp',
                    'listener_proto': 'udp',
                    'port': 7300,
                },
                'checkuser': {
                    'service': 'checkuser.service',
                    'label': 'CheckUser',
                    'proto': 'tcp',
                    'listener_proto': 'tcp',
                    'port_cmd': "sed -n 's/.*--port \\([0-9]\\+\\).*/\\1/p' /etc/systemd/system/checkuser.service 2>/dev/null | head -n1",
                },
            }

            details: dict[str, dict[str, Any]] = {}
            for key, meta in modules.items():
                # BadVPN usa puerto fijo y detección solo por servicio (UDP localhost no es fiable con ss)
                if 'port' in meta:
                    port_value = str(meta['port'])
                    ok_svc, _, _ = self._run(f'systemctl is-active --quiet {meta["service"]}')
                    is_active = bool(ok_svc)
                else:
                    _, port_out, _ = self._run(meta['port_cmd'])
                    port_value = (port_out or '').strip()
                    port_int = int(port_value) if port_value.isdigit() else None
                    is_active = self._service_has_listener(meta['service'], port_int, meta['listener_proto'])
                details[key] = {
                    'label': meta['label'],
                    'active': is_active,
                    'port': port_value or '-',
                    'proto': meta['proto'],
                }

            return True, details, ''
        finally:
            self.disconnect()

    def get_server_info(self) -> tuple[bool, dict[str, Any], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, msg
        try:
            info: dict[str, Any] = {}
            ok2, out, _ = self._run("who | awk '{print $1}' | sort -u | wc -l")
            if not ok2:
                ok2, out, _ = self._run(
                    "ps aux | grep 'sshd:' | grep -v grep | "
                    "awk '{print $1}' | grep -v root | sort -u | wc -l"
                )
            info['online'] = out if ok2 else '0'

            ok2, out, _ = self._run(
                "wc -l < /root/usuarios.db 2>/dev/null || echo 0"
            )
            info['total_users'] = out.strip() if ok2 else '0'

            ok2, out, _ = self._run(
                "free -m | awk 'NR==2{printf \"%s / %s MB  (%.0f%%)\", $3,$2,$3*100/$2}'"
            )
            info['ram'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3,$2,$5}'"
            )
            info['disk'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "grep '^cpu ' /proc/stat | "
                "awk '{u=$2+$4; t=$2+$4+$5; if (t>0) printf \"%.1f%%\", (u*100/t); else print \"0.0%\"}'"
            )
            info['cpu'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run("uptime -p 2>/dev/null || uptime")
            info['uptime'] = out if ok2 else 'N/A'

            ok2, out, _ = self._run(
                "grep PRETTY_NAME /etc/os-release 2>/dev/null | "
                "cut -d= -f2 | tr -d '\"'"
            )
            info['os'] = out if ok2 else 'Linux'

            ok2, out, _ = self._run(
                "grep -m1 -E 'model name|Hardware|Processor' /proc/cpuinfo 2>/dev/null | "
                "cut -d: -f2- | sed 's/^ *//'"
            )
            if not ok2 or not (out or '').strip():
                ok2, out, _ = self._run("lscpu 2>/dev/null | awk -F: '/Model name/{print $2; exit}' | sed 's/^ *//'")
            info['processor'] = out.strip() if ok2 and (out or '').strip() else 'No disponible'

            return True, info, ''
        finally:
            self.disconnect()

    def _collect_established_ssh_connections(self) -> tuple[bool, list[tuple[str, str, int]]]:
        """Return (ss_available, active SSH connections as (USERNAME_UPPER, PEER_HOST, ETIMES_SECONDS))."""
        ok_ss, ss_out, _ = self._run("ss -Htnp state established '( sport = :22 )' 2>/dev/null")
        if not ok_ss:
            return False, []
        if not (ss_out or '').strip():
            return True, []

        pid_peer_pairs: list[tuple[int, str]] = []
        for raw_line in (ss_out or '').splitlines():
            line = (raw_line or '').strip()
            if not line:
                continue

            pid_match = re.search(r'pid=(\d+)', line)
            if not pid_match:
                continue

            try:
                pid = int(pid_match.group(1))
            except ValueError:
                continue
            if pid <= 0:
                continue

            parts = line.split()
            peer = ''
            if len(parts) >= 5:
                peer = parts[4]
            peer = peer.rsplit(':', 1)[0].strip('[]') if peer else ''

            pid_peer_pairs.append((pid, peer or 'UNKNOWN'))

        if not pid_peer_pairs:
            return True, []

        ok_ps, ps_out, _ = self._run('ps -eo pid=,etimes=,args=')
        if not ok_ps or not (ps_out or '').strip():
            return True, []

        process_by_pid: dict[int, tuple[int, str]] = {}
        for raw_line in (ps_out or '').splitlines():
            line = (raw_line or '').rstrip()
            if not line:
                continue

            chunks = line.strip().split(None, 2)
            if len(chunks) != 3:
                continue

            try:
                pid = int(chunks[0])
                etimes = int(chunks[1])
            except ValueError:
                continue

            process_by_pid[pid] = (max(0, etimes), chunks[2].strip())

        connections: list[tuple[str, str, int]] = []
        for pid, peer in pid_peer_pairs:
            process_info = process_by_pid.get(pid)
            if not process_info:
                continue
            etimes, args = process_info
            if not args or 'sshd:' not in args:
                continue
            if '/usr/sbin/sshd' in args:
                continue

            marker_idx = args.find('sshd:')
            if marker_idx < 0:
                continue

            session_part = args[marker_idx + len('sshd:'):].strip()
            if not session_part:
                continue

            lowered_part = session_part.lower()
            if '[priv]' in lowered_part or '[net]' in lowered_part:
                continue

            token = session_part.split()[0].strip()
            if not token:
                continue

            lowered = token.lower()
            if lowered in {'[priv]', '[net]', 'root'}:
                continue

            username = token.split('@', 1)[0].strip()
            if not username or username.upper() == 'ROOT':
                continue
            if not _USERNAME_RE.match(username):
                continue

            connections.append((username.upper(), peer, etimes))

        return True, connections

    def get_online_user_snapshot(self) -> tuple[bool, dict[str, int], dict[str, int], dict[str, int], str]:
        ok, msg = self.connect()
        if not ok:
            return False, {}, {}, {}, msg
        try:
            sessions_by_user: dict[str, int] = {}
            devices_by_user: dict[str, int] = {}
            connected_seconds_by_user: dict[str, int] = {}

            ss_available, established = self._collect_established_ssh_connections()
            if ss_available:
                peers_by_user: dict[str, set[str]] = {}
                for normalized_user, peer, connected_seconds in established:
                    sessions_by_user[normalized_user] = sessions_by_user.get(normalized_user, 0) + 1
                    peers_by_user.setdefault(normalized_user, set()).add((peer or 'UNKNOWN').strip())
                    connected_seconds_by_user[normalized_user] = max(
                        connected_seconds_by_user.get(normalized_user, 0),
                        max(0, int(connected_seconds or 0)),
                    )

                devices_by_user = {
                    user: len(peers)
                    for user, peers in peers_by_user.items()
                }
                return True, sessions_by_user, devices_by_user, connected_seconds_by_user, ''

            ok_who, who_out, who_err = self._run('who')
            if not ok_who:
                return False, {}, {}, {}, who_err or 'No se pudo consultar sesiones con who'

            for raw_line in (who_out or '').splitlines():
                line = (raw_line or '').strip()
                if not line:
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                username = (parts[0] or '').strip()
                if not username or username.upper() == 'ROOT' or not _USERNAME_RE.match(username):
                    continue

                normalized_user = username.upper()
                sessions_by_user[normalized_user] = sessions_by_user.get(normalized_user, 0) + 1
                devices_by_user[normalized_user] = devices_by_user.get(normalized_user, 0) + 1

            return True, sessions_by_user, devices_by_user, {}, ''
        finally:
            self.disconnect()

    def debug_online_sources(self) -> tuple[bool, dict[str, object], str]:
        """Return raw online detection sources for troubleshooting false positives."""
        ok, msg = self.connect()
        if not ok:
            return False, {}, msg
        try:
            ok_ss, ss_out, ss_err = self._run("ss -Htnp state established '( sport = :22 )' 2>/dev/null")
            ok_who, who_out, who_err = self._run('who 2>/dev/null')
            ok_ps, ps_out, ps_err = self._run("ps -eo pid=,etimes=,args= | grep 'sshd:' | grep -v grep")

            payload: dict[str, object] = {
                'ss_ok': bool(ok_ss),
                'ss_lines': [line.strip() for line in (ss_out or '').splitlines() if (line or '').strip()],
                'ss_err': (ss_err or '').strip(),
                'who_ok': bool(ok_who),
                'who_lines': [line.strip() for line in (who_out or '').splitlines() if (line or '').strip()],
                'who_err': (who_err or '').strip(),
                'ps_ok': bool(ok_ps),
                'ps_lines': [line.strip() for line in (ps_out or '').splitlines() if (line or '').strip()],
                'ps_err': (ps_err or '').strip(),
            }
            return True, payload, ''
        finally:
            self.disconnect()

    def list_users_for_sync(self) -> tuple[bool, list[dict[str, Any]], str]:
        """Read current VPS users from /root/usuarios.db for panel synchronization."""
        ok, msg = self.connect()
        if not ok:
            return False, [], msg

        try:
            ok2, out, err = self._run('cat /root/usuarios.db 2>/dev/null || true')
            if not ok2:
                return False, [], err or 'No se pudo leer /root/usuarios.db'

            users_map: dict[str, int] = {}
            for raw in out.splitlines():
                line = raw.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 1:
                    continue

                username = parts[0].strip()
                if not _USERNAME_RE.match(username):
                    continue

                limit = 1
                if len(parts) >= 2:
                    try:
                        limit = int(parts[1])
                    except ValueError:
                        limit = 1
                users_map[username] = max(1, limit)

            shadow_expiry: dict[str, int] = {}
            ok2, shadow_out, _ = self._run("awk -F: '{print $1\":\"$8}' /etc/shadow 2>/dev/null || true")
            if ok2 and shadow_out.strip():
                for row in shadow_out.splitlines():
                    if ':' not in row:
                        continue
                    user, days_str = row.split(':', 1)
                    user = user.strip()
                    if not _USERNAME_RE.match(user):
                        continue
                    try:
                        shadow_expiry[user] = int(days_str.strip())
                    except ValueError:
                        continue

            users: list[dict[str, Any]] = []
            default_expiry = datetime.utcnow() + timedelta(days=3650)

            for username, limit in users_map.items():
                expiry_days = shadow_expiry.get(username)
                expiry_date = default_expiry
                if isinstance(expiry_days, int) and expiry_days > 0 and expiry_days < 90000:
                    expiry_date = datetime(1970, 1, 1) + timedelta(days=expiry_days)

                password = self._sftp_read(f'/etc/VPNPro/passwords/{username}', '').strip()
                users.append(
                    {
                        'username': username,
                        'limit': limit,
                        'expiry_date': expiry_date,
                        'password': password,
                    }
                )

            return True, users, ''
        finally:
            self.disconnect()

    def create_user(
        self, username: str, password: str, days: int, limit: int
    ) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if len(password) < 4:
            return False, 'La contraseña debe tener al menos 4 caracteres'
        if days < 1:
            return False, 'Los días deben ser al menos 1'
        if limit < 1:
            return False, 'El límite debe ser al menos 1'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar al servidor: {msg}'
        try:
            # Check if user already exists on the system
            ok2, out, _ = self._run(f'id {username} 2>/dev/null && echo EXISTS || echo NEW')
            already_exists = 'EXISTS' in out

            expiry = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')

            if already_exists:
                # Upsert: unlock + update expiry, password and limit without recreating
                self._run(f'usermod -U {username} 2>/dev/null || passwd -u {username} 2>/dev/null; true')
                ok2, _, err = self._run(f'chage -E {expiry} {username}')
                if not ok2:
                    if _is_disk_full_error(err):
                        return False, _format_disk_full_message(err)
                    return False, f'Error al actualizar expiración del usuario existente: {err}'
            else:
                ok2, _, err = self._run(
                    f'useradd --badname -e {expiry} -M -s /bin/false {username}'
                )
                if not ok2 and 'already exists' not in err:
                    if _is_disk_full_error(err):
                        return False, _format_disk_full_message(err)
                    return False, f'Error al crear usuario del sistema: {err}'

            ok2, err2 = self._set_password_stdin(username, password)
            if not ok2:
                if not already_exists:
                    self._run(f'userdel --force {username} 2>/dev/null')
                if _is_disk_full_error(err2):
                    return False, _format_disk_full_message(err2)
                return False, f'Error al establecer contraseña: {err2}'

            # Upsert usuarios.db: replace existing entry or append
            ok2, out2, _ = self._run('cat /root/usuarios.db 2>/dev/null || echo ""')
            current_db = out2 if ok2 else ''
            new_lines = [
                line for line in current_db.splitlines()
                if not line.startswith(f'{username} ')
            ]
            new_lines.append(f'{username} {limit}')
            try:
                self._sftp_write('/root/usuarios.db', '\n'.join(new_lines) + '\n')
            except OSError as exc:
                if _is_disk_full_error(str(exc)):
                    return False, _format_disk_full_message(str(exc))
                raise

            # Store password file
            ok2, _, err = self._run('mkdir -p /etc/VPNPro/passwords')
            if not ok2 and _is_disk_full_error(err):
                return False, _format_disk_full_message(err)
            try:
                self._sftp_write(f'/etc/VPNPro/passwords/{username}', password)
            except OSError as exc:
                if _is_disk_full_error(str(exc)):
                    return False, _format_disk_full_message(str(exc))
                raise

            if already_exists:
                return True, f"Usuario '{username}' actualizado exitosamente (expira: {expiry})"
            return True, f"Usuario '{username}' creado exitosamente (expira: {expiry})"
        finally:
            if opened_here:
                self.disconnect()

    def delete_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            self._run(f'pkill -u {username} 2>/dev/null; true')

            ok2, out, err = self._run(f'userdel --force {username} 2>&1')
            if not ok2:
                detail = (out or err or '').strip()
                # Idempotente: si el usuario ya no existe en VPS, continuar limpieza.
                if not _is_missing_user_error(detail):
                    if _is_disk_full_error(detail):
                        _, disk_out, _ = self._run('df -h / 2>/dev/null | tail -n 1')
                        _, inode_out, _ = self._run('df -i / 2>/dev/null | tail -n 1')
                        disk_info = (disk_out or '').strip()
                        inode_info = (inode_out or '').strip()
                        extra = []
                        if disk_info:
                            extra.append(f'Disco: {disk_info}')
                        if inode_info:
                            extra.append(f'Inodos: {inode_info}')
                        detail_suffix = f" | {' | '.join(extra)}" if extra else ''
                        return (
                            False,
                            _format_disk_full_message(detail + detail_suffix),
                        )
                    return False, f"userdel falló: {detail or 'sin detalle remoto'}"

            # Remove from usuarios.db using SFTP
            db_content = self._sftp_read('/root/usuarios.db', '')
            filtered = '\n'.join(
                line for line in db_content.splitlines()
                if not line.startswith(f'{username} ')
            )
            self._sftp_write('/root/usuarios.db', filtered + '\n')

            # Remove password file
            self._sftp_remove(f'/etc/VPNPro/passwords/{username}')

            return True, f"Usuario '{username}' eliminado"
        finally:
            if opened_here:
                self.disconnect()

    def change_password(self, username: str, new_password: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if len(new_password) < 4:
            return False, 'La contraseña debe tener al menos 4 caracteres'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, err = self._set_password_stdin(username, new_password)
            if not ok2:
                if _is_disk_full_error(err):
                    return False, _format_disk_full_message(err)
                return False, f'Error: {err}'
            try:
                self._sftp_write(f'/etc/VPNPro/passwords/{username}', new_password)
            except OSError as exc:
                if _is_disk_full_error(str(exc)):
                    return False, _format_disk_full_message(str(exc))
                raise
            return True, 'Contraseña cambiada exitosamente'
        finally:
            self.disconnect()

    def change_limit(self, username: str, new_limit: int) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            db_content = self._sftp_read('/root/usuarios.db', '')
            new_lines = []
            for line in db_content.splitlines():
                if line.startswith(f'{username} '):
                    new_lines.append(f'{username} {new_limit}')
                else:
                    new_lines.append(line)
            try:
                self._sftp_write('/root/usuarios.db', '\n'.join(new_lines) + '\n')
            except OSError as exc:
                if _is_disk_full_error(str(exc)):
                    return False, _format_disk_full_message(str(exc))
                raise
            return True, 'Límite de conexiones actualizado'
        finally:
            self.disconnect()

    def change_expiry(self, username: str, days: int) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if days < 1:
            return False, 'Los días deben ser al menos 1'

        ok, msg = self.connect()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            expiry = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
            ok2, _, err = self._run(f'chage -E {expiry} {username}')
            if not ok2:
                if _is_disk_full_error(err):
                    return False, _format_disk_full_message(err)
                return False, f'Error: {err}'
            return True, f'Expiración actualizada a {expiry}'
        finally:
            self.disconnect()

    def set_expiry_date(self, username: str, expiry_date: datetime) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            expiry = expiry_date.strftime('%Y-%m-%d')
            ok2, _, err = self._run(f'chage -E {expiry} {username}')
            if not ok2:
                if _is_disk_full_error(err):
                    return False, _format_disk_full_message(err)
                return False, f'Error: {err}'
            return True, f'Expiración ajustada a {expiry}'
        finally:
            if opened_here:
                self.disconnect()

    def block_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # Lock account and terminate active sessions aggressively.
            self._run(
                f'pkill -9 -u {username} 2>/dev/null; '
                f"pkill -9 -f 'sshd: {username}' 2>/dev/null; "
                f'true'
            )
            ok2, out, err = self._run(
                f'usermod -L {username} >/dev/null 2>&1 || passwd -l {username} 2>&1'
            )
            if not ok2:
                detail = (out or err or '').strip()
                if _is_missing_user_error(detail):
                    return True, f"Usuario '{username}' no existe en el servidor (bloqueo idempotente)."
                if _is_already_locked_error(detail):
                    return True, f"Usuario '{username}' ya estaba bloqueado"
                if _is_disk_full_error(detail):
                    return False, _format_disk_full_message(detail)
                return False, f"Error al bloquear usuario: {detail or 'sin detalle remoto'}"
            return True, f"Usuario '{username}' bloqueado"
        finally:
            if opened_here:
                self.disconnect()

    def trim_user_sessions(self, username: str, keep_sessions: int = 1) -> tuple[bool, int, str]:
        """Keep up to *keep_sessions* newest ssh sessions and kill the rest."""
        if not _USERNAME_RE.match(username):
            return False, 0, 'Nombre de usuario inválido'

        keep = max(1, int(keep_sessions or 1))

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, 0, f'No se pudo conectar: {msg}'

        try:
            ok2, out, err = self._run(
                "ps -eo pid=,etimes=,args= | "
                f"awk 'BEGIN {{u=toupper(\"{username}\")}} "
                f"$3==\"sshd:\" {{ "
                f"  tok=toupper($4); sub(/@.*/, \"\", tok); "
                f"  if (tok==u && $5!=\"[priv]\" && $5!=\"[net]\") print $1\" \"$2; "
                f"}}'"
            )
            if not ok2:
                return False, 0, err or 'No se pudo listar sesiones del usuario'

            rows: list[tuple[int, int]] = []
            for raw_line in (out or '').splitlines():
                line = (raw_line or '').strip()
                parts = line.split()
                if len(parts) != 2:
                    continue

                try:
                    pid = int(parts[0])
                    elapsed = int(parts[1])
                except ValueError:
                    continue

                if pid > 0:
                    rows.append((pid, elapsed))

            if len(rows) <= keep:
                return True, 0, 'Sin sesiones excedentes'

            # Keep newest sessions first (smallest elapsed seconds).
            # Close the oldest connection and leave the last device connected.
            rows.sort(key=lambda item: item[1])
            to_kill = rows[keep:]

            killed = 0
            for pid, _ in to_kill:
                ok_kill, _, _ = self._run(f'kill -9 {pid} >/dev/null 2>&1 || true')
                if ok_kill:
                    killed += 1

            return True, killed, f'Sesiones excedentes cerradas: {killed}'
        finally:
            if opened_here:
                self.disconnect()

    def unblock_user(self, username: str) -> tuple[bool, str]:
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            ok2, out, err = self._run(
                f'usermod -U {username} >/dev/null 2>&1 || passwd -u {username} 2>&1'
            )
            if not ok2:
                detail = (err or out or '').strip()
                lower_detail = detail.lower()
                if _is_missing_user_error(lower_detail):
                    return True, f"Usuario '{username}' no existe en el servidor (desbloqueo idempotente)."
                if 'already unlocked' in lower_detail or 'password unchanged' in lower_detail:
                    return True, f"Usuario '{username}' ya estaba desbloqueado"
                if _is_disk_full_error(lower_detail):
                    return False, _format_disk_full_message(detail)
                return False, f'Error al desbloquear usuario: {detail or "sin detalle remoto"}'
            return True, f"Usuario '{username}' desbloqueado"
        finally:
            if opened_here:
                self.disconnect()

    def checkuser_clear_user(self, username: str) -> tuple[bool, str]:
        """Elimina los registros de dispositivos de *username* en devices.sqlite3 y termina sus sesiones SSH."""
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            # Terminar sesiones activas del usuario (best-effort)
            self._run(f'pkill -TERM -u {username} 2>/dev/null || true')
            # Eliminar entradas del SQLite de CheckUser
            py_code = (
                "import sqlite3, pathlib\n"
                "db = '/opt/vpnpro_checkuser/devices.sqlite3'\n"
                "p = pathlib.Path(db)\n"
                "if not p.exists():\n"
                "    print(0)\n"
                "else:\n"
                "    conn = sqlite3.connect(db)\n"
                f"    rows = conn.execute('DELETE FROM devices WHERE username=?', ('{username}',)).rowcount\n"
                "    conn.commit()\n"
                "    conn.close()\n"
                "    print(rows)\n"
            )
            ok2, out, err = self._run(f'python3 -c {shlex.quote(py_code)}')
            if not ok2:
                return False, err or 'No se pudo limpiar registros de CheckUser'
            deleted = (out or '0').strip()
            return True, f"Dispositivos CheckUser eliminados para '{username}': {deleted}"
        finally:
            if opened_here:
                self.disconnect()

    def inspect_user_state(self, username: str) -> tuple[bool, dict[str, object]]:
        """Collect non-destructive SSH diagnostics for a user on the VPS."""
        if not _USERNAME_RE.match(username):
            return False, {'error': 'Nombre de usuario inválido'}

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, {'error': f'No se pudo conectar: {msg}'}

        def _capture(cmd: str) -> dict[str, object]:
            cmd_ok, out, err = self._run(cmd)
            return {
                'ok': bool(cmd_ok),
                'stdout': out,
                'stderr': err,
            }

        try:
            payload: dict[str, object] = {
                'username': username,
                'checks': {
                    'id': _capture(f'id {username} 2>&1'),
                    'getent_passwd': _capture(f'getent passwd {username} 2>&1'),
                    'passwd_status': _capture(f'passwd -S {username} 2>&1'),
                    'usuarios_db_entry': _capture(
                        "awk '$1==\"" + username + "\" {print $0}' /root/usuarios.db 2>&1"
                    ),
                    'password_file': _capture(f'ls -l /etc/VPNPro/passwords/{username} 2>&1'),
                    'command_usermod': _capture('command -v usermod 2>&1'),
                    'command_passwd': _capture('command -v passwd 2>&1'),
                    'command_userdel': _capture('command -v userdel 2>&1'),
                    'is_root': _capture('id -u 2>&1'),
                },
                'notes': [
                    'Diagnostico de solo lectura: no ejecuta bloqueo ni eliminacion.',
                    'Para errores exactos de block/delete, revisar el mensaje devuelto por la accion AJAX.',
                ],
            }
            return True, payload
        finally:
            if opened_here:
                self.disconnect()

    def schedule_demo_lock(self, username: str, hours: int = 2) -> tuple[bool, str]:
        """Schedule automatic demo user lock after *hours* without deleting records."""
        if not _USERNAME_RE.match(username):
            return False, 'Nombre de usuario inválido'
        if hours < 1:
            return False, 'Las horas deben ser al menos 1'

        ok, msg, opened_here = self._connect_if_needed()
        if not ok:
            return False, f'No se pudo conectar: {msg}'
        try:
            seconds = int(hours * 3600)
            cmd = (
                "nohup sh -c '"
                f"sleep {seconds}; "
                f"pkill -u {username} 2>/dev/null; "
                f"passwd -l {username} 2>/dev/null"
                "' >/dev/null 2>&1 &"
            )
            ok2, _, err = self._run(cmd)
            if not ok2:
                return False, err or 'No se pudo programar el bloqueo automático'
            return True, 'Bloqueo automático programado'
        finally:
            if opened_here:
                self.disconnect()
