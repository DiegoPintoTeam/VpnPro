/* main.js — VPNPro Web Panel */

// ── Theme switcher ─────────────────────────────────────
(function () {
  const THEME_KEY = 'vpnpro-theme';
  const RANDOM_DAILY = 'random_daily';
  const THEMES = ['enterprise', 'carbon', 'oceanic', 'crimson', 'forest', 'midnight', 'solar', 'mono', 'neon', 'arctic'];
  const THEME_CLASSES = THEMES.map(name => `theme-${name}`);
  const select = document.getElementById('themeSelect');
  const body = document.body;

  function dailyTheme() {
    const now = new Date();
    const dayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
    let hash = 0;
    for (let i = 0; i < dayKey.length; i += 1) {
      hash = (hash * 31 + dayKey.charCodeAt(i)) >>> 0;
    }
    return THEMES[hash % THEMES.length];
  }

  function resolveTheme(theme) {
    let chosen = theme;
    if (chosen === RANDOM_DAILY) {
      chosen = dailyTheme();
    }

    if (!THEMES.includes(chosen)) {
      chosen = 'enterprise';
    }

    return chosen;
  }

  function applyTheme(theme) {
    const chosen = resolveTheme(theme);
    const nextClass = `theme-${chosen}`;

    // Remove only mismatched theme classes to avoid visual flicker.
    THEME_CLASSES.forEach((themeClass) => {
      if (themeClass !== nextClass && body.classList.contains(themeClass)) {
        body.classList.remove(themeClass);
      }
    });
    if (!body.classList.contains(nextClass)) {
      body.classList.add(nextClass);
    }

    if (select) {
      select.value = theme === RANDOM_DAILY ? RANDOM_DAILY : chosen;
      select.title = theme === RANDOM_DAILY ? `Tema del dia: ${chosen}` : '';
    }
  }

  applyTheme(localStorage.getItem(THEME_KEY) || 'enterprise');

  if (body.classList.contains('theme-preload')) {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        body.classList.remove('theme-preload');
      });
    });
  }

  if (select) {
    select.addEventListener('change', () => {
      const nextTheme = select.value;
      localStorage.setItem(THEME_KEY, nextTheme);
      applyTheme(nextTheme);
    });
  }
})();

// ── Uppercase search inputs (global) ────────────────
(function () {
  const SEARCH_SELECTOR = 'input[type="search"], input[placeholder*="Buscar"], input[id*="Search"], input[id*="search"]';

  function bindUppercase(input) {
    if (!(input instanceof HTMLInputElement)) return;
    if (input.dataset.uppercaseSearchBound === '1') return;

    input.style.textTransform = 'uppercase';
    input.setAttribute('autocapitalize', 'characters');
    input.dataset.uppercaseSearchBound = '1';

    input.addEventListener('input', function () {
      const upperValue = (this.value || '').toUpperCase();
      if (this.value !== upperValue) {
        this.value = upperValue;
      }
    });

    const initial = (input.value || '').toUpperCase();
    if (input.value !== initial) {
      input.value = initial;
    }
  }

  function scanAndBind(root) {
    if (!(root instanceof Element || root instanceof Document)) return;
    root.querySelectorAll(SEARCH_SELECTOR).forEach(bindUppercase);
  }

  scanAndBind(document);

  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.matches && node.matches(SEARCH_SELECTOR)) {
          bindUppercase(node);
        }
        scanAndBind(node);
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();

window.normalizeVpnUsernameInput = function normalizeVpnUsernameInput(value) {
  return String(value || '')
    .toUpperCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2212\uFE58\uFE63\uFF0D]/g, '-')
    .replace(/\s*-\s*/g, '-')
    .replace(/\s+/g, '');
};

// ── Sidebar toggle ──────────────────────────────────────
(function () {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const wrapper = document.getElementById('mainWrapper');
  const overlay = document.getElementById('sidebarOverlay');

  if (!toggle || !sidebar) return;

  function isMobile() {
    return window.innerWidth < 768;
  }

  function setToggleState(expanded) {
    toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  }

  function openSidebar() {
    sidebar.classList.add('open');
    if (overlay) overlay.classList.add('active');
    document.body.classList.add('sidebar-open');
    setToggleState(true);
  }

  function closeSidebar() {
    sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    document.body.classList.remove('sidebar-open');
    setToggleState(false);
  }

  setToggleState(true);

  toggle.addEventListener('click', () => {
    if (isMobile()) {
      if (sidebar.classList.contains('open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    } else {
      const collapsed = sidebar.style.width === '0px';
      if (collapsed) {
        sidebar.style.width = 'var(--sidebar-width)';
        sidebar.style.overflow = '';
        if (wrapper) wrapper.style.marginLeft = 'var(--sidebar-width)';
        setToggleState(true);
      } else {
        sidebar.style.width = '0px';
        sidebar.style.overflow = 'hidden';
        if (wrapper) wrapper.style.marginLeft = '0';
        setToggleState(false);
      }
    }
  });

  // Cerrar con el overlay (tap en el fondo oscuro)
  if (overlay) {
    overlay.addEventListener('click', () => {
      if (isMobile()) closeSidebar();
    });
  }

  // Close sidebar on outside click (mobile)
  document.addEventListener('click', (e) => {
    if (isMobile() && sidebar.classList.contains('open')) {
      if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
        closeSidebar();
      }
    }
  });
})();


// ── In-page banners (same visual style across views) ───
window.showPanelBanner = function showPanelBanner(message, category = 'success', timeoutMs = 4000) {
  const host = document.querySelector('.page-header') || document.querySelector('.content-area');
  if (!host) return;

  const alertDiv = document.createElement('div');
  alertDiv.className = `alert alert-${category} alert-dismissible fade show mb-3`;
  alertDiv.innerHTML = `${message} <button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
  host.insertAdjacentElement('afterend', alertDiv);

  if (timeoutMs > 0) {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alertDiv);
      bsAlert.close();
    }, timeoutMs);
  }
};

window.buildUserBlockAction = function buildUserBlockAction({
  user,
  blockActionTemplate,
  unblockActionTemplate,
}) {
  if (!user) return null;

  const userId = String(user.id || '');
  const username = String(user.username || '');
  const isBlocked = Boolean(user.is_blocked);

  if (isBlocked) {
    return {
      action: String(unblockActionTemplate || '').replace('999999', userId),
      msg: `¿Desbloquear el usuario '${username}'?`,
      btnClass: 'btn btn-success',
      title: 'Desbloquear usuario',
      icon: 'fas fa-lock-open',
    };
  }

  return {
    action: String(blockActionTemplate || '').replace('999999', userId),
    msg: `¿Bloquear el usuario '${username}'? Se cerrarán sus sesiones activas.`,
    btnClass: 'btn btn-warning',
    title: 'Bloquear usuario',
    icon: 'fas fa-user-lock',
  };
};

window.renderUserDaysCell = function renderUserDaysCell(user) {
  if (!user) return '<span class="text-success">0 día(s)</span>';
  if (user.is_expired) {
    return '<span class="text-danger fw-bold">Expirado</span>';
  }

  const days = Number(user.days_remaining || 0);
  if (days <= 3) {
    return `<span class="badge bg-warning text-dark">${days} día(s)</span>`;
  }
  return `<span class="text-success">${days} día(s)</span>`;
};

window.buildUserRenewInfo = function buildUserRenewInfo({ username = '', expiry = '', isExpired = false, days = 0 }) {
  let badge = '';
  if (isExpired) {
    badge = '<span class="badge bg-danger ms-1">EXPIRADO</span>';
  } else if (Number(days || 0) <= 3) {
    badge = `<span class="badge bg-warning text-dark ms-1">${Number(days || 0)} día(s)</span>`;
  }

  const safeUsername = String(username || '').trim();
  if (safeUsername) {
    return `<strong>Usuario:</strong> ${safeUsername}<br><strong>Vencimiento actual:</strong> ${expiry} ${badge}`;
  }
  return `<strong>Vencimiento actual:</strong> ${expiry} ${badge}`;
};

window.applyUserStateToRow = function applyUserStateToRow({
  row,
  user,
  renderDaysCell,
  getBlockAction,
}) {
  if (!row || !user) return;

  row.dataset.userState = user.is_blocked ? 'blocked' : (user.is_expired ? 'expired' : 'active');

  const limitCell = row.querySelector('.js-user-limit');
  if (limitCell) {
    limitCell.textContent = String(user.connection_limit || 1);
  }

  const expiryCell = row.querySelector('.js-user-expiry');
  if (expiryCell) {
    expiryCell.textContent = user.expiry_date || '';
  }

  const daysCell = row.querySelector('.js-user-days');
  if (daysCell && typeof renderDaysCell === 'function') {
    daysCell.innerHTML = renderDaysCell(user);
  }

  const stateBadge = row.querySelector('.user-state-badge');
  if (stateBadge) {
    if (user.is_blocked) {
      stateBadge.className = 'badge bg-warning text-dark user-state-badge';
      stateBadge.textContent = 'Bloqueado';
    } else if (user.is_expired) {
      stateBadge.className = 'badge bg-danger user-state-badge';
      stateBadge.textContent = 'Expirado';
    } else {
      stateBadge.className = 'badge bg-success user-state-badge';
      stateBadge.textContent = 'Activo';
    }
  }

  const blockForm = row.querySelector('.js-block-toggle-form');
  const blockBtn = blockForm ? blockForm.querySelector('button[type="submit"]') : null;
  if (!blockForm || !blockBtn || typeof getBlockAction !== 'function') {
    return;
  }

  const cfg = getBlockAction(user);
  if (!cfg) return;

  blockForm.action = cfg.action;
  blockForm.dataset.msg = cfg.msg;
  blockBtn.className = cfg.btnClass;
  blockBtn.title = cfg.title;
  blockBtn.innerHTML = `<i class="${cfg.icon}"></i>`;
};

window.initUserOnlineChecker = function initUserOnlineChecker({
  endpoint,
  intervalMs = 60000,
  badgeKey = 'username',
}) {
  if (!endpoint) return;

  const cadenceMs = Math.max(1000, Number(intervalMs) || 60000);
  const trimBannerCooldownMs = Math.max(30000, cadenceMs * 6);

  if (!window.__vpnproTrimBannerState || typeof window.__vpnproTrimBannerState !== 'object') {
    window.__vpnproTrimBannerState = {};
  }

  const normalizeUser = (value) => String(value || '').trim().toUpperCase();
  const buildEndpointUrl = () => {
    const url = new URL(endpoint, window.location.origin);
    const pageParams = new URLSearchParams(window.location.search);
    const isResellerUsersView = window.location.pathname.includes('/reseller/users');
    const visibleUserIds = Array.from(document.querySelectorAll('.online-badge[data-user-id]'))
      .map((badge) => Number.parseInt(String(badge.dataset.userId || '').trim(), 10))
      .filter((userId) => Number.isInteger(userId) && userId > 0);
    const rawServerId = isResellerUsersView ? '' : String(pageParams.get('server_id') || '').trim();
    const serverId = Number.parseInt(rawServerId, 10);
    const hasSingleServerFilter = Number.isInteger(serverId) && serverId > 0;
    const isSingleUserView = visibleUserIds.length === 1;

    if (visibleUserIds.length > 0) {
      url.searchParams.set('user_ids', Array.from(new Set(visibleUserIds)).join(','));
    }

    if (hasSingleServerFilter && !isResellerUsersView) {
      url.searchParams.set('server_id', String(serverId));
    }

    if (isSingleUserView || hasSingleServerFilter || isResellerUsersView) {
      url.searchParams.set('fresh', '1');
    }

    return url.toString();
  };
  const getBadgeLimit = (badge) => {
    const row = badge && typeof badge.closest === 'function' ? badge.closest('tr') : null;
    const limitCell = row ? row.querySelector('.js-user-limit') : null;
    const raw = limitCell ? String(limitCell.textContent || '').trim() : '';
    const parsed = Number.parseInt(raw, 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
    return 1;
  };

  const formatConnectedDuration = (seconds) => {
    const totalSeconds = Math.max(0, Number.parseInt(seconds, 10) || 0);

    let remaining = totalSeconds;
    const weeks = Math.floor(remaining / 604800);
    remaining %= 604800;
    const days = Math.floor(remaining / 86400);
    remaining %= 86400;
    const hours = Math.floor(remaining / 3600);
    remaining %= 3600;
    const minutes = Math.floor(remaining / 60);
    const secs = remaining % 60;

    const parts = [];
    if (weeks > 0) parts.push(`${weeks}w`);
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (secs > 0) parts.push(`${secs}s`);

    return parts.join(' ');
  };

  const paintStateBadge = (badge, info) => {
    const row = badge && typeof badge.closest === 'function' ? badge.closest('tr') : null;
    const stateBadge = row ? row.querySelector('.user-state-badge') : null;
    if (!stateBadge || !row) {
      return;
    }

    const baseState = String(row.dataset.userState || '').trim().toLowerCase();
    if (baseState === 'blocked') {
      stateBadge.className = 'badge bg-warning text-dark user-state-badge';
      stateBadge.textContent = 'Bloqueado';
      return;
    }
    if (baseState === 'expired') {
      stateBadge.className = 'badge bg-danger user-state-badge';
      stateBadge.textContent = 'Expirado';
      return;
    }

    const connectedSeconds = info ? Number(info.connected_seconds || 0) : 0;
    if (info && Number(info.sessions || 0) > 0 && connectedSeconds > 0) {
      stateBadge.className = 'badge bg-info text-dark user-state-badge';
      stateBadge.textContent = formatConnectedDuration(connectedSeconds);
      stateBadge.title = 'Tiempo conectado';
      return;
    }

    stateBadge.className = 'badge bg-success user-state-badge';
    stateBadge.textContent = 'Activo';
    stateBadge.title = '';
  };

  const paintOffline = () => {
    document.querySelectorAll('.online-badge').forEach((badge) => {
      const limit = getBadgeLimit(badge);
      badge.innerHTML = `<span class="badge bg-danger">0/${limit}</span>`;
      paintStateBadge(badge, null);
    });
  };

  const paintInitialSnapshot = () => {
    document.querySelectorAll('.online-badge').forEach((badge) => {
      const limit = getBadgeLimit(badge);
      badge.innerHTML = `<span class="badge bg-secondary">0/${limit}</span>`;
    });
  };

  const performOnlineCheck = () => {
    if (document.visibilityState === 'hidden') {
      return;
    }

    const timeoutMs = Math.max(5000, Math.min(20000, Math.floor(cadenceMs / 2)));
    let settled = false;
    let timeoutId = null;
    // Safety net: guarantees badges always resolve to a definitive state.
    const watchdogId = setTimeout(() => {
      if (!settled) {
        settled = true;
        paintOffline();
      }
    }, timeoutMs + 1000);

    let controller = null;
    const fetchOptions = {};
    if (typeof AbortController !== 'undefined') {
      controller = new AbortController();
      fetchOptions.signal = controller.signal;
      timeoutId = setTimeout(() => {
        try {
          controller.abort();
        } catch {
          // Ignore abort failures and let watchdog/catch paint offline.
        }
      }, timeoutMs);
    }

    fetch(buildEndpointUrl(), fetchOptions)
      .then(r => r.json())
      .then((data) => {
        if (settled) return;
        if (!data || !data.ok) {
          settled = true;
          paintOffline();
          return;
        }

        const trimmedSessions = Array.isArray(data.trimmed_sessions) ? data.trimmed_sessions : [];
        const autoBlockErrors = Array.isArray(data.errors) ? data.errors : [];

        if (trimmedSessions.length > 0 && typeof window.showPanelBanner === 'function') {
          const normalizedUsers = trimmedSessions
            .map((value) => String(value || '').trim().toUpperCase())
            .filter(Boolean)
            .sort();
          const signature = normalizedUsers.join('|');
          const now = Date.now();
          const lastShownAt = Number(window.__vpnproTrimBannerState[signature] || 0);

          if (!signature || (now - lastShownAt) >= trimBannerCooldownMs) {
            if (signature) {
              window.__vpnproTrimBannerState[signature] = now;
            }
            window.showPanelBanner(
              `Control de sesiones: se cerraron conexiones excedentes en ${trimmedSessions.join(', ')}`,
              'warning',
              7000,
            );
          }
        }
        if (autoBlockErrors.length > 0 && typeof window.showPanelBanner === 'function') {
          window.showPanelBanner(
            `Errores del control de sesiones: ${autoBlockErrors.join(' | ')}`,
            'danger',
            9000,
          );
        }

        const online = (data.online && typeof data.online === 'object') ? data.online : {};
        document.querySelectorAll('.online-badge').forEach((badge) => {
          const username = normalizeUser(badge.dataset.user);
          const key = badgeKey === 'userId' ? String(badge.dataset.userId || '') : username;
          const info = online[key];
          if (info && Number(info.sessions || 0) > 0) {
            badge.innerHTML = `<span class="badge bg-success">${info.sessions}/${info.limit}</span>`;
            paintStateBadge(badge, info);
          } else {
            const limit = (info && Number(info.limit || 0) > 0) ? Number(info.limit) : getBadgeLimit(badge);
            badge.innerHTML = `<span class="badge bg-danger">0/${limit}</span>`;
            paintStateBadge(badge, null);
          }
        });
        settled = true;
      })
      .catch(() => {
        if (settled) return;
        settled = true;
        paintOffline();
      })
      .finally(() => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
        clearTimeout(watchdogId);
      });
  };

  paintInitialSnapshot();
  performOnlineCheck();
  setInterval(performOnlineCheck, cadenceMs);
};

window.initUserModalBindings = function initUserModalBindings({
  pwdActionTemplate,
  limitActionTemplate,
  renewActionTemplate,
  renewInfoBuilder,
}) {
  if (pwdActionTemplate) {
    document.querySelectorAll('.btn-open-pwd-modal').forEach((btn) => {
      if (btn.dataset.pwdModalBound === '1') return;
      btn.dataset.pwdModalBound = '1';
      btn.addEventListener('click', function () {
        const userId = this.dataset.userId;
        const username = this.dataset.username || '';
        const form = document.getElementById('pwdModalForm');
        const title = document.getElementById('pwdModalTitle');
        if (form) form.action = pwdActionTemplate.replace('999999', userId);
        if (title) title.textContent = `Contraseña · ${username}`;
      });
    });
  }

  if (limitActionTemplate) {
    document.querySelectorAll('.btn-open-limit-modal').forEach((btn) => {
      if (btn.dataset.limitModalBound === '1') return;
      btn.dataset.limitModalBound = '1';
      btn.addEventListener('click', function () {
        const userId = this.dataset.userId;
        const username = this.dataset.username || '';
        const limit = this.dataset.limit || '1';
        const form = document.getElementById('limitModalForm');
        const title = document.getElementById('limitModalTitle');
        const input = document.getElementById('limitModalInput');
        if (form) form.action = limitActionTemplate.replace('999999', userId);
        if (title) title.textContent = `Límite · ${username}`;
        if (input) input.value = limit;
      });
    });
  }

  if (renewActionTemplate) {
    document.querySelectorAll('.btn-open-renew-modal, .btn-open-expiry-modal').forEach((btn) => {
      if (btn.dataset.renewModalBound === '1') return;
      btn.dataset.renewModalBound = '1';
      btn.addEventListener('click', function () {
        const userId = this.dataset.userId;
        const username = this.dataset.username || '';
        const expiry = this.dataset.expiry || '';
        const isExpired = this.dataset.isExpired === '1';
        const days = parseInt(this.dataset.daysRemaining || '0', 10);

        const form = document.getElementById('renewModalForm') || document.getElementById('expiryModalForm');
        const title = document.getElementById('renewModalTitle') || document.getElementById('expiryModalTitle');
        const info = document.getElementById('renewModalInfo') || document.getElementById('expiryModalInfo');

        if (form) form.action = renewActionTemplate.replace('999999', userId);
        if (title) title.textContent = `Renovar · ${username}`;
        if (info) {
          if (typeof renewInfoBuilder === 'function') {
            info.innerHTML = renewInfoBuilder({ username, expiry, isExpired, days });
          } else {
            let badge = '';
            if (isExpired) {
              badge = '<span class="badge bg-danger ms-1">EXPIRADO</span>';
            } else if (days <= 3) {
              badge = `<span class="badge bg-warning text-dark ms-1">${days} día(s)</span>`;
            }
            info.innerHTML = `<strong>Vencimiento actual:</strong> ${expiry} ${badge}`;
          }
        }
      });
    });
  }
};

window.initPasswordToggleBindings = function initPasswordToggleBindings({
  buttonSelector = '.btn-show-pwd',
  hiddenMask = '••••••',
}) {
  function setIconsState(container, isVisible) {
    if (!container) return;
    container.querySelectorAll('.btn-show-pwd i').forEach((icon) => {
      if (isVisible) {
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  }

  document.querySelectorAll(buttonSelector).forEach((btn) => {
    if (btn.dataset.passwordToggleBound === '1') return;
    btn.dataset.passwordToggleBound = '1';
    btn.addEventListener('click', function (e) {
      e.preventDefault();

      let span = this.previousElementSibling;
      if (!(span instanceof HTMLElement) || !span.classList.contains('pwd-hidden')) {
        const row = this.closest('tr');
        span = row ? row.querySelector('.pwd-hidden') : null;
      }
      if (!span) return;

      // Si la columna de contraseña está oculta (móvil), mostrar via modal
      const pwdCell = span.closest('td');
      if (pwdCell && getComputedStyle(pwdCell).display === 'none') {
        const pwd = span.dataset.pwd || '';
        const row = this.closest('tr');
        const usernameEl = row ? row.querySelector('.fw-semibold') : null;
        const username = usernameEl ? usernameEl.textContent.trim() : '';
        if (typeof window.showPanelNotice === 'function') {
          window.showPanelNotice({
            title: 'Contraseña',
            message: `<strong>${escapeHtml(username)}</strong><br><br><code style="font-size:1.1rem;letter-spacing:.05em;">${escapeHtml(pwd)}</code>`,
            category: 'info',
            buttonText: 'Cerrar',
            isHtml: true,
          });
        }
        return;
      }

      const rowContainer = this.closest('tr');
      if (span.textContent === hiddenMask) {
        span.textContent = span.dataset.pwd || '';
        setIconsState(rowContainer, true);
      } else {
        span.textContent = hiddenMask;
        setIconsState(rowContainer, false);
      }
    });
  });
};

window.initFormPasswordToggle = function initFormPasswordToggle({
  buttonSelector = '.btn-toggle-pwd-form',
  inputSelector = '.form-password-input',
} = {}) {
  document.querySelectorAll(buttonSelector).forEach((btn) => {
    if (btn.dataset.formPasswordToggleBound === '1') return;
    btn.dataset.formPasswordToggleBound = '1';

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      const input = this.parentElement.querySelector(inputSelector);
      if (!input) return;

      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';

      const icon = this.querySelector('i');
      if (icon) {
        if (isPassword) {
          icon.classList.remove('fa-eye');
          icon.classList.add('fa-eye-slash');
        } else {
          icon.classList.remove('fa-eye-slash');
          icon.classList.add('fa-eye');
        }
      }
    });
  });
};

window.initAjaxUserDeletion = function initAjaxUserDeletion({
  selector = '.btn-delete-user',
  getDeleteUrl,
  getUsername,
  removeRow,
}) {
  document.querySelectorAll(selector).forEach((btn) => {
    if (btn.dataset.ajaxDeleteBound === '1') return;
    btn.dataset.ajaxDeleteBound = '1';
    btn.addEventListener('click', async function () {
      const username = (typeof getUsername === 'function')
        ? getUsername(this)
        : (this.dataset.username || '');

      const isConfirmed = await window.confirmPanelAction({
        title: '¿Confirmar?',
        scope: 'USUARIOS VPN',
        message: `¿Eliminar el usuario '${username}' del servidor?`,
      });

      if (!isConfirmed) {
        return;
      }

      try {
        const url = (typeof getDeleteUrl === 'function') ? getDeleteUrl(this) : '';
        if (!url) {
          if (typeof window.showPanelBanner === 'function') {
            window.showPanelBanner('No se pudo resolver la URL de eliminación.', 'danger', 4500);
          }
          return;
        }

        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
          },
        });

        let data = null;
        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (response.ok && data && data.ok) {
          if (typeof removeRow === 'function') {
            removeRow(this);
          } else {
            const row = this.closest('tr');
            if (row) row.remove();
          }

          if (typeof window.showPanelBanner === 'function') {
            window.showPanelBanner(data.message || `Usuario '${username}' eliminado.`, data.category || 'success', 4000);
          }
        } else if (typeof window.showPanelBanner === 'function') {
          const errorMessage = (data && data.message) ? data.message : 'Error al eliminar usuario.';
          window.showPanelBanner(errorMessage, (data && data.category) || 'danger', 4500);
        }
      } catch (error) {
        console.error(error);
        if (typeof window.showPanelBanner === 'function') {
          window.showPanelBanner('Error de conexión.', 'danger', 4500);
        }
      }
    });
  });
};

window.removeUserRow = function removeUserRow(btn, tableInstance) {
  const row = btn && typeof btn.closest === 'function' ? btn.closest('tr') : null;
  if (!row) return;
  if (tableInstance && typeof tableInstance.row === 'function') {
    tableInstance.row(row).remove().draw();
    return;
  }
  row.remove();
};

window.initAjaxUserActionForms = function initAjaxUserActionForms({
  selector = '.js-ajax-user-action',
  onSuccess,
}) {
  document.querySelectorAll(selector).forEach((form) => {
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.ajaxBound === '1') return;
    form.dataset.ajaxBound = '1';

    form.addEventListener('submit', async function (e) {
      e.preventDefault();

      if (!lockFormSubmission(this)) {
        return;
      }

      try {
        if (this.classList.contains('form-confirm')) {
          const confirmed = await window.confirmPanelAction({
            title: this.dataset.confirmTitle || '¿Confirmar?',
            message: this.dataset.msg || '¿Confirmar esta acción?',
            scope: this.dataset.confirmScope || '',
            confirmText: this.dataset.confirmText || 'Sí, continuar',
            cancelText: this.dataset.cancelText || 'Cancelar',
          });
          if (!confirmed) {
            return;
          }
        }

        const formData = new FormData(this);
        const submitted = Object.fromEntries(formData.entries());
        const payload = new URLSearchParams();
        formData.forEach((value, key) => {
          payload.append(key, String(value));
        });

        const response = await fetch(this.action, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
          },
          body: payload.toString(),
        });

        let data = null;
        try {
          data = await response.json();
        } catch {
          data = null;
        }

        if (response.ok && data && data.ok) {
          if (typeof onSuccess === 'function') {
            onSuccess({ form: this, data, submitted });
          }

          if (typeof window.showPanelBanner === 'function' && data.message) {
            window.showPanelBanner(data.message, data.category || 'success', 4500);
          }

          const modalEl = this.closest('.modal');
          if (modalEl) {
            const instance = bootstrap.Modal.getInstance(modalEl) || bootstrap.Modal.getOrCreateInstance(modalEl);
            instance.hide();
          }
          return;
        }

        const errorMessage = (data && data.message) ? data.message : 'No se pudo completar la acción.';
        if (typeof window.showPanelBanner === 'function') {
          window.showPanelBanner(errorMessage, (data && data.category) || 'danger', 5000);
        }
      } catch (_error) {
        if (typeof window.showPanelBanner === 'function') {
          window.showPanelBanner('Error de conexión. Intenta nuevamente.', 'danger', 5000);
        }
      } finally {
        unlockFormSubmission(this);
      }
    });
  });
};


// ── Confirmation dialogs ────────────────────────────────
function escapeHtml(text) {
  return (text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

window.confirmPanelAction = async function confirmPanelAction({
  title = '¿Confirmar?',
  message = '¿Confirmar esta acción?',
  scope = '',
  confirmText = 'Sí, continuar',
  cancelText = 'Cancelar',
}) {
  const css = getComputedStyle(document.body);
  const escapedMessage = escapeHtml(message).replace(/\n/g, '<br>');
  const escapedScope = escapeHtml(scope);
  const html = `${escapedScope ? `<div style="font-weight:700;letter-spacing:.04em;margin-bottom:8px;">${escapedScope}</div>` : ''}<div>${escapedMessage}</div>`;

  const result = await Swal.fire({
    icon: 'warning',
    title,
    html,
    showCancelButton: true,
    confirmButtonColor: '#ef4444',
    cancelButtonColor: '#6b7280',
    confirmButtonText: confirmText,
    cancelButtonText: cancelText,
    background: css.getPropertyValue('--bg-card').trim() || '#111b27',
    color: css.getPropertyValue('--text-primary').trim() || '#e5edf5',
  });

  return result.isConfirmed;
};

function lockFormSubmission(form) {
  if (!form) return false;
  if (form.dataset.submitting === '1') return false;

  form.dataset.submitting = '1';
  form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach((el) => {
    if (el.dataset.prevDisabled == null) {
      el.dataset.prevDisabled = el.disabled ? '1' : '0';
    }
    el.disabled = true;
  });
  return true;
}

function unlockFormSubmission(form) {
  if (!form) return;
  delete form.dataset.submitting;
  form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach((el) => {
    const prevDisabled = el.dataset.prevDisabled === '1';
    el.disabled = prevDisabled;
    delete el.dataset.prevDisabled;
  });
}

window.addEventListener('pageshow', () => {
  document.querySelectorAll('form[data-submitting="1"]').forEach((form) => {
    unlockFormSubmission(form);
  });
});

window.showPanelNotice = async function showPanelNotice({
  title = 'Aviso',
  message = '',
  scope = '',
  category = 'info',
  buttonText = 'Entendido',
  isHtml = false,
}) {
  const css = getComputedStyle(document.body);
  const safeMessage = isHtml ? message : escapeHtml(message).replace(/\n/g, '<br>');
  const escapedScope = escapeHtml(scope);
  const html = `${escapedScope ? `<div style="font-weight:700;letter-spacing:.04em;margin-bottom:8px;">${escapedScope}</div>` : ''}<div>${safeMessage}</div>`;

  const iconMap = {
    success: 'success',
    warning: 'warning',
    danger: 'error',
    error: 'error',
    info: 'info',
  };

  await Swal.fire({
    icon: iconMap[category] || 'info',
    title,
    html,
    confirmButtonColor: '#ef4444',
    confirmButtonText: buttonText,
    background: css.getPropertyValue('--bg-card').trim() || '#111b27',
    color: css.getPropertyValue('--text-primary').trim() || '#e5edf5',
  });
};

if (Array.isArray(window.__panelNotices) && window.__panelNotices.length > 0) {
  (async () => {
    for (const notice of window.__panelNotices) {
      if (notice && notice.useConfirmStyle) {
        await window.confirmPanelAction({
          title: notice.title || '¿Confirmar?',
          message: notice.message || '',
          scope: notice.scope || '',
          confirmText: notice.confirmText || 'Sí, continuar',
          cancelText: notice.cancelText || 'Cancelar',
        });
      } else {
        await window.showPanelNotice(notice);
      }
    }
    window.__panelNotices = [];
  })();
}

window.showCreatedUserNotice = async function showCreatedUserNotice({
  username = '',
  password = '',
  expiryDate = '',
  serverName = '',
  connectionLimit = '',
  title = 'Usuario creado',
}) {
  const safeUsername = String(username || '').trim();
  const safePassword = String(password || '').trim();
  const safeExpiryDate = String(expiryDate || '').trim().split(' ')[0] || '';
  const safeServerName = String(serverName || '').trim();
  const safeConnectionLimit = String(connectionLimit || '').trim();
  if (!safeUsername || !safePassword) return;
  if (!window.matchMedia('(max-width: 640px)').matches) return;
  if (typeof window.showPanelNotice !== 'function') return;

  const rowStyle = [
    'display:flex',
    'justify-content:space-between',
    'align-items:flex-start',
    'gap:10px',
    'padding:8px 0',
    'border-bottom:1px solid rgba(148,163,184,.2)',
  ].join(';');
  const labelStyle = 'font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;font-weight:700;color:var(--text-muted,#94a3b8);';
  const valueStyle = 'font-size:.95rem;font-weight:600;color:var(--text-primary,#e5edf5);text-align:right;word-break:break-word;max-width:62%;';
  const passwordStyle = [
    'font-size:1rem',
    'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
    'letter-spacing:.05em',
    'padding:4px 8px',
    'border-radius:8px',
    'background:rgba(2,132,199,.12)',
    'border:1px solid rgba(2,132,199,.35)',
    'color:#bae6fd',
  ].join(';');

  const rows = [
    `<div style="${rowStyle}"><span style="${labelStyle}">Usuario</span><span style="${valueStyle}">${escapeHtml(safeUsername)}</span></div>`,
    `<div style="${rowStyle}"><span style="${labelStyle}">Contraseña</span><span style="${valueStyle}"><code style="${passwordStyle}">${escapeHtml(safePassword)}</code></span></div>`,
  ];
  if (safeExpiryDate) {
    rows.push(`<div style="${rowStyle}"><span style="${labelStyle}">Fecha de expiración</span><span style="${valueStyle}">${escapeHtml(safeExpiryDate)}</span></div>`);
  }
  if (safeConnectionLimit) {
    rows.push(`<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;padding:8px 0;"><span style="${labelStyle}">Límite de conexiones</span><span style="${valueStyle}">${escapeHtml(safeConnectionLimit)}</span></div>`);
  }
  if (safeServerName) {
    rows.push(`<div style="${rowStyle}"><span style="${labelStyle}">Servidor</span><span style="${valueStyle}">${escapeHtml(safeServerName)}</span></div>`);
  }

  await window.showPanelNotice({
    title,
    category: 'success',
    buttonText: 'Entendido',
    isHtml: true,
    message: `<div style="text-align:left;border:1px solid rgba(148,163,184,.18);border-radius:12px;padding:10px 12px;background:rgba(15,23,42,.22);">${rows.join('')}</div>`,
  });
};

document.querySelectorAll('.form-confirm:not(.js-ajax-user-action)').forEach(form => {
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const isConfirmed = await window.confirmPanelAction({
      title: this.dataset.confirmTitle || '¿Confirmar?',
      message: this.dataset.msg || '¿Confirmar esta acción?',
      scope: this.dataset.confirmScope || '',
      confirmText: this.dataset.confirmText || 'Sí, continuar',
      cancelText: this.dataset.cancelText || 'Cancelar',
    });
    if (isConfirmed) {
      if (!lockFormSubmission(this)) return;
      this.submit();
    }
  });
});

document.querySelectorAll('form').forEach(form => {
  const method = (form.getAttribute('method') || 'get').toLowerCase();
  if (method !== 'post') return;
  if (form.classList.contains('form-confirm')) return;
  if (form.classList.contains('js-ajax-user-action')) return;
  if (form.classList.contains('js-port-form')) return;
  if (form.dataset.allowMultiSubmit === '1') return;

  form.addEventListener('submit', function (e) {
    if (!lockFormSubmission(this)) {
      e.preventDefault();
    }
  });
});


// ── Auto-dismiss alerts after 5 s ──────────────────────
setTimeout(() => {
  document.querySelectorAll('.alert.alert-dismissible').forEach(el => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
    bsAlert.close();
  });
}, 5000);
