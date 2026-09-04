MSG_REQUIRED_FIELDS = 'Todos los campos son obligatorios.'
MSG_USERNAME_FORMAT = 'Formato de usuario invalido. Usa solo MAYUSCULAS con guion intermedio.'
MSG_DEMO_ALREADY_EXISTS = 'Ya tienes un demo activo. Solo se permite 1 demo por revendedor.'
MSG_DEMO_NAME_EXHAUSTED = 'No fue posible generar un nombre demo disponible. Intenta de nuevo.'


def msg_demo_create_failed(detail: str) -> str:
    return f'Error al crear usuario demo: {detail}'


def msg_demo_schedule_warning(detail: str) -> str:
    return f'Advertencia demo: no se pudo programar bloqueo automatico en servidor ({detail}).'


def msg_credits_insufficient(required: int, available: int, third_person: bool = False) -> str:
    verb = 'tiene' if third_person else 'tienes'
    return f'Creditos insuficientes. Requiere {required} y {verb} {available}.'
