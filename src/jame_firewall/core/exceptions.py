"""Jerarquía tipada de excepciones de dominio para JameFirewall."""


class JameFirewallError(Exception):
    """Excepción base del sistema JameFirewall."""


class PrivilegesRequiredError(JameFirewallError):
    """Se requieren privilegios de Administrador de Windows (UAC) para la operación."""


class FirewallExecutionError(JameFirewallError):
    """Error al interactuar con el servicio de Firewall de Windows (netsh/powershell)."""


class ConfigStorageError(JameFirewallError):
    """Error al leer o persistir la configuración JSON en disco."""


class RegistryScanError(JameFirewallError):
    """Error al inspeccionar claves de instalación en el Registro de Windows."""


class OperationCancelledError(JameFirewallError):
    """El cierre interrumpió la operación antes del siguiente paso de I/O."""


class InstanceCoordinationError(JameFirewallError):
    """No se pudo establecer o liberar la exclusión segura entre procesos."""
