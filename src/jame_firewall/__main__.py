"""Punto de entrada principal para el ejecutable JameFirewall."""

import contextlib
import sys
import traceback

from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter
from jame_firewall.presentation.windows.main_window import JameFirewallApp


def main() -> None:
    """Función de arranque de la aplicación JameFirewall."""
    uac = WindowsUACAdapter()

    # Si no es administrador en Windows, solicitar elevación
    if not uac.is_admin() and uac.request_elevation():
        sys.exit(0)

    try:
        container = AppContainer.create_production()
        app = JameFirewallApp(container)
        app.run()
    except Exception as ex:
        # Registrar fallo fatal de arranque
        err_trace = traceback.format_exc()
        with contextlib.suppress(OSError), open("crash_log.txt", "w", encoding="utf-8") as f:
            f.write(err_trace)
        print(f"Fatal Error in JameFirewall: {ex}", file=sys.stderr)


if __name__ == "__main__":
    main()
