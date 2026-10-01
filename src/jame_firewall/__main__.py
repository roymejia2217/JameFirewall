"""Punto de entrada principal para el ejecutable JameFirewall."""

import contextlib
import ctypes
import sys
import traceback

from jame_firewall.core.exceptions import ConfigStorageError, InstanceCoordinationError
from jame_firewall.core.ports import InstanceLockPort
from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.infrastructure.os.instance_lock import WindowsInstanceLock
from jame_firewall.infrastructure.os.uac_manager import WindowsUACAdapter
from jame_firewall.presentation.windows.main_window import JameFirewallApp


def _notify_startup(message: str, *, duplicate: bool = False, error: bool = False) -> None:
    """Native startup notice, without creating another Tk interpreter or loading config."""
    title = "JameFirewall - instancia activa" if duplicate else "JameFirewall"
    if sys.platform == "win32":
        try:
            loader = getattr(ctypes, "WinDLL", None)
            if loader is None:
                raise OSError("Windows notification API is unavailable")
            user32 = loader("user32", use_last_error=True, winmode=0x800)
            show = user32.MessageBoxW
            show.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
            show.restype = ctypes.c_int32
            if show(None, message, title, 0x10000 | (0x10 if error else 0x40)):
                return
        except OSError:
            pass
    print(f"{title}: {message}", file=sys.stderr)


def main() -> None:
    """Elevate first, then hold machine-wide exclusion throughout the application lifetime."""
    try:
        uac = WindowsUACAdapter()
        if not uac.is_admin():
            if not uac.request_elevation():
                _notify_startup(
                    "Se requieren privilegios de administrador para abrir JameFirewall.", error=True
                )
            # The elevated child obtains its own lock; the parent never claims ownership.
            return

        instance: InstanceLockPort = WindowsInstanceLock()
        if not instance.acquire():
            _notify_startup(
                "JameFirewall ya está abierto en este equipo. Utilice la instancia existente.",
                duplicate=True,
            )
            return
        app: JameFirewallApp | None = None
        try:
            container = AppContainer.create_production()
            app = JameFirewallApp(container)
            app.run()
        finally:
            if app is not None:
                app.dispose()
            # If worker cleanup fails, retain ownership until actual process termination.
            instance.release()
    except ConfigStorageError as ex:
        print(f"JameFirewall configuration error: {ex}", file=sys.stderr)
        _notify_startup(str(ex), error=True)
    except InstanceCoordinationError as ex:
        print(f"JameFirewall coordination error: {ex}", file=sys.stderr)
        _notify_startup(f"No se pudo comprobar la exclusión entre instancias: {ex}", error=True)
    except Exception as ex:
        err_trace = traceback.format_exc()
        with contextlib.suppress(OSError), open("crash_log.txt", "w", encoding="utf-8") as f:
            f.write(err_trace)
        print(f"Fatal Error in JameFirewall: {ex}", file=sys.stderr)
        _notify_startup(f"No se pudo iniciar JameFirewall: {ex}", error=True)


if __name__ == "__main__":
    main()
