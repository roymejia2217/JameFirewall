"""Ventana principal y controlador de interfaz de usuario para JameFirewall."""

import contextlib
import sys
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import messagebox
from tkinter.constants import BOTH, END, RIGHT, YES, X

import ttkbootstrap as ttk
from ttkbootstrap.widgets.scrolled import ScrolledText

from jame_firewall.core.entities import StatusSnapshot, SystemStatus
from jame_firewall.infrastructure.container import AppContainer
from jame_firewall.presentation import constants as C
from jame_firewall.presentation.queue_dispatcher import QueueDispatcher
from jame_firewall.presentation.windows.config_window import ConfigWindow


def get_resource_path(relative_path: str) -> Path:
    """Devuelve la ruta absoluta de un recurso, compatible con PyInstaller."""
    if getattr(sys, "frozen", False):
        base_path = Path(getattr(sys, "_MEIPASS", sys.executable))
    else:
        # Raíz del paquete
        base_path = Path(__file__).resolve().parent.parent.parent.parent
    return base_path / relative_path


class JameFirewallApp:
    """Controlador y vista principal de la aplicación de escritorio JameFirewall."""

    def __init__(self, container: AppContainer) -> None:
        self._container = container
        self._closing = False
        self.root = ttk.Window(themename=C.APP_THEME)
        self.root.title(C.APP_TITLE)
        self.root.geometry(C.APP_GEOMETRY)
        self.root.resizable(False, True)

        self.dispatcher = QueueDispatcher(root_tk=self.root, log_sink=self.append_log)

        self._setup_icons()
        self._setup_styles()
        self._setup_ui()
        self._start_async_init()

    def _setup_icons(self) -> None:
        icon_path = get_resource_path(C.APP_ICON_RESOURCE)
        if icon_path.exists():
            with contextlib.suppress(tk.TclError, AttributeError):
                self.root.iconbitmap(str(icon_path))

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 9, "bold"))
        style.configure("TLabelframe", padding=10)
        style.configure("TLabelframe.Label", font=("Helvetica", 10, "bold"))

    def _setup_ui(self) -> None:
        main_container = ttk.Frame(self.root, padding=10)
        main_container.pack(fill=BOTH, expand=YES)

        # === ESTADO DEL SISTEMA ===
        self.status_frame = ttk.Labelframe(
            main_container, text=C.LBL_SYSTEM_STATUS, style="TLabelframe"
        )
        self.status_frame.pack(fill=X, pady=(0, 10))

        status_container = ttk.Frame(self.status_frame)
        status_container.pack(fill=X, pady=5)

        self.status_label = ttk.Label(
            status_container,
            text=C.STATUS_LOADING,
            font=("Helvetica", 10, "bold"),
            bootstyle="light",
        )
        self.status_label.pack(anchor="w")

        self.rule_count_label = ttk.Label(
            status_container, text="", font=("Helvetica", 9), bootstyle="secondary", wraplength=320
        )
        self.rule_count_label.pack(anchor="w")

        status_btn_frame = ttk.Frame(self.status_frame)
        status_btn_frame.pack(fill=X, pady=(5, 0))

        self.refresh_button = ttk.Button(
            status_btn_frame,
            text=C.BTN_REFRESH,
            command=self._on_refresh_clicked,
            bootstyle="outline-light",
            width=15,
        )
        self.refresh_button.pack(side=RIGHT)

        self.config_button = ttk.Button(
            status_btn_frame,
            text=C.BTN_CONFIG,
            command=self._on_config_clicked,
            bootstyle="outline-secondary",
            width=15,
        )
        self.config_button.pack(side=RIGHT, padx=(0, 5))

        # === CONTROL DE FIREWALL ===
        self.actions_frame = ttk.Labelframe(
            main_container, text=C.LBL_FIREWALL_CONTROL, style="TLabelframe"
        )
        self.actions_frame.pack(fill=X, pady=(0, 10))

        self.block_button = ttk.Button(
            self.actions_frame,
            text=C.BTN_BLOCK,
            command=self._on_block_clicked,
            bootstyle="secondary",
            width=30,
        )
        self.block_button.pack(pady=5, fill=X)

        self.unblock_button = ttk.Button(
            self.actions_frame,
            text=C.BTN_UNBLOCK,
            command=self._on_unblock_clicked,
            bootstyle="secondary",
            width=30,
        )
        self.unblock_button.pack(pady=5, fill=X)

        # === REGISTRO DE ACTIVIDADES ===
        self.log_frame = ttk.Labelframe(
            main_container, text=C.LBL_ACTIVITY_LOG, style="TLabelframe"
        )
        self.log_frame.pack(fill=BOTH, expand=YES)

        self.log_text = ScrolledText(
            self.log_frame,
            height=10,
            width=50,
            font=("Consolas", 8),
            autohide=True,
            bootstyle="secondary",
        )
        self.log_text.pack(fill=BOTH, expand=YES, padx=5, pady=5)

        self.log_text.text.tag_config("prefix", foreground="#888888", font=("Consolas", 8, "bold"))
        self.log_text.text.tag_config("info", foreground="#ffffff")
        self.log_text.text.tag_config("warn", foreground="#ffcc00")
        self.log_text.text.tag_config("err", foreground="#ff5555")
        self.log_text.text.tag_config("ok", foreground="#55ff55")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def append_log(self, message: str, level: str = "info") -> None:
        """Agrega un mensaje con código de color en el widget de log."""
        self.log_text.text.config(state="normal")
        prefix = C.LOG_INFO
        tag = "info"

        if level in ("ok", "success"):
            prefix = C.LOG_OK
            tag = "ok"
        elif level in ("warn", "warning"):
            prefix = C.LOG_WARN
            tag = "warn"
        elif level in ("err", "error"):
            prefix = C.LOG_ERR
            tag = "err"

        self.log_text.text.insert(END, f"{prefix} ", "prefix")
        self.log_text.text.insert(END, f"{message[:4096]}\n", tag)
        lines = int(self.log_text.text.index("end-1c").split(".")[0])
        if lines > 2000:
            self.log_text.text.delete("1.0", f"{lines - 2000 + 1}.0")
        self.log_text.text.see(END)
        self.log_text.text.config(state="disabled")

    def _set_buttons_state(self, state: str) -> None:
        self.block_button.config(state=state)
        self.unblock_button.config(state=state)
        self.refresh_button.config(state=state)
        self.config_button.config(state=state)

    def _submit_operation(self, worker: Callable[[], None]) -> None:
        if self._closing or self.dispatcher.is_busy:
            return
        self._set_buttons_state("disabled")
        if not self.dispatcher.submit_background_task(worker, on_complete=self._finish_operation):
            self._finish_operation()

    def _finish_operation(self) -> None:
        if self._closing:
            return
        if self._container.uac.is_admin():
            self._set_buttons_state("normal")
        else:
            self._disable_buttons_no_admin()

    def _start_async_init(self) -> None:
        def worker() -> None:
            try:
                is_admin = self._container.uac.is_admin()
                self.dispatcher.post_log(C.MSG_ADMIN_CHECK, "info")
                if is_admin:
                    self.dispatcher.post_log(C.MSG_ADMIN_OK, "ok")
                    snapshot = self._container.audit_use_case.execute(
                        self._container.config_use_case.get_directories()
                    )
                    self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
                else:
                    self.dispatcher.post_log(C.MSG_NO_ADMIN, "warn")
                    self.dispatcher.post_ui_update(self._disable_buttons_no_admin)
            except Exception as ex:
                self._report_error(f"Error de auditoría inicial: {ex}")

        self._submit_operation(worker)

    def _update_status_ui(self, snapshot: StatusSnapshot) -> None:
        self.rule_count_label.config(text=snapshot.detail)
        if snapshot.status == SystemStatus.PROTECTED:
            self.status_label.config(text=C.STATUS_PROTECTED, bootstyle="success")
        elif snapshot.status == SystemStatus.UNPROTECTED:
            self.status_label.config(text=C.STATUS_UNPROTECTED, bootstyle="warning")
        elif snapshot.status == SystemStatus.PARTIAL:
            self.status_label.config(text=C.STATUS_PARTIAL, bootstyle="warning")
        elif snapshot.status == SystemStatus.NO_ADMIN_PRIVILEGES:
            self._disable_buttons_no_admin()
        else:
            self.status_label.config(text=C.STATUS_ERROR, bootstyle="danger")

    def _report_error(self, message: str) -> None:
        self.dispatcher.post_log(message, "err")
        snapshot = StatusSnapshot(SystemStatus.ERROR, 0, message)
        self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))

    def _disable_buttons_no_admin(self) -> None:
        self._set_buttons_state("disabled")
        self.status_label.config(text=C.STATUS_REQ_ADMIN, bootstyle="danger")

    def _on_refresh_clicked(self) -> None:
        if self._closing or self.dispatcher.is_busy:
            return
        self.dispatcher.post_log("Actualizando estado del firewall...", "info")

        def worker() -> None:
            try:
                snapshot = self._container.audit_use_case.execute(
                    self._container.config_use_case.get_directories()
                )
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
                self.dispatcher.post_log(
                    "Estado actualizado"
                    if snapshot.status != SystemStatus.ERROR
                    else snapshot.detail,
                    "info" if snapshot.status != SystemStatus.ERROR else "err",
                )
            except Exception as ex:
                self._report_error(f"Error al actualizar: {ex}")

        self._submit_operation(worker)

    def _on_block_clicked(self) -> None:
        if self._closing or self.dispatcher.is_busy:
            return
        if not self._container.uac.is_admin():
            messagebox.showerror("JameFirewall", "Se requieren privilegios de administrador.")
            return

        def worker() -> None:
            try:
                self.dispatcher.post_log(f"=== {C.BTN_BLOCK} ===", "info")
                dirs = self._container.config_use_case.get_directories()

                summary = self._container.block_use_case.execute(
                    dirs, on_progress=self.dispatcher.post_log
                )
                self.dispatcher.post_log(
                    C.MSG_SUCCESS_BLOCK if not summary.failed_count else "Bloqueo incompleto",
                    "ok" if not summary.failed_count else "err",
                )
                self.dispatcher.post_log(
                    f"+{summary.blocked_count} bloqueados / Omitidos: {summary.skipped_count} / "
                    f"Fallidos: {summary.failed_count}",
                    "ok" if not summary.failed_count else "err",
                )
                snapshot = self._container.audit_use_case.execute(
                    self._container.config_use_case.get_directories()
                )
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
            except Exception as ex:
                self._report_error(f"Error de bloqueo: {ex}")

        self._submit_operation(worker)

    def _on_unblock_clicked(self) -> None:
        if self._closing or self.dispatcher.is_busy:
            return
        if not self._container.uac.is_admin():
            messagebox.showerror("JameFirewall", "Se requieren privilegios de administrador.")
            return

        def worker() -> None:
            try:
                self.dispatcher.post_log(f"=== {C.BTN_UNBLOCK} ===", "info")
                summary = self._container.unblock_use_case.execute(
                    on_progress=self.dispatcher.post_log
                )
                self.dispatcher.post_log(
                    C.MSG_SUCCESS_UNBLOCK if not summary.failed_count else "Desbloqueo incompleto",
                    "ok" if not summary.failed_count else "err",
                )
                if summary.retained_legacy_count:
                    self.dispatcher.post_log(
                        f"{summary.retained_legacy_count} reglas antiguas conservadas. "
                        "Revíselas en Windows Defender Firewall antes de eliminarlas.",
                        "warn",
                    )
                self.dispatcher.post_log(
                    f"-{summary.removed_count} reglas eliminadas / Fallidas: {summary.failed_count}",
                    "ok" if not summary.failed_count else "err",
                )
                snapshot = self._container.audit_use_case.execute(
                    self._container.config_use_case.get_directories()
                )
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
            except Exception as ex:
                self._report_error(f"Error de desbloqueo: {ex}")

        self._submit_operation(worker)

    def _on_config_clicked(self) -> None:
        if self._closing or self.dispatcher.is_busy:
            return
        ConfigWindow(
            parent=self.root,
            manage_config_uc=self._container.config_use_case,
            on_saved_callback=lambda msg: self.append_log(msg, "ok"),
        )

    def _on_close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._set_buttons_state("disabled")
        self.status_label.config(
            text="Cerrando: esperando la operación en curso...", bootstyle="warning"
        )
        self._container.cancellation.cancel()
        self.dispatcher.shutdown()
        self._wait_for_close()

    def _wait_for_close(self) -> None:
        if self.dispatcher.is_idle:
            self.dispatcher.shutdown(wait=True)
            self.root.destroy()
        else:
            self.root.after(100, self._wait_for_close)

    def run(self) -> None:
        self.root.mainloop()
