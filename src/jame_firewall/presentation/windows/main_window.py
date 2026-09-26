"""Ventana principal y controlador de interfaz de usuario para JameFirewall."""

import contextlib
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from tkinter.constants import BOTH, END, RIGHT, YES, X
from typing import Any

import ttkbootstrap as ttk
from ttkbootstrap.widgets.scrolled import ScrolledText

from jame_firewall.core.entities import SystemStatus
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
        icon_path = get_resource_path("res/icon/128.ico")
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
            status_container, text="", font=("Helvetica", 9), bootstyle="secondary"
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
        self.log_text.text.insert(END, f"{message}\n", tag)
        self.log_text.text.see(END)
        self.log_text.text.config(state="disabled")

    def _set_buttons_state(self, state: str) -> None:
        self.block_button.config(state=state)
        self.unblock_button.config(state=state)
        self.refresh_button.config(state=state)

    def _start_async_init(self) -> None:
        def worker() -> None:
            is_admin = self._container.uac.is_admin()
            self.dispatcher.post_log(C.MSG_ADMIN_CHECK, "info")
            if is_admin:
                self.dispatcher.post_log(C.MSG_ADMIN_OK, "ok")
                snapshot = self._container.audit_use_case.execute()
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
            else:
                self.dispatcher.post_log(C.MSG_NO_ADMIN, "warn")
                self.dispatcher.post_ui_update(self._disable_buttons_no_admin)

        self.dispatcher.submit_background_task(worker)

    def _update_status_ui(self, snapshot: Any) -> None:
        if snapshot.status == SystemStatus.PROTECTED:
            self.status_label.config(text=C.STATUS_PROTECTED, bootstyle="success")
            self.rule_count_label.config(text=f"Reglas: {snapshot.rule_count}")
        elif snapshot.status == SystemStatus.UNPROTECTED:
            self.status_label.config(text=C.STATUS_UNPROTECTED, bootstyle="warning")
            self.rule_count_label.config(text="0 reglas")
        elif snapshot.status == SystemStatus.NO_ADMIN_PRIVILEGES:
            self._disable_buttons_no_admin()
        else:
            self.status_label.config(text=C.STATUS_ERROR, bootstyle="danger")

    def _disable_buttons_no_admin(self) -> None:
        self._set_buttons_state("disabled")
        self.status_label.config(text=C.STATUS_REQ_ADMIN, bootstyle="danger")

    def _on_refresh_clicked(self) -> None:
        self._set_buttons_state("disabled")
        self.dispatcher.post_log("Actualizando estado del firewall...", "info")

        def worker() -> None:
            try:
                snapshot = self._container.audit_use_case.execute()
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
                self.dispatcher.post_log("Estado actualizado exitosamente", "ok")
            except Exception as ex:
                self.dispatcher.post_log(f"Error al actualizar: {ex}", "err")
            finally:
                self.dispatcher.post_ui_update(lambda: self._set_buttons_state("normal"))

        self.dispatcher.submit_background_task(worker)

    def _on_block_clicked(self) -> None:
        if not self._container.uac.is_admin():
            messagebox.showerror("JameFirewall", "Se requieren privilegios de administrador.")
            return

        self._set_buttons_state("disabled")

        def worker() -> None:
            try:
                self.dispatcher.post_log(f"=== {C.BTN_BLOCK} ===", "info")
                dirs = self._container.config_use_case.get_directories()

                self._container.block_use_case._on_progress = lambda msg, lvl: (
                    self.dispatcher.post_log(msg, lvl)
                )

                summary = self._container.block_use_case.execute(dirs)
                self.dispatcher.post_log(C.MSG_SUCCESS_BLOCK, "ok")
                self.dispatcher.post_log(
                    f"+{summary.blocked_count} bloqueados / Ignorados: {summary.skipped_count}",
                    "ok",
                )
                snapshot = self._container.audit_use_case.execute()
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
            except Exception as ex:
                self.dispatcher.post_log(f"Error de bloqueo: {ex}", "err")
            finally:
                self.dispatcher.post_ui_update(lambda: self._set_buttons_state("normal"))

        self.dispatcher.submit_background_task(worker)

    def _on_unblock_clicked(self) -> None:
        if not self._container.uac.is_admin():
            messagebox.showerror("JameFirewall", "Se requieren privilegios de administrador.")
            return

        self._set_buttons_state("disabled")

        def worker() -> None:
            try:
                self.dispatcher.post_log(f"=== {C.BTN_UNBLOCK} ===", "info")
                self._container.unblock_use_case._on_progress = lambda msg, lvl: (
                    self.dispatcher.post_log(msg, lvl)
                )
                summary = self._container.unblock_use_case.execute()
                self.dispatcher.post_log(C.MSG_SUCCESS_UNBLOCK, "ok")
                self.dispatcher.post_log(f"-{summary.removed_count} reglas eliminadas", "ok")
                snapshot = self._container.audit_use_case.execute()
                self.dispatcher.post_ui_update(lambda: self._update_status_ui(snapshot))
            except Exception as ex:
                self.dispatcher.post_log(f"Error de desbloqueo: {ex}", "err")
            finally:
                self.dispatcher.post_ui_update(lambda: self._set_buttons_state("normal"))

        self.dispatcher.submit_background_task(worker)

    def _on_config_clicked(self) -> None:
        ConfigWindow(
            parent=self.root,
            manage_config_uc=self._container.config_use_case,
            on_saved_callback=lambda msg: self.append_log(msg, "ok"),
        )

    def _on_close(self) -> None:
        self.dispatcher.shutdown()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
