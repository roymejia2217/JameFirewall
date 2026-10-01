"""Ventana modal de configuración de directorios para JameFirewall."""

import contextlib
import os
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox
from tkinter.constants import BOTH, BOTTOM, END, LEFT, RIGHT, SINGLE, YES, X, Y
from typing import Any

import ttkbootstrap as ttk

from jame_firewall.core.use_cases.manage_config import ManageConfigDirectoriesUseCase
from jame_firewall.presentation import constants as C


class ConfigWindow(ttk.Toplevel):
    """Modal de configuración y gestión de directorios de búsqueda."""

    def __init__(
        self,
        parent: Any,
        manage_config_uc: ManageConfigDirectoriesUseCase,
        on_saved_callback: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._manage_config_uc = manage_config_uc
        self._on_saved_callback = on_saved_callback

        self.title(C.LBL_CONFIG_TITLE)
        self.geometry("520x420")
        self.resizable(False, False)

        with contextlib.suppress(tk.TclError, AttributeError):
            self.iconbitmap(parent.iconbitmap())

        self.current_dirs = [str(p) for p in self._manage_config_uc.get_directories()]
        self._setup_ui()

        self.transient(parent)
        self.grab_set()
        self.focus_set()

    def _setup_ui(self) -> None:
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(fill=BOTH, expand=YES)

        # Encabezado
        lbl_dirs = ttk.Label(main_frame, text=C.LBL_DIRECTORIES, font=("Helvetica", 10, "bold"))
        lbl_dirs.pack(anchor="w", pady=(0, 5))

        # Lista con Scrollbar
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=BOTH, expand=YES)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.listbox = tk.Listbox(
            list_frame,
            font=("Consolas", 9),
            selectmode=SINGLE,
            yscrollcommand=scrollbar.set,
            bg="#2b2b2b",
            fg="#ffffff",
            borderwidth=0,
            highlightthickness=0,
        )
        self.listbox.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar.config(command=self.listbox.yview)

        # Poblar lista inicial
        for d in self.current_dirs:
            self.listbox.insert(END, d)

        # Botonera de acciones
        btn_frame = ttk.Frame(main_frame, padding=(0, 10, 0, 0))
        btn_frame.pack(fill=X)

        self.btn_add = ttk.Button(
            btn_frame,
            text=C.BTN_ADD,
            command=self.add_dir,
            bootstyle="secondary",
            width=5,
        )
        self.btn_add.pack(side=LEFT, padx=(0, 5))

        self.btn_remove = ttk.Button(
            btn_frame,
            text=C.BTN_REMOVE,
            command=self.remove_dir,
            bootstyle="secondary",
            width=5,
        )
        self.btn_remove.pack(side=LEFT, padx=(0, 5))

        self.btn_auto = ttk.Button(
            btn_frame,
            text=C.BTN_AUTODETECT,
            command=self.auto_detect,
            bootstyle="outline-light",
        )
        self.btn_auto.pack(side=RIGHT)

        ttk.Separator(main_frame).pack(fill=X, pady=15)

        # Botones de pie
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=X, side=BOTTOM)

        self.btn_save = ttk.Button(
            action_frame,
            text=C.BTN_SAVE,
            command=self.save_and_close,
            bootstyle="light",
            width=15,
        )
        self.btn_save.pack(side=RIGHT, padx=(5, 0))

        self.btn_cancel = ttk.Button(
            action_frame,
            text=C.BTN_CANCEL,
            command=self.destroy,
            bootstyle="outline-secondary",
            width=15,
        )
        self.btn_cancel.pack(side=RIGHT)

    def add_dir(self) -> None:
        """Selecciona y agrega un nuevo directorio asegurando importación de os/pathlib."""
        path = filedialog.askdirectory(parent=self, title="Seleccionar directorio")
        if path:
            norm_path = os.path.normpath(path)
            if norm_path not in self.current_dirs:
                self.current_dirs.append(norm_path)
                self.listbox.insert(END, norm_path)

    def remove_dir(self) -> None:
        """Elimina el directorio seleccionado de la lista visual."""
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            val = self.listbox.get(index)
            self.current_dirs.remove(val)
            self.listbox.delete(index)

    def auto_detect(self) -> None:
        """Ejecuta auto-descubrimiento en Registro y actualiza la lista visual."""
        updated_dirs = [
            str(p)
            for p in self._manage_config_uc.discover_directories(
                [Path(d) for d in self.current_dirs]
            )
        ]
        new_count = len(updated_dirs) - len(self.current_dirs)

        self.listbox.delete(0, END)
        self.current_dirs = updated_dirs
        for d in self.current_dirs:
            self.listbox.insert(END, d)

        if new_count > 0:
            messagebox.showinfo("JameFirewall", f"{C.MSG_PATHS_FOUND} {new_count}")
        else:
            messagebox.showinfo("JameFirewall", C.MSG_NO_NEW_PATHS)

    def save_and_close(self) -> None:
        """Persiste los directorios mediante el caso de uso y cierra el modal."""
        paths_to_save = [Path(d) for d in self.current_dirs]
        if not self._manage_config_uc.replace_directories(paths_to_save):
            messagebox.showerror(
                "JameFirewall",
                "No se pudo guardar la configuración. Se conserva la anterior. "
                "Revise las rutas y los permisos o el espacio disponible, y vuelva a intentar.",
                parent=self,
            )
            return

        if self._on_saved_callback:
            self._on_saved_callback(f"{C.MSG_CONF_SAVED}: {len(self.current_dirs)} rutas")
        self.destroy()
