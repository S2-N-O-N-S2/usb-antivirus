"""
Panel / ventana de errores de análisis.
Muestra los archivos que ClamAV no pudo analizar y el motivo.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional

from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BORDER,
    ACCENT2, TEXT_PRI, TEXT_SEC, MUTED, WARN,
    FONT_SMALL, FONT_TINY,
    btn_secondary, apply_global_styles,
)


class ErrorsWindow(tk.Toplevel):
    """Ventana separada que muestra todos los errores del último análisis."""

    COLUMNS = [
        ("#",        38, "center"),
        ("Archivo", 300, "w"),
        ("Motivo",  380, "w"),
    ]

    def __init__(self, parent, skipped_files: list[str]):
        super().__init__(parent)
        self.title("Archivos con errores — USB Antivirus")
        self.configure(bg=BG_DARK)
        self.geometry("820x480")
        self.minsize(600, 300)
        self.grab_set()
        self._files = skipped_files
        self._build()

    def _build(self):
        apply_global_styles(self)

        # Cabecera
        hdr = tk.Frame(self, bg=BG_PANEL, padx=16, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚠  Archivos no analizados",
                 font=("Segoe UI", 12, "bold"),
                 fg=WARN, bg=BG_PANEL).pack(side="left")
        tk.Label(hdr, text=f"{len(self._files)} archivo(s)",
                 font=FONT_SMALL, fg=MUTED, bg=BG_PANEL).pack(side="right")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Explicación
        info = tk.Frame(self, bg="#1c1f26", padx=16, pady=8)
        info.pack(fill="x")
        tk.Label(info,
                 text="Estos archivos no pudieron ser analizados. "
                      "Los motivos más comunes son: el archivo estaba en uso, "
                      "no había permisos de lectura, o desapareció durante el análisis. "
                      "No significa que sean peligrosos.",
                 font=FONT_TINY, fg=TEXT_SEC, bg="#1c1f26",
                 wraplength=760, justify="left").pack(anchor="w")

        # Tabla
        frame = tk.Frame(self, bg=BG_DARK)
        frame.pack(fill="both", expand=True, padx=12, pady=8)

        col_ids = [c[0] for c in self.COLUMNS]
        tree = ttk.Treeview(frame, columns=col_ids, show="headings",
                             style="App.Treeview", selectmode="browse")

        for col, width, anchor in self.COLUMNS:
            tree.heading(col, text=col, anchor="w")
            tree.column(col, width=width, minwidth=30, anchor=anchor)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=tree.yview,
                             style="App.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(frame, orient="horizontal",
                             command=tree.xview,
                             style="App.Horizontal.TScrollbar")
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Colores alternos
        tree.tag_configure("odd",  background=BG_CARD)
        tree.tag_configure("even", background=BG_DARK)

        for i, entry in enumerate(self._files):
            # Parseo robusto de rutas Windows.
            # ClamAV puede enviar: "C:\ruta\archivo.exe: mensaje ERROR"
            # o separadores propios del scanner " — ".
            # Estrategia: buscar el último ": " que NO sea parte de "C:\"
            path   = entry
            reason = "Error de acceso o archivo en uso"

            if " — " in entry:
                # Separador explícito del scanner
                parts  = entry.split(" — ", 1)
                path   = parts[0].strip()
                reason = parts[1].strip()
            else:
                # Buscar ": " después de la ruta Windows (mínimo 3 chars antes)
                # para evitar dividir en "C:" de la letra de unidad.
                idx = -1
                search = entry
                pos = 0
                while True:
                    found = search.find(": ", pos)
                    if found == -1:
                        break
                    # Ignorar si es justo después de una letra de unidad ("C: ")
                    if found == 1 and entry[0].isalpha():
                        pos = found + 1
                        continue
                    idx = found
                    break
                if idx > 2:
                    path   = entry[:idx].strip()
                    reason = entry[idx + 2:].strip() or "Error de acceso"

            from pathlib import Path as _Path
            display_path = path  # mostrar ruta completa en la columna Archivo
            tag  = "odd" if i % 2 else "even"
            tree.insert("", "end", values=(i + 1, display_path, reason), tags=(tag,))

        if not self._files:
            tree.insert("", "end",
                        values=("", "Sin errores en este análisis", ""),
                        tags=("even",))

        # Pie
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self, bg=BG_DARK, padx=16, pady=8)
        foot.pack(fill="x")

        def _copy_all():
            text = "\n".join(self._files)
            self.clipboard_clear()
            self.clipboard_append(text)
        btn_secondary(foot, "📋 Copiar lista", _copy_all).pack(side="left")
        btn_secondary(foot, "Cerrar", self.destroy).pack(side="right")


class ErrorsBadge(tk.Frame):
    """
    Badge compacto que se muestra en la ventana principal cuando hay errores.
    Al hacer clic abre ErrorsWindow.
    """

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=BG_DARK, **kwargs)
        self._count = 0
        self._files: list[str] = []
        self._parent = parent

        self._btn = tk.Button(
            self,
            text="",
            font=("Segoe UI", 8, "bold"),
            fg=WARN, bg="#2d1b00",
            activebackground="#3d2800",
            activeforeground=WARN,
            relief="flat",
            padx=8, pady=3,
            cursor="hand2",
            command=self._open,
            bd=0,
            highlightthickness=1,
            highlightbackground=WARN,
        )

    def update_errors(self, count: int, skipped_files: list[str]):
        self._count = count
        self._files = list(skipped_files)
        if count > 0:
            self._btn.config(
                text=f"⚠ {count} archivo(s) con error — ver detalle")
            self._btn.pack(fill="x")
        else:
            self._btn.pack_forget()

    def clear(self):
        self._count = 0
        self._files = []
        self._btn.pack_forget()

    def _open(self):
        ErrorsWindow(self._parent, self._files)
