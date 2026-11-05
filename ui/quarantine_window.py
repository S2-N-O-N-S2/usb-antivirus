"""
Ventana de gestión de cuarentena.
Muestra los archivos aislados, permite restaurarlos o eliminarlos definitivamente.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from core.quarantine import restore_file, delete_quarantined_file, list_quarantine
from utils.theme import ACCENT, BG_DARK, BG_PANEL, BG_CARD, BORDER, TEXT_PRI, WARN, DANGER, OK

COLOR_BG    = BG_DARK
COLOR_BG2   = BG_PANEL
COLOR_TEXT  = TEXT_PRI
COLOR_ACCENT= ACCENT
COLOR_WARN  = WARN
COLOR_DANGER= DANGER
COLOR_BTN   = BG_CARD


class QuarantineWindow(tk.Toplevel):

    COLUMNS = (
        ("ID",       40),
        ("Nombre original",  200),
        ("Ruta original",    300),
        ("Detección",        180),
        ("Categoría",        140),
        ("Aislado en",       140),
    )

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Cuarentena — USB Antivirus")
        self.configure(bg=COLOR_BG)
        self.geometry("980x520")
        self.minsize(700, 400)
        self.grab_set()
        self._items: list[dict] = []
        self._build()
        self._load()

    def _build(self):
        # Título
        tk.Label(self, text="🔒  Cuarentena",
                 font=("Segoe UI", 14, "bold"),
                 fg=COLOR_ACCENT, bg=COLOR_BG).pack(anchor="w", padx=16, pady=(12, 4))

        tk.Label(self,
                 text="Los archivos aislados se almacenan de forma segura. "
                      "No se ejecutan automáticamente.",
                 font=("Segoe UI", 9), fg="#8ecae6", bg=COLOR_BG).pack(anchor="w", padx=16)

        # Tabla
        frame = tk.Frame(self, bg=COLOR_BG)
        frame.pack(fill="both", expand=True, padx=16, pady=8)

        style = ttk.Style(self)
        style.configure("Quar.Treeview",
                         background=COLOR_BG2, foreground=COLOR_TEXT,
                         fieldbackground=COLOR_BG2, rowheight=24,
                         font=("Segoe UI", 9))
        style.configure("Quar.Treeview.Heading",
                         background=COLOR_BG, foreground=COLOR_ACCENT,
                         font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Quar.Treeview", background=[("selected", "#2d6a4f")])

        col_ids = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(frame, columns=col_ids, show="headings",
                                   style="Quar.Treeview", selectmode="browse")
        for col, w in self.COLUMNS:
            self._tree.heading(col, text=col, anchor="w")
            self._tree.column(col, width=w, minwidth=30, anchor="w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Botones
        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(fill="x", padx=16, pady=(0, 12))

        self._btn_restore = self._btn(btn_frame, "⬆ Restaurar", COLOR_BTN, self._restore)
        self._btn_restore.pack(side="left", padx=(0, 8))

        self._btn_delete = self._btn(btn_frame, "🗑 Eliminar definitivamente", COLOR_DANGER, self._delete)
        self._btn_delete.pack(side="left", padx=(0, 8))

        self._btn(btn_frame, "↺ Actualizar", COLOR_BTN, self._load).pack(side="left")
        self._btn(btn_frame, "Cerrar", COLOR_BTN, self.destroy).pack(side="right")

        self._status = tk.Label(self, text="", font=("Segoe UI", 9),
                                 fg=COLOR_ACCENT, bg=COLOR_BG)
        self._status.pack(anchor="w", padx=16, pady=(0, 8))

    def _btn(self, parent, text, color, command):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg=COLOR_TEXT, relief="flat",
                         font=("Segoe UI", 10), padx=12, pady=5,
                         cursor="hand2", activebackground=color,
                         activeforeground="#ffffff")

    def _load(self):
        self._items = list_quarantine()
        for item in self._tree.get_children():
            self._tree.delete(item)
        for item in self._items:
            orig = item.get("original_path", "")
            name = orig.split("\\")[-1] if "\\" in orig else orig.split("/")[-1]
            ts = (item.get("quarantined_at") or "")[:19].replace("T", " ")
            self._tree.insert("", "end",
                               iid=str(item["id"]),
                               values=(
                                   item["id"], name, orig,
                                   item.get("detection", "—"),
                                   item.get("category", "—"),
                                   ts,
                               ))
        count = len(self._items)
        self._status.config(text=f"{count} archivo(s) en cuarentena.")

    def _get_selected(self) -> dict | None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning("Cuarentena", "Selecciona un archivo primero.", parent=self)
            return None
        qid = int(sel[0])
        for item in self._items:
            if item["id"] == qid:
                return item
        return None

    def _restore(self):
        item = self._get_selected()
        if not item:
            return
        orig = item.get("original_path", "")
        qpath = item.get("quarantine_path", "")
        if not messagebox.askyesno(
            "Confirmar restauración",
            f"¿Restaurar este archivo a su ubicación original?\n\n"
            f"Archivo: {orig}\n\n"
            f"⚠ Solo restaura si estás seguro de que no es peligroso.",
            parent=self,
        ):
            return
        ok, msg = restore_file(item["id"], qpath, orig)
        if ok:
            messagebox.showinfo("Restauración", msg, parent=self)
        else:
            messagebox.showerror("Error de restauración", msg, parent=self)
        self._load()

    def _delete(self):
        item = self._get_selected()
        if not item:
            return
        orig = item.get("original_path", "")
        qpath = item.get("quarantine_path", "")

        if not messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Eliminar definitivamente este archivo?\n\n{orig}\n\n"
            "Esta acción NO se puede deshacer.",
            parent=self, icon="warning",
        ):
            return
        # Segunda confirmación
        if not messagebox.askyesno(
            "Segunda confirmación",
            "Confirma que deseas ELIMINAR PERMANENTEMENTE este archivo.\n\n"
            "Haz clic en Sí solo si estás completamente seguro.",
            parent=self, icon="warning",
        ):
            return

        ok, msg = delete_quarantined_file(item["id"], qpath)
        if ok:
            messagebox.showinfo("Eliminación", msg, parent=self)
        else:
            messagebox.showerror("Error", msg, parent=self)
        self._load()
