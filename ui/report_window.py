"""
Ventana de reportes e historial de análisis.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

from config.settings import settings
from core.database import get_scans, get_detections_for_scan
from utils.theme import ACCENT, BG_DARK, BG_PANEL, BG_CARD, BORDER, TEXT_PRI, TEXT_SEC

COLOR_BG    = BG_DARK
COLOR_BG2   = BG_PANEL
COLOR_TEXT  = TEXT_PRI
COLOR_ACCENT= ACCENT
COLOR_BTN   = BG_CARD
COLOR_SEL   = "#2d6a4f"


class ReportWindow(tk.Toplevel):

    SCAN_COLS = (
        ("ID",       40),
        ("Tipo",    120),
        ("Objetivo",240),
        ("Iniciado",140),
        ("Archivos", 80),
        ("Amenazas", 80),
        ("Estado",   90),
    )

    DET_COLS = (
        ("Nombre",   180),
        ("Detección",200),
        ("Categoría",150),
        ("Riesgo",    80),
        ("Tamaño",    80),
        ("Detectado", 140),
    )

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Historial de análisis — USB Antivirus")
        self.configure(bg=COLOR_BG)
        self.geometry("1100x600")
        self.minsize(800, 450)
        self.grab_set()
        self._build()
        self._load_history()

    def _build(self):
        tk.Label(self, text="📋  Historial de análisis",
                 font=("Segoe UI", 14, "bold"),
                 fg=COLOR_ACCENT, bg=COLOR_BG).pack(anchor="w", padx=16, pady=(12, 4))

        # Panel superior: lista de análisis
        top = tk.Frame(self, bg=COLOR_BG)
        top.pack(fill="x", padx=16)

        self._scan_tree = self._make_tree(top, self.SCAN_COLS, height=7)
        self._scan_tree.pack(fill="x")
        self._scan_tree.bind("<<TreeviewSelect>>", self._on_scan_select)

        # Panel inferior: detecciones del análisis seleccionado
        tk.Label(self, text="Detecciones del análisis seleccionado:",
                 font=("Segoe UI", 10, "bold"),
                 fg="#8ecae6", bg=COLOR_BG).pack(anchor="w", padx=16, pady=(8, 2))

        bot = tk.Frame(self, bg=COLOR_BG)
        bot.pack(fill="both", expand=True, padx=16)

        self._det_tree = self._make_tree(bot, self.DET_COLS, height=8)
        self._det_tree.pack(fill="both", expand=True)

        # Botones
        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(fill="x", padx=16, pady=(4, 12))

        self._btn(btn_frame, "📁 Abrir carpeta de reportes", COLOR_BTN, self._open_reports_dir).pack(side="left", padx=(0,8))
        self._btn(btn_frame, "↺ Actualizar", COLOR_BTN, self._load_history).pack(side="left")
        self._btn(btn_frame, "Cerrar", COLOR_BTN, self.destroy).pack(side="right")

        self._status = tk.Label(self, text="", font=("Segoe UI", 9),
                                 fg=COLOR_ACCENT, bg=COLOR_BG)
        self._status.pack(anchor="w", padx=16, pady=(0, 4))

    def _make_tree(self, parent, columns, height=8) -> ttk.Treeview:
        style = ttk.Style(self)
        style.configure("Rep.Treeview",
                         background=COLOR_BG2, foreground=COLOR_TEXT,
                         fieldbackground=COLOR_BG2, rowheight=22,
                         font=("Segoe UI", 9))
        style.configure("Rep.Treeview.Heading",
                         background=COLOR_BG, foreground=COLOR_ACCENT,
                         font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Rep.Treeview", background=[("selected", COLOR_SEL)])

        col_ids = [c[0] for c in columns]
        tree = ttk.Treeview(parent, columns=col_ids, show="headings",
                             style="Rep.Treeview", height=height, selectmode="browse")
        for col, w in columns:
            tree.heading(col, text=col, anchor="w")
            tree.column(col, width=w, minwidth=30, anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    def _btn(self, parent, text, color, command):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg=COLOR_TEXT, relief="flat",
                         font=("Segoe UI", 10), padx=12, pady=5,
                         cursor="hand2", activebackground=color)

    def _load_history(self):
        for item in self._scan_tree.get_children():
            self._scan_tree.delete(item)
        scans = get_scans(200)
        for s in scans:
            ts = (s.get("started_at") or "")[:19].replace("T", " ")
            self._scan_tree.insert("", "end", iid=str(s["id"]),
                                    values=(
                                        s["id"], s["scan_type"],
                                        s["target"][:50],
                                        ts,
                                        s["files_scanned"],
                                        s["threats_found"],
                                        s["status"],
                                    ))
        self._status.config(text=f"{len(scans)} análisis en historial.")
        # Limpiar detecciones
        for item in self._det_tree.get_children():
            self._det_tree.delete(item)

    def _on_scan_select(self, event):
        sel = self._scan_tree.selection()
        if not sel:
            return
        scan_id = int(sel[0])
        for item in self._det_tree.get_children():
            self._det_tree.delete(item)
        dets = get_detections_for_scan(scan_id)
        for d in dets:
            ts = (d.get("detected_at") or "")[:19].replace("T", " ")
            self._det_tree.insert("", "end", values=(
                d["file_name"], d["detection"], d["category"],
                d["risk_label"], d.get("file_size", 0), ts,
            ))
        if not dets:
            self._det_tree.insert("", "end", values=("(Sin detecciones)", "", "", "", "", ""))

    def _open_reports_dir(self):
        rdir = settings.reports_dir
        if not rdir.exists():
            messagebox.showwarning("Reportes", f"La carpeta no existe:\n{rdir}", parent=self)
            return
        try:
            import subprocess
            subprocess.Popen(["explorer", str(rdir.resolve())])
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)
