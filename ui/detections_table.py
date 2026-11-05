"""
Tabla de detecciones y ventana de detalle completa.
Incluye: indicador de confianza, descripción de riesgo, botón abrir ubicación.
"""

import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Optional

from core.scanner import Detection
from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BG_INPUT, BORDER,
    ACCENT, ACCENT2, TEXT_PRI, TEXT_SEC, MUTED,
    OK, WARN, DANGER, INFO,
    RISK, RISK_BG, RISK_ICON,
    FONT_BODY, FONT_SMALL, FONT_TINY, FONT_MONO,
    btn_secondary, btn_warn, btn_danger,
    apply_global_styles,
)


class DetectionsTable(tk.Frame):

    COLUMNS = [
        ("#",          42,  "center"),
        ("Riesgo",    100,  "w"),
        ("Confianza", 155,  "w"),
        ("Nombre",    185,  "w"),
        ("Tipo",       52,  "w"),
        ("Detección", 185,  "w"),
        ("Tamaño",     78,  "e"),
        ("Hora",       86,  "center"),
    ]

    def __init__(self, parent,
                 on_select: Optional[Callable[[Detection], None]] = None,
                 **kwargs):
        super().__init__(parent, bg=BG_DARK, **kwargs)
        self._on_select  = on_select
        self._detections: list[Detection] = []
        self._build()

    def _build(self):
        apply_global_styles(self)

        col_ids = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(
            self, columns=col_ids, show="headings",
            style="App.Treeview", selectmode="browse",
        )
        for col, width, anchor in self.COLUMNS:
            # El heading siempre "w" para que coincida con los datos
            self._tree.heading(col, text=col, anchor="w")
            self._tree.column(col, width=width, minwidth=28,
                              anchor=anchor, stretch=True)

        vsb = ttk.Scrollbar(self, orient="vertical",
                             command=self._tree.yview,
                             style="App.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(self, orient="horizontal",
                             command=self._tree.xview,
                             style="App.Horizontal.TScrollbar")
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        for lvl, color in RISK.items():
            self._tree.tag_configure(
                f"r{lvl}",
                foreground=color,
                background=RISK_BG.get(lvl, BG_CARD),
            )
        self._tree.tag_configure("empty",
                                  foreground=MUTED, background=BG_DARK)
        self._tree.tag_configure("whitelisted",
                                  foreground="#4b5563", background=BG_DARK)

        self._tree.bind("<Double-1>",         self._on_double)
        self._tree.bind("<Button-3>",         self._on_right_click)
        self._show_placeholder()

        # Menú contextual
        self._ctx_menu = tk.Menu(self, tearoff=0,
                                  bg=BG_PANEL, fg=TEXT_PRI,
                                  activebackground=ACCENT,
                                  activeforeground=BG_DARK)
        self._ctx_menu.add_command(label="🔍 Ver detalle",
                                    command=self._ctx_detail)
        self._ctx_menu.add_command(label="📂 Abrir ubicación",
                                    command=self._ctx_open_location)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="🔒 Mover a cuarentena",
                                    command=self._ctx_quarantine)
        self._ctx_menu.add_command(label="📋 Copiar ruta",
                                    command=self._ctx_copy_path)
        self._ctx_menu.add_command(label="📋 Copiar SHA-256",
                                    command=self._ctx_copy_sha)

    def _show_placeholder(self):
        self._tree.insert("", "end", iid="__placeholder__",
                          values=("", "", "",
                                  "Sin detecciones — inicia un análisis",
                                  "", "", "", ""),
                          tags=("empty",))

    def add_detection(self, det: Detection):
        from utils.threat_classifier import assess_confidence
        from utils.whitelist import is_whitelisted

        if self._tree.exists("__placeholder__"):
            self._tree.delete("__placeholder__")

        idx = len(self._detections) + 1
        self._detections.append(det)

        wl   = is_whitelisted(det.sha256)
        conf = assess_confidence(det.file_path, det.detection_name, det.file_ext)

        badge      = f"{RISK_ICON.get(det.risk_level, '●')} {det.risk_label}"
        conf_badge = f"{conf.icon} {conf.label}"
        hora       = det.detected_at[11:19]
        tags       = ("whitelisted",) if wl else (f"r{det.risk_level}",)

        self._tree.insert(
            "", "end", iid=str(idx),
            values=(idx, badge, conf_badge, det.file_name,
                    det.file_ext or "—", det.detection_name[:38],
                    det.file_size_str, hora),
            tags=tags,
        )
        self._tree.yview_moveto(1.0)

    def clear(self):
        self._detections.clear()
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._show_placeholder()

    def get_selected(self) -> Optional[Detection]:
        sel = self._tree.selection()
        if not sel or sel[0] == "__placeholder__":
            return None
        try:
            idx = int(sel[0]) - 1
            if 0 <= idx < len(self._detections):
                return self._detections[idx]
        except (ValueError, IndexError):
            pass
        return None

    def all_detections(self) -> list[Detection]:
        return list(self._detections)

    def _on_double(self, _event):
        det = self.get_selected()
        if det and self._on_select:
            self._on_select(det)

    def _on_right_click(self, event):
        row = self._tree.identify_row(event.y)
        if row and row != "__placeholder__":
            self._tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    # ── Acciones del menú contextual ─────────────────────────────────────────

    def _ctx_detail(self):
        det = self.get_selected()
        if det and self._on_select:
            self._on_select(det)

    def _ctx_open_location(self):
        det = self.get_selected()
        if not det:
            return
        _open_file_location(det.file_path)

    def _ctx_quarantine(self):
        """Abre la ventana principal de cuarentena para el archivo seleccionado."""
        det = self.get_selected()
        if not det:
            return
        # Buscar la ventana principal (Tk root) y llamar su método de cuarentena
        try:
            root = self.winfo_toplevel()
            if hasattr(root, "_quarantine_selected"):
                root._quarantine_selected()
            else:
                messagebox.showinfo(
                    "Cuarentena",
                    f"Selecciona el archivo en la tabla y usa el botón "
                    f"'🔒 Cuarentena' de la barra de acciones.",
                )
        except Exception:
            pass

    def _ctx_copy_path(self):
        det = self.get_selected()
        if det:
            self.clipboard_clear()
            self.clipboard_append(det.file_path)

    def _ctx_copy_sha(self):
        det = self.get_selected()
        if det:
            self.clipboard_clear()
            self.clipboard_append(det.sha256)


# ──────────────────────────────────────────────────────────────────────────────
# Utilidades
# ──────────────────────────────────────────────────────────────────────────────

def _open_file_location(file_path: str):
    """Abre el Explorador de Windows en la carpeta del archivo y lo selecciona."""
    import os
    from pathlib import Path
    p = Path(file_path)
    if not p.exists():
        messagebox.showwarning(
            "Archivo no encontrado",
            f"El archivo ya no existe en esa ubicación:\n{file_path}\n\n"
            "Es posible que haya sido movido, eliminado o aislado en cuarentena.")
        return
    try:
        # /select muestra el explorador con el archivo resaltado
        subprocess.Popen(["explorer", "/select,", str(p.resolve())])
    except Exception as e:
        # Fallback: abrir solo la carpeta
        try:
            os.startfile(str(p.parent))
        except Exception:
            messagebox.showerror("Error", f"No se pudo abrir la ubicación:\n{e}")


# ──────────────────────────────────────────────────────────────────────────────
# Ventana de detalle completa
# ──────────────────────────────────────────────────────────────────────────────

class DetectionDetailWindow(tk.Toplevel):

    def __init__(self, parent, det: Detection):
        super().__init__(parent)
        self.title(f"Detalle — {det.file_name}")
        self.configure(bg=BG_DARK)
        self.resizable(True, True)
        self.minsize(580, 500)
        self.grab_set()
        self._det = det
        self._build(det)
        self._center()

    def _center(self):
        self.update_idletasks()
        w = max(self.winfo_width(), 600)
        h = max(self.winfo_height(), 540)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self, d: Detection):
        from utils.threat_classifier import classify, assess_confidence
        from utils.whitelist import is_whitelisted, add_to_whitelist

        threat = classify(d.detection_name)
        conf   = assess_confidence(d.file_path, d.detection_name, d.file_ext)
        wl     = is_whitelisted(d.sha256)

        risk_color = RISK.get(d.risk_level, WARN)
        risk_bg    = RISK_BG.get(d.risk_level, BG_CARD)
        icon       = RISK_ICON.get(d.risk_level, "●")

        # ── Banner de riesgo ──────────────────────────────────────────────────
        banner = tk.Frame(self, bg=risk_bg,
                          highlightthickness=2,
                          highlightbackground=risk_color)
        banner.pack(fill="x")
        tk.Frame(banner, bg=risk_color, width=5).pack(side="left", fill="y")
        inner = tk.Frame(banner, bg=risk_bg, padx=14, pady=10)
        inner.pack(side="left", fill="both", expand=True)

        top_row = tk.Frame(inner, bg=risk_bg)
        top_row.pack(fill="x")
        tk.Label(top_row,
                 text=f"{icon}  {threat.category.upper()}  —  {threat.risk_label}",
                 font=("Segoe UI", 12, "bold"),
                 fg=risk_color, bg=risk_bg).pack(side="left")

        tk.Label(inner, text=d.detection_name,
                 font=("Segoe UI", 9), fg=TEXT_SEC, bg=risk_bg).pack(anchor="w")

        # ── Descripción del tipo de amenaza ───────────────────────────────────
        desc_frame = tk.Frame(self, bg="#111827", padx=14, pady=10)
        desc_frame.pack(fill="x")
        tk.Label(desc_frame, text="¿QUÉ ES ESTA AMENAZA?",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg="#111827").pack(anchor="w")
        tk.Label(desc_frame, text=threat.description,
                 font=("Segoe UI", 9),
                 fg=TEXT_PRI, bg="#111827",
                 wraplength=540, justify="left").pack(anchor="w", pady=(4, 0))

        # ── Acción recomendada ────────────────────────────────────────────────
        action_bg = "#1a2e05" if d.risk_level <= 2 else "#2d1b00" if d.risk_level == 3 else "#3f0f0f"
        action_frame = tk.Frame(self, bg=action_bg, padx=14, pady=8)
        action_frame.pack(fill="x")
        tk.Label(action_frame, text="ACCIÓN RECOMENDADA",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=action_bg).pack(anchor="w")
        tk.Label(action_frame, text=threat.action,
                 font=("Segoe UI", 9, "bold"),
                 fg=risk_color, bg=action_bg,
                 wraplength=540, justify="left").pack(anchor="w", pady=(3, 0))

        # ── Indicador de confianza ────────────────────────────────────────────
        conf_bg = "#1f2937" if wl else BG_CARD
        conf_frame = tk.Frame(self, bg=conf_bg,
                               highlightthickness=1,
                               highlightbackground=conf.color if not wl else BORDER,
                               padx=14, pady=8)
        conf_frame.pack(fill="x")
        tk.Label(conf_frame,
                 text=f"{conf.icon}  {conf.label}",
                 font=("Segoe UI", 10, "bold"),
                 fg=conf.color, bg=conf_bg).pack(anchor="w")
        tk.Label(conf_frame, text=conf.explanation,
                 font=FONT_TINY, fg=TEXT_SEC, bg=conf_bg).pack(anchor="w")
        if wl:
            tk.Label(conf_frame,
                     text="✓ Este archivo está en tu lista blanca.",
                     font=("Segoe UI", 9, "bold"),
                     fg=OK, bg=conf_bg).pack(anchor="w", pady=(4, 0))

        # ── Ficha de datos ────────────────────────────────────────────────────
        separator = tk.Frame(self, bg=BORDER, height=1)
        separator.pack(fill="x")

        body = tk.Frame(self, bg=BG_DARK, padx=16, pady=10)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="INFORMACIÓN DEL ARCHIVO",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

        fields = [
            ("Nombre",         d.file_name),
            ("Ruta completa",  d.file_path),
            ("Extensión",      d.file_ext or "—"),
            ("Tamaño",         d.file_size_str),
            ("Categoría",      threat.category),
            ("Nivel de riesgo",f"{threat.risk_label}  ({d.risk_level}/5)"),
            ("SHA-256",        d.sha256),
            ("Detectado",      d.detected_at[:19].replace("T", " ")),
        ]
        for label, value in fields:
            self._field_row(body, label, value)

        # ── Botones de acción ─────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self, bg=BG_DARK, padx=16, pady=10)
        foot.pack(fill="x")

        # Izquierda
        left_btns = tk.Frame(foot, bg=BG_DARK)
        left_btns.pack(side="left")

        btn_secondary(left_btns, "📂 Abrir ubicación",
                      lambda: _open_file_location(d.file_path)
                      ).pack(side="left", padx=(0, 6))

        def _copy_path():
            self.clipboard_clear()
            self.clipboard_append(d.file_path)
            self._flash_status("Ruta copiada al portapapeles")
        btn_secondary(left_btns, "📋 Copiar ruta",
                      _copy_path).pack(side="left", padx=(0, 6))

        def _copy_sha():
            self.clipboard_clear()
            self.clipboard_append(d.sha256)
            self._flash_status("SHA-256 copiado al portapapeles")
        btn_secondary(left_btns, "🔑 Copiar SHA-256",
                      _copy_sha).pack(side="left")

        # Derecha
        right_btns = tk.Frame(foot, bg=BG_DARK)
        right_btns.pack(side="right")

        btn_secondary(right_btns, "Cerrar",
                      self.destroy).pack(side="right", padx=(6, 0))

        if not wl and d.sha256 != "No calculado":
            def _add_wl():
                from tkinter import simpledialog
                reason = simpledialog.askstring(
                    "Lista blanca",
                    "¿Por qué es seguro este archivo? (opcional)",
                    parent=self,
                ) or "Marcado manualmente como seguro"
                if add_to_whitelist(d.sha256, d.file_name, d.detection_name, reason):
                    messagebox.showinfo(
                        "Lista blanca",
                        f"Agregado a lista blanca:\n{d.file_name}\n\n"
                        "No volverá a aparecer como amenaza.",
                        parent=self)
                    self.destroy()
            btn_warn(right_btns, "🟢 Marcar como seguro",
                     _add_wl).pack(side="right", padx=(0, 6))

        # Barra de estado interna
        self._status_lbl = tk.Label(self, text="",
                                     font=FONT_TINY, fg=ACCENT2, bg=BG_DARK,
                                     anchor="w")
        self._status_lbl.pack(fill="x", padx=16, pady=(0, 4))

    def _field_row(self, parent, label: str, value: str):
        row = tk.Frame(parent, bg=BG_DARK)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label + ":",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK,
                 width=16, anchor="e").pack(side="left")
        var = tk.StringVar(value=value)
        e = tk.Entry(row, textvariable=var,
                     font=FONT_TINY,
                     fg=TEXT_PRI, bg=BG_INPUT,
                     readonlybackground=BG_INPUT,
                     relief="flat",
                     highlightthickness=1,
                     highlightbackground=BORDER,
                     state="readonly")
        e.pack(side="left", fill="x", expand=True, padx=(6, 0))

    def _flash_status(self, msg: str):
        self._status_lbl.config(text=msg)
        self.after(2500, lambda: self._status_lbl.config(text=""))
