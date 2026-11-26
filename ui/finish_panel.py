"""
Panel de finalización que aparece al terminar, cancelar o encontrar error.
Muestra un resumen visual claro del resultado del análisis.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from core.scanner import ScanResult
from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BG_INPUT, BORDER,
    ACCENT, ACCENT2, TEXT_PRI, TEXT_SEC, MUTED,
    OK, WARN, DANGER, INFO,
    FONT_TINY, FONT_SMALL, FONT_BODY,
    btn_primary, btn_secondary, btn_danger, btn_warn,
    _fmt_elapsed,
)


class FinishPanel(tk.Toplevel):
    """
    Ventana modal que aparece automáticamente cuando termina un análisis.
    Muestra: resultado, estadísticas, amenazas encontradas y acciones rápidas.
    """

    def __init__(self, parent, result: ScanResult,
                 on_quarantine_all: Optional[Callable] = None,
                 on_view_report:    Optional[Callable] = None):
        super().__init__(parent)
        self.title("Análisis finalizado — USB Antivirus")
        self.configure(bg=BG_DARK)
        self.resizable(False, False)
        self.grab_set()
        self._result = result
        self._on_quarantine_all = on_quarantine_all
        self._on_view_report    = on_view_report
        self._build()
        self._center()

    def _center(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    def _build(self):
        r = self._result

        # ── Colores y textos según estado ─────────────────────────────────────
        if r.status == "cancelled":
            bg_top  = "#1c1400"
            color   = WARN
            icon    = "⏹"
            title   = "Análisis detenido"
            subtitle= "El análisis fue cancelado por el usuario."
        elif r.status == "error":
            bg_top  = "#1a0000"
            color   = DANGER
            icon    = "✕"
            title   = "Error durante el análisis"
            subtitle= r.error_message or "Ocurrió un error inesperado."
        elif r.threats_found > 0:
            bg_top  = "#1a0505"
            color   = DANGER
            icon    = "⚠"
            title   = f"Se encontraron {r.threats_found} amenaza(s)"
            subtitle= "Revisa las detecciones y toma acción."
        else:
            bg_top  = "#051a0a"
            color   = OK
            icon    = "✓"
            title   = "Sin amenazas detectadas"
            subtitle= "El análisis completó sin encontrar malware."

        # ── Banner principal ──────────────────────────────────────────────────
        top = tk.Frame(self, bg=bg_top, padx=24, pady=20)
        top.pack(fill="x")
        tk.Frame(top, bg=color, width=5).pack(side="left", fill="y")

        inner = tk.Frame(top, bg=bg_top, padx=16)
        inner.pack(side="left", fill="both", expand=True)

        tk.Label(inner,
                 text=f"{icon}  {title}",
                 font=("Segoe UI", 16, "bold"),
                 fg=color, bg=bg_top).pack(anchor="w")
        tk.Label(inner, text=subtitle,
                 font=("Segoe UI", 10),
                 fg=TEXT_SEC, bg=bg_top).pack(anchor="w", pady=(4, 0))

        # ── Estadísticas ──────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        stats_frame = tk.Frame(self, bg=BG_DARK, padx=24, pady=16)
        stats_frame.pack(fill="x")

        # Métricas derivadas
        _speed = (r.files_scanned / r.elapsed_sec) if r.elapsed_sec > 0 else 0
        _speed_str = f"{_speed:,.0f} arch/s" if _speed >= 1 else "< 1 arch/s"
        _rate  = (r.threats_found / r.files_scanned * 100) if r.files_scanned > 0 else 0
        _rate_str = f"{_rate:.3f}%" if r.files_scanned > 0 else "—"

        stats = [
            ("📁 Archivos examinados", f"{r.files_scanned:,}",  TEXT_PRI),
            ("⚠ Amenazas detectadas", str(r.threats_found),
             DANGER if r.threats_found > 0 else OK),
            ("❌ Errores",              str(r.errors),
             WARN if r.errors > 0 else TEXT_SEC),
            ("⏱ Tiempo total",         _fmt_elapsed(r.elapsed_sec), ACCENT2),
            ("⚡ Velocidad",            _speed_str,                ACCENT),
            ("🎯 Tasa de detección",    _rate_str,
             DANGER if _rate > 0 else OK),
            ("🔧 Workers usados",       str(r.workers_used),       TEXT_SEC),
            ("⏭ Archivos omitidos",    str(r.files_skipped),
             WARN if r.files_skipped > 0 else TEXT_SEC),
            ("📅 Tipo de análisis",     r.scan_type,               TEXT_SEC),
        ]

        for i, (label, value, vcolor) in enumerate(stats):
            col = i % 3
            row = i // 3
            cell = tk.Frame(stats_frame, bg=BG_CARD,
                            highlightthickness=1,
                            highlightbackground=BORDER,
                            padx=12, pady=8)
            cell.grid(row=row, column=col, padx=5, pady=4, sticky="nsew")
            stats_frame.columnconfigure(col, weight=1)
            tk.Label(cell, text=value,
                     font=("Segoe UI", 14, "bold"),
                     fg=vcolor, bg=BG_CARD).pack(anchor="center")
            tk.Label(cell, text=label,
                     font=("Segoe UI", 8),
                     fg=MUTED, bg=BG_CARD).pack(anchor="center")

        # ── Lista de amenazas (si hay) ────────────────────────────────────────
        if r.detections:
            tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
            det_frame = tk.Frame(self, bg=BG_DARK, padx=24, pady=8)
            det_frame.pack(fill="x")
            tk.Label(det_frame, text="AMENAZAS ENCONTRADAS",
                     font=("Segoe UI", 8, "bold"),
                     fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

            for det in r.detections[:8]:   # máximo 8 en el panel
                row_f = tk.Frame(det_frame, bg=BG_CARD,
                                  highlightthickness=1,
                                  highlightbackground=BORDER,
                                  padx=10, pady=6)
                row_f.pack(fill="x", pady=2)

                from utils.theme import RISK, RISK_ICON
                icon_r = RISK_ICON.get(det.risk_level, "●")
                color_r = RISK.get(det.risk_level, WARN)
                tk.Label(row_f, text=f"{icon_r} {det.risk_label}",
                         font=("Segoe UI", 9, "bold"),
                         fg=color_r, bg=BG_CARD, width=14,
                         anchor="w").pack(side="left")
                tk.Label(row_f, text=det.file_name,
                         font=("Segoe UI", 9, "bold"),
                         fg=TEXT_PRI, bg=BG_CARD).pack(side="left", padx=(0, 8))
                tk.Label(row_f, text=det.detection_name,
                         font=("Segoe UI", 8),
                         fg=TEXT_SEC, bg=BG_CARD).pack(side="left")

            if len(r.detections) > 8:
                tk.Label(det_frame,
                         text=f"... y {len(r.detections) - 8} más. Ver tabla de detecciones.",
                         font=FONT_TINY, fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(4, 0))

        # ── Mensaje de errores ────────────────────────────────────────────────
        if r.errors > 0:
            err_frame = tk.Frame(self, bg="#1c1400",
                                  highlightthickness=1,
                                  highlightbackground=WARN,
                                  padx=14, pady=8)
            err_frame.pack(fill="x", padx=24, pady=(4, 0))
            tk.Label(err_frame,
                     text=f"⚠  {r.errors} archivo(s) no pudieron analizarse "
                          f"(en uso, sin permisos o protegidos por el sistema). "
                          f"Ver panel de errores para más detalles.",
                     font=FONT_TINY, fg=WARN, bg="#1c1400",
                     wraplength=480, justify="left").pack(anchor="w")

        # ── Acciones ──────────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(8, 0))
        foot = tk.Frame(self, bg=BG_DARK, padx=24, pady=12)
        foot.pack(fill="x")

        # Cerrar siempre disponible
        btn_primary(foot, "Aceptar", self.destroy).pack(side="right")

        if r.status == "completed" and r.threats_found > 0:
            if self._on_quarantine_all:
                btn_warn(foot, "🔒 Aislar todas las amenazas",
                         self._quarantine_all_and_close).pack(side="left", padx=(0, 8))

        if self._on_view_report:
            btn_secondary(foot, "📋 Ver reporte",
                          self._view_report_and_close).pack(side="left")

    def _quarantine_all_and_close(self):
        if self._on_quarantine_all:
            self._on_quarantine_all()
        self.destroy()

    def _view_report_and_close(self):
        if self._on_view_report:
            self._on_view_report()
        self.destroy()
