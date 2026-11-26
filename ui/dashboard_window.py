"""
Panel de métricas históricas — USB Antivirus.

Muestra estadísticas acumuladas, distribución de amenazas por categoría
y nivel de riesgo, extensiones más infectadas y tendencia de los últimos
análisis. Implementado íntegramente con Tkinter/Canvas; sin dependencias
externas.
"""

import tkinter as tk
from tkinter import ttk

from core.database import (
    get_global_stats,
    get_threats_by_category,
    get_threats_by_risk,
    get_top_extensions,
    get_scan_trend,
    get_scan_type_breakdown,
)
from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BG_INPUT, BORDER,
    ACCENT, ACCENT2, TEXT_PRI, TEXT_SEC, MUTED,
    OK, WARN, DANGER, INFO,
    FONT_SMALL, FONT_TINY, FONT_BODY,
    btn_secondary, _fmt_elapsed,
    RISK,
)

# Paleta para gráficas de barras de categorías
_BAR_COLORS = [
    "#ef4444", "#f97316", "#f59e0b", "#0ea5e9",
    "#8b5cf6", "#ec4899", "#10b981", "#06b6d4",
    "#84cc16", "#a78bfa",
]

_RISK_COLORS_LIST = [
    RISK.get(5, "#ef4444"),  # Crítico
    RISK.get(4, "#f97316"),  # Alto
    RISK.get(3, "#f59e0b"),  # Medio
    RISK.get(2, "#84cc16"),  # Bajo
    RISK.get(1, "#22d3ee"),  # Muy bajo
    RISK.get(0, "#3b82f6"),  # Prueba
]

_RISK_LABELS_MAP = {
    5: "Crítico", 4: "Alto", 3: "Medio",
    2: "Bajo", 1: "Muy bajo", 0: "Prueba",
}


# ─────────────────────────────────────────────────────────────────────────────
# Widget helpers
# ─────────────────────────────────────────────────────────────────────────────

def _section(parent: tk.Widget, title: str) -> tk.Frame:
    """Crea un bloque con título de sección y retorna el frame interior."""
    outer = tk.Frame(parent, bg=BG_DARK)
    outer.pack(fill="x", padx=16, pady=(0, 12))
    tk.Label(outer, text=title,
             font=("Segoe UI", 8, "bold"),
             fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))
    inner = tk.Frame(outer, bg=BG_DARK)
    inner.pack(fill="x")
    return inner


def _big_stat(parent: tk.Widget, value: str, label: str,
              color: str = TEXT_PRI) -> tk.Frame:
    """Tarjeta grande con un número destacado y una etiqueta debajo."""
    f = tk.Frame(parent, bg=BG_CARD,
                 highlightthickness=1, highlightbackground=BORDER,
                 padx=12, pady=10)
    tk.Label(f, text=value,
             font=("Segoe UI", 20, "bold"),
             fg=color, bg=BG_CARD).pack(anchor="center")
    tk.Label(f, text=label,
             font=("Segoe UI", 8),
             fg=MUTED, bg=BG_CARD).pack(anchor="center")
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Mini gráfica de barras horizontales (Canvas puro)
# ─────────────────────────────────────────────────────────────────────────────

class HBarChart(tk.Canvas):
    """
    Gráfica de barras horizontales dibujada con Canvas.
    items: list of (label, value, color)
    """

    BAR_H    = 18
    GAP      = 6
    LBL_W    = 140
    VAL_W    = 42
    MIN_W    = 300

    def __init__(self, parent: tk.Widget,
                 items: list[tuple[str, int, str]],
                 **kwargs):
        n = len(items)
        height = max(60, n * (self.BAR_H + self.GAP) + 10)
        super().__init__(parent, bg=BG_CARD,
                         highlightthickness=0,
                         height=height,
                         **kwargs)
        self._items = items
        self.bind("<Configure>", self._redraw)

    def _redraw(self, event=None):
        self.delete("all")
        if not self._items:
            self.create_text(10, 20, text="Sin datos", fill=MUTED,
                             font=FONT_TINY, anchor="w")
            return

        w = self.winfo_width() or self.MIN_W
        max_val = max((v for _, v, _ in self._items), default=1) or 1
        bar_area = max(10, w - self.LBL_W - self.VAL_W - 16)

        for i, (label, value, color) in enumerate(self._items):
            y = 5 + i * (self.BAR_H + self.GAP)

            # Etiqueta izquierda — truncar si es muy larga
            short = label if len(label) <= 20 else label[:18] + "…"
            self.create_text(4, y + self.BAR_H // 2,
                             text=short, fill=TEXT_SEC,
                             font=FONT_TINY, anchor="w",
                             width=self.LBL_W - 6)

            # Fondo de barra
            x0 = self.LBL_W
            self.create_rectangle(x0, y, x0 + bar_area, y + self.BAR_H,
                                   fill=BG_INPUT, outline="", width=0)

            # Barra rellena
            fill_w = int(bar_area * value / max_val)
            if fill_w > 0:
                self.create_rectangle(x0, y, x0 + fill_w, y + self.BAR_H,
                                       fill=color, outline="", width=0)

            # Valor a la derecha
            self.create_text(x0 + bar_area + 6, y + self.BAR_H // 2,
                             text=str(value), fill=TEXT_PRI,
                             font=FONT_TINY, anchor="w")


# ─────────────────────────────────────────────────────────────────────────────
# Mini sparkline de línea (Canvas puro)
# ─────────────────────────────────────────────────────────────────────────────

class SparkLine(tk.Canvas):
    """
    Gráfica de línea simple para mostrar una tendencia.
    series: list of numeric values (izq → der = más antiguo → más reciente)
    color:  color de la línea
    label:  etiqueta que aparece bajo el eje X
    """

    def __init__(self, parent: tk.Widget,
                 series: list[float],
                 color: str = ACCENT,
                 label: str = "",
                 height: int = 80,
                 **kwargs):
        super().__init__(parent, bg=BG_CARD,
                         highlightthickness=0,
                         height=height,
                         **kwargs)
        self._series = series
        self._color  = color
        self._label  = label
        self.bind("<Configure>", self._redraw)

    def _redraw(self, event=None):
        self.delete("all")
        series = self._series
        if not series:
            self.create_text(10, 20, text="Sin datos", fill=MUTED,
                             font=FONT_TINY, anchor="w")
            return

        w = self.winfo_width()  or 300
        h = self.winfo_height() or 80
        pad_x, pad_y = 8, 10

        # Área de dibujo
        aw = w - 2 * pad_x
        ah = h - 2 * pad_y - 14   # 14px para etiqueta inferior

        min_v = min(series)
        max_v = max(series)
        span  = max_v - min_v or 1

        def _px(i: int, v: float):
            x = pad_x + i * aw / max(len(series) - 1, 1)
            y = pad_y + ah - (v - min_v) / span * ah
            return x, y

        # Línea de base
        self.create_line(pad_x, pad_y + ah, pad_x + aw, pad_y + ah,
                         fill=BORDER, width=1)

        # Polilínea
        pts: list[float] = []
        for i, v in enumerate(series):
            pts.extend(_px(i, v))
        if len(pts) >= 4:
            self.create_line(*pts, fill=self._color, width=2, smooth=True)

        # Punto final destacado
        if series:
            lx, ly = _px(len(series) - 1, series[-1])
            self.create_oval(lx - 3, ly - 3, lx + 3, ly + 3,
                             fill=self._color, outline="")

        # Etiqueta
        if self._label:
            self.create_text(w // 2, h - 4, text=self._label,
                             fill=MUTED, font=FONT_TINY, anchor="center")


# ─────────────────────────────────────────────────────────────────────────────
# Ventana principal del Dashboard
# ─────────────────────────────────────────────────────────────────────────────

class DashboardWindow(tk.Toplevel):
    """
    Ventana modal con métricas históricas de USB Antivirus.
    Se abre desde el menú Archivo → Métricas o desde el botón del header.
    """

    def __init__(self, parent: tk.Widget):
        super().__init__(parent)
        self.title("Métricas — USB Antivirus")
        self.configure(bg=BG_DARK)
        self.geometry("860x640")
        self.minsize(760, 500)
        self.grab_set()
        self._build()
        self._load()
        self._center()

    # ── Centrado en pantalla ──────────────────────────────────────────────────

    def _center(self):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w  = self.winfo_width()
        h  = self.winfo_height()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    # ── Construcción del layout ───────────────────────────────────────────────

    def _build(self):
        # ── Cabecera ──────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG_PANEL, padx=20, pady=14)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=ACCENT, width=4).pack(side="left", fill="y")
        inner_hdr = tk.Frame(hdr, bg=BG_PANEL, padx=14)
        inner_hdr.pack(side="left", fill="both", expand=True)
        tk.Label(inner_hdr, text="📊  Métricas",
                 font=("Segoe UI", 14, "bold"),
                 fg=TEXT_PRI, bg=BG_PANEL).pack(anchor="w")
        tk.Label(inner_hdr,
                 text="Estadísticas acumuladas de todos los análisis realizados en esta USB.",
                 font=FONT_TINY, fg=MUTED, bg=BG_PANEL).pack(anchor="w")
        btn_secondary(hdr, "↺  Actualizar", self._load).pack(
            side="right", padx=(0, 4))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Área scrollable ───────────────────────────────────────────────────
        wrapper = tk.Frame(self, bg=BG_DARK)
        wrapper.pack(fill="both", expand=True)

        canvas = tk.Canvas(wrapper, bg=BG_DARK,
                           highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(wrapper, orient="vertical",
                             command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self._scroll_frame = tk.Frame(canvas, bg=BG_DARK)
        self._scroll_win = canvas.create_window(
            (0, 0), window=self._scroll_frame, anchor="nw")

        self._scroll_frame.bind("<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(
                self._scroll_win, width=e.width))

        # Rueda del ratón
        canvas.bind_all("<MouseWheel>",
            lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        # ── Pie ───────────────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self, bg=BG_PANEL, padx=16, pady=8)
        foot.pack(fill="x")
        btn_secondary(foot, "Cerrar", self.destroy).pack(side="right")

    # ── Carga y renderizado de datos ──────────────────────────────────────────

    def _load(self):
        # Limpiar contenido anterior
        for w in self._scroll_frame.winfo_children():
            w.destroy()

        try:
            stats     = get_global_stats()
            by_cat    = get_threats_by_category()
            by_risk   = get_threats_by_risk()
            top_ext   = get_top_extensions()
            trend     = get_scan_trend(20)
            by_type   = get_scan_type_breakdown()
        except Exception as e:
            tk.Label(self._scroll_frame,
                     text=f"Error cargando métricas: {e}",
                     font=FONT_BODY, fg=DANGER, bg=BG_DARK).pack(pady=20)
            return

        tk.Frame(self._scroll_frame, bg=BG_DARK, height=16).pack()

        self._render_global(stats)
        self._render_trend(trend)
        self._render_categories(by_cat, by_risk)
        self._render_extensions(top_ext, by_type)

        tk.Frame(self._scroll_frame, bg=BG_DARK, height=16).pack()

    # ── Bloque 1: Totales globales ────────────────────────────────────────────

    def _render_global(self, s: dict):
        frame = _section(self._scroll_frame, "Resumen global")

        total_scans   = s.get("total_scans",   0) or 0
        total_files   = s.get("total_files",   0) or 0
        total_threats = s.get("total_threats", 0) or 0
        total_errors  = s.get("total_errors",  0) or 0
        total_elapsed = s.get("total_elapsed", 0) or 0
        avg_elapsed   = s.get("avg_elapsed",   0) or 0
        clean_scans   = s.get("clean_scans",   0) or 0
        quarantined   = s.get("total_quarantined", 0) or 0

        # Tasa de detección global
        rate_str = "—"
        if total_files > 0:
            rate = total_threats / total_files * 100
            rate_str = f"{rate:.2f}%"

        # Tasa de análisis limpios
        clean_pct = "—"
        if total_scans > 0:
            pct = clean_scans / total_scans * 100
            clean_pct = f"{pct:.0f}%"

        cards = [
            (f"{total_scans:,}",             "Análisis realizados",      ACCENT2),
            (f"{total_files:,}",             "Archivos examinados",      TEXT_PRI),
            (f"{total_threats:,}",           "Amenazas detectadas",
             DANGER if total_threats > 0 else OK),
            (rate_str,                        "Tasa de detección",
             WARN if total_threats > 0 else OK),
            (f"{clean_scans:,}  ({clean_pct})", "Análisis sin amenazas",  OK),
            (f"{quarantined:,}",             "En cuarentena",            WARN),
            (_fmt_elapsed(total_elapsed),    "Tiempo total acumulado",   MUTED),
            (_fmt_elapsed(avg_elapsed),      "Duración media por análisis", MUTED),
            (f"{total_errors:,}",            "Errores acumulados",
             WARN if total_errors > 0 else TEXT_SEC),
        ]

        # 3 tarjetas por fila
        for i, (val, lbl, color) in enumerate(cards):
            col = i % 3
            row = i // 3
            c = _big_stat(frame, val, lbl, color)
            c.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

        for col in range(3):
            frame.columnconfigure(col, weight=1)

    # ── Bloque 2: Tendencia de análisis recientes ─────────────────────────────

    def _render_trend(self, trend: list[dict]):
        if not trend:
            return

        frame = _section(self._scroll_frame, "Tendencia — últimos análisis")

        # Dos sparklines lado a lado: archivos escaneados y amenazas
        files_series   = [t["files_scanned"] for t in trend]
        threats_series = [t["threats_found"] for t in trend]
        elapsed_series = [t["elapsed_sec"]   for t in trend]

        spark_frame = tk.Frame(frame, bg=BG_DARK)
        spark_frame.pack(fill="x")
        spark_frame.columnconfigure(0, weight=3)
        spark_frame.columnconfigure(1, weight=3)
        spark_frame.columnconfigure(2, weight=2)

        for col_idx, (series, color, label) in enumerate([
            (files_series,   ACCENT,  "Archivos escaneados"),
            (threats_series, DANGER,  "Amenazas detectadas"),
            (elapsed_series, ACCENT2, "Duración (seg)"),
        ]):
            cell = tk.Frame(spark_frame, bg=BG_CARD,
                            highlightthickness=1,
                            highlightbackground=BORDER,
                            padx=8, pady=6)
            cell.grid(row=0, column=col_idx, padx=4, sticky="nsew")

            # Valor actual (el último)
            last = series[-1] if series else 0
            if label == "Duración (seg)":
                disp = _fmt_elapsed(last)
            else:
                disp = f"{int(last):,}"

            tk.Label(cell, text=disp,
                     font=("Segoe UI", 14, "bold"),
                     fg=color, bg=BG_CARD).pack(anchor="w")
            tk.Label(cell, text=label,
                     font=FONT_TINY, fg=MUTED, bg=BG_CARD).pack(anchor="w")

            sp = SparkLine(cell, series, color=color, height=70)
            sp.pack(fill="x", pady=(6, 0))

        # Tabla compacta de los últimos 10 análisis
        tk.Frame(frame, bg=BORDER, height=1).pack(fill="x", pady=(10, 6))
        tk.Label(frame, text="Últimos 10 análisis",
                 font=FONT_TINY, fg=MUTED, bg=BG_DARK).pack(anchor="w")

        tbl = tk.Frame(frame, bg=BG_CARD,
                        highlightthickness=1,
                        highlightbackground=BORDER)
        tbl.pack(fill="x", pady=(4, 0))

        # Cabecera
        hdr_cols = ["#", "Tipo", "Fecha", "Archivos", "Amenazas", "Tiempo", "Estado"]
        hdr_widths = [3, 10, 10, 10, 10, 10, 11]
        for ci, (htext, hw) in enumerate(zip(hdr_cols, hdr_widths)):
            tk.Label(tbl, text=htext,
                     font=("Segoe UI", 8, "bold"),
                     fg=ACCENT2, bg=BG_PANEL,
                     width=hw, anchor="w",
                     padx=6, pady=4).grid(
                row=0, column=ci, sticky="ew", padx=1, pady=1)

        # Datos (los más recientes primero)
        for ri, row in enumerate(reversed(trend[-10:]), start=1):
            status = row.get("status", "")
            st_color = OK if status == "completed" else WARN
            st_label = "✓ Listo" if status == "completed" else "⏹ Cancelado"
            thr = row["threats_found"]
            thr_color = DANGER if thr > 0 else TEXT_SEC

            vals = [
                (str(row["id"]),            TEXT_SEC),
                (row["scan_type"][:10],     TEXT_PRI),
                (row["date"],               TEXT_SEC),
                (f"{row['files_scanned']:,}", TEXT_PRI),
                (str(thr),                  thr_color),
                (_fmt_elapsed(row["elapsed_sec"]), MUTED),
                (st_label,                  st_color),
            ]
            bg = BG_CARD if ri % 2 == 0 else BG_INPUT
            for ci, (val, vc) in enumerate(vals):
                tk.Label(tbl, text=val,
                         font=FONT_TINY, fg=vc, bg=bg,
                         width=hdr_widths[ci], anchor="w",
                         padx=6, pady=3).grid(
                    row=ri, column=ci, sticky="ew", padx=1, pady=0)

        for ci in range(len(hdr_cols)):
            tbl.columnconfigure(ci, weight=1)

    # ── Bloque 3: Categorías y niveles de riesgo ──────────────────────────────

    def _render_categories(self, by_cat: list[dict], by_risk: list[dict]):
        if not by_cat and not by_risk:
            frame = _section(self._scroll_frame,
                             "Distribución de amenazas por categoría y riesgo")
            tk.Label(frame,
                     text="Sin amenazas registradas en el historial.",
                     font=FONT_BODY, fg=MUTED, bg=BG_DARK).pack(anchor="w")
            return

        outer = tk.Frame(self._scroll_frame, bg=BG_DARK)
        outer.pack(fill="x", padx=16, pady=(0, 12))
        outer.columnconfigure(0, weight=3)
        outer.columnconfigure(1, weight=2)

        # Columna izquierda: por categoría
        left = tk.Frame(outer, bg=BG_DARK)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(left, text="POR CATEGORÍA",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

        if by_cat:
            cat_items = [
                (r["category"], r["count"], _BAR_COLORS[i % len(_BAR_COLORS)])
                for i, r in enumerate(by_cat)
            ]
            chart = HBarChart(left, cat_items)
            chart.pack(fill="x")
        else:
            tk.Label(left, text="Sin datos.", font=FONT_TINY,
                     fg=MUTED, bg=BG_DARK).pack(anchor="w")

        # Columna derecha: por nivel de riesgo
        right = tk.Frame(outer, bg=BG_DARK)
        right.grid(row=0, column=1, sticky="nsew")
        tk.Label(right, text="POR NIVEL DE RIESGO",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

        if by_risk:
            risk_items = []
            for r in by_risk:
                lvl   = r.get("risk_level") or 3
                label = _RISK_LABELS_MAP.get(int(lvl), r.get("risk_label", "?"))
                color = RISK.get(int(lvl), WARN)
                risk_items.append((label, r["count"], color))
            chart_r = HBarChart(right, risk_items)
            chart_r.pack(fill="x")
        else:
            tk.Label(right, text="Sin datos.", font=FONT_TINY,
                     fg=MUTED, bg=BG_DARK).pack(anchor="w")

    # ── Bloque 4: Extensiones y tipos de análisis ─────────────────────────────

    def _render_extensions(self, top_ext: list[dict], by_type: list[dict]):
        outer = tk.Frame(self._scroll_frame, bg=BG_DARK)
        outer.pack(fill="x", padx=16, pady=(0, 12))
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, weight=1)

        # Izquierda: extensiones más infectadas
        left = tk.Frame(outer, bg=BG_DARK)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(left, text="EXTENSIONES MÁS INFECTADAS",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

        if top_ext:
            ext_items = [
                (r["ext"], r["count"], _BAR_COLORS[i % len(_BAR_COLORS)])
                for i, r in enumerate(top_ext)
            ]
            HBarChart(left, ext_items).pack(fill="x")
        else:
            tk.Label(left, text="Sin datos.", font=FONT_TINY,
                     fg=MUTED, bg=BG_DARK).pack(anchor="w")

        # Derecha: tipos de análisis realizados
        right = tk.Frame(outer, bg=BG_DARK)
        right.grid(row=0, column=1, sticky="nsew")
        tk.Label(right, text="TIPOS DE ANÁLISIS REALIZADOS",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(anchor="w", pady=(0, 6))

        if by_type:
            type_colors = [ACCENT, ACCENT2, WARN, OK, INFO, DANGER]
            type_items = [
                (r["scan_type"], r["count"],
                 type_colors[i % len(type_colors)])
                for i, r in enumerate(by_type)
            ]
            HBarChart(right, type_items).pack(fill="x")

            # Total con porcentaje
            total = sum(r["count"] for r in by_type)
            frame_pct = tk.Frame(right, bg=BG_DARK)
            frame_pct.pack(fill="x", pady=(6, 0))
            for i, r in enumerate(by_type):
                pct = r["count"] / total * 100 if total else 0
                color = type_colors[i % len(type_colors)]
                tk.Label(frame_pct,
                         text=f"  {r['scan_type']}: {r['count']}  ({pct:.0f}%)",
                         font=FONT_TINY, fg=color, bg=BG_DARK,
                         anchor="w").pack(anchor="w")
        else:
            tk.Label(right, text="Sin análisis registrados.", font=FONT_TINY,
                     fg=MUTED, bg=BG_DARK).pack(anchor="w")
