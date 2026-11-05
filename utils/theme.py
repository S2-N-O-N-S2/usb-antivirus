"""
Paleta de colores y fábrica de widgets con estilo profesional.
Inspirado en interfaces de seguridad reales (Malwarebytes, Bitdefender).
Tema oscuro con acentos verde-cian y alertas rojas/naranjas.
"""

import tkinter as tk
from tkinter import ttk

# ── Paleta principal ──────────────────────────────────────────────────────────
BG_DARK    = "#0d1117"   # fondo principal — casi negro azulado
BG_PANEL   = "#161b22"   # paneles secundarios
BG_CARD    = "#1c2128"   # tarjetas / secciones
BG_INPUT   = "#21262d"   # entradas de texto
BORDER     = "#30363d"   # bordes sutiles

# Acentos
ACCENT     = "#00c896"   # verde menta — color principal de acción
ACCENT2    = "#0ea5e9"   # azul cielo — información
ACCENT_HOV = "#00e5a8"   # hover del acento verde

# Estado
OK         = "#00c896"   # limpio / correcto
WARN       = "#f59e0b"   # advertencia
DANGER     = "#ef4444"   # peligro / amenaza
CRITICAL   = "#dc2626"   # crítico
INFO       = "#0ea5e9"   # informativo
MUTED      = "#6e7681"   # texto secundario

# Texto
TEXT_PRI   = "#f0f6fc"   # texto principal — blanco suave
TEXT_SEC   = "#8b949e"   # texto secundario — gris
TEXT_DIM   = "#484f58"   # texto desactivado

# Riesgo (tabla de detecciones)
RISK = {
    0: "#3b82f6",   # prueba — azul
    1: "#22d3ee",   # muy bajo — cyan
    2: "#84cc16",   # bajo — verde
    3: "#f59e0b",   # medio — naranja
    4: "#f97316",   # alto — naranja intenso
    5: "#ef4444",   # crítico — rojo
}

RISK_BG = {
    0: "#1e3a5f",
    1: "#164e63",
    2: "#1a2e05",
    3: "#451a03",
    4: "#431407",
    5: "#450a0a",
}

RISK_ICON = {
    0: "🔵",
    1: "🔵",
    2: "🟡",
    3: "🟠",
    4: "🔴",
    5: "💀",
}


# ── Fuentes ───────────────────────────────────────────────────────────────────
FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_HEAD   = ("Segoe UI", 13, "bold")
FONT_SUBHEAD= ("Segoe UI", 10, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_SMALL  = ("Segoe UI", 9)
FONT_TINY   = ("Segoe UI", 8)
FONT_MONO   = ("Consolas", 9)
FONT_NUM    = ("Segoe UI", 18, "bold")   # números grandes de estadísticas


# ── Estilos ttk globales ──────────────────────────────────────────────────────

def apply_global_styles(root: tk.Misc):
    """Aplica los estilos ttk globales. Llamar una vez al iniciar la app."""
    s = ttk.Style(root)
    s.theme_use("clam")

    # Treeview general
    s.configure("App.Treeview",
                 background=BG_CARD,
                 foreground=TEXT_PRI,
                 fieldbackground=BG_CARD,
                 rowheight=28,
                 borderwidth=0,
                 font=FONT_SMALL)
    s.configure("App.Treeview.Heading",
                 background=BG_PANEL,
                 foreground=ACCENT2,
                 font=("Segoe UI", 9, "bold"),
                 relief="flat",
                 borderwidth=0)
    s.map("App.Treeview",
          background=[("selected", "#1f3a2e")],
          foreground=[("selected", ACCENT)])

    # Barra de progreso verde
    s.configure("Scan.Horizontal.TProgressbar",
                 troughcolor=BG_INPUT,
                 background=ACCENT,
                 borderwidth=0,
                 thickness=12)

    # Scrollbar
    s.configure("App.Vertical.TScrollbar",
                 background=BG_PANEL,
                 troughcolor=BG_DARK,
                 borderwidth=0,
                 arrowsize=12)
    s.configure("App.Horizontal.TScrollbar",
                 background=BG_PANEL,
                 troughcolor=BG_DARK,
                 borderwidth=0,
                 arrowsize=12)


# ── Fábrica de widgets ────────────────────────────────────────────────────────

def btn_primary(parent, text: str, command, width: int = 0) -> tk.Button:
    """Botón de acción principal — verde menta."""
    kw = dict(width=width) if width else {}
    return tk.Button(parent, text=text, command=command,
                     bg=ACCENT, fg=BG_DARK,
                     activebackground=ACCENT_HOV, activeforeground=BG_DARK,
                     relief="flat", font=("Segoe UI", 10, "bold"),
                     padx=18, pady=8, cursor="hand2",
                     bd=0, highlightthickness=0, **kw)


def btn_secondary(parent, text: str, command, width: int = 0) -> tk.Button:
    """Botón secundario — fondo oscuro con borde sutil."""
    kw = dict(width=width) if width else {}
    return tk.Button(parent, text=text, command=command,
                     bg=BG_CARD, fg=TEXT_PRI,
                     activebackground=BG_INPUT, activeforeground=TEXT_PRI,
                     relief="flat", font=FONT_BODY,
                     padx=14, pady=7, cursor="hand2",
                     bd=0, highlightthickness=1,
                     highlightbackground=BORDER,
                     highlightcolor=ACCENT, **kw)


def btn_danger(parent, text: str, command, width: int = 0) -> tk.Button:
    """Botón de acción destructiva — rojo."""
    kw = dict(width=width) if width else {}
    return tk.Button(parent, text=text, command=command,
                     bg="#3f0f0f", fg="#fca5a5",
                     activebackground=DANGER, activeforeground=TEXT_PRI,
                     relief="flat", font=FONT_BODY,
                     padx=14, pady=7, cursor="hand2",
                     bd=0, highlightthickness=1,
                     highlightbackground=DANGER, **kw)


def btn_warn(parent, text: str, command, width: int = 0) -> tk.Button:
    """Botón de advertencia — naranja."""
    kw = dict(width=width) if width else {}
    return tk.Button(parent, text=text, command=command,
                     bg="#3f2a00", fg="#fcd34d",
                     activebackground=WARN, activeforeground=BG_DARK,
                     relief="flat", font=FONT_BODY,
                     padx=14, pady=7, cursor="hand2",
                     bd=0, highlightthickness=1,
                     highlightbackground=WARN, **kw)


def btn_scan(parent, text: str, command, icon: str = "",
             color: str = BG_CARD, fg: str = TEXT_PRI) -> tk.Button:
    """Botón de análisis — rectangular, icono a la izquierda, ancho completo."""
    label = f"  {icon}  {text}" if icon else f"  {text}"
    return tk.Button(parent, text=label, command=command,
                     bg=color, fg=fg,
                     activebackground=BG_INPUT, activeforeground=ACCENT,
                     relief="flat", font=("Segoe UI", 10),
                     pady=10, anchor="w", padx=8,
                     cursor="hand2",
                     bd=0, highlightthickness=1,
                     highlightbackground=BORDER,
                     highlightcolor=ACCENT)


def card(parent, **kwargs) -> tk.Frame:
    """Marco con estilo de tarjeta."""
    return tk.Frame(parent, bg=BG_CARD,
                    highlightthickness=1,
                    highlightbackground=BORDER,
                    **kwargs)


def separator(parent, orient="horizontal") -> tk.Frame:
    if orient == "horizontal":
        return tk.Frame(parent, bg=BORDER, height=1)
    return tk.Frame(parent, bg=BORDER, width=1)


def section_label(parent, text: str) -> tk.Label:
    return tk.Label(parent, text=text.upper(),
                    font=("Segoe UI", 8, "bold"),
                    fg=MUTED, bg=BG_DARK,
                    anchor="w")


def stat_card(parent, title: str, value: str,
              value_color: str = TEXT_PRI,
              bg: str = BG_CARD) -> tuple[tk.Frame, tk.Label]:
    """
    Tarjeta de estadística compacta.
    Devuelve (frame, label_valor) para poder actualizar el valor.
    """
    f = tk.Frame(parent, bg=bg,
                 highlightthickness=1,
                 highlightbackground=BORDER,
                 padx=8, pady=6)
    lbl_val = tk.Label(f, text=value,
                       font=("Segoe UI", 16, "bold"),
                       fg=value_color, bg=bg)
    lbl_val.pack(anchor="center")
    tk.Label(f, text=title,
             font=("Segoe UI", 8),
             fg=MUTED, bg=bg).pack(anchor="center")
    return f, lbl_val


def status_dot(parent, color: str = OK) -> tk.Label:
    """Círculo de estado (●)."""
    return tk.Label(parent, text="●",
                    font=("Segoe UI", 12),
                    fg=color, bg=parent["bg"])


def _fmt_elapsed(s: float) -> str:
    """Convierte segundos en texto legible: '2 h 15 min 30 s'."""
    s = int(s)
    if s < 60:   return f"{s} s"
    m, s = divmod(s, 60)
    if m < 60:   return f"{m} min {s} s"
    h, m = divmod(m, 60)
    return f"{h} h {m} min {s} s"
