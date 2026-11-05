"""
Panel lateral izquierdo — botones de análisis, progreso determinista,
estadísticas en tiempo real y estado del motor.
"""

import threading
import time as _time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from utils.file_utils import get_windows_drives, get_drive_type, count_files, format_eta
from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BG_INPUT, BORDER,
    ACCENT, ACCENT2, TEXT_PRI, TEXT_SEC, MUTED,
    OK, WARN, DANGER, INFO,
    FONT_SUBHEAD, FONT_BODY, FONT_SMALL, FONT_TINY,
    btn_scan, btn_danger, btn_secondary, separator, section_label,
    apply_global_styles, _fmt_elapsed,
)


class ScanPanel(tk.Frame):

    def __init__(self, parent,
                 on_scan_file:   Callable[[str], None],
                 on_scan_folder: Callable[[str], None],
                 on_scan_drive:  Callable[[str], None],
                 on_scan_full:   Callable[[], None],
                 on_scan_quick:  Callable[[], None],
                 on_cancel:      Callable[[], None],
                 **kwargs):
        super().__init__(parent, bg=BG_PANEL, **kwargs)
        self._on_scan_file   = on_scan_file
        self._on_scan_folder = on_scan_folder
        self._on_scan_drive  = on_scan_drive
        self._on_scan_full   = on_scan_full
        self._on_scan_quick  = on_scan_quick
        self._on_cancel      = on_cancel
        self._scanning       = False
        self._total_files    = 0
        self._scanned_files  = 0
        self._count_stop     = threading.Event()
        self._scan_start     = 0.0
        self._timer_running  = False
        self._num_workers    = 1
        self._time_callback  = None   # se conecta desde main_window
        self._build()

    # ──────────────────────────────────────────────────────────────────────────
    # Construcción
    # ──────────────────────────────────────────────────────────────────────────

    def _build(self):
        # Título del panel
        tk.Label(self, text="ANÁLISIS",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_PANEL).pack(anchor="w", padx=14, pady=(14, 4))

        # ── Botones de análisis ───────────────────────────────────────────────
        btn_cfg = [
            ("⚡", "Análisis rápido",     self._do_quick,  ACCENT,   BG_DARK),
            ("🗄", "Analizar archivo",     self._do_file,   BG_CARD,  TEXT_PRI),
            ("📂", "Analizar carpeta",     self._do_folder, BG_CARD,  TEXT_PRI),
            ("💾", "Analizar unidad/USB",  self._do_drive,  BG_CARD,  TEXT_PRI),
            ("🔍", "Análisis completo",    self._do_full,   BG_CARD,  TEXT_PRI),
        ]
        for icon, label, cmd, bg, fg in btn_cfg:
            b = btn_scan(self, label, cmd, icon=icon, color=bg, fg=fg)
            b.pack(fill="x", padx=10, pady=2)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=10, pady=8)

        # Botón cancelar
        self._btn_cancel = btn_danger(self, "⏹  Cancelar análisis", self._on_cancel)
        self._btn_cancel.pack(fill="x", padx=10, pady=(0, 8))
        self._btn_cancel.config(state="disabled")

        separator(self).pack(fill="x", padx=10)

        # ── Barra de progreso ─────────────────────────────────────────────────
        prog_frame = tk.Frame(self, bg=BG_PANEL)
        prog_frame.pack(fill="x", padx=10, pady=(10, 0))

        # Fila: porcentaje (izq) y conteo (der)
        pct_row = tk.Frame(prog_frame, bg=BG_PANEL)
        pct_row.pack(fill="x")
        self._lbl_pct = tk.Label(pct_row, text="0%",
                                  font=("Segoe UI", 10, "bold"),
                                  fg=ACCENT, bg=BG_PANEL)
        self._lbl_pct.pack(side="left")
        self._lbl_pct_files = tk.Label(pct_row, text="",
                                        font=FONT_TINY, fg=MUTED, bg=BG_PANEL)
        self._lbl_pct_files.pack(side="right")

        # Barra determinista
        style = ttk.Style(self)
        style.configure("Scan.Horizontal.TProgressbar",
                         troughcolor=BG_INPUT,
                         background=ACCENT,
                         borderwidth=0,
                         thickness=10)
        self._progress = ttk.Progressbar(
            prog_frame, orient="horizontal",
            mode="determinate", maximum=100,
            style="Scan.Horizontal.TProgressbar",
        )
        self._progress.pack(fill="x", pady=(3, 0))

        # Archivo actual — altura fija para evitar que empuje el layout
        current_frame = tk.Frame(self, bg=BG_PANEL, height=16)
        current_frame.pack(fill="x", padx=10, pady=(2, 4))
        current_frame.pack_propagate(False)   # altura fija — no se expande
        self._lbl_current = tk.Label(current_frame, text="",
                                      font=("Segoe UI", 7),
                                      fg=MUTED, bg=BG_PANEL,
                                      anchor="w")
        self._lbl_current.pack(fill="both", expand=True)

        separator(self).pack(fill="x", padx=10, pady=(2, 0))

        # ── Estadísticas compactas ────────────────────────────────────────────
        tk.Label(self, text="PROGRESO",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_PANEL).pack(anchor="w", padx=14, pady=(8, 4))

        stats_frame = tk.Frame(self, bg=BG_PANEL)
        stats_frame.pack(fill="x", padx=10)

        self._lbl_elapsed   = self._mini_stat(stats_frame, "Tiempo")
        self._lbl_eta       = self._mini_stat(stats_frame, "Estimado")
        self._lbl_remain    = self._mini_stat(stats_frame, "Restante")
        self._lbl_total     = self._mini_stat(stats_frame, "Total archivos")
        self._lbl_workers   = self._mini_stat(stats_frame, "Workers")

        separator(self).pack(fill="x", padx=10, pady=(8, 0))

        # ── Estado del motor ──────────────────────────────────────────────────
        tk.Label(self, text="MOTOR",
                 font=("Segoe UI", 8, "bold"),
                 fg=MUTED, bg=BG_PANEL).pack(anchor="w", padx=14, pady=(8, 4))

        eng = tk.Frame(self, bg=BG_PANEL)
        eng.pack(fill="x", padx=10)
        self._lbl_ver    = self._mini_stat(eng, "Versión")
        self._lbl_db     = self._mini_stat(eng, "Firmas")
        self._lbl_eng_ok = self._mini_stat(eng, "Estado", WARN)

    def _mini_stat(self, parent, label: str,
                   val_color: str = TEXT_SEC) -> tk.Label:
        row = tk.Frame(parent, bg=BG_PANEL)
        row.pack(fill="x", pady=1)
        tk.Label(row, text=label + ":", font=FONT_TINY,
                 fg=MUTED, bg=BG_PANEL, width=16, anchor="w").pack(side="left")
        lbl = tk.Label(row, text="—", font=FONT_TINY,
                       fg=val_color, bg=BG_PANEL, anchor="w")
        lbl.pack(side="left")
        return lbl

    # ──────────────────────────────────────────────────────────────────────────
    # Acciones de botones
    # ──────────────────────────────────────────────────────────────────────────

    def _do_quick(self):
        if not self._scanning: self._on_scan_quick()

    def _do_file(self):
        if self._scanning: return
        p = filedialog.askopenfilename(title="Seleccionar archivo")
        if p: self._on_scan_file(p)

    def _do_folder(self):
        if self._scanning: return
        p = filedialog.askdirectory(title="Seleccionar carpeta")
        if p: self._on_scan_folder(p)

    def _do_drive(self):
        if not self._scanning:
            DriveSelectDialog(self, self._on_scan_drive)

    def _do_full(self):
        if self._scanning: return
        if messagebox.askyesno("Análisis completo",
                               "Se analizarán todas las unidades del equipo.\n"
                               "Puede tardar 1-4 horas.\n\n¿Continuar?"):
            self._on_scan_full()

    # ──────────────────────────────────────────────────────────────────────────
    # Control de estado
    # ──────────────────────────────────────────────────────────────────────────

    def set_scanning(self, scanning: bool):
        self._scanning = scanning
        self._btn_cancel.config(state="normal" if scanning else "disabled")
        if scanning:
            self._scan_start    = _time.time()
            self._timer_running = True
            self._tick()
        else:
            self._timer_running = False
            self._count_stop.set()
            self._progress.config(value=100)
            self._lbl_pct.config(text="100%", fg=OK)
            self._lbl_remain.config(text="—", fg=MUTED)

    def set_time_callback(self, callback):
        """Permite que main_window reciba el tiempo real cada segundo."""
        self._time_callback = callback

    def set_workers(self, n: int):
        self._num_workers = n
        self._lbl_workers.config(
            text=f"{n}  {'🟢' * n}",
            fg=ACCENT if n > 1 else TEXT_SEC)

    def reset_stats(self):
        self._lbl_elapsed.config(text="—")
        self._lbl_eta.config(text="—")
        self._lbl_remain.config(text="—")
        self._lbl_total.config(text="—")
        self._lbl_workers.config(text="—")
        self._lbl_current.config(text="")
        self._lbl_pct.config(text="0%", fg=ACCENT)
        self._lbl_pct_files.config(text="")
        self._progress.config(value=0)
        self._total_files   = 0
        self._scanned_files = 0

    def _tick(self):
        """Corre cada segundo. Actualiza tiempo, ETA y ajusta el total dinámicamente."""
        if not self._timer_running:
            return
        try:
            elapsed = _time.time() - self._scan_start
            self._lbl_elapsed.config(text=_fmt_elapsed(elapsed))

            # Notificar a main_window para que actualice la tarjeta de tiempo
            if self._time_callback:
                self._time_callback(elapsed)

            scanned = self._scanned_files

            # ── Ajustar total dinámicamente ───────────────────────────────────
            if self._total_files > 0:
                ratio = scanned / self._total_files if self._total_files > 0 else 0

                if scanned > self._total_files:
                    self._total_files = int(scanned * 1.15)
                    self._lbl_total.config(
                        text=f"{self._total_files:,}~", fg=WARN)

                elif ratio > 0.90 and elapsed > 30:
                    speed = scanned / elapsed if elapsed > 0 else 1
                    real_total = int(scanned / max(ratio, 0.85))
                    if real_total < self._total_files:
                        self._total_files = real_total
                        self._lbl_total.config(
                            text=f"{self._total_files:,}~", fg=INFO)

            # ── ETA basada en velocidad real ──────────────────────────────────
            if scanned > 10 and elapsed > 3 and self._total_files > 0:
                speed     = scanned / elapsed
                remain    = max(0, self._total_files - scanned)
                eta_sec   = remain / speed if speed > 0 else 0
                est_total = self._total_files / speed

                self._lbl_eta.config(text=_fmt_elapsed(est_total), fg=INFO)
                self._lbl_remain.config(
                    text=_fmt_elapsed(eta_sec) if eta_sec > 1 else "< 1 s",
                    fg=OK if eta_sec < 120 else INFO)
            elif scanned == 0:
                self._lbl_remain.config(text="calculando...", fg=MUTED)

            self.after(1000, self._tick)

        except tk.TclError:
            # El widget fue destruido mientras el timer estaba activo
            self._timer_running = False

    def update_progress(self, files: int, threats: int, errors: int,
                        elapsed: float, current_file: str = "",
                        active_workers: int = 0):
        """Llamado desde main_window en cada callback de progreso."""

        # Guardar fuente de verdad para el tick
        self._scanned_files = files

        # Expandir total si ClamAV encontró más de lo estimado
        if files > self._total_files and self._total_files > 0:
            self._total_files = int(files * 1.2)

        # Barra de porcentaje
        if self._total_files > 0:
            pct = min(99, int(files * 100 / self._total_files))
            self._progress.config(value=pct)
            self._lbl_pct.config(
                text=f"{pct}%",
                fg=ACCENT if pct < 99 else OK)
            self._lbl_pct_files.config(
                text=f"{files:,} / {self._total_files:,}")
        else:
            cur = float(self._progress["value"])
            self._progress.config(value=(cur + 1.5) % 95)
            self._lbl_pct.config(text="…", fg=ACCENT)
            self._lbl_pct_files.config(text=f"{files:,}")

        if current_file:
            # Truncar por la derecha para caber en una línea
            short = ("…" + current_file[-32:]) if len(current_file) > 33 else current_file
            self._lbl_current.config(text=short)

        if active_workers > 0:
            self.set_workers(active_workers)

    def start_file_count(self, targets):
        """
        Cuenta los archivos del/los objetivo(s) en un hilo para no bloquear la UI.
        Acepta un string (ruta única) o una lista de rutas.
        """
        if isinstance(targets, str):
            targets = [targets]

        self._total_files = 0
        self._count_stop.clear()
        self._lbl_total.config(text="contando...", fg=MUTED)
        self._lbl_eta.config(text="calculando...", fg=MUTED)
        self._lbl_remain.config(text="—", fg=MUTED)

        def _run():
            total = 0
            for t in targets:
                if self._count_stop.is_set():
                    break
                total += count_files(t, stop_flag=self._count_stop)
            # Factor por comprimidos: ClamAV analiza internos de ZIPs/MSIs
            adjusted = int(total * 1.6)
            self._total_files = adjusted
            est = format_eta(adjusted / 45) if adjusted > 0 else "—"
            self.after(0, self._lbl_total.config,
                       {"text": f"{adjusted:,}~", "fg": TEXT_SEC})
            self.after(0, self._lbl_eta.config,
                       {"text": est, "fg": INFO})

        threading.Thread(target=_run, daemon=True).start()

    def update_engine_info(self, version: str, db_date: str, ok: bool, msg: str = ""):
        ver_short = version.split("/")[0] if "/" in version else version
        ver_short = ver_short[:28] if ver_short else "—"
        self._lbl_ver.config(text=ver_short)
        self._lbl_db.config(text=db_date or "—")
        self._lbl_eng_ok.config(
            text="OK" if ok else "ERROR",
            fg=OK if ok else DANGER)


# ──────────────────────────────────────────────────────────────────────────────
# Diálogo de selección de unidad
# ──────────────────────────────────────────────────────────────────────────────

class DriveSelectDialog(tk.Toplevel):

    def __init__(self, parent, on_select: Callable[[str], None]):
        super().__init__(parent)
        self.title("Seleccionar unidad")
        self.configure(bg=BG_DARK)
        self.resizable(False, False)
        self.grab_set()
        self._on_select = on_select
        self._build()
        self._center()

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        # Cabecera
        hdr = tk.Frame(self, bg=BG_PANEL)
        hdr.pack(fill="x")
        tk.Label(hdr, text="💾  Seleccionar unidad para analizar",
                 font=("Segoe UI", 11, "bold"),
                 fg=TEXT_PRI, bg=BG_PANEL,
                 padx=16, pady=12).pack(anchor="w")
        tk.Frame(hdr, bg=BORDER, height=1).pack(fill="x")

        # Lista de unidades
        frame = tk.Frame(self, bg=BG_DARK, padx=16, pady=12)
        frame.pack(fill="both", expand=True)

        drives = get_windows_drives()
        self._var = tk.StringVar(value=drives[0] if drives else "")

        for drive in drives:
            dtype = get_drive_type(drive)
            icon  = "💾" if dtype == "Fijo" else "🔌" if dtype == "Extraíble" else "💿"
            row = tk.Frame(frame, bg=BG_CARD,
                           highlightthickness=1,
                           highlightbackground=BORDER)
            row.pack(fill="x", pady=3)
            tk.Radiobutton(
                row,
                text=f"  {icon}  {drive}   [{dtype}]",
                variable=self._var, value=drive,
                font=FONT_BODY,
                fg=TEXT_PRI, bg=BG_CARD,
                selectcolor=BG_DARK,
                activebackground=BG_CARD,
                activeforeground=ACCENT,
                padx=10, pady=8,
            ).pack(anchor="w", fill="x")

        if not drives:
            tk.Label(frame, text="No se encontraron unidades.",
                     font=FONT_BODY, fg=WARN, bg=BG_DARK).pack()

        # Botones
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        btn_row = tk.Frame(self, bg=BG_DARK, padx=16, pady=10)
        btn_row.pack(fill="x")

        from utils.theme import btn_primary, btn_secondary
        btn_primary(btn_row, "Analizar unidad", self._confirm).pack(side="left", padx=(0, 8))
        btn_secondary(btn_row, "Cancelar",       self.destroy).pack(side="left")

    def _confirm(self):
        drive = self._var.get()
        if drive:
            self.destroy()
            self._on_select(drive)
