"""
Ventana principal de USB Antivirus — diseño profesional.
"""

import os
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from typing import Optional

from config.settings import settings
from core.scanner import (
    scanner, ScanResult, ScanProgress, Detection,
    check_clamav_environment, get_engine_version, get_db_date,
)
from core.database import init_db, start_scan, finish_scan, add_detection
from core.quarantine import quarantine_file
from core.report import generate_report
from ui.scan_panel import ScanPanel
from ui.detections_table import DetectionsTable, DetectionDetailWindow
from ui.quarantine_window import QuarantineWindow
from ui.report_window import ReportWindow
from ui.settings_window import SettingsWindow
from ui.errors_panel import ErrorsBadge
from ui.finish_panel import FinishPanel
from ui.dashboard_window import DashboardWindow
from utils.file_utils import get_windows_drives, get_drive_type
from utils.theme import (
    BG_DARK, BG_PANEL, BG_CARD, BORDER,
    ACCENT, ACCENT2, TEXT_PRI, TEXT_SEC, MUTED,
    OK, WARN, DANGER, INFO,
    FONT_SMALL, FONT_TINY,
    btn_primary, btn_secondary, btn_danger, btn_warn,
    separator, stat_card, status_dot, apply_global_styles,
    _fmt_elapsed,
)


class MainWindow(tk.Tk):

    APP_TITLE   = "USB Antivirus"
    APP_VERSION = "1.0.0"

    def __init__(self):
        super().__init__()
        self.title(f"{self.APP_TITLE} {self.APP_VERSION}")
        self.configure(bg=BG_DARK)
        self.geometry("1200x720")
        self.minsize(1000, 600)

        apply_global_styles(self)
        init_db()

        self._current_scan_id: int = 0
        self._current_result: Optional[ScanResult] = None
        self._is_scanning = False

        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_statusbar()

        self.after(300, self._check_engine)

    # ──────────────────────────────────────────────────────────────────────────
    # Menú
    # ──────────────────────────────────────────────────────────────────────────

    def _build_menu(self):
        mb = tk.Menu(self, bg=BG_PANEL, fg=TEXT_PRI, relief="flat",
                     activebackground=ACCENT, activeforeground=BG_DARK,
                     borderwidth=0)
        for menu_label, items in [
            ("Archivo", [
                ("📊  Métricas",      self._open_dashboard),
                ("🔒  Cuarentena",    self._open_quarantine),
                ("📋  Reportes",      self._open_reports),
                None,
                ("⚙  Configuración", self._open_settings),
                None,
                ("Salir",             self._on_exit),
            ]),
            ("Ayuda", [
                ("Acerca de",         self._show_about),
            ]),
        ]:
            m = tk.Menu(mb, tearoff=0, bg=BG_PANEL, fg=TEXT_PRI,
                        activebackground=ACCENT, activeforeground=BG_DARK)
            for item in items:
                if item is None:
                    m.add_separator()
                else:
                    m.add_command(label=item[0], command=item[1])
            mb.add_cascade(label=menu_label, menu=m)
        self.config(menu=mb)

    # ──────────────────────────────────────────────────────────────────────────
    # Cabecera
    # ──────────────────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_PANEL, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Franja de acento en el borde superior
        tk.Frame(hdr, bg=ACCENT, height=3).place(x=0, y=0, relwidth=1)

        # Logo
        logo = tk.Frame(hdr, bg=BG_PANEL)
        logo.pack(side="left", padx=(20, 0))
        tk.Label(logo, text="🛡", font=("Segoe UI", 22),
                 fg=ACCENT, bg=BG_PANEL).pack(side="left", pady=14)
        txt = tk.Frame(logo, bg=BG_PANEL)
        txt.pack(side="left", padx=(6, 0))
        tk.Label(txt, text="USB ANTIVIRUS",
                 font=("Segoe UI", 14, "bold"),
                 fg=TEXT_PRI, bg=BG_PANEL).pack(anchor="w")
        tk.Label(txt, text=f"v{self.APP_VERSION}  •  ClamAV  •  Sin conexión",
                 font=FONT_TINY, fg=MUTED, bg=BG_PANEL).pack(anchor="w")

        # Indicador de estado del motor (derecha del logo)
        self._hdr_status_frame = tk.Frame(hdr, bg=BG_PANEL)
        self._hdr_status_frame.pack(side="left", padx=30)
        self._hdr_dot   = status_dot(self._hdr_status_frame, WARN)
        self._hdr_dot.pack(side="left")
        self._hdr_engine_lbl = tk.Label(
            self._hdr_status_frame, text="Verificando motor...",
            font=FONT_SMALL, fg=WARN, bg=BG_PANEL)
        self._hdr_engine_lbl.pack(side="left", padx=(4, 0))

        # Botones de navegación (derecha)
        nav = tk.Frame(hdr, bg=BG_PANEL)
        nav.pack(side="right", padx=16)
        for text, cmd in [
            ("⚙  Config",         self._open_settings),
            ("🔒  Cuarentena",     self._open_quarantine),
            ("📋  Reportes",       self._open_reports),
            ("📊  Métricas",       self._open_dashboard),
        ]:
            b = btn_secondary(nav, text, cmd)
            b.pack(side="right", padx=3, pady=12)

    # ──────────────────────────────────────────────────────────────────────────
    # Cuerpo principal
    # ──────────────────────────────────────────────────────────────────────────

    def _build_body(self):
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True)

        # ── Panel izquierdo (sidebar) — ancho reducido para dejar más espacio
        sidebar = tk.Frame(body, bg=BG_PANEL, width=240)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        self._scan_panel = ScanPanel(
            sidebar,
            on_scan_file   = lambda p: self._start_scan(p, "Archivo"),
            on_scan_folder = lambda p: self._start_scan(p, "Carpeta"),
            on_scan_drive  = lambda p: self._start_scan(p, "Unidad"),
            on_scan_full   = self._start_full_scan,
            on_scan_quick  = self._start_quick_scan,
            on_cancel      = self._cancel_scan,
        )
        self._scan_panel.pack(fill="both", expand=True)
        # Conectar callback de tiempo para sincronizar tarjeta superior
        self._scan_panel.set_time_callback(
            lambda e: self._update_stat("time", _fmt_elapsed(e), ACCENT2)
        )

        # ── Divisor vertical ──────────────────────────────────────────────────
        separator(body, "vertical").pack(side="left", fill="y")

        # ── Panel derecho ─────────────────────────────────────────────────────
        right = tk.Frame(body, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True)

        self._build_stats_bar(right)
        self._build_detections_panel(right)

    def _build_stats_bar(self, parent):
        """Fila de 4 tarjetas de estadísticas en tiempo real."""
        bar = tk.Frame(parent, bg=BG_DARK)
        bar.pack(fill="x", padx=12, pady=(10, 6))
        bar.rowconfigure(0, weight=1)

        configs = [
            ("Archivos",  "0",   TEXT_PRI, "scanned"),
            ("Amenazas",  "0",   DANGER,   "threats"),
            ("Errores",   "0",   WARN,     "errors"),
            ("Tiempo",    "0 s", ACCENT2,  "time"),
        ]
        self._stat_labels: dict[str, tk.Label] = {}
        for i, (title, val, color, key) in enumerate(configs):
            f, lbl = stat_card(bar, title, val, value_color=color)
            f.grid(row=0, column=i, padx=3, sticky="nsew")
            bar.columnconfigure(i, weight=1)
            self._stat_labels[key] = lbl

    def _build_detections_panel(self, parent):
        """Panel de detecciones con cabecera de acciones."""
        # Cabecera
        hdr = tk.Frame(parent, bg=BG_DARK)
        hdr.pack(fill="x", padx=16, pady=(0, 4))

        left_hdr = tk.Frame(hdr, bg=BG_DARK)
        left_hdr.pack(side="left")
        tk.Label(left_hdr, text="DETECCIONES",
                 font=("Segoe UI", 9, "bold"),
                 fg=MUTED, bg=BG_DARK).pack(side="left")
        self._lbl_detect_count = tk.Label(
            left_hdr, text="",
            font=("Segoe UI", 9, "bold"),
            fg=DANGER, bg=BG_DARK)
        self._lbl_detect_count.pack(side="left", padx=(8, 0))

        # Botones de acción
        act = tk.Frame(hdr, bg=BG_DARK)
        act.pack(side="right")
        btn_secondary(act, "📂 Ubicación",
                      self._open_location).pack(side="left", padx=2)
        btn_secondary(act, "🔍 Ver detalle",
                      self._view_detail).pack(side="left", padx=2)
        btn_warn(act, "🔒 Cuarentena",
                 self._quarantine_selected).pack(side="left", padx=2)
        btn_danger(act, "🗑 Eliminar",
                   self._delete_selected).pack(side="left", padx=2)

        # Badge de errores (se muestra solo cuando hay errores)
        self._errors_badge = ErrorsBadge(parent)
        self._errors_badge.pack(fill="x", padx=16, pady=(0, 2))

        # Tabla
        self._table = DetectionsTable(parent, on_select=self._view_detail_obj)
        self._table.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Banner de firmas antiguas (oculto por defecto)
        self._banner_old_db = tk.Frame(parent, bg="#2d1b00",
                                       highlightthickness=1,
                                       highlightbackground=WARN)
        tk.Label(self._banner_old_db,
                 text="⚠  Las firmas tienen más de 7 días — amenazas recientes pueden no detectarse.",
                 font=FONT_SMALL, fg=WARN, bg="#2d1b00",
                 padx=12, pady=6).pack(side="left")
        btn_warn(self._banner_old_db, "Cómo actualizar",
                 self._show_update_instructions).pack(side="right", padx=8, pady=4)

    # ──────────────────────────────────────────────────────────────────────────
    # Barra de estado
    # ──────────────────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=BG_PANEL, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        tk.Frame(bar, bg=BORDER, height=1).place(x=0, y=0, relwidth=1)

        self._lbl_status = tk.Label(bar, text="Listo",
                                    font=FONT_TINY, fg=TEXT_SEC, bg=BG_PANEL,
                                    anchor="w")
        self._lbl_status.pack(side="left", padx=10)

        self._lbl_time_status = tk.Label(bar, text="",
                                         font=FONT_TINY, fg=MUTED, bg=BG_PANEL,
                                         anchor="e")
        self._lbl_time_status.pack(side="right", padx=10)

    # ──────────────────────────────────────────────────────────────────────────
    # Verificación del motor
    # ──────────────────────────────────────────────────────────────────────────

    def _check_engine(self):
        ok, msg = check_clamav_environment()
        ver   = get_engine_version() if ok else "—"
        date  = get_db_date()        if ok else "—"
        self._scan_panel.update_engine_info(ver, date, ok, msg)

        if ok:
            self._hdr_dot.config(fg=OK)
            self._hdr_engine_lbl.config(text=f"Motor OK  •  Firmas: {date}", fg=OK)
            self._set_status("Motor ClamAV listo.", OK)
            self._check_db_age(date)
        else:
            self._hdr_dot.config(fg=DANGER)
            self._hdr_engine_lbl.config(text="Motor no disponible", fg=DANGER)
            self._set_status(f"⚠ {msg}", DANGER)

    def _check_db_age(self, date_str: str):
        try:
            db_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
            if (datetime.now() - db_date).days > 7:
                self._banner_old_db.pack(fill="x", padx=16, pady=(0, 6))
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────────
    # Lanzar análisis
    # ──────────────────────────────────────────────────────────────────────────

    def _start_scan(self, target: str, scan_type: str):
        self._start_scan_multi([target], scan_type)

    def _start_scan_multi(self, targets: list, scan_type: str):
        if self._is_scanning:
            messagebox.showwarning("Análisis en curso",
                                   "Cancela el análisis actual antes de iniciar uno nuevo.")
            return
        ok, msg = check_clamav_environment()
        if not ok:
            messagebox.showerror("Motor no disponible", msg)
            return

        display = targets[0] if len(targets) == 1 else f"{len(targets)} carpetas"

        self._is_scanning = True
        self._table.clear()
        self._errors_badge.clear()
        self._scan_panel.set_scanning(True)
        self._scan_panel.reset_stats()
        self._lbl_detect_count.config(text="")
        self._update_stat("scanned", "0")
        self._update_stat("threats", "0")
        self._update_stat("errors",  "0")
        self._update_stat("time",    "0 s")
        self._set_status("Detectando tipo de disco...", INFO)

        self._scan_panel.start_file_count(targets)  # pasa lista completa

        self._current_scan_id = start_scan(
            scan_type=scan_type, target=display,
            engine_ver=get_engine_version(), db_date=get_db_date(),
        )

        import threading as _thr
        def _detect():
            from utils.file_utils import auto_detect_workers
            cfg = str(settings.get("num_workers", "auto")).strip().lower()
            if cfg == "auto":
                workers, desc = auto_detect_workers(targets[0])
            else:
                try:
                    workers = max(1, min(4, int(cfg)))
                    desc = f"Manual: {workers} worker(s)"
                except (ValueError, TypeError):
                    from utils.file_utils import auto_detect_workers as aw
                    workers, desc = aw(targets[0])
            self.after(0, self._launch, targets, scan_type, display, workers, desc)

        _thr.Thread(target=_detect, daemon=True).start()

    def _launch(self, targets, scan_type, display, workers, disk_desc):
        self._set_status(f"Analizando: {display}  •  {disk_desc}", INFO)
        self._scan_panel.set_workers(workers)
        scanner.scan(
            targets=targets, scan_type=scan_type,
            on_progress=self._on_progress,
            on_detection=self._on_detection,
            on_finished=self._on_finished,
            scan_id=self._current_scan_id,
            num_workers=workers,
        )

    def _start_full_scan(self):
        drives = get_windows_drives()
        if not drives:
            messagebox.showerror("Análisis completo",
                                 "No se encontraron unidades disponibles.")
            return
        self._start_scan_multi(drives, "Completo")

    def _start_quick_scan(self):
        userprofile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        paths = [
            os.path.join(userprofile, "Desktop"),
            os.path.join(userprofile, "Downloads"),
            os.path.join(userprofile, "Documents"),
            os.path.join(userprofile, "AppData", "Local", "Temp"),
            os.path.join(userprofile, "AppData", "Roaming"),
        ]
        for drive in get_windows_drives():
            if get_drive_type(drive) == "Extraíble":
                paths.append(drive)
        existing = [p for p in paths if os.path.exists(p)]
        if not existing:
            messagebox.showerror("Análisis rápido",
                                 "No se encontraron las carpetas del perfil.")
            return
        lista = "\n".join(f"  • {p}" for p in existing)
        if messagebox.askyesno("⚡ Análisis rápido",
                               f"Carpetas a analizar:\n\n{lista}\n\n"
                               "Tiempo estimado: 2–10 min.\n\n¿Continuar?"):
            self._start_scan_multi(existing, "Rápido")

    def _cancel_scan(self):
        if self._is_scanning:
            scanner.cancel()
            self._set_status("Cancelando análisis...", WARN)

    # ──────────────────────────────────────────────────────────────────────────
    # Callbacks del scanner
    # ──────────────────────────────────────────────────────────────────────────

    def _on_progress(self, p: ScanProgress):
        self.after(0, self._apply_progress, p)

    def _apply_progress(self, p: ScanProgress):
        self._update_stat("scanned", f"{p.files_scanned:,}")
        self._update_stat("threats", str(p.threats_found),
                          DANGER if p.threats_found > 0 else TEXT_PRI)
        self._update_stat("errors",  str(p.errors),
                          WARN if p.errors > 0 else TEXT_PRI)
        # El tiempo lo maneja el callback del _tick del panel
        # para que sea la misma fuente que el sidebar
        self._scan_panel.update_progress(
            p.files_scanned, p.threats_found, p.errors,
            p.elapsed_sec, p.current_file, p.active_workers,
        )

    def _on_detection(self, det: Detection):
        self.after(0, self._apply_detection, det)

    def _apply_detection(self, det: Detection):
        db_id = add_detection(
            scan_id=self._current_scan_id,
            file_path=det.file_path, file_name=det.file_name,
            file_ext=det.file_ext, file_size=det.file_size,
            sha256=det.sha256, detection=det.detection_name,
            category=det.category, risk_level=det.risk_level,
            risk_label=det.risk_label,
        )
        det.db_detection_id = db_id
        self._table.add_detection(det)
        n = len(self._table.all_detections())
        self._lbl_detect_count.config(text=f"  ⚠ {n} amenaza(s)")
        self._update_stat("threats", str(n), DANGER)

    def _on_finished(self, result: ScanResult):
        self._current_result = result
        self.after(0, self._apply_finished, result)

    def _apply_finished(self, result: ScanResult):
        self._is_scanning = False
        self._scan_panel.set_scanning(False)

        self._update_stat("scanned", f"{result.files_scanned:,}")
        self._update_stat("threats", str(result.threats_found),
                          DANGER if result.threats_found > 0 else OK)
        self._update_stat("errors",  str(result.errors),
                          WARN if result.errors > 0 else TEXT_PRI)
        self._update_stat("time",    _fmt_elapsed(result.elapsed_sec), ACCENT2)

        finish_scan(
            scan_id=self._current_scan_id,
            files_scanned=result.files_scanned,
            threats_found=result.threats_found,
            errors=result.errors,
            files_skipped=len(result.skipped_files),
            elapsed_sec=result.elapsed_sec,
            status=result.status,
        )

        # Mostrar badge de errores si los hay
        if result.errors > 0 or result.skipped_files:
            self._errors_badge.update_errors(
                result.errors, result.skipped_files)

        if settings.get("generate_report_on_finish", True) and result.status != "cancelled":
            generate_report(result)

        # ── Panel de finalización ─────────────────────────────────────────────
        def _quarantine_all():
            from core.quarantine import quarantine_file
            for det in self._table.all_detections():
                if det.db_detection_id:
                    quarantine_file(det.file_path, det.db_detection_id)
            self._set_status(
                f"Todas las amenazas aisladas en cuarentena.", OK)

        FinishPanel(
            self,
            result=result,
            on_quarantine_all=_quarantine_all if result.threats_found > 0 else None,
            on_view_report=self._open_reports,
        )

        # Actualizar barra de estado (sin messagebox adicional — FinishPanel ya informa)
        if result.status == "cancelled":
            self._set_status("Análisis cancelado.", WARN)
            self._hdr_dot.config(fg=WARN)
        elif result.status == "error":
            # FinishPanel ya muestra el error — solo actualizar la barra de estado
            self._set_status(f"Error: {result.error_message}", DANGER)
            self._hdr_dot.config(fg=DANGER)
        else:
            n = result.threats_found
            if n > 0:
                self._set_status(
                    f"⚠ {n} amenaza(s) en {result.files_scanned:,} archivos "
                    f"— {result.elapsed_sec:.1f} s", DANGER)
                self._hdr_dot.config(fg=DANGER)
            else:
                self._set_status(
                    f"✓ Sin amenazas — {result.files_scanned:,} archivos "
                    f"en {result.elapsed_sec:.1f} s", OK)
                self._hdr_dot.config(fg=OK)

    # ──────────────────────────────────────────────────────────────────────────
    # Acciones sobre detecciones
    # ──────────────────────────────────────────────────────────────────────────

    def _view_detail(self):
        det = self._table.get_selected()
        if not det:
            messagebox.showinfo("Detalle", "Selecciona una detección primero.")
            return
        self._view_detail_obj(det)

    def _open_location(self):
        det = self._table.get_selected()
        if not det:
            messagebox.showinfo("Ubicación", "Selecciona una detección primero.")
            return
        from ui.detections_table import _open_file_location
        _open_file_location(det.file_path)

    def _view_detail_obj(self, det: Detection):
        DetectionDetailWindow(self, det)

    def _quarantine_selected(self):
        det = self._table.get_selected()
        if not det:
            messagebox.showinfo("Cuarentena", "Selecciona una detección primero.")
            return
        if not messagebox.askyesno("Confirmar cuarentena",
                                   f"¿Mover a cuarentena?\n\n"
                                   f"Archivo: {det.file_name}\n"
                                   f"Detección: {det.detection_name}"):
            return
        ok, msg, _ = quarantine_file(det.file_path, det.db_detection_id)
        if ok:
            messagebox.showinfo("Cuarentena", msg)
            self._set_status(f"Aislado: {det.file_name}", OK)
        else:
            messagebox.showerror("Error de cuarentena", msg)

    def _delete_selected(self):
        det = self._table.get_selected()
        if not det:
            messagebox.showinfo("Eliminar", "Selecciona una detección primero.")
            return
        from utils.file_utils import is_system_path
        if is_system_path(det.file_path):
            messagebox.showerror("Eliminación bloqueada",
                                 "Ruta del sistema protegida. Usa cuarentena.")
            return
        if not messagebox.askyesno("⚠ Confirmar eliminación",
                                   f"¿Eliminar PERMANENTEMENTE?\n\n{det.file_path}\n\n"
                                   "Esta acción NO se puede deshacer.", icon="warning"):
            return
        if not messagebox.askyesno("Segunda confirmación",
                                   f"Confirma la eliminación definitiva de:\n{det.file_path}",
                                   icon="warning"):
            return
        try:
            os.remove(det.file_path)
            messagebox.showinfo("Eliminado", f"Archivo eliminado:\n{det.file_path}")
            self._set_status(f"Eliminado: {det.file_name}", WARN)
        except PermissionError:
            messagebox.showerror("Sin permisos",
                                 "El archivo está en uso o requiere permisos de administrador.")
        except FileNotFoundError:
            messagebox.showwarning("No encontrado", "El archivo ya no existe.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ──────────────────────────────────────────────────────────────────────────
    # Ventanas secundarias
    # ──────────────────────────────────────────────────────────────────────────

    def _open_quarantine(self): QuarantineWindow(self)
    def _open_reports(self):    ReportWindow(self)
    def _open_settings(self):   SettingsWindow(self, on_save=self._check_engine)
    def _open_dashboard(self):  DashboardWindow(self)

    def _show_update_instructions(self):
        """Muestra instrucciones para actualizar las firmas."""
        import subprocess
        from pathlib import Path
        bat = settings.app_root / "update_signatures.bat"
        msg = (
            "Para actualizar las firmas antivirus necesitas Internet.\n\n"
            "Pasos:\n"
            "  1. Conecta esta USB a una PC con Internet\n"
            "  2. Ejecuta: update_signatures.bat\n"
            "  3. Espera que descargue (~100 MB)\n"
            "  4. Vuelve a usar la USB sin Internet\n\n"
        )
        if bat.exists():
            msg += f"Archivo encontrado en:\n{bat}"
            if messagebox.askyesno("Actualizar firmas", msg + "\n\n¿Abrir update_signatures.bat ahora?"):
                try:
                    subprocess.Popen([str(bat)], shell=True,
                                     cwd=str(settings.app_root))
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Actualizar firmas", msg)

    def _show_about(self):
        messagebox.showinfo("Acerca de USB Antivirus",
                            f"USB Antivirus {self.APP_VERSION}\n\n"
                            "Motor: ClamAV 1.5.4\n"
                            "Análisis ZIP, PDF, Office, HTML, YARA\n"
                            "Sin Internet · Sin instalación · Sin rastro\n\n"
                            "No transmite datos al exterior.")

    # ──────────────────────────────────────────────────────────────────────────
    # Utilidades
    # ──────────────────────────────────────────────────────────────────────────

    def _update_stat(self, key: str, value: str, color: str = ""):
        lbl = self._stat_labels.get(key)
        if lbl:
            kw = {"text": value}
            if color:
                kw["fg"] = color
            lbl.config(**kw)

    def _set_status(self, text: str, color: str = TEXT_SEC):
        self._lbl_status.config(text=text, fg=color)
        self._lbl_time_status.config(
            text=datetime.now().strftime("%H:%M:%S"), fg=MUTED)

    def _on_exit(self):
        if self._is_scanning:
            if not messagebox.askyesno("Salir",
                                       "Hay un análisis activo. ¿Cancelar y salir?"):
                return
            scanner.cancel()
        self.destroy()
