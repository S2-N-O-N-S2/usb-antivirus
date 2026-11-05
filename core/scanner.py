"""
Motor de análisis multi-worker.

Cada worker lanza su propio proceso clamscan.exe sobre un subconjunto de rutas.
Los resultados se agregan en un ScanResult compartido con lock thread-safe.

Número de workers configurable (1-4). En SSD hay ganancia real; en HDD
usar 1-2 workers para no saturar el cabezal de lectura.
"""

import subprocess
import threading
import os
import re
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from config.settings import settings
from utils.threat_classifier import classify
from utils.file_utils import sha256_of_file, get_file_size, format_size

logger = logging.getLogger("scanner")


# ──────────────────────────────────────────────────────────────────────────────
# Estructuras de datos
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Detection:
    file_path: str
    file_name: str
    file_ext: str
    file_size: int
    file_size_str: str
    detection_name: str
    category: str
    risk_level: int
    risk_label: str
    risk_color: str
    sha256: str
    detected_at: str
    db_detection_id: int = 0
    worker_id: int = 0          # qué worker lo encontró (informativo)


@dataclass
class ScanResult:
    scan_type: str
    target: str
    started_at: str
    finished_at: str = ""
    engine_version: str = ""
    db_date: str = ""
    files_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    files_skipped: int = 0
    elapsed_sec: float = 0.0
    detections: list[Detection] = field(default_factory=list)
    status: str = "running"
    error_message: str = ""
    skipped_files: list[str] = field(default_factory=list)
    workers_used: int = 1


@dataclass
class ScanProgress:
    files_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    current_file: str = ""
    elapsed_sec: float = 0.0
    active_workers: int = 0
    status: str = "running"


# Tipos callback
ProgressCallback  = Callable[[ScanProgress], None]
DetectionCallback = Callable[[Detection], None]
FinishedCallback  = Callable[[ScanResult], None]


# ──────────────────────────────────────────────────────────────────────────────
# Verificación del entorno
# ──────────────────────────────────────────────────────────────────────────────

def check_clamav_environment() -> tuple[bool, str]:
    clamscan = settings.clamscan_exe
    if not clamscan.exists():
        return False, f"No se encontró clamscan.exe en:\n{clamscan}"
    db_dir = settings.database_dir
    signatures = list(db_dir.glob("*.cvd")) + list(db_dir.glob("*.cld"))
    if not signatures:
        return False, (
            f"No se encontraron bases de firmas (.cvd / .cld) en:\n{db_dir}\n\n"
            "Ejecuta freshclam en una computadora con Internet para descargarlas."
        )
    return True, "Motor y firmas OK"


def get_engine_version() -> str:
    try:
        r = subprocess.run(
            [str(settings.clamscan_exe), "--version"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return (r.stdout or r.stderr or "").strip().splitlines()[0]
    except Exception as e:
        return f"Desconocida ({e})"


def get_db_date() -> str:
    db_dir = settings.database_dir
    files = sorted(
        list(db_dir.glob("*.cvd")) + list(db_dir.glob("*.cld")),
        key=lambda f: f.stat().st_mtime, reverse=True,
    )
    if not files:
        return "No disponible"
    return datetime.fromtimestamp(files[0].stat().st_mtime).strftime("%Y-%m-%d %H:%M")


# ──────────────────────────────────────────────────────────────────────────────
# Parseo de salida de clamscan
# ──────────────────────────────────────────────────────────────────────────────

_RE_FOUND   = re.compile(r"^(.+):\s+(.+?)\s+FOUND\s*$")
_RE_OK      = re.compile(r"^(.+):\s+OK\s*$")
_RE_ERROR   = re.compile(r"^(.+):\s+(.+?)\s+ERROR\s*$", re.IGNORECASE)
_RE_CANT    = re.compile(r"^(.+):\s+(Can't .+)$",        re.IGNORECASE)
_RE_SCANNED = re.compile(r"Scanned files:\s*(\d+)",       re.IGNORECASE)
_RE_TIME    = re.compile(r"Time:\s*([\d.]+)\s*sec",       re.IGNORECASE)
# Warnings de acceso en stderr de ClamAV Windows:
# "LibClamAV Warning: Can't open file ruta: código"
_RE_WARN_PATH = re.compile(
    r"LibClamAV Warning:.*?(?:open|access|read)\s+(?:file\s+)?(.+?):\s*\d+",
    re.IGNORECASE,
)


def _parse_line(line: str) -> tuple[str, str, str]:
    line = line.rstrip()
    if m := _RE_FOUND.match(line):    return "found",           m.group(1), m.group(2)
    if m := _RE_OK.match(line):       return "ok",              m.group(1), ""
    if m := _RE_ERROR.match(line):    return "error",           m.group(1), m.group(2)
    if m := _RE_CANT.match(line):     return "error",           m.group(1), m.group(2)
    if m := _RE_SCANNED.search(line): return "summary_scanned", m.group(1), line
    if m := _RE_TIME.search(line):    return "summary_time",    m.group(1), line
    return "other", "", line


# ──────────────────────────────────────────────────────────────────────────────
# Worker individual
# ──────────────────────────────────────────────────────────────────────────────

class _Worker:
    """
    Ejecuta clamscan sobre un subconjunto de rutas y notifica al ClamScanner
    usando callbacks thread-safe.
    """

    def __init__(self, worker_id: int, targets: list[str],
                 cancel_flag: threading.Event,
                 on_partial: Callable,   # callback interno del ClamScanner
                 scan_id: int):
        self.worker_id   = worker_id
        self.targets     = targets
        self._cancel     = cancel_flag
        self._on_partial = on_partial
        self.scan_id     = scan_id
        self._process: Optional[subprocess.Popen] = None

        # Estadísticas locales (se suman al resultado global)
        self.files_scanned = 0
        self.threats_found = 0
        self.errors        = 0
        self.skipped:  list[str]      = []
        self.detections: list[Detection] = []
        self.done          = False
        self.error_msg     = ""

    def terminate(self):
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
            except Exception:
                pass

    def run(self):
        try:
            cmd = self._build_cmd()
            logger.info("[Worker %d] %s", self.worker_id,
                        " ".join(str(c) for c in cmd))

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,   # separado para no mezclar con detecciones
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

            # Leer stdout (detecciones + resumen) en el hilo actual
            for raw in self._process.stdout:
                if self._cancel.is_set():
                    break
                self._handle_line(raw)

            # Leer stderr en un hilo aparte (warnings, errores de acceso)
            # Usa _RE_WARN_PATH definido a nivel de módulo.
            def _read_stderr():
                for line in self._process.stderr:
                    line = line.rstrip()
                    if not line:
                        continue
                    logger.debug("[Worker %d] stderr: %s", self.worker_id, line)

                    # Formato Windows: "LibClamAV Warning: Can't open file ruta: código"
                    m = _RE_WARN_PATH.search(line)
                    if m:
                        path_err = m.group(1).strip()
                        self.errors += 1
                        self.skipped.append(path_err)
                        self._on_partial("error", path_err, self.worker_id)
                    # Formato clásico: "ruta: mensaje ERROR"
                    elif _RE_ERROR.match(line):
                        mm = _RE_ERROR.match(line)
                        self.errors += 1
                        self.skipped.append(mm.group(1))
                        self._on_partial("error", mm.group(1), self.worker_id)

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            self._process.wait()
            stderr_thread.join(timeout=5)

        except Exception as e:
            self.error_msg = str(e)
            logger.exception("[Worker %d] excepción", self.worker_id)
        finally:
            self.done = True

    def _build_cmd(self) -> list[str]:
        db_dir   = settings.database_dir
        yara_dir = settings.get_path("clamav_dir") / "yara"

        cmd = [
            str(settings.clamscan_exe),
            "--recursive",
            "--infected",          # solo detecciones en stdout → más rápido
            f"--database={db_dir}",
            # NO --stdout aquí: con stderr separado no lo necesitamos
            # y así los errores van a stderr sin mezclar con las detecciones
            "--scan-archive=yes",
            "--scan-ole2=yes",
            "--scan-pdf=yes",
            "--scan-html=yes",
            "--scan-mail=yes",
            "--scan-swf=yes",
            "--detect-pua=yes",
            "--alert-encrypted=yes",
            "--max-scansize=200M",
            "--max-filesize=100M",
            "--max-recursion=16",
            "--max-files=10000",
        ]

        if yara_dir.exists():
            yara_files = (list(yara_dir.glob("*.yar")) +
                          list(yara_dir.glob("*.yara")))
            for yf in yara_files[:20]:
                cmd.append(f"--database={yf}")

        cmd.extend(self.targets)
        return cmd

    def _handle_line(self, raw: str):
        """Procesa líneas de stdout de clamscan (detecciones + resumen)."""
        line_type, path, detail = _parse_line(raw)

        if line_type == "found":
            self.files_scanned += 1
            self.threats_found += 1
            det = self._make_detection(path, detail)
            self.detections.append(det)
            self._on_partial("found", det, self.worker_id)

        elif line_type == "summary_scanned":
            # Resumen final: total real de archivos examinados
            try:
                self.files_scanned = int(path)
            except ValueError:
                pass
            self._on_partial("summary_scanned", path, self.worker_id)

    def _make_detection(self, file_path: str, detection_name: str) -> Detection:
        p = Path(file_path)
        size = get_file_size(file_path)
        sha  = sha256_of_file(file_path) or "No calculado"
        t    = classify(detection_name)
        return Detection(
            file_path=file_path,
            file_name=p.name,
            file_ext=p.suffix.lower(),
            file_size=size,
            file_size_str=format_size(size),
            detection_name=detection_name,
            category=t.category,
            risk_level=t.risk_level,
            risk_label=t.risk_label,
            risk_color=t.risk_color,
            sha256=sha,
            detected_at=datetime.now().isoformat(),
            worker_id=self.worker_id,
        )


# ──────────────────────────────────────────────────────────────────────────────
# ClamScanner multi-worker
# ──────────────────────────────────────────────────────────────────────────────

class ClamScanner:
    """
    Lanza N workers en paralelo sobre subconjuntos de rutas.
    Agrega resultados en tiempo real con lock thread-safe.

    num_workers:
      1 = comportamiento original (un solo clamscan)
      2 = dos procesos paralelos  → bueno para SSD o análisis de carpetas distintas
      3-4 = máximo paralelismo    → solo recomendado en SSD rápido
    """

    MAX_WORKERS = 4

    def __init__(self):
        self._cancel_flag = threading.Event()
        self._workers: list[_Worker] = []
        self._lock    = threading.Lock()
        self._running = False

        # Estado global agregado (protegido por _lock)
        self._g_files    = 0
        self._g_threats  = 0
        self._g_errors   = 0
        self._g_active   = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def cancel(self):
        self._cancel_flag.set()
        with self._lock:
            for w in self._workers:
                w.terminate()

    # ── API pública ───────────────────────────────────────────────────────────

    def scan(
        self,
        targets: list[str] | str,
        scan_type: str,
        on_progress:  Optional[ProgressCallback]  = None,
        on_detection: Optional[DetectionCallback] = None,
        on_finished:  Optional[FinishedCallback]  = None,
        scan_id: int = 0,
        num_workers: int = 1,
    ):
        """
        Lanza el análisis en un hilo coordinador.
        num_workers: cuántos procesos clamscan correr en paralelo (1-4).
        """
        if isinstance(targets, str):
            targets = [targets]

        num_workers = max(1, min(num_workers, self.MAX_WORKERS))

        coordinator = threading.Thread(
            target=self._coordinate,
            args=(targets, scan_type, on_progress, on_detection,
                  on_finished, scan_id, num_workers),
            daemon=True,
        )
        coordinator.start()
        return coordinator

    # ── Coordinador ───────────────────────────────────────────────────────────

    def _coordinate(
        self,
        targets: list[str],
        scan_type: str,
        on_progress:  Optional[ProgressCallback],
        on_detection: Optional[DetectionCallback],
        on_finished:  Optional[FinishedCallback],
        scan_id: int,
        num_workers: int,
    ):
        self._running = True
        self._cancel_flag.clear()
        self._g_files = self._g_threats = self._g_errors = 0

        display = targets[0] if len(targets) == 1 else f"{len(targets)} rutas"
        result = ScanResult(
            scan_type=scan_type,
            target=display,
            started_at=datetime.now().isoformat(),
            engine_version=get_engine_version(),
            db_date=get_db_date(),
            workers_used=num_workers,
        )
        start_time = time.time()

        try:
            ok, msg = check_clamav_environment()
            if not ok:
                result.status = "error"
                result.error_message = msg
                if on_finished:
                    on_finished(result)
                return

            # Dividir rutas entre workers
            # Si hay una sola ruta raíz y varios workers, la pasamos a todos
            # para que clamscan divida internamente (cada uno trabaja distinto subárbol).
            # Si hay varias rutas, las repartimos round-robin.
            buckets = self._distribute(targets, num_workers)
            actual_workers = len(buckets)

            # Callbacks parciales thread-safe
            def on_partial(event: str, data, wid: int):
                with self._lock:
                    if event == "found":
                        self._g_files   += 1
                        self._g_threats += 1
                        result.files_scanned  = self._g_files
                        result.threats_found  = self._g_threats
                        result.detections.append(data)
                        if on_detection:
                            on_detection(data)
                    elif event == "ok":
                        self._g_files += 1
                        result.files_scanned = self._g_files
                    elif event == "error":
                        self._g_files  += 1
                        self._g_errors += 1
                        result.errors         = self._g_errors
                        result.files_scanned  = self._g_files
                        result.skipped_files.append(data)
                    elif event == "summary_scanned":
                        # El resumen final de clamscan tiene el conteo exacto
                        # Solo actualizamos si es mayor que lo que llevábamos
                        try:
                            real_count = int(data)
                            if real_count > self._g_files:
                                self._g_files = real_count
                                result.files_scanned = real_count
                        except (ValueError, TypeError):
                            pass

                    # Notificar progreso en detecciones y errores inmediatamente
                    if event in ("found", "error"):
                        if on_progress:
                            on_progress(ScanProgress(
                                files_scanned=self._g_files,
                                threats_found=self._g_threats,
                                errors=self._g_errors,
                                current_file=os.path.basename(str(
                                    data.file_path if hasattr(data, "file_path") else data)),
                                elapsed_sec=time.time() - start_time,
                                active_workers=self._g_active,
                            ))

            # Crear y lanzar workers
            workers = []
            self._workers = []
            for i, bucket in enumerate(buckets):
                w = _Worker(i + 1, bucket, self._cancel_flag, on_partial, scan_id)
                workers.append(w)
                self._workers.append(w)

            with self._lock:
                self._g_active = actual_workers

            threads = []
            for w in workers:
                t = threading.Thread(target=w.run, daemon=True)
                threads.append(t)
                t.start()
                logger.info("[Coordinator] Worker %d iniciado → %s",
                            w.worker_id, w.targets)

            # ── Timer de progreso ──────────────────────────────────────────────
            # Con --infected clamscan no imprime archivos limpios, así que
            # enviamos un tick cada 2 segundos para actualizar el tiempo en la UI
            stop_timer = threading.Event()
            def _progress_timer():
                while not stop_timer.wait(2.0):
                    with self._lock:
                        files   = self._g_files
                        threats = self._g_threats
                        errors  = self._g_errors
                    if on_progress:
                        on_progress(ScanProgress(
                            files_scanned=files,
                            threats_found=threats,
                            errors=errors,
                            elapsed_sec=time.time() - start_time,
                            active_workers=self._g_active,
                        ))
            timer_thread = threading.Thread(target=_progress_timer, daemon=True)
            timer_thread.start()

            # Esperar a que terminen todos los workers
            for t in threads:
                t.join()
            stop_timer.set()

            elapsed = time.time() - start_time
            result.elapsed_sec  = elapsed
            result.finished_at  = datetime.now().isoformat()
            result.files_skipped = len(result.skipped_files)

            if self._cancel_flag.is_set():
                result.status = "cancelled"
            else:
                result.status = "completed"

            # Última notificación de progreso con totales finales
            if on_progress:
                on_progress(ScanProgress(
                    files_scanned=result.files_scanned,
                    threats_found=result.threats_found,
                    errors=result.errors,
                    elapsed_sec=elapsed,
                    active_workers=0,
                ))

        except Exception as exc:
            result.status = "error"
            result.error_message = str(exc)
            logger.exception("[Coordinator] excepción fatal")
        finally:
            self._running = False
            self._g_active = 0
            if on_finished:
                on_finished(result)

    # ── Distribución de rutas ─────────────────────────────────────────────────

    # Carpetas de alto riesgo — se analizan primero (priority scanning)
    # El Worker 0 siempre recibe estas rutas si existen en el objetivo
    _HIGH_RISK_HINTS = [
        "temp", "tmp", "appdata\\local\\temp",
        "downloads", "descargas",
        "appdata\\roaming",
        "startup", "inicio",
        "recycle.bin", "$recycle.bin",
        "public\\downloads", "usuarios\\público",
    ]

    def _distribute(self, targets: list[str], num_workers: int) -> list[list[str]]:
        """
        Distribuye rutas entre workers con priority scanning:
        1) Separa subdirectorios de alto riesgo → Worker 0 (prioridad)
        2) Reparte el resto entre los demás workers
        3) Si un worker termina antes, la distribución inicial ya balanceó la carga
        """
        if len(targets) == 1 and num_workers > 1:
            subdirs = self._get_subdirs_sorted(targets[0])
            if len(subdirs) >= num_workers:
                return self._priority_split(subdirs, num_workers)
            return [targets]

        if len(targets) <= num_workers:
            # Ordenar por prioridad antes de asignar 1:1
            sorted_targets = self._sort_by_priority(targets)
            return [[t] for t in sorted_targets]

        sorted_targets = self._sort_by_priority(targets)
        return self._priority_split(sorted_targets, num_workers)

    def _priority_split(self, items: list[str], n: int) -> list[list[str]]:
        """
        Reparte items en n buckets garantizando n buckets activos.
        Las rutas de alto riesgo se distribuyen entre TODOS los workers
        (round-robin), no solo el Worker 0, para que todos empiecen
        con carpetas peligrosas y se usen los n workers solicitados.
        """
        high, low = [], []
        for item in items:
            if self._is_high_risk(item):
                high.append(item)
            else:
                low.append(item)

        buckets: list[list[str]] = [[] for _ in range(n)]

        # Alto riesgo: round-robin entre TODOS los workers
        for i, item in enumerate(high):
            buckets[i % n].append(item)

        # Bajo riesgo: round-robin equilibrado
        for i, item in enumerate(low):
            buckets[i % n].append(item)

        # Filtrar buckets vacíos solo si hay menos rutas que workers
        non_empty = [b for b in buckets if b]
        if len(items) < n:
            return non_empty
        return non_empty

    def _sort_by_priority(self, items: list[str]) -> list[str]:
        """Ordena rutas poniendo las de alto riesgo primero."""
        return sorted(items, key=lambda p: (0 if self._is_high_risk(p) else 1))

    def _is_high_risk(self, path: str) -> bool:
        p = path.lower().replace("/", "\\")
        return any(hint in p for hint in self._HIGH_RISK_HINTS)

    def _get_subdirs_sorted(self, root: str) -> list[str]:
        """
        Devuelve subdirectorios del primer nivel ordenados por prioridad.
        Alto riesgo primero, el resto alfabético.
        """
        p = Path(root)
        if p.is_file():
            return [root]
        try:
            subdirs = [
                str(child) for child in p.iterdir()
                if child.is_dir() and not child.is_symlink()
            ]
            return self._sort_by_priority(subdirs)
        except PermissionError:
            return [root]


# Instancia global
scanner = ClamScanner()
