"""
Utilidades para manejo seguro de archivos:
 - calcular SHA-256
 - listar unidades disponibles en Windows
 - determinar si una ruta es accesible
 - formatear tamaños
 - detectar tipo de disco y workers óptimos
"""

import hashlib
import os
import string
import ctypes
import subprocess
import re
import threading
import time as _time
from pathlib import Path
from typing import Optional


def sha256_of_file(path: str | Path, chunk_size: int = 65536) -> Optional[str]:
    """Calcula el hash SHA-256 de un archivo. Devuelve None si no es accesible."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def format_size(size_bytes: int) -> str:
    """Devuelve tamaño legible: '1.23 MB', '456 KB', etc."""
    if size_bytes < 0:
        return "Desconocido"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def get_file_size(path: str | Path) -> int:
    """Tamaño del archivo en bytes, o -1 si no es accesible."""
    try:
        return os.path.getsize(path)
    except Exception:
        return -1


def get_windows_drives() -> list[str]:
    """
    Devuelve lista de letras de unidad disponibles en Windows, p.ej. ['C:\\', 'D:\\', 'E:\\'].
    Usa la API de Windows para mayor fiabilidad.
    """
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter in enumerate(string.ascii_uppercase):
            if bitmask & (1 << i):
                drives.append(f"{letter}:\\")
    except Exception:
        # Fallback: probar letras comunes
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    return drives


def get_drive_type(drive: str) -> str:
    """
    Devuelve tipo de unidad: 'Fijo', 'Extraíble', 'Red', 'CD/DVD', 'RAM', 'Desconocido'.
    """
    type_map = {
        0: "Desconocido",
        1: "Sin raíz",
        2: "Extraíble",
        3: "Fijo",
        4: "Red",
        5: "CD/DVD",
        6: "RAM",
    }
    try:
        t = ctypes.windll.kernel32.GetDriveTypeW(drive)
        return type_map.get(t, "Desconocido")
    except Exception:
        return "Desconocido"


def is_path_accessible(path: str | Path) -> bool:
    """Comprueba si una ruta existe y puede leerse."""
    try:
        p = Path(path)
        return p.exists() and os.access(p, os.R_OK)
    except Exception:
        return False


def safe_relative_path(file_path: str | Path, base_path: str | Path) -> str:
    """Ruta relativa de file_path respecto a base_path, o ruta absoluta si no es posible."""
    try:
        return str(Path(file_path).relative_to(Path(base_path)))
    except ValueError:
        return str(file_path)


def is_system_path(path: str | Path) -> bool:
    """
    Indica si la ruta pertenece a directorios protegidos del sistema.
    Ayuda a prevenir eliminaciones peligrosas.
    """
    protected = [
        "windows", "system32", "syswow64", "winnt",
        "program files", "program files (x86)",
        "programdata", "boot", "efi",
    ]
    p_str = str(path).lower().replace("/", "\\")
    for prot in protected:
        if f"\\{prot}\\" in p_str or p_str.startswith(f"c:\\{prot}"):
            return True
    return False


def unique_quarantine_name(original_name: str, quarantine_dir: Path) -> Path:
    """
    Genera un nombre único para el archivo en cuarentena.
    Formato: <nombre_original>.<contador>.quar
    """
    base = Path(original_name).name
    candidate = quarantine_dir / f"{base}.quar"
    counter = 1
    while candidate.exists():
        candidate = quarantine_dir / f"{base}.{counter}.quar"
        counter += 1
    return candidate


def count_files(path: str | Path,
                stop_flag=None,
                max_count: int = 500_000) -> int:
    """
    Cuenta los archivos en una ruta (recursivamente) de forma rápida.
    - stop_flag: threading.Event; si se activa, detiene el conteo.
    - max_count: límite para no tardar demasiado en discos enormes.
    Devuelve el número de archivos encontrados (puede ser parcial si se alcanza el límite).
    """
    total = 0
    try:
        p = Path(path)
        if p.is_file():
            return 1
        for root, dirs, files in os.walk(str(p)):
            if stop_flag and stop_flag.is_set():
                break
            total += len(files)
            if total >= max_count:
                break
            # Saltar puntos de reanálisis y enlaces simbólicos para evitar ciclos
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(root, d))
            ]
    except Exception:
        pass
    return total


def format_eta(seconds: float) -> str:
    """
    Convierte segundos a texto legible: '2 h 15 min', '45 min', '30 s'.
    """
    if seconds <= 0:
        return "calculando..."
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    secs    = seconds % 60
    if minutes < 60:
        return f"{minutes} min {secs} s"
    hours   = minutes // 60
    mins    = minutes % 60
    return f"{hours} h {mins} min"


# ──────────────────────────────────────────────────────────────────────────────
# Detección automática de tipo de disco y workers óptimos
# ──────────────────────────────────────────────────────────────────────────────

def _get_drive_letter(path: str) -> str:
    """Extrae la letra de unidad de una ruta, p.ej. 'C:\\Users\\...' → 'C'."""
    p = Path(path).resolve()
    drive = p.drive          # 'C:' o ''
    return drive[0].upper() if drive else "C"


def _is_ssd_via_wmi(drive_letter: str) -> Optional[bool]:
    """
    Consulta WMI para saber si el disco que contiene drive_letter es SSD.
    Devuelve True=SSD, False=HDD, None=no se pudo determinar.
    Requiere Windows; no eleva permisos.
    """
    try:
        # PowerShell: busca el disco físico asociado a la partición
        script = (
            f"$vol = Get-Partition | Where-Object {{ $_.DriveLetter -eq '{drive_letter}' }} | "
            f"Get-Disk; "
            f"if ($vol) {{ $vol.MediaType }} else {{ 'Unknown' }}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout.strip().lower()
        if "ssd" in output or "solid" in output:
            return True
        if "hdd" in output or "unspecified" in output:
            return False
        # MediaType values: 3=HDD, 4=SSD — buscar coincidencia exacta de palabra
        # para evitar falsos positivos con fechas, nombres de disco, etc.
        import re as _re
        if _re.search(r'\bHDD\b', result.stdout, _re.IGNORECASE):
            return False
        if _re.search(r'\bSSD\b', result.stdout, _re.IGNORECASE):
            return True
        # Valor numérico exacto al inicio de línea o como token solo
        if _re.search(r'(?:^|\s)3(?:\s|$)', result.stdout):
            return False
        if _re.search(r'(?:^|\s)4(?:\s|$)', result.stdout):
            return True
    except Exception:
        pass
    return None


def _is_ssd_via_seek_benchmark(path: str, samples: int = 6) -> Optional[bool]:
    """
    Benchmark de latencia de acceso aleatorio como fallback.
    SSD: latencia < ~0.3 ms por acceso.
    HDD: latencia > ~5 ms por acceso.
    Devuelve True=SSD, False=HDD, None=no se pudo determinar.
    """
    try:
        test_file = None
        # Buscar un archivo existente de al menos 1 MB en la ruta
        p = Path(path)
        search_root = p if p.is_dir() else p.parent
        for f in search_root.rglob("*"):
            if f.is_file() and f.stat().st_size > 1_048_576:
                test_file = str(f)
                break

        if not test_file:
            return None

        file_size = os.path.getsize(test_file)
        import random
        times = []
        with open(test_file, "rb") as fh:
            for _ in range(samples):
                offset = random.randint(0, max(0, file_size - 4096))
                t0 = _time.perf_counter()
                fh.seek(offset)
                fh.read(512)
                times.append(_time.perf_counter() - t0)

        avg_ms = (sum(times) / len(times)) * 1000
        # SSD: < 1 ms promedio, HDD: > 5 ms promedio
        if avg_ms < 1.5:
            return True
        if avg_ms > 4.0:
            return False
    except Exception:
        pass
    return None


def detect_disk_type(path: str) -> str:
    """
    Detecta el tipo de disco de la ruta dada.
    Devuelve: 'SSD' | 'HDD' | 'Extraíble' | 'Desconocido'
    """
    try:
        letter = _get_drive_letter(path)
        drive  = f"{letter}:\\"

        # Primero verificar si es extraíble
        if get_drive_type(drive) == "Extraíble":
            return "Extraíble"

        # Intentar WMI (método más fiable)
        result = _is_ssd_via_wmi(letter)
        if result is True:
            return "SSD"
        if result is False:
            return "HDD"

        # Fallback: benchmark de seek
        result = _is_ssd_via_seek_benchmark(path)
        if result is True:
            return "SSD"
        if result is False:
            return "HDD"

    except Exception:
        pass

    return "Desconocido"


def auto_detect_workers(path: str) -> tuple[int, str]:
    """
    Detecta automáticamente cuántos workers usar según el tipo de disco.

    Reglas:
      SSD / NVMe          → 3 workers  (paralelismo alto sin riesgo)
      HDD                 → 1 worker   (cabezal único, más hilos = más lento)
      Extraíble (USB 3.x) → 2 workers  (bus USB puede manejar algo de paralelismo)
      Extraíble (USB 2.x) → 1 worker
      Desconocido         → 1 worker   (seguro por defecto)

    Devuelve (num_workers, descripción).
    """
    disk_type = detect_disk_type(path)

    if disk_type == "SSD":
        return 3, "SSD detectado — 3 workers paralelos"

    if disk_type == "HDD":
        return 1, "HDD detectado — 1 worker (óptimo para disco mecánico)"

    if disk_type == "Extraíble":
        # Intentar distinguir USB 3.x de 2.x por velocidad de lectura rápida
        speed = _estimate_read_speed_mb(path)
        if speed is not None and speed > 50:   # > 50 MB/s → USB 3.x
            return 2, f"USB 3.x detectado ({speed:.0f} MB/s) — 2 workers"
        return 1, "USB 2.x / unidad extraíble lenta — 1 worker"

    return 1, "Tipo de disco desconocido — 1 worker (conservador)"


def _estimate_read_speed_mb(path: str, duration: float = 0.4) -> Optional[float]:
    """
    Lee datos durante `duration` segundos y estima la velocidad en MB/s.
    Devuelve None si no se puede calcular.
    """
    try:
        p = Path(path)
        root = p if p.is_dir() else p.parent
        test_file = None
        for f in root.rglob("*"):
            if f.is_file() and f.stat().st_size > 512_000:
                test_file = str(f)
                break
        if not test_file:
            return None

        bytes_read = 0
        t0 = _time.perf_counter()
        with open(test_file, "rb") as fh:
            while _time.perf_counter() - t0 < duration:
                chunk = fh.read(65536)
                if not chunk:
                    break
                bytes_read += len(chunk)

        elapsed = _time.perf_counter() - t0
        if elapsed > 0:
            return (bytes_read / elapsed) / (1024 * 1024)
    except Exception:
        pass
    return None
