"""
Generación de reportes locales: JSON, TXT y CSV.
Los reportes se guardan en reports/ con nombre basado en fecha y hora.
No se transmite ningún dato fuera del equipo.
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.settings import settings
from core.scanner import ScanResult

logger = logging.getLogger("report")


def _reports_dir() -> Path:
    d = settings.reports_dir
    d.mkdir(parents=True, exist_ok=True)
    return d


def _report_filename(scan_type: str, fmt: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_type = scan_type.replace(" ", "_").replace("/", "-")
    return _reports_dir() / f"reporte_{safe_type}_{ts}.{fmt}"


# ──────────────────────────────────────────────────────────────────────────────
# Generadores
# ──────────────────────────────────────────────────────────────────────────────

def generate_json(result: ScanResult) -> Optional[Path]:
    path = _report_filename(result.scan_type, "json")
    try:
        data = _build_dict(result)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("Reporte JSON: %s", path)
        return path
    except Exception as e:
        logger.error("No se pudo generar reporte JSON: %s", e)
        return None


def generate_txt(result: ScanResult) -> Optional[Path]:
    path = _report_filename(result.scan_type, "txt")
    try:
        lines = _build_txt_lines(result)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info("Reporte TXT: %s", path)
        return path
    except Exception as e:
        logger.error("No se pudo generar reporte TXT: %s", e)
        return None


def generate_csv(result: ScanResult) -> Optional[Path]:
    path = _report_filename(result.scan_type, "csv")
    try:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Ruta completa", "Nombre", "Extensión", "Tamaño",
                "Detección", "Categoría", "Nivel de riesgo", "Etiqueta de riesgo",
                "SHA-256", "Detectado en", "Acción",
            ])
            for d in result.detections:
                writer.writerow([
                    d.file_path, d.file_name, d.file_ext, d.file_size_str,
                    d.detection_name, d.category, d.risk_level, d.risk_label,
                    d.sha256, d.detected_at, "Pendiente",
                ])
        logger.info("Reporte CSV: %s", path)
        return path
    except Exception as e:
        logger.error("No se pudo generar reporte CSV: %s", e)
        return None


def generate_report(result: ScanResult) -> dict[str, Optional[Path]]:
    """
    Genera reportes según el formato configurado.
    - "json": solo JSON
    - "txt":  solo TXT
    - "csv":  solo CSV
    - "all":  JSON + TXT + CSV
    JSON es el formato por defecto si no está configurado.
    """
    fmt = settings.get("report_format", "json")
    paths: dict[str, Optional[Path]] = {}

    if fmt == "json":
        paths["json"] = generate_json(result)
    elif fmt == "txt":
        paths["txt"] = generate_txt(result)
    elif fmt == "csv":
        paths["csv"] = generate_csv(result)
    elif fmt == "all":
        paths["json"] = generate_json(result)
        paths["txt"]  = generate_txt(result)
        paths["csv"]  = generate_csv(result)
    else:
        # Fallback: JSON
        paths["json"] = generate_json(result)

    return paths


# ──────────────────────────────────────────────────────────────────────────────
# Constructores internos
# ──────────────────────────────────────────────────────────────────────────────

def _build_dict(result: ScanResult) -> dict:
    return {
        "reporte": {
            "generado_en": datetime.now().isoformat(),
            "tipo_analisis": result.scan_type,
            "objetivo": result.target,
            "inicio": result.started_at,
            "fin": result.finished_at,
            "motor": result.engine_version,
            "fecha_firmas": result.db_date,
            "estado": result.status,
        },
        "resumen": {
            "archivos_examinados": result.files_scanned,
            "amenazas_detectadas": result.threats_found,
            "errores": result.errors,
            "archivos_omitidos": result.files_skipped,
            "tiempo_segundos": round(result.elapsed_sec, 2),
        },
        "detecciones": [
            {
                "ruta": d.file_path,
                "nombre": d.file_name,
                "extension": d.file_ext,
                "tamano": d.file_size_str,
                "deteccion": d.detection_name,
                "categoria": d.category,
                "nivel_riesgo": d.risk_level,
                "etiqueta_riesgo": d.risk_label,
                "sha256": d.sha256,
                "detectado_en": d.detected_at,
            }
            for d in result.detections
        ],
        "archivos_omitidos": result.skipped_files,
    }


def _build_txt_lines(result: ScanResult) -> list[str]:
    sep = "=" * 70
    lines = [
        sep,
        "  USB ANTIVIRUS — REPORTE DE ANÁLISIS",
        sep,
        f"  Generado     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Tipo         : {result.scan_type}",
        f"  Objetivo     : {result.target}",
        f"  Inicio       : {result.started_at}",
        f"  Fin          : {result.finished_at}",
        f"  Motor        : {result.engine_version}",
        f"  Firmas       : {result.db_date}",
        f"  Estado       : {result.status}",
        sep,
        "  RESUMEN",
        sep,
        f"  Archivos examinados  : {result.files_scanned}",
        f"  Amenazas detectadas  : {result.threats_found}",
        f"  Errores              : {result.errors}",
        f"  Archivos omitidos    : {result.files_skipped}",
        f"  Tiempo (s)           : {result.elapsed_sec:.2f}",
        "",
    ]

    if result.detections:
        lines += [sep, "  DETECCIONES", sep]
        for i, d in enumerate(result.detections, 1):
            lines += [
                f"  [{i}] {d.file_name}",
                f"      Ruta      : {d.file_path}",
                f"      Detección : {d.detection_name}",
                f"      Categoría : {d.category}",
                f"      Riesgo    : {d.risk_label}",
                f"      Tamaño    : {d.file_size_str}",
                f"      SHA-256   : {d.sha256}",
                f"      Fecha     : {d.detected_at}",
                "",
            ]
    else:
        lines += ["", "  Sin detecciones.", ""]

    if result.skipped_files:
        lines += [sep, "  ARCHIVOS OMITIDOS / ERRORES", sep]
        for f in result.skipped_files:
            lines.append(f"  - {f}")

    lines += [sep, "  FIN DEL REPORTE", sep]
    return lines
