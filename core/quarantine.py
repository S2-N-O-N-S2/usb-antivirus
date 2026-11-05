"""
Sistema de cuarentena local.
- Mueve archivos a la carpeta quarantine/ con nombre único *.quar
- Registra la ruta original, hash y fecha en SQLite
- Permite restaurar o eliminar definitivamente
- Nunca ejecuta archivos aislados
- Verifica integridad antes de borrar el original
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Optional

from config.settings import settings
from utils.file_utils import sha256_of_file, unique_quarantine_name, is_system_path
from core.database import (
    log_quarantine, get_quarantine_items,
    update_quarantine_status, update_detection_action,
)

logger = logging.getLogger("quarantine")


class QuarantineError(Exception):
    pass


def _ensure_quarantine_dir() -> Path:
    qdir = settings.quarantine_dir
    qdir.mkdir(parents=True, exist_ok=True)
    # Crear archivo README para advertir de no ejecutar
    readme = qdir / "NO_EJECUTAR.txt"
    if not readme.exists():
        readme.write_text(
            "CUARENTENA DE USB ANTIVIRUS\n"
            "==============================\n"
            "Esta carpeta contiene archivos potencialmente peligrosos aislados.\n"
            "NO abra, ejecute ni mueva estos archivos manualmente.\n"
            "Utilice la aplicación USB Antivirus para gestionarlos.\n",
            encoding="utf-8",
        )
    return qdir


def quarantine_file(file_path: str, detection_id: int) -> tuple[bool, str, Optional[str]]:
    """
    Mueve file_path a cuarentena.
    Devuelve (éxito, mensaje, ruta_cuarentena_o_None).
    """
    src = Path(file_path)

    if not src.exists():
        return False, f"El archivo ya no existe:\n{file_path}", None

    if is_system_path(file_path):
        return False, (
            "Operación bloqueada: el archivo está en una ruta del sistema protegida.\n"
            f"{file_path}"
        ), None

    qdir = _ensure_quarantine_dir()
    dest = unique_quarantine_name(src.name, qdir)

    # Calcular hash antes de mover
    original_sha = sha256_of_file(src) or ""

    try:
        shutil.move(str(src), str(dest))
    except PermissionError as e:
        return False, (
            f"Sin permisos para mover el archivo.\n"
            f"Es posible que esté en uso o requiera permisos de administrador.\n{e}"
        ), None
    except Exception as e:
        return False, f"Error al mover a cuarentena:\n{e}", None

    # Verificar que el archivo llegó correctamente
    if not dest.exists():
        return False, "El archivo no llegó a cuarentena. No se eliminó el original.", None

    moved_sha = sha256_of_file(dest) or ""
    if original_sha and moved_sha and original_sha != moved_sha:
        # Integridad comprometida: restaurar
        try:
            shutil.move(str(dest), str(src))
        except Exception:
            pass
        return False, "Error de integridad: el hash del archivo cambió durante el movimiento.", None

    # Registrar en base de datos
    try:
        log_quarantine(
            detection_id=detection_id,
            original_path=str(src),
            quarantine_path=str(dest),
            sha256=original_sha,
        )
        update_detection_action(detection_id, "quarantined", str(dest))
    except Exception as e:
        logger.warning("No se pudo registrar en BD: %s", e)

    logger.info("Cuarentena: %s → %s", src, dest)
    return True, f"Archivo aislado correctamente en:\n{dest}", str(dest)


def restore_file(quarantine_id: int, quarantine_path: str, original_path: str) -> tuple[bool, str]:
    """
    Restaura un archivo desde cuarentena a su ubicación original.
    Requiere confirmación previa en la UI.
    """
    qfile = Path(quarantine_path)
    if not qfile.exists():
        return False, f"El archivo en cuarentena no existe:\n{quarantine_path}"

    dest = Path(original_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists():
        return False, (
            f"Ya existe un archivo en la ruta de destino:\n{original_path}\n"
            "Muévalo o cámbiele el nombre antes de restaurar."
        )

    try:
        shutil.move(str(qfile), str(dest))
    except PermissionError as e:
        return False, f"Sin permisos para restaurar:\n{e}"
    except Exception as e:
        return False, f"Error al restaurar:\n{e}"

    if not dest.exists():
        return False, "El archivo no llegó a su destino. El original de cuarentena puede haberse perdido."

    update_quarantine_status(quarantine_id, "restored")
    logger.info("Restaurado: %s → %s", qfile, dest)
    return True, f"Archivo restaurado en:\n{dest}"


def delete_quarantined_file(quarantine_id: int, quarantine_path: str) -> tuple[bool, str]:
    """
    Elimina definitivamente un archivo de cuarentena.
    Requiere doble confirmación en la UI antes de llamar esto.
    """
    qfile = Path(quarantine_path)
    if not qfile.exists():
        # Ya no existe, marcar como eliminado igualmente
        update_quarantine_status(quarantine_id, "deleted")
        return True, "El archivo ya no existía en cuarentena. Registro eliminado."

    try:
        os.remove(str(qfile))
    except PermissionError as e:
        return False, f"Sin permisos para eliminar:\n{e}"
    except Exception as e:
        return False, f"Error al eliminar:\n{e}"

    update_quarantine_status(quarantine_id, "deleted")
    logger.info("Eliminado definitivamente: %s", qfile)
    return True, "Archivo eliminado definitivamente de la cuarentena."


def list_quarantine() -> list[dict]:
    """Devuelve todos los archivos actualmente en cuarentena."""
    return get_quarantine_items()
