"""
Lista blanca local por SHA-256.
Los archivos marcados como seguros no aparecen como amenaza en análisis futuros.
Se guarda en config/whitelist.json dentro de la USB.

Optimización: los datos se cachean en memoria para evitar leer el archivo
en cada detección durante un análisis (puede haber miles de llamadas).
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.settings import settings

logger = logging.getLogger("whitelist")

# ── Caché en memoria ──────────────────────────────────────────────────────────
# Se carga una vez y se mantiene sincronizado al escribir.
_cache: Optional[dict] = None


def _wl_path() -> Path:
    p = settings.get_path("config_dir") / "whitelist.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load() -> dict:
    global _cache
    if _cache is not None:
        return _cache
    p = _wl_path()
    if p.exists():
        try:
            _cache = json.loads(p.read_text(encoding="utf-8"))
            return _cache
        except Exception:
            pass
    _cache = {}
    return _cache


def _save(data: dict):
    global _cache
    try:
        _wl_path().write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _cache = data   # actualizar caché tras escritura exitosa
    except OSError as e:
        logger.error("No se pudo guardar lista blanca: %s", e)
        raise


def _invalidate_cache():
    """Fuerza recarga desde disco en la próxima llamada a _load()."""
    global _cache
    _cache = None


def is_whitelisted(sha256: str) -> bool:
    """Devuelve True si el hash está en la lista blanca. Usa caché."""
    if not sha256 or sha256 == "No calculado":
        return False
    return sha256.lower() in _load()


def add_to_whitelist(sha256: str, file_name: str,
                     detection: str, reason: str = "") -> bool:
    """Agrega un hash a la lista blanca. Devuelve True si se guardó."""
    if not sha256 or sha256 == "No calculado":
        logger.warning("No se puede agregar a lista blanca: hash no disponible.")
        return False
    data = _load()
    data[sha256.lower()] = {
        "file_name":  file_name,
        "detection":  detection,
        "reason":     reason,
        "added_at":   datetime.now().isoformat(),
    }
    try:
        _save(data)
        logger.info("Lista blanca: agregado %s (%s)", file_name, sha256[:12])
        return True
    except OSError:
        return False


def remove_from_whitelist(sha256: str) -> bool:
    """Elimina un hash de la lista blanca."""
    data = _load()
    key = sha256.lower()
    if key in data:
        del data[key]
        try:
            _save(data)
            return True
        except OSError:
            return False
    return False


def get_all() -> list[dict]:
    """Devuelve todos los elementos de la lista blanca."""
    data = _load()
    return [{"sha256": k, **v} for k, v in data.items()]


def count() -> int:
    return len(_load())


def reload() -> None:
    """Fuerza recarga desde disco (útil si el archivo fue editado externamente)."""
    _invalidate_cache()
    _load()
