"""
Gestión de configuración persistente en JSON.

PORTABILIDAD: Las rutas por defecto se calculan desde el directorio del
ejecutable. Si el usuario personaliza una ruta en Configuración, ese valor
personalizado se respeta y se guarda. Las rutas relativas se resuelven
desde APP_ROOT para mantener portabilidad.
"""

import json
import os
import sys
from pathlib import Path


def get_app_root() -> Path:
    """
    Devuelve la ruta raíz de la aplicación.
    - Frozen (PyInstaller): directorio del .exe → la USB
    - Script: directorio que contiene el paquete principal
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_app_root_safe() -> Path:
    try:
        return get_app_root()
    except Exception:
        return Path(os.getcwd())


APP_ROOT = get_app_root_safe()


def _rel(subfolder: str) -> str:
    return str(APP_ROOT / subfolder)


# ── Valores por defecto ───────────────────────────────────────────────────────
DEFAULTS = {
    "clamav_dir":     _rel("clamav"),
    "database_dir":   _rel("database"),
    "quarantine_dir": _rel("quarantine"),
    "reports_dir":    _rel("reports"),
    "logs_dir":       _rel("logs"),
    "config_dir":     _rel("config"),
    "max_file_size_mb":          500,
    "scan_timeout_sec":          120,
    "num_workers":               "auto",
    "theme":                     "dark",
    "show_clean_files":          False,
    "generate_report_on_finish": True,
    "report_format":             "json",
}

# Claves que SON rutas — su valor por defecto es relativo a APP_ROOT,
# pero si el usuario las personaliza, el valor personalizado tiene precedencia.
_PATH_KEYS = {
    "clamav_dir", "database_dir", "quarantine_dir",
    "reports_dir", "logs_dir", "config_dir",
}

_CONFIG_FILE = APP_ROOT / "config" / "settings.json"


class Settings:

    def __init__(self):
        self._data: dict = {}
        self.load()

    def load(self):
        """
        Carga la configuración guardada mezclándola con los defaults.
        Las rutas personalizadas se respetan; las no guardadas usan el default
        calculado desde APP_ROOT (portabilidad automática en nueva PC).
        """
        saved: dict = {}
        if _CONFIG_FILE.exists():
            try:
                with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
            except Exception:
                saved = {}

        # Construir _data: defaults primero, encima los valores guardados.
        # Para claves de ruta: si el valor guardado es una ruta absoluta de
        # OTRA computadora (no existe), descartarla y usar el default.
        self._data = dict(DEFAULTS)
        for k, v in saved.items():
            if k in _PATH_KEYS:
                # Solo usar el valor guardado si la ruta existe o
                # si es relativa (no comienza con letra de unidad distinta)
                saved_path = Path(str(v))
                if saved_path.exists():
                    self._data[k] = str(v)
                # else: ruta no existe en esta PC → mantener default calculado
            else:
                self._data[k] = v

    def save(self):
        """
        Guarda la configuración completa.
        Las rutas se guardan solo si difieren del default (para no contaminar
        la portabilidad cuando se copia a otra PC).
        """
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        to_save = {}
        for k, v in self._data.items():
            if k in _PATH_KEYS:
                # Solo guardar si el usuario lo personalizó (difiere del default)
                default_val = DEFAULTS.get(k, "")
                if str(v) != str(default_val):
                    to_save[k] = str(v)
            else:
                to_save[k] = v
        with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2, ensure_ascii=False)

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value):
        self._data[key] = value
        self.save()

    def get_path(self, key: str) -> Path:
        """
        Devuelve la Path para una clave.
        Respeta valores personalizados; usa default desde APP_ROOT si no hay.
        """
        val = self._data.get(key)
        if val:
            p = Path(str(val))
            # Si es ruta relativa, resolverla desde APP_ROOT
            if not p.is_absolute():
                return APP_ROOT / p
            return p
        # Fallback al mapa de defaults
        folder_map = {
            "clamav_dir":     "clamav",
            "database_dir":   "database",
            "quarantine_dir": "quarantine",
            "reports_dir":    "reports",
            "logs_dir":       "logs",
            "config_dir":     "config",
        }
        return APP_ROOT / folder_map.get(key, key)

    # ── Propiedades de acceso rápido ──────────────────────────────────────────

    @property
    def clamscan_exe(self) -> Path:
        return self.get_path("clamav_dir") / "clamscan.exe"

    @property
    def freshclam_exe(self) -> Path:
        return self.get_path("clamav_dir") / "freshclam.exe"

    @property
    def database_dir(self) -> Path:
        return self.get_path("database_dir")

    @property
    def quarantine_dir(self) -> Path:
        return self.get_path("quarantine_dir")

    @property
    def reports_dir(self) -> Path:
        return self.get_path("reports_dir")

    @property
    def logs_dir(self) -> Path:
        return self.get_path("logs_dir")

    @property
    def app_root(self) -> Path:
        return APP_ROOT

    def all(self) -> dict:
        return dict(self._data)


# Instancia global compartida
settings = Settings()
