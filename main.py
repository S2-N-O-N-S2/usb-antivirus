"""
USB Antivirus — Punto de entrada principal.

Ejecutar desde script:
    python main.py

Portabilidad:
    En modo ejecutable PyInstaller (frozen), sys.executable apunta al .exe
    en la USB. Todas las rutas se calculan desde ahí, sin depender de rutas
    absolutas de ninguna computadora específica.
"""

import sys
import os
from pathlib import Path


def _get_root() -> Path:
    """
    Calcula el directorio raíz de la aplicación de forma portable.
    - Frozen (exe): directorio del .exe → la USB
    - Script: directorio que contiene main.py
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


# Raíz de la aplicación — debe calcularse ANTES de cualquier importación
_APP_ROOT = _get_root()

# Asegurar que la raíz está en sys.path para importar los paquetes locales
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

# ── Configurar logging ────────────────────────────────────────────────────────
# Importar settings DESPUÉS de ajustar sys.path
import logging

try:
    from config.settings import settings
    _log_dir = settings.logs_dir
    _log_dir.mkdir(parents=True, exist_ok=True)
    _log_file = _log_dir / "usb_antivirus.log"
except Exception as _e:
    # Fallback: log junto al exe si la carpeta logs/ no está disponible
    _log_file = _APP_ROOT / "usb_antivirus.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(str(_log_file), encoding="utf-8", errors="replace"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")


def main():
    logger.info("=== USB Antivirus iniciado ===")
    logger.info("Raiz: %s", _APP_ROOT)
    logger.info("Frozen: %s", getattr(sys, "frozen", False))
    logger.info("ClamAV: %s", settings.clamscan_exe)
    logger.info("Firmas: %s", settings.database_dir)

    # Verificar que las carpetas de trabajo existen (crearlas si no)
    for folder_key in ("quarantine_dir", "reports_dir", "logs_dir", "config_dir"):
        try:
            settings.get_path(folder_key).mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            logger.error("Sin permisos para crear carpeta %s: %s", folder_key, e)
        except Exception as e:
            logger.warning("No se pudo crear carpeta %s: %s", folder_key, e)

    # Lanzar UI
    try:
        from ui.main_window import MainWindow
        app = MainWindow()
        app.protocol("WM_DELETE_WINDOW", app._on_exit)
        app.mainloop()
    except ImportError as e:
        logger.critical("No se pudo importar la interfaz: %s", e)
        _show_fatal_error(
            "Error al cargar la interfaz",
            f"No se encontró un módulo necesario:\n{e}\n\n"
            "Verifica que la carpeta LISTO_PARA_USB está completa."
        )
        sys.exit(1)
    except Exception as e:
        logger.critical("Error fatal: %s", e, exc_info=True)
        _show_fatal_error("Error fatal al iniciar", str(e))
        raise

    logger.info("=== USB Antivirus cerrado ===")


def _show_fatal_error(title: str, message: str):
    """Muestra un error fatal incluso si tkinter no carga."""
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        print(f"\n[ERROR FATAL] {title}\n{message}\n")


if __name__ == "__main__":
    main()
