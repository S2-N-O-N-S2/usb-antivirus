"""
Historial de análisis almacenado en SQLite local.
La base de datos se guarda en config/history.db dentro de la USB.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.settings import settings


def _db_path() -> Path:
    p = settings.get_path("config_dir") / "history.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea las tablas si no existen."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                scan_type   TEXT NOT NULL,
                target      TEXT NOT NULL,
                engine_ver  TEXT,
                db_date     TEXT,
                files_scanned   INTEGER DEFAULT 0,
                threats_found   INTEGER DEFAULT 0,
                errors          INTEGER DEFAULT 0,
                files_skipped   INTEGER DEFAULT 0,
                elapsed_sec     REAL DEFAULT 0,
                status      TEXT DEFAULT 'running',
                notes       TEXT
            );

            CREATE TABLE IF NOT EXISTS detections (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id),
                file_path   TEXT NOT NULL,
                file_name   TEXT NOT NULL,
                file_ext    TEXT,
                file_size   INTEGER,
                sha256      TEXT,
                detection   TEXT NOT NULL,
                category    TEXT,
                risk_level  INTEGER,
                risk_label  TEXT,
                detected_at TEXT NOT NULL,
                action_taken TEXT DEFAULT 'none',
                quarantine_path TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS quarantine_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id    INTEGER REFERENCES detections(id),
                original_path   TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                sha256          TEXT,
                quarantined_at  TEXT NOT NULL,
                restored_at     TEXT,
                deleted_at      TEXT,
                status          TEXT DEFAULT 'quarantined'
            );
        """)


# ── Scans ──────────────────────────────────────────────────────────────────────

def start_scan(scan_type: str, target: str, engine_ver: str = "", db_date: str = "") -> int:
    """Registra el inicio de un análisis y devuelve su ID."""
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans (started_at, scan_type, target, engine_ver, db_date, status)
               VALUES (?, ?, ?, ?, ?, 'running')""",
            (datetime.now().isoformat(), scan_type, target, engine_ver, db_date),
        )
        return cur.lastrowid


def finish_scan(scan_id: int, files_scanned: int, threats_found: int,
                errors: int, files_skipped: int, elapsed_sec: float,
                status: str = "completed", notes: str = ""):
    """Actualiza el registro de un análisis al terminar."""
    with _connect() as conn:
        conn.execute(
            """UPDATE scans SET
                finished_at=?, files_scanned=?, threats_found=?,
                errors=?, files_skipped=?, elapsed_sec=?, status=?, notes=?
               WHERE id=?""",
            (datetime.now().isoformat(), files_scanned, threats_found,
             errors, files_skipped, elapsed_sec, status, notes, scan_id),
        )


def get_scans(limit: int = 100) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Detecciones ────────────────────────────────────────────────────────────────

def add_detection(scan_id: int, file_path: str, file_name: str, file_ext: str,
                  file_size: int, sha256: str, detection: str, category: str,
                  risk_level: int, risk_label: str) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO detections
               (scan_id, file_path, file_name, file_ext, file_size, sha256,
                detection, category, risk_level, risk_label, detected_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, file_path, file_name, file_ext, file_size, sha256,
             detection, category, risk_level, risk_label,
             datetime.now().isoformat()),
        )
        return cur.lastrowid


def update_detection_action(detection_id: int, action: str, quarantine_path: str = ""):
    with _connect() as conn:
        conn.execute(
            "UPDATE detections SET action_taken=?, quarantine_path=? WHERE id=?",
            (action, quarantine_path, detection_id),
        )


def get_detections_for_scan(scan_id: int) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM detections WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Cuarentena ────────────────────────────────────────────────────────────────

def log_quarantine(detection_id: int, original_path: str,
                   quarantine_path: str, sha256: str) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO quarantine_log
               (detection_id, original_path, quarantine_path, sha256, quarantined_at, status)
               VALUES (?,?,?,?,?,?)""",
            (detection_id, original_path, quarantine_path, sha256,
             datetime.now().isoformat(), "quarantined"),
        )
        return cur.lastrowid


def get_quarantine_items() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """SELECT q.*, d.detection, d.category, d.risk_label
               FROM quarantine_log q
               LEFT JOIN detections d ON q.detection_id = d.id
               WHERE q.status = 'quarantined'
               ORDER BY q.quarantined_at DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def update_quarantine_status(quarantine_id: int, status: str):
    """status: 'quarantined' | 'restored' | 'deleted'"""
    field = "restored_at" if status == "restored" else "deleted_at" if status == "deleted" else None
    with _connect() as conn:
        if field:
            conn.execute(
                f"UPDATE quarantine_log SET status=?, {field}=? WHERE id=?",
                (status, datetime.now().isoformat(), quarantine_id),
            )
        else:
            conn.execute(
                "UPDATE quarantine_log SET status=? WHERE id=?",
                (status, quarantine_id),
            )


# ── Métricas ───────────────────────────────────────────────────────────────────

def get_global_stats() -> dict:
    """Totales acumulados de todos los análisis completados."""
    with _connect() as conn:
        row = conn.execute("""
            SELECT
                COUNT(*)                        AS total_scans,
                COALESCE(SUM(files_scanned), 0) AS total_files,
                COALESCE(SUM(threats_found), 0) AS total_threats,
                COALESCE(SUM(errors), 0)        AS total_errors,
                COALESCE(SUM(elapsed_sec), 0)   AS total_elapsed,
                COALESCE(AVG(elapsed_sec), 0)   AS avg_elapsed,
                SUM(CASE WHEN threats_found = 0 AND status = 'completed'
                         THEN 1 ELSE 0 END)     AS clean_scans
            FROM scans
            WHERE status IN ('completed', 'cancelled')
        """).fetchone()
        q_row = conn.execute("""
            SELECT
                COUNT(*) AS total_quarantined,
                SUM(CASE WHEN status = 'restored' THEN 1 ELSE 0 END) AS total_restored,
                SUM(CASE WHEN status = 'deleted'  THEN 1 ELSE 0 END) AS total_deleted
            FROM quarantine_log
        """).fetchone()
    result = dict(row) if row else {}
    result.update(dict(q_row) if q_row else {})
    return result


def get_threats_by_category() -> list[dict]:
    """Conteo de detecciones agrupadas por categoría (top 10)."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                COALESCE(category, 'No determinada') AS category,
                COUNT(*) AS count
            FROM detections
            GROUP BY category
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
    return [dict(r) for r in rows]


def get_threats_by_risk() -> list[dict]:
    """Conteo de detecciones agrupadas por nivel de riesgo (0-5)."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                COALESCE(risk_level, 3)  AS risk_level,
                COALESCE(risk_label, '?') AS risk_label,
                COUNT(*) AS count
            FROM detections
            GROUP BY risk_level
            ORDER BY risk_level DESC
        """).fetchall()
    return [dict(r) for r in rows]


def get_top_extensions(limit: int = 8) -> list[dict]:
    """Extensiones de archivo más frecuentes en detecciones."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                COALESCE(NULLIF(file_ext, ''), '(sin ext)') AS ext,
                COUNT(*) AS count
            FROM detections
            GROUP BY file_ext
            ORDER BY count DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_scan_trend(limit: int = 20) -> list[dict]:
    """Últimos N análisis completados con fecha, archivos y amenazas (para gráfica)."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                id,
                SUBSTR(started_at, 1, 10)  AS date,
                scan_type,
                files_scanned,
                threats_found,
                elapsed_sec,
                status
            FROM scans
            WHERE status IN ('completed', 'cancelled')
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return list(reversed([dict(r) for r in rows]))


def get_scan_type_breakdown() -> list[dict]:
    """Conteo de análisis por tipo."""
    with _connect() as conn:
        rows = conn.execute("""
            SELECT scan_type, COUNT(*) AS count
            FROM scans
            WHERE status IN ('completed', 'cancelled')
            GROUP BY scan_type
            ORDER BY count DESC
        """).fetchall()
    return [dict(r) for r in rows]
