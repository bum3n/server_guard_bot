"""Хранилище истории метрик (SQLite) для графиков и суточных отчётов."""
import os
import sqlite3
import threading
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics.db")
RETENTION_SECONDS = 8 * 24 * 3600
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metrics ("
        "ts INTEGER PRIMARY KEY, cpu REAL, ram REAL, swap REAL, disk REAL, rx REAL, tx REAL)"
    )
    return conn


def add_sample(cpu, ram, swap, disk, rx=0.0, tx=0.0, ts=None):
    """Сохраняет одну точку. rx/tx — скорость в КБ/с. Возвращает True при успехе."""
    ts = int(ts if ts is not None else time.time())
    try:
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?,?)",
                    (ts, cpu, ram, swap, disk, rx, tx),
                )
                conn.commit()
            finally:
                conn.close()
        return True
    except Exception:
        return False


def purge_old(now=None):
    now = int(now if now is not None else time.time())
    try:
        with _lock:
            conn = _connect()
            try:
                conn.execute("DELETE FROM metrics WHERE ts < ?", (now - RETENTION_SECONDS,))
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass


def get_samples(hours, now=None, max_points=400):
    """Возвращает список (ts, cpu, ram, swap, disk, rx, tx) за период, прореженный до max_points."""
    now = int(now if now is not None else time.time())
    try:
        with _lock:
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT ts, cpu, ram, swap, disk, rx, tx FROM metrics WHERE ts >= ? ORDER BY ts",
                    (now - int(hours * 3600),),
                ).fetchall()
            finally:
                conn.close()
    except Exception:
        return []
    if len(rows) > max_points:
        step = len(rows) / max_points
        rows = [rows[int(i * step)] for i in range(max_points)]
    return rows


def get_summary(hours=24, now=None):
    """Агрегаты за период: max/avg CPU и RAM, max диска. Возвращает dict или None, если данных нет."""
    rows = get_samples(hours, now=now, max_points=100000)
    if not rows:
        return None
    cpu = [r[1] for r in rows]
    ram = [r[2] for r in rows]
    disk = [r[4] for r in rows]
    return {
        "count": len(rows),
        "cpu_max": max(cpu),
        "cpu_avg": sum(cpu) / len(cpu),
        "ram_max": max(ram),
        "ram_avg": sum(ram) / len(ram),
        "disk_max": max(disk),
    }
