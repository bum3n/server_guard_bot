"""Обслуживание сервера: обновления, диск, логи служб, перезагрузка, проверка портов."""
import os
import socket
import subprocess
import time

import psutil


def format_duration(seconds):
    """Секунды -> '3 д. 4 ч. 12 мин.'"""
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days} д.")
    if hours or days:
        parts.append(f"{hours} ч.")
    parts.append(f"{minutes} мин.")
    return " ".join(parts)


def get_uptime_seconds():
    try:
        return time.time() - psutil.boot_time()
    except Exception:
        return 0


def human_size(num_bytes):
    num = float(num_bytes or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if num < 1024 or unit == "ТБ":
            return f"{num:.0f} {unit}" if unit == "Б" else f"{num:.1f} {unit}"
        num /= 1024


def check_port(port, host="127.0.0.1", timeout=0.6):
    """True, если на локальном порту кто-то слушает (TCP)."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def count_upgradable():
    """Возвращает (количество, список имён пакетов) доступных обновлений apt."""
    try:
        res = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=40)
    except Exception:
        return None, []
    names = []
    for line in res.stdout.splitlines():
        if "/" in line and "[upgradable" in line:
            names.append(line.split("/")[0])
    return len(names), names


def run_upgrade():
    """apt-get update + upgrade без вопросов. Возвращает (успех, хвост лога)."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    log = ""
    try:
        r1 = subprocess.run(["apt-get", "update"], capture_output=True, text=True, timeout=180, env=env)
        log += r1.stdout[-500:]
        r2 = subprocess.run(
            ["apt-get", "upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"],
            capture_output=True, text=True, timeout=900, env=env,
        )
        log += "\n" + r2.stdout[-1500:]
        return r2.returncode == 0, log.strip()[-1500:]
    except subprocess.TimeoutExpired:
        return False, "Таймаут выполнения apt-get"
    except Exception as e:
        return False, str(e)


def _dir_size(path):
    total = 0
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    for root, _dirs, files in os.walk(path, onerror=lambda e: None):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def get_disk_report():
    """Что занимает место: словарь {описание: размер в байтах}."""
    items = {
        "/var/log": "/var/log",
        "Кэш apt": "/var/cache/apt",
        "Бэкапы на сервере": "/root/backups",
        "Корзина и временные файлы": "/tmp",
    }
    report = {name: _dir_size(path) for name, path in items.items() if os.path.exists(path)}
    try:
        res = subprocess.run(["journalctl", "--disk-usage"], capture_output=True, text=True, timeout=5)
        report["Журнал systemd"] = res.stdout.strip()
    except Exception:
        pass
    return report


def cleanup_disk():
    """Безопасная очистка: кэш apt и журнал старше 7 дней. Возвращает текст результата."""
    out = []
    try:
        subprocess.run(["apt-get", "clean"], capture_output=True, text=True, timeout=60)
        out.append("• Кэш apt очищен")
    except Exception as e:
        out.append(f"• Кэш apt: ошибка {e}")
    try:
        r = subprocess.run(["journalctl", "--vacuum-time=7d"], capture_output=True, text=True, timeout=60)
        last = (r.stderr or r.stdout).strip().splitlines()
        out.append("• Журнал: " + (last[-1] if last else "очищен"))
    except Exception as e:
        out.append(f"• Журнал: ошибка {e}")
    return "\n".join(out)


def get_service_logs(unit, lines=25):
    """Последние строки журнала службы (unit должен быть проверен вызывающим кодом)."""
    try:
        res = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(int(lines)), "--no-pager", "-o", "short"],
            capture_output=True, text=True, timeout=6,
        )
        return res.stdout.strip() or "Записей нет."
    except Exception as e:
        return f"Ошибка чтения журнала: {e}"


def reboot_server():
    """Перезагрузка сервера (асинхронно, чтобы бот успел ответить)."""
    subprocess.Popen(["systemctl", "reboot"])
