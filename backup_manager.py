import os
import tarfile
import datetime
import tempfile
import shutil
import glob
import telebot
import config

# Базовые системные директории и конфиги для бэкапа по умолчанию
DEFAULT_BACKUP_PATHS = [
    # 1. Веб-сервер
    "/etc/nginx",
    # 2. Безопасность и фаервол
    "/etc/fail2ban",
    "/etc/ufw",
    "/etc/ssh/sshd_config",
    # 3. Службы автозапуска systemd
    "/etc/systemd/system/server_guard.service",
    # 4. Рабочая папка самого бота
    os.path.dirname(os.path.abspath(__file__)),
]

# Пользовательские пути из config.py / .env
CUSTOM_PATHS = getattr(config, "BACKUP_DIRECTORIES", [])
BACKUP_PATHS = list(dict.fromkeys(DEFAULT_BACKUP_PATHS + CUSTOM_PATHS))

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))

def make_backup_archive():
    """Создает компактный tar.gz архив без мусора (venv, node_modules, git, cache, db-wal, metrics.db)."""
    now_msk = datetime.datetime.now(MSK_TZ)
    date_str = now_msk.strftime("%Y-%m-%d_%H-%M")
    archive_name = f"backup_server_{date_str}.tar.gz"
    temp_dir = tempfile.gettempdir()
    archive_path = os.path.join(temp_dir, archive_name)

    def exclude_filter(tarinfo):
        # Нормализуем путь к POSIX-формату и разбиваем на составляющие
        norm_name = tarinfo.name.replace("\\", "/").strip("/")
        parts = norm_name.split("/")

        # Полный запрет каталогов зависимостей и служебных папок
        ignored_dirs = {"venv", ".venv", "__pycache__", ".git", "node_modules", ".cache", ".local"}
        if any(part in ignored_dirs for part in parts):
            return None

        # Исключаем временные файлы журналов SQLite WAL/SHM, кэш и логи
        ignored_extensions = (".pyc", ".pyo", ".log", "-wal", "-shm")
        if norm_name.endswith(ignored_extensions):
            return None

        # Исключаем разрастающуюся базу замеров метрик Server Guard
        if norm_name.endswith("metrics.db"):
            return None

        return tarinfo

    with tarfile.open(archive_path, "w:gz") as tar:
        for path in BACKUP_PATHS:
            if os.path.exists(path):
                arcname = os.path.relpath(path, "/root") if path.startswith("/root") else path.lstrip("/")
                tar.add(path, arcname=arcname, filter=exclude_filter)

    return archive_path

BACKUP_DIR = "/root/backups"   # локальные копии на сервере
KEEP_BACKUPS = 7               # сколько последних копий хранить
TG_LIMIT_MB = 49               # лимит Telegram на файл ~50 МБ


def verify_archive(path):
    """Проверяет целостность архива. Возвращает число файлов внутри (0 = архив поврежден/пуст)."""
    try:
        with tarfile.open(path, "r:gz") as tar:
            return len(tar.getnames())
    except Exception:
        return 0


def save_local_copy(archive_path):
    """Копирует архив в BACKUP_DIR и оставляет только KEEP_BACKUPS последних. Возвращает путь или None."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        dst = os.path.join(BACKUP_DIR, os.path.basename(archive_path))
        shutil.copy2(archive_path, dst)
        files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_bum3n_*.tar.gz")))
        for old in files[:-KEEP_BACKUPS]:
            try:
                os.remove(old)
            except OSError:
                pass
        return dst
    except Exception:
        return None


def save_local_fin_copy(fin_bytes, date_str_file=None):
    """Сохраняет копию архива Финляндии в BACKUP_DIR и ротирует старые копии."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        if not date_str_file:
            date_str_file = datetime.datetime.now(MSK_TZ).strftime("%Y-%m-%d_%H-%M")
        dst = os.path.join(BACKUP_DIR, f"backup_fin_{date_str_file}.tar.gz")
        with open(dst, "wb") as f:
            f.write(fin_bytes)
        files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_fin_*.tar.gz")))
        for old in files[:-KEEP_BACKUPS]:
            try:
                os.remove(old)
            except OSError:
                pass
        return dst
    except Exception:
        return None


def save_local_ru_copy(ru_bytes, date_str_file=None):
    """Сохраняет копию архива России в BACKUP_DIR и ротирует старые копии."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        if not date_str_file:
            date_str_file = datetime.datetime.now(MSK_TZ).strftime("%Y-%m-%d_%H-%M")
        dst = os.path.join(BACKUP_DIR, f"backup_ru_{date_str_file}.tar.gz")
        with open(dst, "wb") as f:
            f.write(ru_bytes)
        files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_ru_*.tar.gz")))
        for old in files[:-KEEP_BACKUPS]:
            try:
                os.remove(old)
            except OSError:
                pass
        return dst
    except Exception:
        return None


def get_last_backup_info():
    """
    Возвращает словарь с информацией о последних созданных бэкапах:
    размер и дата последнего архива для Нидерландов и Финляндии.
    """
    info = {
        "nl_size_str": "~13.1 MB",
        "nl_date_str": None,
        "nl_mb": 13.1,
        "fin_size_str": "~122 KB",
        "fin_date_str": None,
        "fin_kb": 122.0,
        "ru_size_str": "~1.4 MB",
        "ru_date_str": None,
        "ru_kb": 1400.0
    }

    # 1. Проверяем последний архив Нидерландов на диске
    nl_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_bum3n_*.tar.gz")))
    if nl_files:
        latest_nl = nl_files[-1]
        try:
            sz = os.path.getsize(latest_nl) / (1024 * 1024)
            mtime = os.path.getmtime(latest_nl)
            dt = datetime.datetime.fromtimestamp(mtime, tz=MSK_TZ)
            info["nl_mb"] = sz
            info["nl_size_str"] = f"{sz:.2f} MB"
            info["nl_date_str"] = dt.strftime("%d.%m %H:%M")
        except Exception:
            pass

    # 2. Проверяем последний архив Финляндии на диске
    fin_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_fin_*.tar.gz")))
    if fin_files:
        latest_fin = fin_files[-1]
        try:
            sz_bytes = os.path.getsize(latest_fin)
            sz_kb = sz_bytes / 1024
            sz_mb = sz_bytes / (1024 * 1024)
            mtime = os.path.getmtime(latest_fin)
            dt = datetime.datetime.fromtimestamp(mtime, tz=MSK_TZ)
            info["fin_kb"] = sz_kb
            info["fin_size_str"] = f"{sz_mb:.2f} MB" if sz_mb >= 1.0 else f"{sz_kb:.1f} KB"
            info["fin_date_str"] = dt.strftime("%d.%m %H:%M")
        except Exception:
            pass

    # 3. Проверяем последний архив России на диске
    ru_files = sorted(glob.glob(os.path.join(BACKUP_DIR, "backup_ru_*.tar.gz")))
    if ru_files:
        latest_ru = ru_files[-1]
        try:
            sz_bytes = os.path.getsize(latest_ru)
            sz_kb = sz_bytes / 1024
            sz_mb = sz_bytes / (1024 * 1024)
            mtime = os.path.getmtime(latest_ru)
            dt = datetime.datetime.fromtimestamp(mtime, tz=MSK_TZ)
            info["ru_kb"] = sz_kb
            info["ru_size_str"] = f"{sz_mb:.2f} MB" if sz_mb >= 1.0 else f"{sz_kb:.1f} KB"
            info["ru_date_str"] = dt.strftime("%d.%m %H:%M")
        except Exception:
            pass

    return info


def split_file(path, chunk_mb=TG_LIMIT_MB):
    """Режет файл на части .part001, .part002... Возвращает список путей."""
    chunk = chunk_mb * 1024 * 1024
    parts = []
    with open(path, "rb") as src:
        i = 1
        while True:
            data = src.read(chunk)
            if not data:
                break
            part_path = f"{path}.part{i:03d}"
            with open(part_path, "wb") as dst:
                dst.write(data)
            parts.append(part_path)
            i += 1
    return parts


def send_backup_nl(bot: telebot.TeleBot, chat_id: int):
    """Генерирует и отправляет резервную копию Нидерландов."""
    archive_path = None
    parts = []
    try:
        archive_path = make_backup_archive()
        files_count = verify_archive(archive_path)
        if files_count == 0:
            return False, "Архив Нидерландов поврежден или пуст"

        size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        date_str = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M")
        local_copy = save_local_copy(archive_path)
        local_line = f"• **Копия на сервере:** `{BACKUP_DIR}` (хранится {KEEP_BACKUPS} последних)\n" if local_copy else ""

        caption_nl = (
            f"📦 **Резервная копия 🇳🇱 Нидерланды готова!**\n\n"
            f"• **Время (МСК):** `{date_str}`\n"
            f"• **Размер архива:** `{size_mb:.2f} MB`\n"
            f"• **Проверка целостности:** ✅ файлов: `{files_count}`\n"
            f"{local_line}"
            f"• **Состав:** Базы 3X-UI, Vaultwarden, боты (Antigravity, `vpn_guard`, WeekTrack), Arcade Hub, Beszel Hub, SSH/WARP-ключи, Nginx, сервисы, тетрадки `/notebooks`, SSL, веб-страницы."
        )

        if size_mb <= TG_LIMIT_MB:
            with open(archive_path, "rb") as doc:
                bot.send_document(chat_id, doc, caption=caption_nl, parse_mode="Markdown")
        else:
            parts = split_file(archive_path)
            for n, part in enumerate(parts, 1):
                part_caption = caption_nl if n == 1 else f"Часть {n}/{len(parts)}"
                with open(part, "rb") as doc:
                    bot.send_document(chat_id, doc, caption=part_caption, parse_mode="Markdown")

        return True, f"Нидерланды успешно отправлены ({size_mb:.2f} MB)"
    except Exception as e:
        return False, f"Ошибка отправки Нидерландов: {e}"
    finally:
        for p in parts:
            if os.path.exists(p):
                os.remove(p)
        if archive_path and os.path.exists(archive_path):
            os.remove(archive_path)


def send_backup_fin(bot: telebot.TeleBot, chat_id: int):
    """Генерирует и отправляет резервную копию Финляндии."""
    import io
    import remote_monitor

    try:
        date_str = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M")
        fin_bytes = remote_monitor.make_remote_backup_archive()
        if not fin_bytes:
            return False, "Не удалось сформировать архив на финском сервере"

        fin_mb = len(fin_bytes) / (1024 * 1024)
        fin_kb = len(fin_bytes) / 1024
        fin_bio = io.BytesIO(fin_bytes)
        fin_bio.name = f"backup_fin_{datetime.datetime.now(MSK_TZ).strftime('%Y%m%d_%H%M%S')}.tar.gz"

        size_label = f"{fin_mb:.2f} MB" if fin_mb >= 1.0 else f"{fin_kb:.1f} KB"
        local_copy = save_local_fin_copy(fin_bytes)
        local_line = f"• **Копия на сервере:** `{BACKUP_DIR}` (хранится {KEEP_BACKUPS} последних)\n" if local_copy else ""

        caption_fin = (
            f"📦 **Резервная копия 🇫🇮 Финляндия готова!**\n\n"
            f"• **Время (МСК):** `{date_str}`\n"
            f"• **Размер архива:** `{size_label}`\n"
            f"{local_line}"
            f"• **Состав:** База 3X-UI, Smart DNS (Nginx stream map 14k+ доменов, сайт `dns.bbumn.ru`, SSL), AdGuard Home (конфиг + статистика), Telemetry API, WARP, UFW/Fail2Ban."
        )
        bot.send_document(chat_id, fin_bio, caption=caption_fin, parse_mode="Markdown")
        return True, f"Финляндия успешно отправлена ({size_label})"
    except Exception as e:
        return False, f"Ошибка отправки Финляндии: {e}"


def send_backup_ru(bot: telebot.TeleBot, chat_id: int):
    """Генерирует, проверяет целостность и отправляет резервную копию России."""
    import io
    import remote_monitor

    try:
        date_str = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M")
        ru_bytes = remote_monitor.make_remote_backup_archive(server_id="ru")
        if not ru_bytes:
            return False, "Не удалось сформировать архив на российском сервере"

        ru_bio_verify = io.BytesIO(ru_bytes)
        with tarfile.open(fileobj=ru_bio_verify, mode="r:gz") as tar:
            files_count = len(tar.getnames())
        if files_count == 0:
            return False, "Архив России пуст"

        ru_mb = len(ru_bytes) / (1024 * 1024)
        ru_kb = len(ru_bytes) / 1024
        ru_bio = io.BytesIO(ru_bytes)
        ru_bio.name = f"backup_ru_{datetime.datetime.now(MSK_TZ).strftime('%Y%m%d_%H%M%S')}.tar.gz"

        size_label = f"{ru_mb:.2f} MB" if ru_mb >= 1.0 else f"{ru_kb:.1f} KB"
        local_copy = save_local_ru_copy(ru_bytes)
        local_line = f"• **Копия на сервере:** `{BACKUP_DIR}` (хранится {KEEP_BACKUPS} последних)\n" if local_copy else ""

        caption_ru = (
            f"📦 **Резервная копия 🇷🇺 Россия готова!**\n\n"
            f"• **Время (МСК):** `{date_str}`\n"
            f"• **Размер архива:** `{size_label}`\n"
            f"• **Проверка целостности:** ✅ файлов: `{files_count}`\n"
            f"{local_line}"
            f"• **Состав:** Realm Relay (`/etc/realm`, бинарник, `realm.service`), UFW правила, Fail2Ban, sysctl BBR, SSH-конфиги."
        )
        bot.send_document(chat_id, ru_bio, caption=caption_ru, parse_mode="Markdown")
        return True, f"Россия успешно отправлена ({size_label})"
    except Exception as e:
        return False, f"Ошибка отправки России: {e}"


def send_backup(bot: telebot.TeleBot, chat_id: int, target: str = "all"):
    """
    Генерирует и отправляет бэкап в чат Telegram:
    target='nl'  -> только Нидерланды
    target='fin' -> только Финляндия
    target='ru'  -> только Россия
    target='all' -> все три сервера (NL + FIN + RU)
    """
    if target == "nl":
        return send_backup_nl(bot, chat_id)
    elif target == "fin":
        return send_backup_fin(bot, chat_id)
    elif target == "ru":
        return send_backup_ru(bot, chat_id)
    else:
        results = [
            ("NL",) + send_backup_nl(bot, chat_id),
            ("FIN",) + send_backup_fin(bot, chat_id),
            ("RU",) + send_backup_ru(bot, chat_id),
        ]
        failed = [f"{tag}: {msg}" for tag, ok, msg in results if not ok]
        ok_list = [f"{tag}: {msg}" for tag, ok, msg in results if ok]
        if not failed:
            return True, "Все 3 архива отправлены (" + "; ".join(ok_list) + ")"
        return False, "Отправлены: [" + "; ".join(ok_list) + "] | Ошибки: [" + "; ".join(failed) + "]"