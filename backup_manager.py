import os
import tarfile
import datetime
import tempfile
import shutil
import glob
import telebot

BACKUP_PATHS = [
    # 1. Сетевые профили, ключи и сертификаты
    "/etc/x-ui/x-ui.db",                 # База клиентов, ключей и настроек 3X-UI Reality
    "/root/cert",                        # Текущие SSL-сертификаты панели и IP
    "/root/h2_cert.pem",                 # HTTP/2 сертификат fallback
    "/root/h2_privkey.pem",              # HTTP/2 ключ fallback
    "/root/wgcf-account.toml",           # Учетная запись Cloudflare WARP
    "/root/wgcf-profile.conf",           # Конфигурация интерфейса WARP / wireproxy
    "/root/.ssh/authorized_keys",        # SSH-ключи для входа без пароля

    # 2. Веб-инфраструктура (Nginx)
    "/etc/nginx/nginx.conf",             # Главный конфиг Nginx
    "/etc/nginx/sites-available",        # Виртуальные хосты (визитка, Mini App, proxy)
    "/var/www/html",                     # Веб-страницы (index.html, compare_app, go.html)

    # 3. Службы автозапуска systemd
    "/etc/systemd/system/server_guard.service",
    "/etc/systemd/system/mem_bot.service",
    "/etc/systemd/system/flashcard_bot.service",
    "/etc/systemd/system/jupyter.service",
    "/etc/systemd/system/wireproxy.service",
    "/etc/systemd/system/anonchat_bot.service",

    # 4. Проекты, боты и базы данных
    "/root/server_guard",                # Код сторожа и settings.json
    "/root/mem_bot",                     # Код мем-бота и все шрифты .ttf
    "/root/flashcard_bot",               # Код бота и flashcards.db
    "/root/notebooks",                   # Учебные тетради Jupyter МИРЭА
    "/root/anonchat_bot",                # Анонимный чат бот

    # 5. Защита
    "/etc/fail2ban/jail.local",          # Кастомные правила банов Fail2Ban (если есть)
]

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))

def make_backup_archive():
    """Создает компактный tar.gz архив без мусора (venv, node_modules, git, cache)."""
    now_msk = datetime.datetime.now(MSK_TZ)
    date_str = now_msk.strftime("%Y-%m-%d_%H-%M")
    archive_name = f"backup_bum3n_{date_str}.tar.gz"
    temp_dir = tempfile.gettempdir()
    archive_path = os.path.join(temp_dir, archive_name)

    def exclude_filter(tarinfo):
        # Исключаем тяжелые каталоги библиотек и кэша
        ignored = ["venv", ".venv", "__pycache__", ".git", "node_modules", ".cache", ".local"]
        for ig in ignored:
            if f"/{ig}/" in tarinfo.name or tarinfo.name.endswith(f"/{ig}"):
                return None
        return tarinfo

    with tarfile.open(archive_path, "w:gz") as tar:
        for path in BACKUP_PATHS:
            if os.path.exists(path):
                # Если файл или папка внутри /root, сохраняем относительный путь root/...
                arcname = os.path.relpath(path, "/root") if path.startswith("/root") else path.lstrip("/")
                tar.add(path, arcname=arcname, filter=exclude_filter)

    return archive_path

BACKUP_DIR = "/root/backups"   # локальные копии на сервере
KEEP_BACKUPS = 7               # сколько последних копий хранить
TG_LIMIT_MB = 49               # лимит Telegram на файл ~50 МБ


def verify_archive(path):
    """Проверяет целостность архива. Возвращает число файлов внутри (0 = архив повреждён/пуст)."""
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


def send_backup(bot: telebot.TeleBot, chat_id: int):
    """Генерирует и отправляет бэкап в чат Telegram по МСК."""
    archive_path = None
    parts = []
    try:
        archive_path = make_backup_archive()
        files_count = verify_archive(archive_path)
        if files_count == 0:
            return False, "Архив повреждён или пуст (проверка целостности не пройдена)"

        size_mb = os.path.getsize(archive_path) / (1024 * 1024)
        date_str = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M")
        local_copy = save_local_copy(archive_path)
        local_line = f"• **Копия на сервере:** `{BACKUP_DIR}` (хранится {KEEP_BACKUPS} последних)\n" if local_copy else ""

        caption = (
            f"📦 **Резервная копия сервера готова!**\n\n"
            f"• **Время (МСК):** `{date_str}`\n"
            f"• **Размер архива:** `{size_mb:.2f} MB`\n"
            f"• **Проверка целостности:** ✅ файлов в архиве: `{files_count}`\n"
            f"{local_line}"
            f"• **Состав:** Базы 3X-UI и ботов, WARP-ключи, Nginx, systemd-сервисы, тетрадки `/notebooks`, SSL, сайт.\n"
            f"• Библиотеки (`venv`) исключены для компактности."
        )

        if size_mb <= TG_LIMIT_MB:
            with open(archive_path, "rb") as doc:
                bot.send_document(chat_id, doc, caption=caption, parse_mode="Markdown")
        else:
            parts = split_file(archive_path)
            for n, part in enumerate(parts, 1):
                part_caption = caption if n == 1 else f"Часть {n}/{len(parts)}"
                if n == 1:
                    part_caption += (
                        f"\n\n⚠️ Архив разбит на {len(parts)} частей. "
                        f"Склейка: `cat {os.path.basename(archive_path)}.part* > {os.path.basename(archive_path)}`"
                    )
                with open(part, "rb") as doc:
                    bot.send_document(chat_id, doc, caption=part_caption, parse_mode="Markdown")
        return True, f"Успешно отправлен ({size_mb:.2f} MB)"
    except Exception as e:
        return False, str(e)
    finally:
        for p in parts:
            if os.path.exists(p):
                os.remove(p)
        if archive_path and os.path.exists(archive_path):
            os.remove(archive_path)
