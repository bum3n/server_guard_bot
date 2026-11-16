import os as _os

def _load_dotenv():
    """Читает .env рядом с config.py и переопределяет секреты."""
    path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".env")
    if not _os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                _os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except Exception:
        pass

_load_dotenv()

# Токен Telegram-бота и ID администратора
BOT_TOKEN = _os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
ADMIN_CHAT_ID = int(_os.environ.get("ADMIN_CHAT_ID", "123456789"))

# Пороги системных алертов
CPU_THRESHOLD = float(_os.environ.get("CPU_THRESHOLD", "85.0"))        # % CPU для тревоги
RAM_THRESHOLD = float(_os.environ.get("RAM_THRESHOLD", "90.0"))        # % RAM для тревоги
DISK_THRESHOLD = float(_os.environ.get("DISK_THRESHOLD", "90.0"))      # % диска для тревоги
CPU_SUSTAINED_CHECKS = int(_os.environ.get("CPU_SUSTAINED_CHECKS", "3")) # Проверок подряд с высокой нагрузкой (3 x 4 сек = 12 сек)
ALERT_COOLDOWN = int(_os.environ.get("ALERT_COOLDOWN", "900"))         # 15 минут между повторными алертами одного типа

# Домен и IP основного сервера
DOMAIN = _os.environ.get("DOMAIN", "localhost")
SERVER_IP = _os.environ.get("SERVER_IP", "127.0.0.1")
SERVER_NAME = _os.environ.get("SERVER_NAME", "Основной сервер")

# Системные службы для автоматического отслеживания по умолчанию
MONITORED_SERVICES = [
    {"unit": "nginx.service", "name": "Nginx Web Server"},
    {"unit": "ssh.service", "name": "OpenSSH Server"},
    {"unit": "fail2ban.service", "name": "Fail2Ban Protection"},
    {"unit": "docker.service", "name": "Docker Engine"},
]

# HTTP/HTTPS проверки доступности сервисов
HTTP_CHECKS = [
    {"name": "Главный сайт / API", "url": f"https://{DOMAIN}/" if DOMAIN != "localhost" else f"http://{SERVER_IP}/"},
]

# Локальные сетевые порты для быстрой проверки доступности (слушает ли служба)
CHECK_PORTS = [
    {"name": "HTTP (Web)", "port": 80},
    {"name": "HTTPS (Web SSL)", "port": 443},
    {"name": "SSH (Console)", "port": 22},
]

# Список серверов (по умолчанию один локальный, расширяется при наличии удаленных нод)
SERVERS = {
    "main": {
        "id": "main",
        "name": SERVER_NAME,
        "flag": "🖥",
        "ip": SERVER_IP,
        "domain": DOMAIN,
        "is_local": True,
        "monitored_services": MONITORED_SERVICES,
        "http_checks": HTTP_CHECKS,
    }
}

# Директории и файлы, включаемые в резервную копию сервера по умолчанию
BACKUP_DIRECTORIES = [
    "/etc/nginx",
    "/etc/fail2ban",
    "/etc/ssh/sshd_config",
    "/etc/systemd/system/server_guard.service",
    _os.path.dirname(_os.path.abspath(__file__)),
]

# Службы, разрешенные для ночного автоперезапуска (настраивается в боте)
NIGHTLY_RESTART_UNITS = []
NIGHTLY_RESTART_TIME = "04:00"

# Критические системные процессы, которые запрещено убивать из интерфейса бота
PROTECTED_PROCESSES = [
    "systemd", "sshd", "ssh", "nginx", "fail2ban", "init", "python3", "python",
    "server_guard", "dockerd", "containerd", "journald", "systemd-resolved"
]

BOT_VERSION = "2.1"

# Список администраторов: основной ADMIN_CHAT_ID + дополнительные из .env (ADMIN_CHAT_IDS=123,456)
ADMIN_IDS = [ADMIN_CHAT_ID]
for _x in _os.environ.get("ADMIN_CHAT_IDS", "").split(","):
    _x = _x.strip()
    if _x.lstrip("-").isdigit() and int(_x) not in ADMIN_IDS:
        ADMIN_IDS.append(int(_x))
