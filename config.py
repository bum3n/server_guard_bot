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
                _os.environ.setdefault(key.strip(), value.strip().strip('"\''))
    except Exception:
        pass

_load_dotenv()

# Токен Telegram-бота и ID администратора
BOT_TOKEN = _os.environ.get("BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
ADMIN_CHAT_ID = int(_os.environ.get("ADMIN_CHAT_ID", "123456789"))

# Пороги алертов
CPU_THRESHOLD = 85.0       # Процент CPU для тревоги
RAM_THRESHOLD = 90.0       # Процент RAM
DISK_THRESHOLD = 90.0      # Процент диска
CPU_SUSTAINED_CHECKS = 3   # Сколько проверок подряд нагрузка должна быть высокой (3 x 4 сек = 12 сек)
ALERT_COOLDOWN = 900       # 15 минут между повторными одинаковыми алертами

# Домен и IP
DOMAIN = _os.environ.get("DOMAIN", "example.com")
SERVER_IP = _os.environ.get("SERVER_IP", "1.2.3.4")

# Прямой URL к панели 3X-UI
XUI_URL = _os.environ.get("XUI_URL", f"https://{DOMAIN}/3x-ui-panel/")

# Системные службы для отслеживания
MONITORED_SERVICES = [
    {"unit": "nginx.service", "name": "Nginx"},
    {"unit": "x-ui.service", "name": "3X-UI / Xray"},
    {"unit": "warp-svc.service", "name": "Cloudflare WARP"},
    {"unit": "jupyter.service", "name": "Jupyter Lab"},
    {"unit": "fail2ban.service", "name": "Fail2Ban"}
]

# HTTP проверки сайтов и сервисов
HTTP_CHECKS = [
    {"name": "Главный сайт", "url": f"https://{DOMAIN}/"},
    {"name": "Панель 3X-UI", "url": XUI_URL}
]

# Локальные порты для проверки "слушает ли служба" (имя, порт)
CHECK_PORTS = [
    {"name": "HTTP (Nginx)", "port": 80},
    {"name": "HTTPS (Nginx)", "port": 443},
    {"name": "Панель 3X-UI", "port": 44506},
    {"name": "MTProto Proxy", "port": 8443},
]

# Тарифные шаблоны для быстрого создания клиентов: (название, ГБ, дней). 0 = безлимит
VPN_TARIFFS = [
    {"title": "👥 50 ГБ / 30 дн.", "gb": 50, "days": 30},
    {"title": "📦 100 ГБ / 30 дн.", "gb": 100, "days": 30},
    {"title": "🚀 300 ГБ / 90 дн.", "gb": 300, "days": 90},
]

# Предупреждать о клиентах, у которых осталось <= N дней или израсходовано >= N% трафика
VPN_WARN_DAYS = 3
VPN_WARN_TRAFFIC_PERCENT = 90

# Службы, которые можно перезапускать по ночному расписанию (настройка в боте)
NIGHTLY_RESTART_UNITS = ["jupyter.service"]
NIGHTLY_RESTART_TIME = "04:00"  # МСК

# Процессы, которые нельзя убить одной кнопкой из бота
PROTECTED_PROCESSES = ["xray", "x-ui", "sshd", "systemd", "nginx", "init", "warp-svc", "fail2ban"]

BOT_VERSION = "2.0"

# Список администраторов: основной ADMIN_CHAT_ID + дополнительные из .env (ADMIN_CHAT_IDS=1,2,3)
ADMIN_IDS = [ADMIN_CHAT_ID]
for _x in _os.environ.get("ADMIN_CHAT_IDS", "").split(","):
    _x = _x.strip()
    if _x.lstrip("-").isdigit() and int(_x) not in ADMIN_IDS:
        ADMIN_IDS.append(int(_x))
