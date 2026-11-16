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

# Пороги алертов
CPU_THRESHOLD = 85.0       # Процент CPU для тревоги
RAM_THRESHOLD = 90.0       # Процент RAM
DISK_THRESHOLD = 90.0      # Процент диска
CPU_SUSTAINED_CHECKS = 3   # Сколько проверок подряд нагрузка должна быть высокой (3 x 4 сек = 12 сек)
ALERT_COOLDOWN = 900       # 15 минут между повторными одинаковыми алертами

# Домен и IP
DOMAIN = _os.environ.get("DOMAIN", "example.com")
SERVER_IP = _os.environ.get("SERVER_IP", "1.2.3.4")

# Список серверов для мульти-серверного мониторинга
SERVERS = {
    "nl": {
        "id": "nl",
        "name": "Нидерланды",
        "flag": "🇳🇱",
        "ip": SERVER_IP,
        "domain": DOMAIN,
        "is_local": True,
        "xui_url": f"https://{DOMAIN}/3x/",
        "monitored_services": [
            {"unit": "nginx.service", "name": "Nginx"},
            {"unit": "x-ui.service", "name": "3X-UI / Xray"},
            {"unit": "warp-svc.service", "name": "Cloudflare WARP"},
            {"unit": "wireproxy.service", "name": "WireProxy (WARP)"},
            {"unit": "antigravity-bot.service", "name": "Antigravity Agent"},
            {"unit": "vpn_guard.service", "name": "bumVPN Guard"},
            {"unit": "happ-sub-adapter.service", "name": "Happ Sub Adapter"},
            {"unit": "jupyter.service", "name": "Jupyter Lab"},
            {"unit": "arcade-hub.service", "name": "Arcade Hub"},
            {"unit": "beszel-hub.service", "name": "Beszel Hub"},
            {"unit": "beszel-agent.service", "name": "Beszel Agent"},
            {"unit": "docker.service", "name": "Docker (Vaultwarden)"},
            {"unit": "mem_bot.service", "name": "MemBot"},
            {"unit": "flashcard_bot.service", "name": "FlashCard Bot"},
            {"unit": "anonchat_bot.service", "name": "AnonChat Bot"},
            {"unit": "weektrack.service", "name": "WeekTrack"},
            {"unit": "fail2ban.service", "name": "Fail2Ban"}
        ],
        "http_checks": [
            {"name": "Главный сайт", "url": f"https://{DOMAIN}/"},
            {"name": "Compare App", "url": f"https://{DOMAIN}/compare/"},
            {"name": "Arcade Hub", "url": f"https://{DOMAIN}/arcade/"},
            {"name": "Vaultwarden", "url": f"https://{DOMAIN}/vault/"},
            {"name": "Beszel Monitor", "url": f"https://{DOMAIN}/monitor/"},
            {"name": "Smart DNS", "url": "https://dns.bbumn.ru/"},
            {"name": "AdGuard Home UI", "url": f"https://{DOMAIN}/adguard/"},
            {"name": "Jupyter Lab", "url": f"https://{DOMAIN}/jupyter/"}
        ]
    },
    "fin": {
        "id": "fin",
        "name": "Финляндия",
        "flag": "🇫🇮",
        "ip": _os.environ.get("SERVER_FIN_IP", "201.58.188.206"),
        "domain": "dns.bbumn.ru",
        "is_local": False,
        "xui_url": "https://201.58.188.206:44506/",
        "monitored_services": [
            {"unit": "AdGuardHome.service", "name": "AdGuard Home (DNS)"},
            {"unit": "x-ui.service", "name": "3X-UI / Xray (FIN)"},
            {"unit": "dns-telemetry.service", "name": "DNS Telemetry"},
            {"unit": "nginx.service", "name": "Nginx"},
            {"unit": "beszel-agent.service", "name": "Beszel Agent"},
            {"unit": "fail2ban.service", "name": "Fail2Ban"}
        ],
        "http_checks": [
            {"name": "Smart DNS (DoH/DoT)", "url": "https://dns.bbumn.ru/"},
            {"name": "Nginx FIN (HTTP)", "url": "http://201.58.188.206/"}
        ]
    },
    "ru": {
        "id": "ru",
        "name": "Россия",
        "flag": "🇷🇺",
        "ip": _os.environ.get("SERVER_RU_IP", "62.173.152.111"),
        "domain": "bum.ru",
        "is_local": False,
        "xui_url": None,
        "monitored_services": [
            {"unit": "realm.service", "name": "Realm Relay (RU➔NL/FI)"},
            {"unit": "ufw.service", "name": "Firewall UFW"},
            {"unit": "fail2ban.service", "name": "Fail2Ban"},
            {"unit": "ssh.service", "name": "OpenSSH Server"}
        ],
        "http_checks": [
            {"name": "Relay HTTPS (bbumn.ru)", "url": f"https://{DOMAIN}/"},
            {"name": "Relay SmartDNS (dns.bbumn.ru)", "url": "https://dns.bbumn.ru/"}
        ],
        "tcp_checks": [
            {"name": "NL Reality (:38813)", "port": 38813},
            {"name": "NL XHTTP (:41840)", "port": 41840},
            {"name": "FI Reality (:38815)", "port": 38815},
            {"name": "FI XHTTP (:41839)", "port": 41839},
            {"name": "SmartDNS DoT (:853)", "port": 853},
            {"name": "Relay TLS (:443)", "port": 443}
        ]
    }
}

# Прямой URL к панели 3X-UI
XUI_URL = f"https://{DOMAIN}/3x/"

# Системные службы для отслеживания
MONITORED_SERVICES = [
    {"unit": "nginx.service", "name": "Nginx"},
    {"unit": "x-ui.service", "name": "3X-UI / Xray"},
    {"unit": "warp-svc.service", "name": "Cloudflare WARP"},
    {"unit": "wireproxy.service", "name": "WireProxy (WARP)"},
    {"unit": "antigravity-bot.service", "name": "Antigravity Agent"},
    {"unit": "vpn_guard.service", "name": "bumVPN Guard"},
    {"unit": "happ-sub-adapter.service", "name": "Happ Sub Adapter"},
    {"unit": "jupyter.service", "name": "Jupyter Lab"},
    {"unit": "arcade-hub.service", "name": "Arcade Hub"},
    {"unit": "beszel-hub.service", "name": "Beszel Hub"},
    {"unit": "beszel-agent.service", "name": "Beszel Agent"},
    {"unit": "docker.service", "name": "Docker (Vaultwarden)"},
    {"unit": "mem_bot.service", "name": "MemBot"},
    {"unit": "flashcard_bot.service", "name": "FlashCard Bot"},
    {"unit": "anonchat_bot.service", "name": "AnonChat Bot"},
    {"unit": "weektrack.service", "name": "WeekTrack"},
    {"unit": "fail2ban.service", "name": "Fail2Ban"}
]

# HTTP проверки
HTTP_CHECKS = [
    {"name": "Главный сайт", "url": f"https://{DOMAIN}/"},
    {"name": "Compare App", "url": f"https://{DOMAIN}/compare/"},
    {"name": "Arcade Hub", "url": f"https://{DOMAIN}/arcade/"},
    {"name": "Vaultwarden", "url": f"https://{DOMAIN}/vault/"},
    {"name": "Beszel Monitor", "url": f"https://{DOMAIN}/monitor/"},
    {"name": "Smart DNS", "url": "https://dns.bbumn.ru/"},
    {"name": "AdGuard Home UI", "url": f"https://{DOMAIN}/adguard/"},
    {"name": "Jupyter Lab", "url": f"https://{DOMAIN}/jupyter/"}
]

# --- Новые опции (всё имеет безопасные значения по умолчанию) ---

# Локальные порты для проверки "слушает ли служба" (имя, порт)
CHECK_PORTS = [
    {"name": "HTTP (Nginx)", "port": 80},
    {"name": "HTTPS (Nginx)", "port": 443},
    {"name": "Панель 3X-UI", "port": 44506},
    {"name": "Vaultwarden", "port": 8088},
    {"name": "Beszel Hub", "port": 8090},
    {"name": "Arcade Hub", "port": 3001},
    {"name": "Jupyter Lab", "port": 8888},
    {"name": "Happ Sub Adapter", "port": 2097},
    {"name": "WireProxy SOCKS5", "port": 40001},
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
PROTECTED_PROCESSES = [
    "xray", "x-ui", "sshd", "systemd", "nginx", "init", "warp-svc",
    "fail2ban", "wireproxy", "antigravity", "vpn_guard", "server_guard"
]

BOT_VERSION = "2.0"

# Список администраторов: основной ADMIN_CHAT_ID + дополнительные из .env (ADMIN_CHAT_IDS=1,2,3)
ADMIN_IDS = [ADMIN_CHAT_ID]
for _x in _os.environ.get("ADMIN_CHAT_IDS", "").split(","):
    _x = _x.strip()
    if _x.lstrip("-").isdigit() and int(_x) not in ADMIN_IDS:
        ADMIN_IDS.append(int(_x))
