import os
import time
import json
import re
import datetime
import logging
from logging.handlers import RotatingFileHandler
import threading
import subprocess
import psutil
import requests
import telebot
from telebot import types

import config
import analyzer
import card_generator
import backup_manager
import vpn_manager
import metrics_store
import security_tools
import maintenance

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("server_guard")
log.setLevel(logging.INFO)
try:
    _fh = RotatingFileHandler(os.path.join(BASE_DIR, "server_guard.log"), maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(_fh)
except Exception:
    pass
_sh = logging.StreamHandler()
_sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_sh)

bot = telebot.TeleBot(config.BOT_TOKEN)
last_alert_time = 0
last_ssl_check_day = -1
last_backup_date_str = ""

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))
SETTINGS_FILE = "/root/server_guard/settings.json"

DEFAULT_SETTINGS = {
    "backup_enabled": True,
    "backup_time": "22:00",
    "filter_system_cpu": True,
    "service_alerts_enabled": {srv["unit"]: True for srv in config.MONITORED_SERVICES},
    "ssh_alerts_enabled": False,
    "ban_alerts_enabled": False,
    "daily_report_enabled": True,
    "daily_report_time": "09:00",
    "quiet_hours_enabled": False,
    "quiet_start": "00:00",
    "quiet_end": "08:00",
    "nightly_restart_enabled": False,
    "last_seen_version": "",
}

active_dashboard_msg = {"chat_id": None, "message_id": None, "last_content": ""}
dashboard_msg = {"chat_id": None, "message_id": None}

STATE_TTL = 600  # сек: забытые шаги мастеров сбрасываются автоматически


class StateDict(dict):
    """dict состояний мастеров: записи автоматически устаревают через STATE_TTL секунд."""

    def __init__(self):
        super().__init__()
        self._ts = {}

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._ts[key] = time.time()

    def get(self, key, default=None):
        if key in self and time.time() - self._ts.get(key, 0) > STATE_TTL:
            self.pop(key, None)
            return default
        return super().get(key, default)

    def pop(self, key, *args):
        self._ts.pop(key, None)
        return super().pop(key, *args)


user_states = StateDict()


def is_admin(chat_id):
    return chat_id in config.ADMIN_IDS

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                res = DEFAULT_SETTINGS.copy()
                res.update(saved)
                alerts_map = DEFAULT_SETTINGS["service_alerts_enabled"].copy()
                alerts_map.update(saved.get("service_alerts_enabled", {}))
                res["service_alerts_enabled"] = alerts_map
                return res
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
    except Exception:
        log.exception("Не удалось сохранить settings.json")

bot_settings = load_settings()
IGNORED_HIGH_CPU_PROCESSES = ["apt-check", "unattended-upgr", "dpkg", "apt-get", "apt"]

def get_systemd_status(unit_name):
    try:
        res = subprocess.run(["systemctl", "is-active", unit_name], capture_output=True, text=True, timeout=2)
        st = res.stdout.strip()
        return "🟢 active" if st == "active" else f"🔴 {st}"
    except Exception:
        return "⚪ unknown"

def check_http(url, timeout=5.0):
    try:
        headers = {
            "User-Agent": "ServerGuard/2.0"
        }
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return "🟢 200 OK" if r.status_code == 200 else f"🟡 {r.status_code}"
    except Exception:
        return "🔴 down"

PROCESS_DESCRIPTIONS = {
    "xray-linux-amd64": "Ядро прокси Xray (шифрование и передача трафика)",
    "xray": "Ядро прокси Xray (шифрование и передача трафика)",
    "x-ui": "Панель управления 3X-UI (веб-интерфейс и база)",
    "warp-svc": "Клиент Cloudflare WARP (socks5 прокси)",
    "systemd-resolved": "Системный DNS-резолвер Linux",
    "sshd": "Служба удаленного доступа SSH",
    "nginx": "Веб-сервер и reverse proxy",
    "fail2ban-server": "Защита от брутфорса и автобан IP",
    "jupyter-lab": "Среда разработки Jupyter Lab",
    "apt-check": "Проверка доступных обновлений Ubuntu",
    "unattended-upgr": "Фоновая установка обновлений безопасности",
    "systemd-journal": "Служба сбора системных журналов и логов",
    "rsyslogd": "Системный демон логирования",
}

def notify_admins(text, photo=None, reply_markup=None):
    """Отправка уведомления всем администраторам из config.ADMIN_IDS."""
    for admin_id in config.ADMIN_IDS:
        try:
            if photo:
                photo.seek(0)
                bot.send_photo(admin_id, photo=photo, caption=text, reply_markup=reply_markup, parse_mode="Markdown")
            else:
                bot.send_message(admin_id, text, reply_markup=reply_markup, parse_mode="Markdown")
        except Exception as e:
            log.warning(f"Не удалось отправить админу {admin_id}: {e}")

def get_process_description(proc, name):
    if name.lower().startswith("python"):
        try:
            cmd = proc.cmdline()
            cmd_str = " ".join(cmd).lower()
            if "server_guard" in cmd_str:
                return "Бот мониторинга Server Guard"
            if "membot" in cmd_str or "mem_bot" in cmd_str:
                return "Telegram-бот MemBot"
            if "flashcard" in cmd_str:
                return "Telegram-бот FlashCard Bot"
            if "anonchat" in cmd_str:
                return "Telegram-бот AnonChat Bot"
            if "jupyter" in cmd_str:
                return "Ядро/сервер Jupyter"
            for arg in cmd[1:]:
                if arg.endswith(".py"):
                    return f"Скрипт Python: {os.path.basename(arg)}"
            return "Фоновый процесс Python"
        except Exception:
            return "Интерпретатор Python"
    
    for key, desc in PROCESS_DESCRIPTIONS.items():
        if key.lower() in name.lower():
            return desc
            
    if name.startswith("kworker") or name.startswith("rcu_") or name.startswith("ksoftirqd"):
        return "Системный поток ядра Linux"
        
    return "Системный/пользовательский процесс"

def get_top_cpu_data(limit=5):
    procs = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            p.cpu_percent(None)
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(1.0)
    results = []
    for p in procs:
        try:
            cpu = p.cpu_percent(None)
            if cpu > 0.1:
                name = p.info['name']
                desc = get_process_description(p, name)
                results.append((name, p.info['pid'], cpu, desc))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:limit]

def get_top_ram_data(limit=6):
    results = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent']):
        try:
            mem_info = p.info['memory_info']
            rss = mem_info.rss if mem_info else 0
            mem_pct = p.info['memory_percent'] or 0.0
            if rss > 1024 * 1024:  # > 1 MB
                name = p.info['name']
                desc = get_process_description(p, name)
                results.append((name, p.info['pid'], rss, mem_pct, desc))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:limit]

def get_top_swap_data(limit=6):
    results = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            swap_bytes = 0
            try:
                info = p.memory_full_info()
                swap_bytes = getattr(info, 'swap', 0)
            except Exception:
                try:
                    with open(f"/proc/{p.info['pid']}/status", "r") as f:
                        for line in f:
                            if line.startswith("VmSwap:"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    swap_bytes = int(parts[1]) * 1024
                                break
                except Exception:
                    pass
            if swap_bytes > 1024:  # > 1 KB
                name = p.info['name']
                desc = get_process_description(p, name)
                results.append((name, p.info['pid'], swap_bytes, desc))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:limit]

def build_top_procs_text_and_kb(mode="cpu"):
    kb = types.InlineKeyboardMarkup()
    lines = []
    
    if mode == "ram":
        lines.append("🔝 **Топ процессов по использованию ОЗУ (RAM):**\n")
        procs = get_top_ram_data(limit=6)
        if not procs:
            lines.append("• Активные процессы с ОЗУ не зафиксированы.")
        else:
            for name, pid, rss, pct, desc in procs:
                mb = rss / (1024 * 1024)
                lines.append(f"• `{name}` (PID {pid}): **{mb:.1f} MB** (`{pct:.1f}%`)\n  └ *{desc}*")
                if mb > 150.0 and not any(p in name.lower() for p in config.PROTECTED_PROCESSES):
                    kb.add(types.InlineKeyboardButton(f"☠️ Убить {name[:12]} (PID {pid})", callback_data=f"kill:{pid}:{name}"))

    elif mode == "swap":
        lines.append("🔝 **Топ процессов по использованию SWAP (файла подкачки):**\n")
        procs = get_top_swap_data(limit=6)
        if not procs:
            lines.append("• Процессы, использующие SWAP, не обнаружены (или SWAP пуст).")
        else:
            for name, pid, swap_b, desc in procs:
                mb = swap_b / (1024 * 1024)
                kb_val = swap_b / 1024
                size_str = f"{mb:.1f} MB" if mb >= 1.0 else f"{kb_val:.0f} KB"
                lines.append(f"• `{name}` (PID {pid}): **{size_str}**\n  └ *{desc}*")
                if mb > 50.0 and not any(p in name.lower() for p in config.PROTECTED_PROCESSES):
                    kb.add(types.InlineKeyboardButton(f"☠️ Убить {name[:12]} (PID {pid})", callback_data=f"kill:{pid}:{name}"))

    else:  # mode == "cpu"
        lines.append("🔝 **Топ процессов по CPU прямо сейчас:**\n")
        procs = get_top_cpu_data(limit=6)
        if not procs:
            lines.append("• Процессы с явным потреблением CPU не зафиксированы.")
        else:
            for name, pid, cpu, desc in procs:
                lines.append(f"• `{name}` (PID {pid}): **{cpu:.1f}%**\n  └ *{desc}*")
                if cpu > 15.0 and not any(p in name.lower() for p in config.PROTECTED_PROCESSES):
                    kb.add(types.InlineKeyboardButton(f"☠️ Убить {name[:12]} (PID {pid})", callback_data=f"kill:{pid}:{name}"))

    btn_cpu = types.InlineKeyboardButton("💻 CPU" + (" (•)" if mode == "cpu" else ""), callback_data="procs:cpu")
    btn_ram = types.InlineKeyboardButton("🧠 ОЗУ" + (" (•)" if mode == "ram" else ""), callback_data="procs:ram")
    btn_swap = types.InlineKeyboardButton("💾 SWAP" + (" (•)" if mode == "swap" else ""), callback_data="procs:swap")
    kb.row(btn_cpu, btn_ram, btn_swap)

    return "\n".join(lines), kb

def format_system_text():
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage('/')
    summary = analyzer.get_system_summary()

    text = (
        f"📊 **Системные ресурсы:**\n"
        f"• **CPU:** `{cpu}%`\n"
        f"• **RAM:** `{ram.percent}%` ({ram.used // (1024*1024)}MB / {ram.total // (1024*1024)}MB)\n"
        f"• **Swap:** `{swap.percent}%` ({swap.used // (1024*1024)}MB / {swap.total // (1024*1024)}MB)\n"
        f"• **Диск:** `{disk.percent}%` (Свободно: {disk.free // (1024*1024*1024)}GB)\n\n"
        f"{summary}\n"
    )
    return text, cpu, ram.percent, swap.percent, disk.percent

def make_status_inline():
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🧹 Выгрузить SWAP", callback_data="flush_swap"),
        types.InlineKeyboardButton("📈 График 24ч", callback_data="show_chart_24")
    )
    return kb

def make_reply_keyboard():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.row("📊 Метрики", "🔗 Ссылки на сервисы", "🛠 Службы и Сайты")
    markup.row("🔝 Топ процессов", "🔑 Клиенты VPN", "🚀 Тест скорости")
    markup.row("📦 Бэкап сервера", "🛡 Защита Fail2Ban")
    markup.row("⚙️ Настройки", "📋 Ошибки в логах")
    return markup

def make_services_inline():
    kb = types.InlineKeyboardMarkup()
    for srv in config.MONITORED_SERVICES:
        st = get_systemd_status(srv["unit"])
        if "🔴" in st:
            btn_action = types.InlineKeyboardButton(f"▶️ Вкл {srv['name']}", callback_data=f"srv:start:{srv['unit']}")
        else:
            btn_action = types.InlineKeyboardButton(f"⏹ Выкл {srv['name']}", callback_data=f"srv:stop:{srv['unit']}")
        btn_restart = types.InlineKeyboardButton(f"🔄 Рестарт", callback_data=f"srv:restart:{srv['unit']}")
        kb.row(btn_action, btn_restart)
    kb.add(types.InlineKeyboardButton("🔄 Обновить SSL сертификат", callback_data="renew_ssl"))
    kb.add(types.InlineKeyboardButton("🔄 Обновить список статусов", callback_data="refresh_services"))
    return kb

SERVICE_LINKS = [
    [("🌐 Главный сайт", f"https://{config.DOMAIN}/"), ("🔑 Панель 3X-UI", f"{config.XUI_URL}")],
    [("📓 Jupyter Lab", f"https://{config.DOMAIN}/jupyter/"), ("🤖 Telegram Bot", "https://t.me/your_bot")],
]

def make_links_inline():
    kb = types.InlineKeyboardMarkup()
    for row in SERVICE_LINKS:
        kb.row(*[types.InlineKeyboardButton(title, url=url) for title, url in row])
    return kb

DEFAULT_HTTP_CHECKS = [
    {"name": "Главный сайт", "url": f"https://{config.DOMAIN}/"},
    {"name": "Панель 3X-UI", "url": f"{config.XUI_URL}"}
]

def build_services_text():
    lines = ["🛠 **Статус служб Linux:**"]
    for srv in config.MONITORED_SERVICES:
        lines.append(f"• {srv['name']}: {get_systemd_status(srv['unit'])}")

    lines.append("\n🌐 **Доступность сайтов (HTTP):**")
    http_checks = getattr(config, "HTTP_CHECKS", DEFAULT_HTTP_CHECKS)
    cleaned_checks = []
    for site in http_checks:
        u = site.get("url", "")
        if not u or "127.0.0.1" in u:
            cleaned_checks = DEFAULT_HTTP_CHECKS
            break
        cleaned_checks.append(site)
    if not cleaned_checks:
        cleaned_checks = DEFAULT_HTTP_CHECKS

    for site in cleaned_checks:
        lines.append(f"• {site['name']}: {check_http(site['url'])}")

    days, exp_date = analyzer.check_ssl_expiry()
    if days is not None:
        icon = "🟢" if days > 10 else "🟡" if days > 3 else "🔴"
        lines.append(f"\n🔒 **SSL-сертификат панели/подписок:** {icon} `{days}` дн. (до {exp_date})")
    return "\n".join(lines)

def make_settings_main_inline():
    kb = types.InlineKeyboardMarkup()
    bk_status = "🟢 ВКЛ" if bot_settings.get("backup_enabled", True) else "🔴 ВЫКЛ"
    kb.row(
        types.InlineKeyboardButton(f"Автобэкап: {bk_status}", callback_data="cfg:toggle_backup"),
        types.InlineKeyboardButton(f"⏰ Время: {bot_settings.get('backup_time', '22:00')}", callback_data="cfg:set_time_prompt")
    )
    flt_status = "🟢 ВКЛ" if bot_settings.get("filter_system_cpu", True) else "🔴 ВЫКЛ"
    ssh_status = "🟢 ВКЛ" if bot_settings.get("ssh_alerts_enabled", True) else "🔴 ВЫКЛ"
    kb.row(
        types.InlineKeyboardButton(f"🛡 Фильтр обновления ОС: {flt_status}", callback_data="cfg:toggle_filter"),
        types.InlineKeyboardButton(f"🔑 Уведомления SSH: {ssh_status}", callback_data="cfg:toggle_ssh")
    )
    rep_status = "🟢 ВКЛ" if bot_settings.get("daily_report_enabled", True) else "🔴 ВЫКЛ"
    kb.row(types.InlineKeyboardButton(f"📊 Ежедневный отчет ({bot_settings.get('daily_report_time', '09:00')}): {rep_status}", callback_data="cfg:toggle_report"))
    kb.row(types.InlineKeyboardButton("🔔 Настройка уведомлений служб ❯", callback_data="cfg:menu_services"))
    return kb

def make_service_alerts_inline():
    kb = types.InlineKeyboardMarkup()
    alerts_map = bot_settings.get("service_alerts_enabled", {})
    for srv in config.MONITORED_SERVICES:
        u = srv["unit"]
        is_on = alerts_map.get(u, True)
        icon = "🟢 ВКЛ" if is_on else "🔴 ВЫКЛ"
        kb.row(types.InlineKeyboardButton(f"{srv['name']}: {icon}", callback_data=f"cfg_srv_toggle:{u}"))
    kb.row(types.InlineKeyboardButton("❮ Назад в Настройки", callback_data="cfg:back_main"))
    return kb

# --- VPN UI функции ---

def make_vpn_main_inline():
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("➕ Добавить клиента", callback_data="vpn:new"),
        types.InlineKeyboardButton("📋 Список клиентов", callback_data="vpn:list")
    )
    return kb

def make_clients_list_inline(clients):
    kb = types.InlineKeyboardMarkup()
    for c in clients:
        kb.add(types.InlineKeyboardButton(f"👤 {c['email']} ({vpn_manager.format_bytes(c['up'] + c['down'])})", callback_data=f"vpn_view:{c['email']}"))
    kb.add(types.InlineKeyboardButton("➕ Добавить нового", callback_data="vpn:new"))
    return kb

def format_client_card(c):
    used_traffic = vpn_manager.format_bytes(c["up"] + c["down"])
    limit_traffic = f"{c['total_gb'] / (1024**3):.1f} GB" if c.get("total_gb", 0) > 0 else "Безлимит ♾"
    
    exp_str = "Безлимит ♾"
    if c.get("expiry_time", 0) > 0:
        dt = datetime.datetime.fromtimestamp(c["expiry_time"] / 1000)
        exp_str = dt.strftime("%d.%m.%Y %H:%M")

    raw_sub, happ_sub = vpn_manager.build_links(c.get("sub_id", ""))
    st_icon = "🟢 Включен" if c.get("enable", True) else "🔴 Отключен"

    text = (
        f"👤 **Клиент:** `{c['email']}` ({st_icon})\n\n"
        f"📊 **Трафик:** `{used_traffic}` / `{limit_traffic}`\n"
        f"⏳ **Срок действия:** `{exp_str}`\n"
        f"🌐 **Серверов привязано:** `{len(c.get('inbound_ids', []))}` (Нидерланды Reality/Hysteria)\n"
        f"⚡ **Flow:** `xtls-rprx-vision`\n\n"
        f"🔗 **Ссылка быстрого перехода в Happ:**\n`{happ_sub}`\n\n"
        f"🔒 **Прямая ссылка 3X-UI:**\n`{raw_sub}`"
    )
    return text, raw_sub, happ_sub

def make_client_view_keyboard(email, happ_url, is_enabled=True):
    """Клавиатура управления клиентом (сразу содержит 'Изменить' и 'Удалить')."""
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🚀 В Happ", url=happ_url),
        types.InlineKeyboardButton("⚙️ Изменить", callback_data=f"vpn_edit:{email}")
    )
    toggle_txt = "🔴 Отключить" if is_enabled else "🟢 Включить"
    kb.row(
        types.InlineKeyboardButton(toggle_txt, callback_data=f"vpn_toggle:{email}"),
        types.InlineKeyboardButton("🗑 Удалить", callback_data=f"vpn_del_confirm:{email}")
    )
    kb.add(types.InlineKeyboardButton("❮ К списку клиентов", callback_data="vpn:list"))
    return kb

# --- Команды бота ---

@bot.message_handler(commands=['start', 'menu'])
def handle_start(message):
    if not is_admin(message.chat.id):
        return
    bot.send_message(
        message.chat.id,
        "🛡 **Центр управления VPS Server Guard активен.**\n"
        f"Версия бота: `v{config.BOT_VERSION}`",
        reply_markup=make_reply_keyboard(),
        parse_mode="Markdown"
    )

@bot.message_handler(commands=['status'])
def handle_status_cmd(message):
    if not is_admin(message.chat.id):
        return
    msg_text, cpu, ram, swap, disk = format_system_text()
    sub = f"Uptime: {maintenance.format_duration(maintenance.get_uptime_seconds())}"
    photo_buf = card_generator.generate_status_card(cpu, ram, swap, disk, subtitle=sub)
    bot.send_photo(message.chat.id, photo_buf, caption=msg_text, reply_markup=make_status_inline(), parse_mode="Markdown")

@bot.message_handler(commands=['backup'])
def handle_backup_cmd(message):
    if not is_admin(message.chat.id):
        return
    bot.send_message(message.chat.id, "⏳ Создаю архив ключевых данных сервера...")
    success, res = backup_manager.send_backup(bot, message.chat.id)
    if not success:
        bot.send_message(message.chat.id, f"❌ Ошибка создания бэкапа: {res}")

@bot.message_handler(commands=['speedtest'])
def handle_speedtest_cmd(message):
    if not is_admin(message.chat.id):
        return
    bot.send_message(message.chat.id, "⏳ Запускаю замер скорости канала VPS (30-40 сек)...")
    bot.send_chat_action(message.chat.id, 'typing')
    res = analyzer.run_speedtest()
    bot.send_message(message.chat.id, f"🚀 **Результаты Speedtest:**\n```text\n{res}\n```", parse_mode="Markdown")

@bot.message_handler(commands=['logs'])
def handle_logs_cmd(message):
    if not is_admin(message.chat.id):
        return
    logs = analyzer.get_critical_logs(lines=15)
    bot.send_message(message.chat.id, f"📋 **Реальные системные ошибки (24ч):**\n```text\n{logs[-3500:]}\n```", parse_mode="Markdown")

@bot.message_handler(commands=['unban'])
def handle_unban_cmd(message):
    if not is_admin(message.chat.id):
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, "Использование: `/unban <IP-адрес>`", parse_mode="Markdown")
        return
    ip = parts[1].strip()
    res = analyzer.unban_ip(ip)
    bot.send_message(message.chat.id, f"Разбан `{ip}`:\n{res}", parse_mode="Markdown")

@bot.message_handler(commands=['help'])
def handle_help_cmd(message):
    if not is_admin(message.chat.id):
        return
    help_text = (
        "📖 **Справка по кнопкам и командам Server Guard:**\n\n"
        "📊 **Метрики** — ресурсы CPU/RAM/Disk, Uptime и график истории нагрузки.\n"
        "🔗 **Ссылки на сервисы** — список прямого перехода к веб-приложениям.\n"
        "🛠 **Службы и Сайты** — статус systemd и HTTP, кнопки включения/выключения.\n"
        "🔝 **Топ процессов** — процессы с высоким потреблением CPU.\n"
        "🔑 **Клиенты VPN** — полная карточка клиента 3X-UI, изменение лимитов, выключение, QR-код.\n"
        "🚀 **Тест скорости** — замер скорости сети VPS через Speedtest.\n"
        "📦 **Бэкап сервера** — архивация и отправка резервной копии.\n"
        "🛡 **Защита Fail2Ban** — заблокированные IP за атаки на SSH и разбан.\n"
        "⚙️ **Настройки** — тихие часы, автобэкап, алерты SSH.\n"
        "📋 **Ошибки в логах** — критические события systemd журнала.\n\n"
        "**Быстрые команды:**\n"
        "• `/status` — метрики VPS\n"
        "• `/chart` — график нагрузки за 24ч\n"
        "• `/backup` — сделать бэкап\n"
        "• `/speedtest` — тест скорости\n"
        "• `/unban IP` — разбанить IP"
    )
    bot.send_message(message.chat.id, help_text, parse_mode="Markdown")

@bot.message_handler(commands=['chart'])
def handle_chart_cmd(message):
    if not is_admin(message.chat.id):
        return
    rows = metrics_store.get_samples(24)
    if not rows:
        bot.send_message(message.chat.id, "История метрик пока накапливается. Попробуйте чуть позже.")
        return
    chart_buf = card_generator.generate_history_chart(rows, 24)
    bot.send_photo(message.chat.id, photo=chart_buf, caption="📈 **График нагрузки и сетевого трафика VPS за 24 часа**", parse_mode="Markdown")

# --- Обработка текста и состояний ---

@bot.message_handler(func=lambda msg: is_admin(msg.chat.id))
def handle_text(message):
    text = message.text or ""

    menu_buttons = [
        "Метрики", "Ссылки на сервисы", "Службы и Сайты", "Топ процессов", "Клиенты VPN",
        "Бэкап сервера", "Настройки", "Тест скорости", "Защита Fail2Ban", "Ошибки в логах"
    ]
    if any(btn in text for btn in menu_buttons):
        user_states.pop(message.chat.id, None)

    state = user_states.get(message.chat.id)

    # 1. Время бэкапа
    if state == "waiting_backup_time":
        raw = text.strip()
        match = re.match(r"^([0-1]?[0-9]|2[0-3])(?::([0-5][0-9]))?$", raw)
        if match:
            h = int(match.group(1))
            m = int(match.group(2)) if match.group(2) else 0
            formatted = f"{h:02d}:{m:02d}"
            bot_settings["backup_time"] = formatted
            save_settings(bot_settings)
            user_states.pop(message.chat.id, None)
            bot.send_message(
                message.chat.id,
                f"✅ Время ежедневного бэкапа установлено на **{formatted} (МСК)**.",
                reply_markup=make_settings_main_inline(),
                parse_mode="Markdown"
            )
            return
        else:
            bot.send_message(message.chat.id, "❌ Введите время в формате `ЧЧ:ММ` (например, `22:00` или `23`):")
            return

    # 2. Мастер VPN: ввод Email
    if state == "vpn_waiting_email":
        email = text.strip()
        user_states[message.chat.id] = {"step": "vpn_confirm", "email": email, "sub_id": ""}
        kb = types.InlineKeyboardMarkup()
        kb.row(
            types.InlineKeyboardButton("🎲 Случайный ID подписки", callback_data="vpn_sub:random"),
            types.InlineKeyboardButton("✏️ Ввести свой ID", callback_data="vpn_sub:custom")
        )
        bot.send_message(message.chat.id, f"👤 Имя клиента: `{email}`\n\nВыберите способ создания ID подписки:", reply_markup=kb, parse_mode="Markdown")
        return

    # 3. Мастер VPN: ввод кастомного subId
    if isinstance(state, dict) and state.get("step") == "vpn_waiting_sub_id":
        state["sub_id"] = text.strip()
        state["step"] = "vpn_limits"
        user_states[message.chat.id] = state
        
        kb = types.InlineKeyboardMarkup()
        kb.row(types.InlineKeyboardButton("♾ Безлимит (по умолчанию)", callback_data="vpn_lim:unlim"))
        kb.row(types.InlineKeyboardButton("✏️ Указать ГБ и дни вручную", callback_data="vpn_lim:manual"))
        bot.send_message(message.chat.id, "Выберите лимиты для клиента:", reply_markup=kb, parse_mode="Markdown")
        return

    # 4. Мастер VPN: ручной ввод ГБ
    if isinstance(state, dict) and state.get("step") == "vpn_waiting_gb":
        try:
            gb = float(text.replace(",", ".").strip())
            state["total_gb"] = gb
            state["step"] = "vpn_waiting_days"
            user_states[message.chat.id] = state
            bot.send_message(message.chat.id, f"Лимит трафика: `{gb}` GB.\n\nТеперь отправьте срок действия в днях (например `30` или `0` для бессрочного):")
        except ValueError:
            bot.send_message(message.chat.id, "❌ Введите число (например, `50` или `100.5`):")
        return

    # 5. Мастер VPN: ручной ввод дней
    if isinstance(state, dict) and state.get("step") == "vpn_waiting_days":
        try:
            days = int(text.strip())
            state["days_limit"] = days
            email = state["email"]
            sub_id = state.get("sub_id")
            total_gb = state.get("total_gb", 0)

            user_states.pop(message.chat.id, None)
            bot.send_message(message.chat.id, "⏳ Создаю клиента через официальный API 3X-UI...")

            ok, res = vpn_manager.create_client(
                email=email,
                sub_id=sub_id,
                total_gb=total_gb,
                days_limit=days
            )

            if not ok:
                bot.send_message(message.chat.id, f"❌ Ошибка создания клиента: `{res}`", parse_mode="Markdown")
                return

            client_data = vpn_manager.get_client_by_email(email)
            if not client_data:
                client_data = {
                    "email": email,
                    "sub_id": res,
                    "total_gb": int(total_gb * (1024**3)),
                    "expiry_time": int((time.time() + days*86400)*1000) if days > 0 else 0,
                    "inbound_ids": [1, 2, 3, 5],
                    "up": 0, "down": 0
                }

            card_text, raw_sub, happ_url = format_client_card(client_data)
            qr_buf = vpn_manager.generate_qr_bytes(raw_sub)
            kb = make_client_view_keyboard(email, happ_url, client_data.get("enable", True))

            bot.send_photo(
                message.chat.id,
                photo=qr_buf,
                caption=f"✅ **Клиент успешно создан во всех 4 серверах!**\n\n{card_text}",
                reply_markup=kb,
                parse_mode="Markdown"
            )
        except ValueError:
            bot.send_message(message.chat.id, "❌ Введите целое число дней (например, `30`):")
        return

    # 6. Редактирование лимита ГБ
    if isinstance(state, dict) and state.get("step") == "vpn_edit_gb":
        target_em = state["target_email"]
        try:
            gb = float(text.replace(",", ".").strip())
            vpn_manager.update_client_limits(target_em, total_gb=gb)
            user_states.pop(message.chat.id, None)
            try:
                bot.delete_message(message.chat.id, message.message_id)
            except Exception:
                pass
            client_data = vpn_manager.get_client_by_email(target_em)
            if client_data:
                card_text, raw_sub, happ_url = format_client_card(client_data)
                kb = make_client_view_keyboard(target_em, happ_url, client_data.get("enable", True))
                qr_buf = vpn_manager.generate_qr_bytes(raw_sub)
                bot.send_photo(message.chat.id, photo=qr_buf, caption=f"✅ **Лимит трафика обновлен (`{gb}` GB)!**\n\n{card_text}", reply_markup=kb, parse_mode="Markdown")
            else:
                bot.send_message(message.chat.id, f"✅ Лимит трафика для `{target_em}` установлен на `{gb}` GB.")
        except ValueError:
            bot.send_message(message.chat.id, "❌ Введите число:")
        return

    # 7. Редактирование срока дней
    if isinstance(state, dict) and state.get("step") == "vpn_edit_days":
        target_em = state["target_email"]
        try:
            days = int(text.strip())
            vpn_manager.update_client_limits(target_em, days_limit=days)
            user_states.pop(message.chat.id, None)
            try:
                bot.delete_message(message.chat.id, message.message_id)
            except Exception:
                pass
            client_data = vpn_manager.get_client_by_email(target_em)
            if client_data:
                card_text, raw_sub, happ_url = format_client_card(client_data)
                kb = make_client_view_keyboard(target_em, happ_url, client_data.get("enable", True))
                qr_buf = vpn_manager.generate_qr_bytes(raw_sub)
                bot.send_photo(message.chat.id, photo=qr_buf, caption=f"✅ **Срок действия обновлен (`{days}` дн.)!**\n\n{card_text}", reply_markup=kb, parse_mode="Markdown")
            else:
                bot.send_message(message.chat.id, f"✅ Срок действия для `{target_em}` обновлен на `{days}` дн.")
        except ValueError:
            bot.send_message(message.chat.id, "❌ Введите целое число дней:")
        return

    # --- Кнопки главного меню ---

    if "Метрики" in text:
        msg_text, cpu, ram, swap, disk = format_system_text()
        sub = f"Uptime: {maintenance.format_duration(maintenance.get_uptime_seconds())}"
        photo_buf = card_generator.generate_status_card(cpu, ram, swap, disk, subtitle=sub)
        bot.send_photo(message.chat.id, photo_buf, caption=msg_text, reply_markup=make_status_inline(), parse_mode="Markdown")

    elif "Ссылки на сервисы" in text:
        bot.send_message(message.chat.id, "Быстрый переход к сервисам VPS:", reply_markup=make_links_inline())

    elif "Службы и Сайты" in text:
        body = build_services_text()
        kb = make_services_inline()
        sent = bot.send_message(message.chat.id, body, reply_markup=kb, parse_mode="Markdown")
        active_dashboard_msg["chat_id"] = sent.chat.id
        active_dashboard_msg["message_id"] = sent.message_id
        active_dashboard_msg["last_content"] = body

    elif "Топ процессов" in text:
        bot.send_chat_action(message.chat.id, 'typing')
        text_msg, kb = build_top_procs_text_and_kb(mode="cpu")
        bot.send_message(message.chat.id, text_msg, reply_markup=kb, parse_mode="Markdown")

    elif "Клиенты VPN" in text or "VPN" in text:
        try:
            clients = vpn_manager.get_clients_list()
            msg = (
                f"🔑 **Управление клиентами VPN (3X-UI OpenAPI):**\n\n"
                f"• Активных клиентов в базе: `{len(clients)}`\n"
                f"• Целевые узлы: **Нидерланды (4 сервера: 1, 2, 3, 5)**\n"
                f"• Интеграция: **Прямой авто-импорт в Happ**\n\n"
                f"Выберите действие:"
            )
            bot.send_message(message.chat.id, msg, reply_markup=make_vpn_main_inline(), parse_mode="Markdown")
        except Exception as e:
            bot.send_message(message.chat.id, f"❌ Ошибка доступа к API: `{e}`", parse_mode="Markdown")

    elif "Бэкап сервера" in text:
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("⚡ Сделать бэкап прямо сейчас", callback_data="run_manual_backup"))
        status_text = "Включен" if bot_settings.get("backup_enabled", True) else "Выключен"
        msg = (
            f"📦 **Управление резервными копиями:**\n\n"
            f"• **Ежедневный автобэкап:** `{status_text}`\n"
            f"• **Время отправки:** `{bot_settings.get('backup_time', '22:00')}` (МСК)\n"
            f"• **Состав:** Базы 3X-UI и ботов, тетрадки, WARP, Nginx, сертификаты, сайт.\n\n"
            f"Архив весит ~1.5 MB и отправляется прямо в этот диалог."
        )
        bot.send_message(message.chat.id, msg, reply_markup=kb, parse_mode="Markdown")

    elif "Настройки" in text:
        user_states.pop(message.chat.id, None)
        msg = (
            "⚙️ **Панель настроек мониторинга и бэкапов:**\n\n"
            "• **Автобэкап:** Включение/выключение и точное время отправки архива по МСК.\n"
            "• **Фильтр автообновлений ОС:** Игнорирует временные 100% всплески процессора от фоновых обновлений Ubuntu (`apt`, `unattended-upgrades`), чтобы не присылать лишних алертов.\n"
            "• **Настройка уведомлений служб:** Позволяет точечно включить или выключить алерты о сбое для каждой службы отдельно."
        )
        bot.send_message(message.chat.id, msg, reply_markup=make_settings_main_inline(), parse_mode="Markdown")

    elif "Тест скорости" in text:
        bot.send_message(message.chat.id, "⏳ Запускаю замер скорости канала VPS (30-40 сек)...")
        bot.send_chat_action(message.chat.id, 'typing')
        res = analyzer.run_speedtest()
        bot.send_message(message.chat.id, f"🚀 **Результаты Speedtest:**\n```text\n{res}\n```", parse_mode="Markdown")

    elif "Защита Fail2Ban" in text:
        banned, total, banned_ips = analyzer.get_fail2ban_stats()
        msg = (
            f"🛡 **Состояние Fail2Ban (защита SSH):**\n"
            f"• Активно в бане: `{banned}`\n"
            f"• Всего поймано атак с запуска: `{total}`\n\n"
        )
        kb = types.InlineKeyboardMarkup()
        if banned_ips:
            msg += "⛔ **Заблокированные IP прямо сейчас:**\n"
            for ip in banned_ips[:10]:
                msg += f"• `{ip}`\n"
                kb.add(types.InlineKeyboardButton(f"🔓 Разбанить {ip}", callback_data=f"unban:{ip}"))
        else:
            msg += "Активных банов в данный момент нет."

        bot.send_message(message.chat.id, msg, reply_markup=kb if banned_ips else None, parse_mode="Markdown")

    elif "Ошибки в логах" in text:
        logs = analyzer.get_critical_logs(lines=15)
        bot.send_message(message.chat.id, f"📋 **Реальные системные ошибки:**\n```text\n{logs[-3500:]}\n```", parse_mode="Markdown")

# --- Коллбэки ---

@bot.callback_query_handler(func=lambda call: True)
def handle_all_callbacks(call):
    if not is_admin(call.message.chat.id):
        return

    data = call.data

    # Службы
    if data.startswith("srv:"):
        _, action, unit = data.split(":", 2)
        bot.answer_callback_query(call.id, f"Выполняю {action} для {unit}...")
        subprocess.run(["systemctl", action, unit])
        
        if action in ["start", "restart"]:
            for _ in range(4):
                time.sleep(1)
                body = build_services_text()
                if "🔴 down" not in body or action == "stop":
                    break
        else:
            time.sleep(1)
            body = build_services_text()

        active_dashboard_msg["last_content"] = body
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=body,
                reply_markup=make_services_inline(),
                parse_mode="Markdown"
            )
        except Exception:
            pass

    elif data == "refresh_services":
        bot.answer_callback_query(call.id, "Обновляю статусы...")
        body = build_services_text()
        active_dashboard_msg["last_content"] = body
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=body,
                reply_markup=make_services_inline(),
                parse_mode="Markdown"
            )
        except Exception:
            pass

    # Выбор режима Топ процессов
    elif data.startswith("procs:"):
        mode = data.split(":", 1)[1]
        mode_title = "CPU" if mode == "cpu" else "ОЗУ (RAM)" if mode == "ram" else "SWAP"
        bot.answer_callback_query(call.id, f"Сортировка: {mode_title}")
        text_msg, kb = build_top_procs_text_and_kb(mode=mode)
        try:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=text_msg,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        except Exception:
            pass

    # Убийство процессов
    elif data.startswith("kill:"):
        _, pid, name = data.split(":", 2)
        if any(p in name.lower() for p in config.PROTECTED_PROCESSES):
            bot.answer_callback_query(call.id, f"❌ Процесс {name} защищен от завершения из бота!", show_alert=True)
            return
        try:
            p = psutil.Process(int(pid))
            p.kill()
            bot.answer_callback_query(call.id, f"Процесс {pid} уничтожен!")
            bot.send_message(call.message.chat.id, f"☠️ Процесс `{name}` (PID `{pid}`) принудительно завершен.", parse_mode="Markdown")
        except psutil.NoSuchProcess:
            bot.answer_callback_query(call.id, "Процесс уже завершился.")
        except Exception as e:
            bot.answer_callback_query(call.id, f"Ошибка: {e}")

    # Разбан IP
    elif data.startswith("unban:"):
        ip = data.split(":", 1)[1]
        res = analyzer.unban_ip(ip)
        bot.answer_callback_query(call.id, "Команда отправлена")
        bot.send_message(call.message.chat.id, f"Разбан `{ip}`:\n{res}", parse_mode="Markdown")

    # SSL
    elif data == "renew_ssl":
        bot.answer_callback_query(call.id, "Обновляю сертификат...")
        status_msg = bot.send_message(call.message.chat.id, "⏳ Обновляю сертификат Let's Encrypt...")
        res = analyzer.renew_ssl()
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=status_msg.message_id, text=res, parse_mode="Markdown")

    # Выгрузка SWAP
    elif data == "flush_swap":
        bot.answer_callback_query(call.id, "Запускаю выгрузку SWAP...")
        wait_msg = bot.send_message(call.message.chat.id, "⏳ Выполняю безопасную выгрузку SWAP в ОЗУ (`swapoff -a && swapon -a`)...")
        res_text = analyzer.flush_swap()
        try:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=wait_msg.message_id, text=res_text, parse_mode="Markdown")
        except Exception:
            bot.send_message(call.message.chat.id, res_text, parse_mode="Markdown")

    # График из метрик
    elif data == "show_chart_24":
        bot.answer_callback_query(call.id)
        rows = metrics_store.get_samples(24)
        if not rows:
            bot.send_message(call.message.chat.id, "История метрик пока накапливается. Попробуйте чуть позже.")
            return
        chart_buf = card_generator.generate_history_chart(rows, 24)
        bot.send_photo(call.message.chat.id, photo=chart_buf, caption="📈 **График нагрузки и сетевого трафика VPS за 24 часа**", parse_mode="Markdown")

    # Ручной бэкап
    elif data == "run_manual_backup":
        bot.answer_callback_query(call.id, "Архивирую файлы...")
        bot.send_message(call.message.chat.id, "⏳ Создаю и отправляю резервную копию...")
        success, msg = backup_manager.send_backup(bot, call.message.chat.id)
        if not success:
            bot.send_message(call.message.chat.id, f"❌ Ошибка создания бэкапа: {msg}")

    # Меню настроек
    elif data == "cfg:toggle_backup":
        bot_settings["backup_enabled"] = not bot_settings.get("backup_enabled", True)
        save_settings(bot_settings)
        bot.answer_callback_query(call.id, "Автобэкап переключен")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=make_settings_main_inline())

    elif data == "cfg:set_time_prompt":
        user_states[call.message.chat.id] = "waiting_backup_time"
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id, "⏰ **Настройка времени:** отправьте желаемое время по МСК (например, `22:00` или `23`):")

    elif data == "cfg:toggle_filter":
        bot_settings["filter_system_cpu"] = not bot_settings.get("filter_system_cpu", True)
        save_settings(bot_settings)
        bot.answer_callback_query(call.id, "Фильтр переключен")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=make_settings_main_inline())

    elif data == "cfg:toggle_ssh":
        bot_settings["ssh_alerts_enabled"] = not bot_settings.get("ssh_alerts_enabled", True)
        save_settings(bot_settings)
        bot.answer_callback_query(call.id, "Уведомления SSH переключены")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=make_settings_main_inline())

    elif data == "cfg:toggle_report":
        bot_settings["daily_report_enabled"] = not bot_settings.get("daily_report_enabled", True)
        save_settings(bot_settings)
        bot.answer_callback_query(call.id, "Ежедневный отчет переключен")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=make_settings_main_inline())

    elif data == "cfg:menu_services":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text="🔔 **Послужебная настройка алертов при падении:**",
            reply_markup=make_service_alerts_inline(),
            parse_mode="Markdown"
        )

    elif data.startswith("cfg_srv_toggle:"):
        unit = data.split(":", 1)[1]
        alerts_map = bot_settings.setdefault("service_alerts_enabled", {})
        alerts_map[unit] = not alerts_map.get(unit, True)
        save_settings(bot_settings)
        bot.answer_callback_query(call.id, "Статус алерта изменен")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=make_service_alerts_inline())

    elif data == "cfg:back_main":
        bot.answer_callback_query(call.id)
        bot.edit_message_text(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            text="⚙️ **Панель настроек мониторинга и бэкапов:**",
            reply_markup=make_settings_main_inline(),
            parse_mode="Markdown"
        )

    # --- VPN Коллбэки ---

    elif data == "vpn:list":
        bot.answer_callback_query(call.id)
        clients = vpn_manager.get_clients_list()
        if not clients:
            bot.send_message(call.message.chat.id, "Клиенты пока не найдены в базе.", reply_markup=make_vpn_main_inline())
            return
        
        if call.message.content_type == "photo":
            bot.delete_message(call.message.chat.id, call.message.message_id)
            bot.send_message(
                call.message.chat.id,
                "📋 **Список активных клиентов Reality/Hysteria:**",
                reply_markup=make_clients_list_inline(clients),
                parse_mode="Markdown"
            )
        else:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text="📋 **Список активных клиентов Reality/Hysteria:**",
                reply_markup=make_clients_list_inline(clients),
                parse_mode="Markdown"
            )

    elif data == "vpn:new":
        bot.answer_callback_query(call.id)
        user_states[call.message.chat.id] = "vpn_waiting_email"
        bot.send_message(
            call.message.chat.id,
            "➕ **Создание нового клиента:**\n\n"
            "Введите имя (email) клиента (например: `Danil`, `Work_Mac`, `Максим`):",
            parse_mode="Markdown"
        )

    elif data == "vpn_sub:random":
        bot.answer_callback_query(call.id)
        state = user_states.get(call.message.chat.id)
        if isinstance(state, dict):
            state["sub_id"] = None
            state["step"] = "vpn_limits"
            kb = types.InlineKeyboardMarkup()
            kb.row(types.InlineKeyboardButton("♾ Безлимит (по умолчанию)", callback_data="vpn_lim:unlim"))
            kb.row(types.InlineKeyboardButton("✏️ Указать ГБ и дни вручную", callback_data="vpn_lim:manual"))
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text="Выберите тарифные лимиты:",
                reply_markup=kb,
                parse_mode="Markdown"
            )

    elif data == "vpn_sub:custom":
        bot.answer_callback_query(call.id)
        state = user_states.get(call.message.chat.id)
        if isinstance(state, dict):
            state["step"] = "vpn_waiting_sub_id"
            bot.send_message(call.message.chat.id, "Введите желаемый ID подписки (латиница и цифры):")

    elif data == "vpn_lim:unlim":
        bot.answer_callback_query(call.id, "Создаю клиента...")
        state = user_states.pop(call.message.chat.id, None)
        if not isinstance(state, dict):
            bot.send_message(call.message.chat.id, "Ошибка сессии. Повторите заново через меню.")
            return

        bot.send_message(call.message.chat.id, "⏳ Создаю клиента через официальный API 3X-UI...")
        ok, res = vpn_manager.create_client(
            email=state["email"],
            sub_id=state.get("sub_id"),
            total_gb=0,
            days_limit=0
        )

        if not ok:
            bot.send_message(call.message.chat.id, f"❌ Ошибка создания: `{res}`", parse_mode="Markdown")
            return

        client_data = vpn_manager.get_client_by_email(state["email"])
        if not client_data:
            client_data = {
                "email": state["email"],
                "sub_id": res,
                "total_gb": 0,
                "expiry_time": 0,
                "inbound_ids": [1, 2, 3, 5],
                "up": 0, "down": 0
            }

        card_text, raw_sub, happ_url = format_client_card(client_data)
        qr_buf = vpn_manager.generate_qr_bytes(raw_sub)
        kb = make_client_view_keyboard(state["email"], happ_url, client_data.get("enable", True))

        bot.send_photo(
            call.message.chat.id,
            photo=qr_buf,
            caption=f"✅ **Клиент успешно создан во всех 4 серверах!**\n\n{card_text}",
            reply_markup=kb,
            parse_mode="Markdown"
        )

    elif data == "vpn_lim:manual":
        bot.answer_callback_query(call.id)
        state = user_states.get(call.message.chat.id)
        if isinstance(state, dict):
            state["step"] = "vpn_waiting_gb"
            bot.send_message(call.message.chat.id, "Введите лимит трафика в **ГБ** (например, `50`, `100` или `0` для безлимита):")

    # Просмотр конкретного клиента
    elif data.startswith("vpn_view:"):
        bot.answer_callback_query(call.id)
        email = data.split(":", 1)[1]
        client_data = vpn_manager.get_client_by_email(email)
        if not client_data:
            bot.send_message(call.message.chat.id, "Клиент не найден.")
            return

        card_text, raw_sub, happ_url = format_client_card(client_data)
        kb = make_client_view_keyboard(email, happ_url, client_data.get("enable", True))

        if call.message.content_type == "photo":
            try:
                bot.edit_message_caption(
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    caption=card_text,
                    reply_markup=kb,
                    parse_mode="Markdown"
                )
                return
            except Exception:
                pass

        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except Exception:
            pass

        qr_buf = vpn_manager.generate_qr_bytes(raw_sub)
        bot.send_photo(
            call.message.chat.id,
            photo=qr_buf,
            caption=card_text,
            reply_markup=kb,
            parse_mode="Markdown"
        )

    # Включение/отключение клиента
    elif data.startswith("vpn_toggle:"):
        email = data.split(":", 1)[1]
        c = vpn_manager.get_client_by_email(email)
        if not c:
            bot.answer_callback_query(call.id, "Клиент не найден")
            return
        new_st = not c.get("enable", True)
        ok = vpn_manager.set_client_enabled(email, new_st)
        st_text = "включен" if new_st else "отключен"
        bot.answer_callback_query(call.id, f"Клиент {st_text}")
        c["enable"] = new_st
        card_text, raw_sub, happ_url = format_client_card(c)
        kb = make_client_view_keyboard(email, happ_url, new_st)
        try:
            bot.edit_message_caption(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                caption=card_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        except Exception:
            pass

    # Подтверждение удаления клиента
    elif data.startswith("vpn_del_confirm:"):
        email = data.split(":", 1)[1]
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup()
        kb.row(
            types.InlineKeyboardButton("✅ Да, удалить", callback_data=f"vpn_del:{email}"),
            types.InlineKeyboardButton("❌ Отмена", callback_data=f"vpn_view:{email}")
        )
        msg_text = f"⚠️ Вы уверены, что хотите **удалить** клиента `{email}`?"
        if call.message.content_type == "photo":
            bot.edit_message_caption(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                caption=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        else:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )

    # Меню редактирования клиента
    elif data.startswith("vpn_edit:"):
        bot.answer_callback_query(call.id)
        email = data.split(":", 1)[1]
        kb = types.InlineKeyboardMarkup()
        kb.row(
            types.InlineKeyboardButton("📊 Лимит ГБ", callback_data=f"vpn_ed_gb:{email}"),
            types.InlineKeyboardButton("⏳ Срок (дней)", callback_data=f"vpn_ed_days:{email}")
        )
        kb.add(types.InlineKeyboardButton("❮ Назад к клиенту", callback_data=f"vpn_view:{email}"))
        msg_text = f"⚙️ **Редактирование профиля:** `{email}`\n\nЧто вы хотите изменить?"
        if call.message.content_type == "photo":
            bot.edit_message_caption(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                caption=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        else:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )

    elif data.startswith("vpn_ed_gb:"):
        email = data.split(":", 1)[1]
        user_states[call.message.chat.id] = {"step": "vpn_edit_gb", "target_email": email}
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("❮ Назад к клиенту", callback_data=f"vpn_view:{email}"))
        msg_text = f"⚙️ **Изменение лимита ГБ для `{email}`**\n\nВведите новый лимит в **ГБ** ответным сообщением (0 = безлимит):"
        if call.message.content_type == "photo":
            bot.edit_message_caption(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                caption=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        else:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )

    elif data.startswith("vpn_ed_days:"):
        email = data.split(":", 1)[1]
        user_states[call.message.chat.id] = {"step": "vpn_edit_days", "target_email": email}
        bot.answer_callback_query(call.id)
        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("❮ Назад к клиенту", callback_data=f"vpn_view:{email}"))
        msg_text = f"⚙️ **Изменение срока для `{email}`**\n\nВведите количество дней действия ответным сообщением от текущего момента (0 = безлимит):"
        if call.message.content_type == "photo":
            bot.edit_message_caption(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                caption=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )
        else:
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=msg_text,
                reply_markup=kb,
                parse_mode="Markdown"
            )

    # Удаление клиента
    elif data.startswith("vpn_del:"):
        email = data.split(":", 1)[1]
        ok = vpn_manager.delete_client(email)
        bot.answer_callback_query(call.id, f"Клиент {email} удален!")
        
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except Exception:
            pass

        if ok:
            bot.send_message(call.message.chat.id, f"🗑 Клиент `{email}` удален из 3X-UI через API.", parse_mode="Markdown")
        else:
            bot.send_message(call.message.chat.id, f"❌ Ошибка удаления `{email}`.", parse_mode="Markdown")

        clients = vpn_manager.get_clients_list()
        bot.send_message(call.message.chat.id, "📋 **Список клиентов:**", reply_markup=make_clients_list_inline(clients), parse_mode="Markdown")

# --- Фоновый цикл ---

def monitoring_loop():
    global last_alert_time, last_ssl_check_day, last_backup_date_str
    high_cpu_counter = 0
    alerted_failed_services = set()
    bg_refresh_ticks = 0
    last_ssh_check_ts = time.time()
    last_net = psutil.net_io_counters()
    last_net_ts = time.time()

    while True:
        try:
            now_ts = time.time()
            dt_net = max(0.5, now_ts - last_net_ts)
            curr_net = psutil.net_io_counters()
            rx_rate = max(0.0, (curr_net.bytes_recv - last_net.bytes_recv) / 1024.0 / dt_net)
            tx_rate = max(0.0, (curr_net.bytes_sent - last_net.bytes_sent) / 1024.0 / dt_net)
            last_net = curr_net
            last_net_ts = now_ts

            current_cpu = psutil.cpu_percent(interval=3)
            ram = psutil.virtual_memory()
            swap = psutil.swap_memory()
            disk = psutil.disk_usage('/')

            metrics_store.add_sample(current_cpu, ram.percent, swap.percent, disk.percent, rx=rx_rate, tx=tx_rate, ts=now_ts)

            if current_cpu >= config.CPU_THRESHOLD:
                high_cpu_counter += 1
            else:
                high_cpu_counter = 0

            trigger_alert = False
            alert_reasons = []

            if high_cpu_counter >= config.CPU_SUSTAINED_CHECKS:
                procs_data = get_top_cpu_data(limit=3)
                top_proc_name = procs_data[0][0].lower() if procs_data else ""
                is_ignorable = bot_settings.get("filter_system_cpu", True) and any(ig in top_proc_name for ig in IGNORED_HIGH_CPU_PROCESSES)

                if not is_ignorable:
                    trigger_alert = True
                    alert_reasons.append(f"Устойчивая нагрузка CPU: {current_cpu:.1f}% (>10 сек)")
                high_cpu_counter = 0

            if ram.percent >= config.RAM_THRESHOLD:
                trigger_alert = True
                alert_reasons.append(f"Высокое потребление RAM: {ram.percent}%")

            if disk.percent >= config.DISK_THRESHOLD:
                trigger_alert = True
                alert_reasons.append(f"Заполнение диска: {disk.percent}%")

            newly_failed = []
            alerts_map = bot_settings.get("service_alerts_enabled", {})

            for srv in config.MONITORED_SERVICES:
                unit = srv["unit"]
                should_alert = alerts_map.get(unit, True)
                status = get_systemd_status(unit)

                if "🔴" in status:
                    if unit not in alerted_failed_services:
                        if should_alert:
                            newly_failed.append(srv)
                        alerted_failed_services.add(unit)
                else:
                    alerted_failed_services.discard(unit)

            if newly_failed:
                trigger_alert = True
                alert_reasons.append("Сбой системной службы")

            # Проверка новых SSH входов
            if bot_settings.get("ssh_alerts_enabled", True):
                logins = security_tools.get_ssh_logins_since(last_ssh_check_ts)
                last_ssh_check_ts = now_ts
                for method, user, ip in logins:
                    geo = security_tools.geoip(ip)
                    geo_str = f" ({geo})" if geo else ""
                    notify_admins(f"🔑 **Успешный SSH вход на сервер!**\n\n• Пользователь: `{user}`\n• Метод: `{method}`\n• IP: `{ip}`{geo_str}")

            now_msk = datetime.datetime.now(MSK_TZ)
            current_time_str = now_msk.strftime("%H:%M")
            target_time_str = bot_settings.get("backup_time", "22:00")
            current_date_str = now_msk.strftime("%Y-%m-%d")

            if bot_settings.get("backup_enabled", True):
                if current_time_str == target_time_str and current_date_str != last_backup_date_str:
                    last_backup_date_str = current_date_str
                    for admin_id in config.ADMIN_IDS:
                        backup_manager.send_backup(bot, admin_id)

            if now_msk.day != last_ssl_check_day:
                last_ssl_check_day = now_msk.day
                days_left, exp_date = analyzer.check_ssl_expiry()
                if days_left is not None and days_left <= 2:
                    kb = types.InlineKeyboardMarkup()
                    kb.add(types.InlineKeyboardButton("🔄 Обновить SSL сейчас", callback_data="renew_ssl"))
                    notify_admins(
                        f"⚠️ **ВНИМАНИЕ: Истекает SSL-сертификат!**\n\n"
                        f"До окончания действия сертификата для IP/подписок осталось всего `{days_left}` дн. (до {exp_date}).",
                        reply_markup=kb
                    )

            bg_refresh_ticks += 1
            if bg_refresh_ticks % 2 == 0 and active_dashboard_msg["message_id"]:
                try:
                    new_body = build_services_text()
                    if new_body != active_dashboard_msg["last_content"]:
                        active_dashboard_msg["last_content"] = new_body
                        bot.edit_message_text(
                            chat_id=active_dashboard_msg["chat_id"],
                            message_id=active_dashboard_msg["message_id"],
                            text=new_body,
                            reply_markup=make_services_inline(),
                            parse_mode="Markdown"
                        )
                except Exception:
                    pass

            curr_time = time.time()
            if trigger_alert and ((curr_time - last_alert_time > config.ALERT_COOLDOWN) or newly_failed):
                last_alert_time = curr_time
                procs_data = get_top_cpu_data(limit=4)
                system_summary = analyzer.get_system_summary()

                msg = (
                    f"⚠️ **ВНИМАНИЕ: Срабатывание триггера VPS!**\n\n"
                    f"🚨 **Причина:**\n• " + "\n• ".join(alert_reasons) + "\n"
                )

                markup = types.InlineKeyboardMarkup()
                if newly_failed:
                    msg += f"\n❌ **Остановлены службы:** `{', '.join([s['name'] for s in newly_failed])}`\n"
                    for s in newly_failed:
                        btn_start = types.InlineKeyboardButton(f"▶️ Запустить {s['name']}", callback_data=f"srv:start:{s['unit']}")
                        btn_restart = types.InlineKeyboardButton(f"🔄 Рестарт {s['name']}", callback_data=f"srv:restart:{s['unit']}")
                        markup.row(btn_start, btn_restart)

                if procs_data:
                    top_lines = []
                    for name, pid, cpu, desc in procs_data:
                        top_lines.append(f"• `{name}` (PID {pid}): **{cpu:.1f}%**\n  └ *{desc}*")
                        if cpu > 15.0 and not any(p in name.lower() for p in config.PROTECTED_PROCESSES):
                            markup.add(types.InlineKeyboardButton(f"☠️ Убить {name[:12]} (PID {pid})", callback_data=f"kill:{pid}:{name}"))
                    msg += f"\n📈 **Виновники нагрузки прямо сейчас:**\n" + "\n".join(top_lines) + "\n\n"

                msg += f"📊 **Сводка системы:**\n{system_summary}"
                notify_admins(msg, reply_markup=markup if markup.keyboard else None)

        except Exception as e:
            log.exception("Ошибка в фоновом цикле мониторинга")

        time.sleep(3)

def setup_bot_commands():
    commands = [
        types.BotCommand("start", "Главное меню и клавиатура"),
        types.BotCommand("status", "Метрики и карточка ресурсов"),
        types.BotCommand("chart", "График истории нагрузки за 24ч"),
        types.BotCommand("backup", "Сделать бэкап сервера прямо сейчас"),
        types.BotCommand("speedtest", "Замер скорости канала VPS"),
        types.BotCommand("logs", "Критические ошибки за 24 часа"),
        types.BotCommand("unban", "Снять бан Fail2Ban (/unban IP)"),
        types.BotCommand("help", "Справка по боту")
    ]
    try:
        bot.set_my_commands(commands)
    except Exception:
        pass

if __name__ == "__main__":
    setup_bot_commands()
    log.info("Запуск Server Guard bot...")
    t = threading.Thread(target=monitoring_loop, daemon=True)
    t.start()
    while True:
        try:
            bot.polling(none_stop=True, interval=1, timeout=20)
        except Exception as e:
            log.warning(f"Сбой polling: {e}, перезапуск через 5 сек...")
            time.sleep(5)
