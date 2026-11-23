import os
import time
import json
import re
import html
import datetime
import logging
from logging.handlers import RotatingFileHandler
import threading
import subprocess
import concurrent.futures
import psutil
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import telebot
from telebot import types

import config
import analyzer
import card_generator
import backup_manager
import metrics_store
import security_tools
import maintenance
import remote_monitor
import server_audit
from rich_formatter import safe_send_message, safe_edit_message, safe_send_photo, rich_to_telegram_html

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
    "service_alerts_enabled": {
        srv["unit"]: True
        for sc in config.SERVERS.values()
        for srv in sc.get("monitored_services", [])
    },
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

active_dashboard_msg = {"chat_id": None, "message_id": None, "last_content": "", "server_id": "nl"}
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
user_servers = {}  # chat_id -> "nl" или "fin"

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

def get_active_server_id(chat_id):
    if chat_id in user_servers:
        return user_servers[chat_id]
    servers_map = bot_settings.get("user_servers", {})
    val = servers_map.get(str(chat_id), servers_map.get(chat_id, "nl"))
    user_servers[chat_id] = val
    return val

def set_active_server_id(chat_id, server_id):
    user_servers[chat_id] = server_id
    if "user_servers" not in bot_settings:
        bot_settings["user_servers"] = {}
    bot_settings["user_servers"][str(chat_id)] = server_id
    save_settings(bot_settings)

def get_active_server_conf(chat_id):
    sid = get_active_server_id(chat_id)
    return config.SERVERS.get(sid, config.SERVERS["nl"])

def get_systemd_status(unit_name):
    res = get_local_systemd_statuses([unit_name])
    return res.get(unit_name, "⚪ unknown")

def get_local_systemd_statuses(unit_names):
    if not unit_names:
        return {}
    try:
        res = subprocess.run(["systemctl", "is-active"] + list(unit_names), capture_output=True, text=True, timeout=2)
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        if len(lines) != len(unit_names):
            return {u: "⚪ unknown" for u in unit_names}
        result = {}
        for i, u in enumerate(unit_names):
            st = lines[i]
            result[u] = "🟢 active" if st == "active" else f"🔴 {st}"
        return result
    except Exception:
        return {u: "⚪ unknown" for u in unit_names}

def check_heavy_system_tasks():
    """Проверяет, запущены ли процессы обновления ОС или активной сборки."""
    package_tools = {"apt", "apt-get", "dpkg", "unattended-upgr", "needrestart", "do-release-upgrade"}
    build_tools = {"pip", "pip3", "npm", "yarn", "cargo", "docker-build"}
    for p in psutil.process_iter(['name']):
        try:
            name = (p.info['name'] or '').lower()
            if any(pt in name for pt in package_tools):
                return f"📦 На сервере выполняется фоновое обновление или установка пакетов ({name})"
            if any(bt in name for bt in build_tools):
                return f"🔨 На сервере запущен процесс сборки/установки зависимостей ({name})"
        except Exception:
            continue
    return None

def diagnose_service_failure(sid, unit, service_name=None):
    """
    Анализирует причины остановки службы через свойства systemd, логи journalctl и состояние ОС.
    Возвращает понятное текстовое описание вероятной причины сбоя.
    """
    heavy_task = check_heavy_system_tasks() if sid == "nl" else None
    if heavy_task:
        return heavy_task

    props = {}
    last_log_lines = []
    try:
        if sid == "nl":
            res = subprocess.run(
                ["systemctl", "show", unit, "-p", "Result,ExecMainStatus,ExecMainCode,ActiveState,SubState"],
                capture_output=True, text=True, timeout=3
            )
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()

            log_res = subprocess.run(
                ["journalctl", "-u", unit, "-n", "4", "--no-pager", "-o", "cat"],
                capture_output=True, text=True, timeout=3
            )
            last_log_lines = [l.strip() for l in log_res.stdout.splitlines() if l.strip()]
        else:
            ok, out, _ = remote_monitor.run_remote_ssh(
                f"systemctl show {unit} -p Result,ExecMainStatus,ExecMainCode,ActiveState,SubState && echo '---LOGS---' && journalctl -u {unit} -n 4 --no-pager -o cat",
                timeout=5,
                server_id=sid
            )
            if ok and out:
                parts = out.split("---LOGS---")
                for line in parts[0].splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        props[k.strip()] = v.strip()
                if len(parts) > 1:
                    last_log_lines = [l.strip() for l in parts[1].splitlines() if l.strip()]
    except Exception as e:
        log.warning(f"Ошибка получения диагностики для {unit}: {e}")

    active_state = props.get("ActiveState", "")
    substate = props.get("SubState", "dead")
    result = props.get("Result", "")
    exit_status = str(props.get("ExecMainStatus", "0"))

    if active_state == "active" or substate == "running":
        return "🟢 Служба активна (кратковременный сетевой сбой при опросе статуса)"

    if substate == "auto-restart":
        return "🔄 Плановый перезапуск службы (systemd auto-restart)"

    try:
        mem = psutil.virtual_memory()
        if mem.percent > 95 and (result in ("signal", "oom-kill") or exit_status in ("9", "137")):
            return "💥 Критическая нехватка RAM (>95%). Процесс принудительно завершён ядром Linux (OOM Killer)"
    except Exception:
        pass

    if result == "success" and exit_status in ("0", 0):
        return "⏹ Служба была штатно остановлена вручную (командой `systemctl stop`, через бота или скриптом)"

    if result == "oom-kill":
        return "💥 Процесс принудительно завершён ядром Linux из-за исчерпания памяти (Out-Of-Memory Killer)"

    if result == "signal":
        if exit_status in ("9", "137"):
            return "🛑 Процесс был принудительно убит по SIGKILL (kill -9 или OOM Killer)"
        elif exit_status in ("15", "143"):
            return "⏹ Процесс получил сигнал планового завершения SIGTERM"
        else:
            return f"🛑 Процесс завершён системным сигналом (код {exit_status})"

    if result == "timeout":
        return "⏱ Превышен лимит времени ожидания ответа службы (Systemd Watchdog / Timeout)"

    if result == "core-dump":
        return "💥 Критический сбой бинарного процесса (Segmentation Fault / Core Dump)"

    log_text = " ".join(last_log_lines).lower()
    if "address already in use" in log_text:
        return "⚠️ Порт службы уже занят другим процессом (`Address already in use`)"
    if "permission denied" in log_text:
        return "🔒 Ошибка доступа к системным ресурсам или файлам (`Permission denied`)"
    if "no space left on device" in log_text:
        return "💾 На диске сервера закончилось свободное место (`No space left on device`)"
    if "modulenotfounderror" in log_text or "importerror" in log_text:
        return "🐍 Ошибка в зависимостях Python (отсутствует модуль или библиотека)"
    if "connection refused" in log_text:
        return "🔌 Не удалось подключиться к зависимой службе (`Connection refused`)"
    if "database is locked" in log_text:
        return "🗄 База данных заблокирована другим процессом (`database is locked`)"
    if "syntaxerror" in log_text:
        return "❌ Синтаксическая ошибка в коде скрипта (`SyntaxError`)"

    relevant_logs = [l for l in last_log_lines if not any(w in l.lower() for w in ["started ", "deactivated ", "consumed "])]
    if relevant_logs:
        last_line = relevant_logs[-1]
        if len(last_line) > 120:
            last_line = last_line[:117] + "..."
        if result == "exit-code" or exit_status != "0":
            return f"⚠️ Процесс завершился с кодом ошибки `{exit_status}`:\n  └ `{last_line}`"
        return f"⚠️ Последняя запись службы:\n  └ `{last_line}`"

    if result == "exit-code" or exit_status != "0":
        return f"⚠️ Процесс аварийно завершился с кодом ошибки `{exit_status}`"

    return f"⚠️ Служба перешла в неактивное состояние (`{substate}`)"

def check_http(url, timeout=3.0):
    try:
        headers = {
            "User-Agent": "ServerGuard/2.0"
        }
        r = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return "🟢 200 OK" if r.status_code == 200 else f"🟡 {r.status_code}"
    except Exception:
        return "🔴 down"

def check_http_all(http_checks, timeout=2.5):
    """Параллельная проверка доступности HTTP сайтов через ThreadPoolExecutor."""
    if not http_checks:
        return []

    def _check(site):
        name = site["name"]
        url = site["url"]
        return name, check_http(url, timeout=timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(http_checks), 8)) as executor:
        results = list(executor.map(_check, http_checks))
    return results

PROCESS_DESCRIPTIONS = {
    "xray-linux-amd64": "Ядро прокси Xray (шифрование и передача трафика)",
    "xray": "Ядро прокси Xray (шифрование и передача трафика)",
    "x-ui": "Панель управления 3X-UI (веб-интерфейс и база)",
    "warp-svc": "Клиент Cloudflare WARP (socks5 прокси)",
    "wireproxy": "Клиент WireProxy (SOCKS5 прокси WARP)",
    "systemd-resolved": "Системный DNS-резолвер Linux",
    "sshd": "Служба удаленного доступа SSH",
    "nginx": "Веб-сервер и reverse proxy",
    "fail2ban-server": "Защита от брутфорса и автобан IP",
    "jupyter-lab": "Среда разработки Jupyter Lab",
    "beszel": "Центральный сервер мониторинга Beszel Hub",
    "beszel-agent": "Агент сбора метрик Beszel Agent",
    "vaultwarden": "Менеджер паролей Vaultwarden (Docker)",
    "docker-proxy": "Прокси сетевых портов Docker",
    "containerd-shim-runc-v2": "Контейнерный рантайм containerd-shim",
    "apt-check": "Проверка доступных обновлений Ubuntu",
    "unattended-upgr": "Фоновая установка обновлений безопасности",
    "systemd-journal": "Служба сбора системных журналов и логов",
    "rsyslogd": "Системный демон логирования",
    "vid1xbot": "Telegram-бот vidx Downloader (@vid1xbot)",
    "smartdns-relay": "Релей SmartDNS UDP/TCP (RU ➔ FIN)",
    "xray-warp": "Служба Xray YouTube Egress (WARP обход)",
    "realm": "Транзитный прокси Realm Relay (RU ➔ NL/FI)",
    "dns_telemetry": "Демон телеметрии DNS bbumn",
    "ufw": "Межсетевой экран UFW (Firewall)",
}

def notify_admins(text, photo=None, reply_markup=None):
    """Отправка уведомления всем администраторам из config.ADMIN_IDS с поддержкой Rich Markdown."""
    sent_messages = []
    for admin_id in config.ADMIN_IDS:
        try:
            if photo:
                m = safe_send_photo(bot, admin_id, photo=photo, caption=text, reply_markup=reply_markup)
            else:
                m = safe_send_message(bot, admin_id, text=text, reply_markup=reply_markup)
            if m:
                sent_messages.append(m)
        except Exception as e:
            log.warning(f"Не удалось отправить админу {admin_id}: {e}")
    return sent_messages

def is_protected_proc(pid, name):
    """Проверка, является ли процесс системно защищенным от завершения."""
    name_l = name.lower()
    if any(p in name_l for p in config.PROTECTED_PROCESSES):
        return True
    try:
        p = psutil.Process(int(pid))
        cmd = " ".join(p.cmdline()).lower()
        if any(p in cmd for p in config.PROTECTED_PROCESSES):
            return True
        if any(b in cmd for b in ["server_guard", "antigravity", "vpn_guard", "wireproxy"]):
            return True
    except Exception:
        pass
    return False

def get_process_description(proc, name):
    cmd = []
    try:
        cmd = proc.cmdline()
    except Exception:
        pass
    cmd_str = " ".join(cmd).lower() if cmd else ""
    name_lower = name.lower()

    # 1. Потоки ядра Linux (PID <= 2 или без cmdline и специфичные имена)
    if proc.pid <= 2 or not cmd:
        kernel_prefixes = (
            "kworker", "rcu", "ksoftirqd", "migration", "cpuhp", "idle_inject",
            "kdevtmpfs", "kauditd", "khungtaskd", "oom_reaper", "kcompactd",
            "ksmd", "khugepaged", "jbd2", "irq/", "scsi_", "pool_workqueue",
            "kswapd", "watchdogd", "ecryptfs", "hwrng"
        )
        if any(name_lower.startswith(kp) for kp in kernel_prefixes) or name_lower in ("kthreadd",):
            return "Системный поток ядра Linux"

    # 2. Python процессы и Telegram-боты
    if name_lower.startswith("python") or "python" in cmd_str:
        if "server_guard" in cmd_str:
            return "Бот мониторинга Server Guard"
        if "antigravity" in cmd_str or "bumagent" in cmd_str:
            return "Telegram-бот Antigravity Agent (@bumagent_bot)"
        if "vpn_guard" in cmd_str or "bumvpn" in cmd_str:
            return "Telegram-бот bumVPN Guard (@bumvpnguard_bot)"
        if "happ_sub_adapter" in cmd_str or "happ" in cmd_str:
            return "Адаптер подписок Happ (happ-sub-adapter)"
        if "membot" in cmd_str or "mem_bot" in cmd_str:
            return "Telegram-бот MemBot"
        if "flashcard" in cmd_str:
            return "Telegram-бот FlashCard Bot"
        if "anonchat" in cmd_str:
            return "Telegram-бот AnonChat Bot"
        if "weektrack" in cmd_str:
            return "Telegram-бот WeekTrack (расписание и маршруты)"
        if "vid1xbot" in cmd_str or "vidx" in cmd_str:
            return "Telegram-бот vidx Downloader (@vid1xbot)"
        if "smartdns-relay" in cmd_str or "smartdns" in cmd_str:
            return "Релей SmartDNS UDP/TCP (RU ➔ FIN AdGuard)"
        if "dns_telemetry" in cmd_str or "telemetry" in cmd_str:
            return "Демон телеметрии DNS bbumn"
        if "ipykernel" in cmd_str:
            return "Интерактивное ядро Jupyter Notebook"
        if "jupyter" in cmd_str:
            return "Среда разработки Jupyter Lab"
        if "speedtest" in cmd_str:
            return "Тест скорости сети VPS (speedtest-cli)"
        if "fail2ban" in cmd_str:
            return "Защита от брутфорса Fail2ban"
        if "check-new-release" in cmd_str or "do-release-upgrade" in cmd_str:
            return "Проверка новых версий Ubuntu"
        if "unattended-upgrades" in cmd_str or "unattended-upgr" in cmd_str:
            return "Фоновое обновление безопасности Ubuntu"
        for arg in cmd[1:]:
            if arg.endswith(".py"):
                return f"Скрипт Python: {os.path.basename(arg)}"
            if "/" in arg:
                base = os.path.basename(arg)
                if base:
                    return f"Модуль Python: {base}"
        return "Фоновый процесс Python"

    # 3. Известные демоны и службы
    if "ssh-ru-tunnel" in cmd_str or ("ssh" in name_lower and "-r" in cmd_str and "ru" in cmd_str):
        return "Обратный SSH-туннель NL ➔ RU Relay"

    known = {
        "xray-warp": "Служба Xray YouTube Egress (WARP обход)",
        "realm": "Транзитный прокси Realm Relay (RU ➔ NL/FI)",
        "smartdns": "Релей SmartDNS UDP/TCP (RU ➔ FIN)",
        "vid1xbot": "Telegram-бот vidx Downloader (@vid1xbot)",
        "ufw": "Межсетевой экран UFW Firewall",
        "xray": "Ядро прокси Xray (шифрование и передача трафика)",
        "x-ui": "Панель управления 3X-UI (веб-интерфейс и база)",
        "wireproxy": "Клиент WireProxy (SOCKS5 прокси WARP)",
        "warp-svc": "Клиент Cloudflare WARP (socks5 прокси)",
        "systemd-resolved": "Системный DNS-резолвер Linux",
        "sshd": "Служба удаленного доступа SSH",
        "nginx": "Веб-сервер и reverse proxy Nginx",
        "fail2ban": "Защита от брутфорса и автобан IP",
        "jupyter": "Среда разработки Jupyter Lab",
        "arcade-hub": "Сервер интерактивных игр Arcade Hub (Node.js)",
        "arcade": "Сервер интерактивных игр Arcade Hub (Node.js)",
        "node": "Сервер интерактивных игр Arcade Hub (Node.js)" if "arcade" in cmd_str else "Среда выполнения Node.js",
        "beszel-hub": "Центральный сервер мониторинга Beszel Hub",
        "beszel-agent": "Агент сбора метрик Beszel Agent",
        "beszel": "Сервер мониторинга Beszel Hub",
        "vaultwarden": "Менеджер паролей Vaultwarden (Docker)",
        "docker-proxy": "Прокси сетевых портов Docker (Vaultwarden)",
        "containerd-shim": "Контейнерный рантайм containerd-shim",
        "docker": "Контейнеризация Docker",
        "containerd": "Среда выполнения контейнеров containerd",
        "mtg": "MTProto Telegram Proxy",
        "adguard": "Блокировщик рекламы и трекеров AdGuard Home",
        "multipathd": "Служба отказоустойчивости дисков Multipath",
        "systemd-journal": "Служба сбора системных журналов и логов",
        "rsyslog": "Системный демон логирования",
        "cron": "Служба планировщика задач Cron",
        "dbus": "Системная шина сообщений D-Bus",
        "qemu-ga": "QEMU Guest Agent (агент виртуализации)",
        "fwupd": "Служба обновления прошивок оборудования",
        "polkit": "Служба авторизации привилегий PolicyKit",
        "agetty": "Терминальная консоль Linux (TTY)",
        "udisks": "Служба управления дисковыми накопителями",
        "modemmanager": "Служба управления модемами ModemManager",
        "psimon": "Мониторинг давления на ресурсы (PSI)",
        "systemd": "Системный менеджер systemd",
    }
    for k, desc in known.items():
        if k in name_lower or k in cmd_str:
            return desc

    # 4. Если есть cmdline, определяем бинарник
    if cmd:
        exe = os.path.basename(cmd[0]).strip("-")
        if exe and exe.lower() != name_lower:
            return f"Процесс {exe}"
        return f"Служба {name}"

    return "Неизвестный процесс"

def get_top_cpu_data(limit=6):
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_times', 'memory_info']):
        try:
            p.cpu_percent(None)
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(0.4)
    results = []
    for p in procs:
        try:
            cpu = p.cpu_percent(None)
            t = p.info.get('cpu_times')
            total_time = (t.user + t.system) if t else 0
            mem_info = p.info.get('memory_info')
            rss = mem_info.rss if mem_info else 0
            name = p.info['name']
            desc = get_process_description(p, name)
            results.append((name, p.info['pid'], cpu, rss, total_time, desc))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Сортировка: сначала по текущему % CPU, при равенстве - по общему времени CPU
    results.sort(key=lambda x: (x[2], x[4]), reverse=True)
    return [(r[0], r[1], r[2], r[3], r[5]) for r in results[:limit]]

def get_top_ram_data(limit=6):
    results = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent']):
        try:
            mem_info = p.info['memory_info']
            rss = mem_info.rss if mem_info else 0
            mem_pct = p.info['memory_percent'] or 0.0
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
            name = p.info['name']
            desc = get_process_description(p, name)
            results.append((name, p.info['pid'], swap_bytes, desc))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    results.sort(key=lambda x: x[2], reverse=True)
    return results[:limit]

NUM_EMOJIS = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]

def build_top_procs_text_and_kb(mode="cpu", server_id="nl"):
    kb = types.InlineKeyboardMarkup()
    srv_conf = config.SERVERS.get(server_id, config.SERVERS["nl"])
    srv_flag = srv_conf.get("flag", "🌐")
    srv_name = srv_conf.get("name", server_id)
    is_local = srv_conf.get("is_local", True)

    now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")
    mode_title = "ОЗУ (RAM)" if mode == "ram" else "SWAP" if mode == "swap" else "CPU"
    header = (
        f"# 🔝 Топ процессов по {mode_title}: {srv_flag} {srv_name}\n\n"
        f"> — 📅 {now_msk} MSK\n"
        f"> — IP: `{srv_conf['ip']}`\n"
    )

    if mode == "ram":
        if is_local:
            procs = get_top_ram_data(limit=6)
        else:
            procs = remote_monitor.get_remote_top_procs(mode="ram", limit=6, server_id=server_id)

        if not procs:
            body = "> ℹ️ _Активные процессы с потреблением ОЗУ не зафиксированы._"
        else:
            rows = [
                "| # | Процесс | PID | ОЗУ | Объем |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ]
            descs = []
            for idx, (name, pid, rss, pct, desc) in enumerate(procs):
                num = NUM_EMOJIS[idx] if idx < len(NUM_EMOJIS) else f"{idx+1}️⃣"
                mb = rss / (1024 * 1024)
                rows.append(f"| {num} | `{name}` | {pid} | `{pct:.1f}%` | `{mb:.1f} MB` |")
                if desc and desc != "Фоновый системный процесс":
                    descs.append(f"- **`{name}`**: _{desc}_")
            body = "\n".join(rows)
            if descs:
                body += "\n\n<details><summary>Назначение процессов</summary>\n\n" + "\n".join(descs) + "\n</details>"

    elif mode == "swap":
        if is_local:
            procs = get_top_swap_data(limit=6)
        else:
            procs = remote_monitor.get_remote_top_procs(mode="swap", limit=6, server_id=server_id)

        if not procs or all(p[2] == 0 for p in procs):
            body = "> 🟢 _Процессы, использующие SWAP, не обнаружены (SWAP полностью свободен)._"
        else:
            rows = [
                "| # | Процесс | PID | SWAP |",
                "| :--- | :--- | :--- | :--- |"
            ]
            descs = []
            valid_idx = 0
            for name, pid, swap_b, desc in procs:
                if swap_b <= 0:
                    continue
                num = NUM_EMOJIS[valid_idx] if valid_idx < len(NUM_EMOJIS) else f"{valid_idx+1}️⃣"
                valid_idx += 1
                mb = swap_b / (1024 * 1024)
                kb_val = swap_b / 1024
                size_str = f"{mb:.1f} MB" if mb >= 1.0 else f"{kb_val:.0f} KB"
                rows.append(f"| {num} | `{name}` | {pid} | `{size_str}` |")
                if desc and desc != "Фоновый системный процесс":
                    descs.append(f"- **`{name}`**: _{desc}_")
            body = "\n".join(rows) if valid_idx > 0 else "> 🟢 _Процессы в SWAP не обнаружены._"
            if descs:
                body += "\n\n<details><summary>Назначение процессов</summary>\n\n" + "\n".join(descs) + "\n</details>"

    else:  # mode == "cpu"
        if is_local:
            procs = get_top_cpu_data(limit=6)
        else:
            procs = remote_monitor.get_remote_top_procs(mode="cpu", limit=6, server_id=server_id)

        if not procs:
            body = "> ℹ️ _Процессы с явным потреблением CPU не зафиксированы._"
        else:
            rows = [
                "| # | Процесс | PID | CPU | Память |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ]
            descs = []
            for idx, item in enumerate(procs):
                num = NUM_EMOJIS[idx] if idx < len(NUM_EMOJIS) else f"{idx+1}️⃣"
                name = item[0]
                pid = item[1]
                cpu = item[2]
                rss = item[3] if len(item) > 4 else 0
                desc = item[-1]
                mb = rss / (1024 * 1024)
                mem_str = f"`{mb:.1f} MB`" if mb > 0.1 else "-"
                rows.append(f"| {num} | `{name}` | {pid} | `{cpu:.1f}%` | {mem_str} |")
                if desc and desc != "Фоновый системный процесс":
                    descs.append(f"- **`{name}`**: _{desc}_")
            body = "\n".join(rows)
            if descs:
                body += "\n\n<details><summary>Назначение процессов</summary>\n\n" + "\n".join(descs) + "\n</details>"

    btn_cpu = types.InlineKeyboardButton("💻 CPU" + (" (•)" if mode == "cpu" else ""), callback_data=f"procs:{server_id}:cpu")
    btn_ram = types.InlineKeyboardButton("🧠 ОЗУ" + (" (•)" if mode == "ram" else ""), callback_data=f"procs:{server_id}:ram")
    btn_swap = types.InlineKeyboardButton("💾 SWAP" + (" (•)" if mode == "swap" else ""), callback_data=f"procs:{server_id}:swap")
    kb.row(btn_cpu, btn_ram, btn_swap)
    kb.add(types.InlineKeyboardButton("🔄 Обновить", callback_data=f"procs_refresh:{server_id}:{mode}"))

    full_text = f"{header}\n{body}"
    return full_text, kb

def format_system_text(server_id="nl"):
    srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
    now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")

    if srv.get("is_local", True):
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        summary = analyzer.get_system_summary()
        uptime_sec = maintenance.get_uptime_seconds()
        uptime_str = maintenance.format_duration(uptime_sec)

        text = (
            f"# 📊 Системные ресурсы: {srv['flag']} {srv['name']}\n\n"
            f"> — 📅 {now_msk} MSK\n"
            f"> — IP: `{srv['ip']}`\n"
            f"> — Аптайм: `{uptime_str}`\n\n"
            f"## ⚡ Использование ресурсов\n"
            f"| Ресурс | Загрузка | Объем / Инфо |\n"
            f"| :--- | :--- | :--- |\n"
            f"| **CPU** | `{cpu:.1f}%` | {psutil.cpu_count(logical=True)} vCPU |\n"
            f"| **RAM** | `{ram.percent:.1f}%` | `{ram.used // (1024*1024)} MB` / `{ram.total // (1024*1024)} MB` |\n"
            f"| **SWAP** | `{swap.percent:.1f}%` | `{swap.used // (1024*1024)} MB` / `{swap.total // (1024*1024)} MB` |\n"
            f"| **Диск** | `{disk.percent:.1f}%` | Свободно: `{disk.free // (1024*1024*1024)} GB` / `{disk.total // (1024*1024*1024)} GB` |\n\n"
            f"## ℹ️ Дополнительно\n"
            f"{summary}\n"
        )
        sub = f"Uptime: {uptime_str}"
        return text, cpu, ram.percent, swap.percent, disk.percent, sub
    else:
        m = remote_monitor.get_remote_system_metrics(server_id=server_id)
        if not m:
            text = f"# ❌ Ошибка связи\n\n> Не удалось получить метрики с сервера {srv['flag']} {srv['name']} (`{srv['ip']}`). Проверьте доступность SSH."
            return text, 0.0, 0.0, 0.0, 0.0, "Uptime: N/A"
        cpu = m["cpu"]
        ram_pct = m["ram_pct"]
        swap_pct = m["swap_pct"]
        disk_pct = m["disk_pct"]
        uptime_str = maintenance.format_duration(m.get('uptime', 0))
        sub = f"Uptime: {uptime_str}"
        text = (
            f"# 📊 Системные ресурсы: {srv['flag']} {srv['name']}\n\n"
            f"> — 📅 {now_msk} MSK\n"
            f"> — IP: `{srv['ip']}`\n"
            f"> — Аптайм: `{uptime_str}`\n\n"
            f"## ⚡ Использование ресурсов\n"
            f"| Ресурс | Загрузка | Объем / Инфо |\n"
            f"| :--- | :--- | :--- |\n"
            f"| **CPU** | `{cpu:.1f}%` | LA: `{m.get('load_avg', 'н/д')}` |\n"
            f"| **RAM** | `{ram_pct:.1f}%` | `{m['ram_used']} MB` / `{m['ram_total']} MB` |\n"
            f"| **SWAP** | `{swap_pct:.1f}%` | `{m['swap_used']} MB` / `{m['swap_total']} MB` |\n"
            f"| **Диск** | `{disk_pct:.1f}%` | Свободно: `{m['disk_free']} GB` / `{m['disk_total']} GB` |\n"
        )
        return text, cpu, ram_pct, swap_pct, disk_pct, sub

def make_status_inline(server_id="nl"):
    kb = types.InlineKeyboardMarkup()
    srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
    if srv.get("is_local", True):
        kb.row(
            types.InlineKeyboardButton("🔄 Обновить", callback_data=f"refresh_metrics:{server_id}"),
            types.InlineKeyboardButton("🧹 Выгрузить SWAP", callback_data="flush_swap")
        )
        kb.add(types.InlineKeyboardButton("📈 График 24ч", callback_data="show_chart_24"))
    else:
        kb.row(
            types.InlineKeyboardButton("🔄 Обновить", callback_data=f"refresh_metrics:{server_id}")
        )
    return kb

def make_audit_inline(server_id="nl"):
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("🔄 Обновить анализ", callback_data=f"audit_refresh:{server_id}"),
        types.InlineKeyboardButton("📈 График 24ч", callback_data=f"chart_24h:{server_id}")
    )
    kb.row(
        types.InlineKeyboardButton("🛠 Службы сервера", callback_data=f"audit_services:{server_id}"),
        types.InlineKeyboardButton("📋 Ошибки в логах", callback_data=f"audit_logs:{server_id}")
    )
    return kb

def make_reply_keyboard(chat_id=None):
    active_sid = get_active_server_id(chat_id)
    active_conf = config.SERVERS.get(active_sid, config.SERVERS["nl"])

    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    # 1. Верхняя кнопка переключения текущего сервера
    markup.row(f"🌐 Сервер: {active_conf['flag']} {active_conf['name']} ⮂")
    # 2. Большая универсальная кнопка полного анализа активного сервера
    markup.row(f"🔍 Полный анализ: {active_conf['flag']} {active_conf['name']}")
    # 3. Основные разделы
    markup.row("📊 Метрики", "🔗 Ссылки на сервисы", "🛠 Службы и Сайты")
    markup.row("🔝 Топ процессов", "🚀 Тест скорости")
    markup.row("📦 Бэкап сервера", "🛡 Защита Fail2Ban")
    markup.row("⚙️ Настройки", "📋 Ошибки в логах")
    return markup

def make_services_inline(server_id="nl"):
    kb = types.InlineKeyboardMarkup()
    srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
    is_local = srv.get("is_local", True)
    services = srv.get("monitored_services", config.MONITORED_SERVICES)

    for s in services:
        unit = s["unit"]
        name = s["name"]
        if is_local:
            st = get_systemd_status(unit)
        else:
            st = remote_monitor.get_remote_systemd_status(unit, server_id=server_id)

        if "🔴" in st:
            btn_action = types.InlineKeyboardButton(f"▶️ Вкл {name}", callback_data=f"srv:{server_id}:start:{unit}")
        else:
            btn_action = types.InlineKeyboardButton(f"⏹ Выкл {name}", callback_data=f"srv:{server_id}:stop:{unit}")
        btn_restart = types.InlineKeyboardButton("🔄 Рестарт", callback_data=f"srv:{server_id}:restart:{unit}")
        kb.row(btn_action, btn_restart)

    if is_local:
        kb.add(types.InlineKeyboardButton("🔄 Обновить SSL сертификат", callback_data="renew_ssl"))
    kb.add(types.InlineKeyboardButton("🔄 Обновить список статусов", callback_data=f"refresh_services:{server_id}"))
    return kb

SERVICE_LINKS = [
    [("🌐 Главный сайт", "https://bbumn.ru/"), ("🖼 Compare App", "https://bbumn.ru/compare/")],
    [("🕹 Arcade Hub", "https://bbumn.ru/arcade/"), ("🔒 Vaultwarden", "https://bbumn.ru/vault/")],
    [("📊 Beszel Monitor", "https://bbumn.ru/monitor/"), ("🛡 Smart DNS", "https://dns.bbumn.ru/")],
    [("📓 Jupyter Lab", "https://bbumn.ru/jupyter/"), ("🔑 Панель 3X-UI", "https://bbumn.ru/3x/")],
    [("🛡 AdGuard Home", "https://bbumn.ru/adguard/"), ("🧠 Antigravity Agent", "https://t.me/bumagent_bot")],
    [("🤖 bumVPN Guard", "https://t.me/bumvpnguard_bot"), ("📅 WeekTrack", "https://t.me/weektrack_bot")],
    [("🎭 AnonChat Bot", "https://t.me/anonchatbum_bot"), ("🃏 FlashCard Bot", "https://t.me/gencarttbot")],
    [("🤖 MemBot", "https://t.me/bumnmembot"), ("📥 vidx Bot", "https://t.me/vid1xbot")],
]

def make_links_inline():
    kb = types.InlineKeyboardMarkup()
    for row in SERVICE_LINKS:
        kb.row(*[types.InlineKeyboardButton(title, url=url) for title, url in row])
    return kb

DEFAULT_HTTP_CHECKS = [
    {"name": "Главный сайт", "url": "https://bbumn.ru/"},
    {"name": "Compare App", "url": "https://bbumn.ru/compare/"},
    {"name": "Arcade Hub", "url": "https://bbumn.ru/arcade/"},
    {"name": "Vaultwarden", "url": "https://bbumn.ru/vault/"},
    {"name": "Beszel Monitor", "url": "https://bbumn.ru/monitor/"},
    {"name": "Smart DNS", "url": "https://dns.bbumn.ru/"},
    {"name": "AdGuard Home UI", "url": "https://bbumn.ru/adguard/"},
    {"name": "Jupyter Lab", "url": "https://bbumn.ru/jupyter/"}
]

def build_services_text(server_id="nl"):
    srv_conf = config.SERVERS.get(server_id, config.SERVERS["nl"])
    flag = srv_conf.get("flag", "🌐")
    name = srv_conf.get("name", server_id)
    is_local = srv_conf.get("is_local", True)
    services = srv_conf.get("monitored_services", config.MONITORED_SERVICES)
    http_checks = srv_conf.get("http_checks", [])

    now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")
    lines = [
        f"# 🛠 Службы и Инфраструктура: {flag} {name}\n",
        f"> — 📅 {now_msk} MSK\n> — IP: `{srv_conf['ip']}`\n"
    ]
    lines.append("## ⚙️ Системные службы (systemd)")
    lines.append("| Служба | Описание / Юнит | Статус |")
    lines.append("| :--- | :--- | :--- |")
    unit_names = [srv["unit"] for srv in services]
    if is_local:
        statuses = get_local_systemd_statuses(unit_names)
    else:
        statuses = remote_monitor.get_remote_systemd_statuses(unit_names, server_id=server_id)

    for srv in services:
        st = statuses.get(srv["unit"], "⚪ unknown")
        lines.append(f"| **{srv['name']}** | `{srv['unit']}` | {st} |")

    tcp_checks = srv_conf.get("tcp_checks", [])
    if tcp_checks:
        lines.append(f"\n## 🔌 Проброшенные порты (`{srv_conf['ip']}`)")
        lines.append("| Сервис / Порт | Статус |")
        lines.append("| :--- | :--- |")
        for p_name, p_st in remote_monitor.check_remote_tcp_ports(tcp_checks, srv_conf["ip"]):
            lines.append(f"| **{p_name}** | {p_st} |")

    if http_checks:
        lines.append(f"\n## 🌐 Доступность веб-сервисов и сайтов")
        lines.append("| Ресурс | Статус |")
        lines.append("| :--- | :--- |")
        http_results = check_http_all(http_checks, timeout=2.5)
        for s_name, s_status in http_results:
            lines.append(f"| **{s_name}** | {s_status} |")

    if is_local:
        days, exp_date = analyzer.check_ssl_expiry()
        if days is not None:
            icon = "🟢" if days > 10 else "🟡" if days > 3 else "🔴"
            lines.append(f"\n## 🔒 Безопасность и SSL\n- **Сертификат Let's Encrypt:** {icon} `{days} дн.` (до {exp_date})")
    return "\n".join(lines)

def build_backup_message_and_kb():
    info = backup_manager.get_last_backup_info()
    status_text = "Включен 🟢" if bot_settings.get("backup_enabled", True) else "Выключен 🔴"
    backup_time = bot_settings.get("backup_time", "22:00")

    nl_size = info["nl_size_str"]
    nl_date = f" (`{info['nl_date_str']}`)" if info.get("nl_date_str") else ""
    fin_size = info["fin_size_str"]
    fin_date = f" (`{info['fin_date_str']}`)" if info.get("fin_date_str") else ""
    ru_size = info.get("ru_size_str", "~1.4 MB")
    ru_date = f" (`{info['ru_date_str']}`)" if info.get("ru_date_str") else ""

    msg = (
        "# 📦 Управление резервными копиями\n\n"
        f"> • **Ежедневный автобэкап:** `{status_text}`\n"
        f"> • **Время отправки:** `{backup_time}` (МСК)\n\n"
        f"## 📊 Размер предыдущих копий\n"
        f"| Сервер | Размер архива | Дата создания |\n"
        f"| :--- | :--- | :--- |\n"
        f"| 🇳🇱 **Нидерланды** | `{nl_size}` | {nl_date or '-'} |\n"
        f"| 🇫🇮 **Финляндия** | `{fin_size}` | {fin_date or '-'} |\n"
        f"| 🇷🇺 **Россия** | `{ru_size}` | {ru_date or '-'} |\n\n"
        f"<details><summary>Состав резервных копий</summary>\n\n"
        f"- Базы данных 3X-UI и хранилище паролей Vaultwarden\n"
        f"- Боты инфраструктуры (AgentBot, bumVPN Guard, vid1x)\n"
        f"- Smart DNS и конфигурации Realm Relay (RU)\n"
        f"- Правила брандмауэра UFW / Fail2Ban\n"
        f"- SSL-сертификаты Let's Encrypt\n"
        f"</details>\n\n"
        f"_Выберите сервер для создания резервной копии:_"
    )

    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton(f"🇳🇱 NL ({nl_size})", callback_data="backup:nl"),
        types.InlineKeyboardButton(f"🇫🇮 FIN ({fin_size})", callback_data="backup:fin"),
        types.InlineKeyboardButton(f"🇷🇺 RU ({ru_size})", callback_data="backup:ru")
    )
    kb.row(
        types.InlineKeyboardButton("📦 Все 3 сервера (NL + FIN + RU)", callback_data="backup:all")
    )
    return msg, kb

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

def handle_full_audit(chat_id, server_id):
    srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
    srv_flag = srv.get("flag", "🌐")
    srv_name = srv.get("name", server_id)
    wait_msg = safe_send_message(
        bot,
        chat_id,
        f"⏳ **Запуск полного анализа сервера {srv_flag} {srv_name}...**\n"
        f"> _Проверяю ресурсы, 24ч историю, службы, L4/L7 доступность, порты, SSL и системные ошибки..._"
    )
    try:
        report_text, photo_buf, score = server_audit.run_server_audit(server_id)
        if wait_msg:
            try:
                bot.delete_message(chat_id, wait_msg.message_id)
            except Exception:
                pass
        kb = make_audit_inline(server_id)
        if photo_buf:
            safe_send_photo(bot, chat_id, photo_buf, caption=report_text, reply_markup=kb)
        else:
            safe_send_message(bot, chat_id, report_text, reply_markup=kb)
    except Exception as e:
        log.exception(f"Ошибка при проведении аудита сервера {server_id}")
        safe_send_message(bot, chat_id, f"❌ **Ошибка при выполнении анализа {srv_flag} {srv_name}:**\n`{e}`")

# --- Команды бота ---

@bot.message_handler(commands=['start', 'menu'])
def handle_start(message):
    if not is_admin(message.chat.id):
        return
    active_sid = get_active_server_id(message.chat.id)
    srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
    now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")
    welcome_text = (
        f"# 🛡️ Центр управления VPS Server Guard\n\n"
        f"> — 📅 {now_msk} MSK\n"
        f"> — Сервер: {srv['flag']} **{srv['name']}**\n"
        f"> — IP: `{srv['ip']}`\n"
        f"> — Версия: `v{config.BOT_VERSION}`\n\n"
        f"Нажмите **«🔍 Полный анализ: {srv['flag']} {srv['name']}»** на клавиатуре для комплексного аудита всех систем."
    )
    safe_send_message(
        bot,
        message.chat.id,
        welcome_text,
        reply_markup=make_reply_keyboard(message.chat.id)
    )

@bot.message_handler(commands=['audit', 'fullcheck'])
def handle_audit_cmd(message):
    if not is_admin(message.chat.id):
        return
    active_sid = get_active_server_id(message.chat.id)
    handle_full_audit(message.chat.id, active_sid)

@bot.message_handler(commands=['status'])
def handle_status_cmd(message):
    if not is_admin(message.chat.id):
        return
    active_sid = get_active_server_id(message.chat.id)
    srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
    msg_text, cpu, ram, swap, disk, sub = format_system_text(active_sid)
    photo_buf = card_generator.generate_status_card(cpu, ram, swap, disk, subtitle=sub, title=f"СТАТУС РЕСУРСОВ VPS ({srv['name'].upper()})")
    safe_send_photo(bot, message.chat.id, photo_buf, caption=msg_text, reply_markup=make_status_inline(active_sid))

@bot.message_handler(commands=['backup'])
def handle_backup_cmd(message):
    if not is_admin(message.chat.id):
        return
    msg, kb = build_backup_message_and_kb()
    safe_send_message(bot, message.chat.id, msg, reply_markup=kb)

@bot.message_handler(commands=['speedtest'])
def handle_speedtest_cmd(message):
    if not is_admin(message.chat.id):
        return
    active_sid = get_active_server_id(message.chat.id)
    srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
    wait_msg = safe_send_message(bot, message.chat.id, f"# ⏳ Запуск теста скорости: {srv['flag']} {srv['name']}\n\n> Замеряю пропускную способность канала VPS (30-45 сек)...")
    bot.send_chat_action(message.chat.id, 'typing')
    res = analyzer.run_speedtest(server_id=active_sid)
    if wait_msg:
        try:
            bot.delete_message(message.chat.id, wait_msg.message_id)
        except Exception:
            pass
    safe_send_message(bot, message.chat.id, res)

@bot.message_handler(commands=['logs'])
def handle_logs_cmd(message):
    if not is_admin(message.chat.id):
        return
    active_sid = get_active_server_id(message.chat.id)
    srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
    if srv.get("is_local", True):
        logs = analyzer.get_critical_logs(lines=15)
    else:
        logs = remote_monitor.get_remote_critical_logs(lines=15, server_id=active_sid)
    safe_logs = html.escape(logs[-3000:], quote=False)
    msg = (
        f"📋 <b>Системные ошибки: {srv['flag']} {srv['name']}</b>\n"
        f"<blockquote>Критические события journalctl за 24 часа:</blockquote>\n\n"
        f"<pre>{safe_logs}</pre>"
    )
    safe_send_message(bot, message.chat.id, msg)

@bot.message_handler(commands=['unban'])
def handle_unban_cmd(message):
    if not is_admin(message.chat.id):
        return
    parts = message.text.split()
    if len(parts) < 2:
        safe_send_message(bot, message.chat.id, "Использование: <code>/unban &lt;IP-адрес&gt;</code>")
        return
    ip = parts[1].strip()
    res = analyzer.unban_ip(ip)
    safe_send_message(bot, message.chat.id, f"Разбан <code>{ip}</code>:\n{res}")

@bot.message_handler(commands=['help'])
def handle_help_cmd(message):
    if not is_admin(message.chat.id):
        return
    help_text = (
        "# 📖 Справка по Server Guard\n\n"
        "## Разделы меню\n"
        "- **🔍 Полный анализ** — комплексный аудит сервера (ресурсы 24ч, службы, HTTP, порты, SSL, ошибки)\n"
        "- **📊 Метрики** — ресурсы CPU/RAM/Disk, Uptime и статусная карточка\n"
        "- **🔗 Ссылки на сервисы** — быстрый переход к веб-приложениям\n"
        "- **🛠 Службы и Сайты** — статус systemd и HTTP, управление процессами\n"
        "- **🔝 Топ процессов** — мониторинг потребителей CPU / ОЗУ / SWAP\n"
        "- **🚀 Тест скорости** — замер скорости канала VPS через Speedtest\n"
        "- **📦 Бэкап сервера** — архивация и отправка резервной копии\n"
        "- **🛡 Защита Fail2Ban** — заблокированные IP за атаки на SSH и разбан\n"
        "- **⚙️ Настройки** — автобэкап, алерты SSH, фильтры\n"
        "- **📋 Ошибки в логах** — журнал критических событий systemd за 24ч\n\n"
        "## Быстрые команды\n"
        "| Команда | Описание |\n"
        "| :--- | :--- |\n"
        "| `/audit` | Полный аудит выбранного сервера |\n"
        "| `/status` | Метрики и карточка VPS |\n"
        "| `/chart` | График нагрузки за 24 часа |\n"
        "| `/backup` | Сделать резервную копию |\n"
        "| `/speedtest` | Тест скорости канала |\n"
        "| `/unban <IP>` | Разблокировать IP-адрес |"
    )
    safe_send_message(bot, message.chat.id, help_text)

@bot.message_handler(commands=['chart'])
def handle_chart_cmd(message):
    if not is_admin(message.chat.id):
        return
    rows = metrics_store.get_samples(24)
    if not rows:
        safe_send_message(bot, message.chat.id, "История метрик пока накапливается. Попробуйте чуть позже.")
        return
    chart_buf = card_generator.generate_history_chart(rows, 24)
    safe_send_photo(bot, message.chat.id, photo=chart_buf, caption="📈 <b>График нагрузки и сетевого трафика VPS за 24 часа</b>")

# --- Обработка текста и состояний ---

@bot.message_handler(func=lambda msg: is_admin(msg.chat.id))
def handle_text(message):
    text = message.text or ""

    menu_buttons = [
        "Полный анализ", "Анализ", "Метрики", "Ссылки на сервисы", "Службы и Сайты", "Топ процессов",
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
            safe_send_message(
                bot,
                message.chat.id,
                f"✅ Время ежедневного бэкапа установлено на **{formatted} (МСК)**.",
                reply_markup=make_settings_main_inline()
            )
            return
        else:
            safe_send_message(bot, message.chat.id, "❌ Введите время в формате `ЧЧ:ММ` (например, `22:00` или `23`):")
            return

    # --- Переключение активного сервера (nl -> fin -> ru -> nl) ---
    if "Сервер:" in text or "⮂" in text:
        cur_sid = get_active_server_id(message.chat.id)
        order = [sid for sid in ("nl", "fin", "ru") if sid in config.SERVERS]
        idx = order.index(cur_sid) if cur_sid in order else 0
        next_sid = order[(idx + 1) % len(order)]
        set_active_server_id(message.chat.id, next_sid)
        srv = config.SERVERS[next_sid]
        now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")
        safe_send_message(
            bot,
            message.chat.id,
            f"# 🔄 Активный сервер переключен: {srv['flag']} {srv['name']}\n\n"
            f"> — 📅 {now_msk} MSK\n"
            f"> — IP: `{srv['ip']}`\n\n"
            f"Все разделы «🔍 Полный анализ», «📊 Метрики», «🛠 Службы», «🔝 Топ процессов» теперь показывают состояние этого сервера.",
            reply_markup=make_reply_keyboard(message.chat.id)
        )
        return

    # --- Кнопки главного меню ---

    active_sid = get_active_server_id(message.chat.id)

    # 1. Полный анализ
    if "Полный анализ" in text or "Анализ" in text:
        handle_full_audit(message.chat.id, active_sid)

    elif "Метрики" in text:
        msg_text, cpu, ram, swap, disk, sub = format_system_text(active_sid)
        srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
        photo_buf = card_generator.generate_status_card(cpu, ram, swap, disk, subtitle=sub, title=f"СТАТУС РЕСУРСОВ VPS ({srv['name'].upper()})")
        safe_send_photo(bot, message.chat.id, photo_buf, caption=msg_text, reply_markup=make_status_inline(active_sid))

    elif "Ссылки на сервисы" in text:
        safe_send_message(bot, message.chat.id, "# 🔗 Ссылки на сервисы VPS\n\n> Выберите необходимый сервис для перехода:", reply_markup=make_links_inline())

    elif "Службы и Сайты" in text:
        body = build_services_text(active_sid)
        kb = make_services_inline(active_sid)
        sent = safe_send_message(bot, message.chat.id, body, reply_markup=kb)
        if sent:
            active_dashboard_msg["chat_id"] = sent.chat.id
            active_dashboard_msg["message_id"] = sent.message_id
            active_dashboard_msg["last_content"] = body
            active_dashboard_msg["server_id"] = active_sid

    elif "Топ процессов" in text:
        bot.send_chat_action(message.chat.id, 'typing')
        text_msg, kb = build_top_procs_text_and_kb(mode="cpu", server_id=active_sid)
        safe_send_message(bot, message.chat.id, text_msg, reply_markup=kb)

    elif "Бэкап сервера" in text:
        msg, kb = build_backup_message_and_kb()
        safe_send_message(bot, message.chat.id, msg, reply_markup=kb)

    elif "Настройки" in text:
        user_states.pop(message.chat.id, None)
        msg = (
            "# ⚙️ Панель настроек мониторинга и бэкапов\n\n"
            "- **Автобэкап:** Включение/выключение и точное время отправки архива по МСК.\n"
            "- **Фильтр автообновлений ОС:** Игнорирует временные 100% всплески процессора от фоновых обновлений Ubuntu (`apt`, `unattended-upgrades`).\n"
            "- **Настройка уведомлений служб:** Позволяет точечно включить или выключить алерты о сбое для каждой службы отдельно."
        )
        safe_send_message(bot, message.chat.id, msg, reply_markup=make_settings_main_inline())

    elif "Тест скорости" in text:
        srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
        srv_name = f"{srv['flag']} {srv['name']}"
        wait_msg = safe_send_message(bot, message.chat.id, f"# ⏳ Запуск теста скорости: {srv_name}\n\n> Замеряю пропускную способность канала VPS (30-45 сек)...")
        bot.send_chat_action(message.chat.id, 'typing')
        res = analyzer.run_speedtest(server_id=active_sid)
        if wait_msg:
            try:
                bot.delete_message(message.chat.id, wait_msg.message_id)
            except Exception:
                pass
        safe_send_message(bot, message.chat.id, res)

    elif "Защита Fail2Ban" in text:
        srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
        if not srv.get("is_local", True):
            banned, total, banned_ips = remote_monitor.get_remote_fail2ban_stats(server_id=active_sid)
        else:
            banned, total, banned_ips = analyzer.get_fail2ban_stats()

        msg = (
            f"# 🛡️ Защита Fail2Ban (SSH): {srv['flag']} {srv['name']}\n\n"
            f"| Параметр | Значение |\n"
            f"| :--- | :--- |\n"
            f"| Активно в бане | `{banned}` IP |\n"
            f"| Всего поймано атак | `{total}` IP |\n\n"
        )
        kb = types.InlineKeyboardMarkup()
        if banned_ips:
            msg += "## ⛔ Заблокированные IP прямо сейчас:\n"
            for ip in banned_ips[:10]:
                msg += f"- `{ip}`\n"
                kb.add(types.InlineKeyboardButton(f"🔓 Разбанить {ip}", callback_data=f"unban:{active_sid}:{ip}"))
        else:
            msg += "> 🟢 **Активных банов в данный момент нет. Сервер в полной безопасности.**"

        safe_send_message(bot, message.chat.id, msg, reply_markup=kb if banned_ips else None)

    elif "Ошибки в логах" in text:
        srv = config.SERVERS.get(active_sid, config.SERVERS["nl"])
        if not srv.get("is_local", True):
            logs = remote_monitor.get_remote_critical_logs(lines=15, server_id=active_sid)
        else:
            logs = analyzer.get_critical_logs(lines=15)
        clean_logs = logs[-3000:]
        msg = (
            f"# 📋 Системные ошибки: {srv['flag']} {srv['name']}\n"
            f"> Критические события journalctl за 24 часа:\n\n"
            f"```\n{clean_logs}\n```"
        )
        safe_send_message(bot, message.chat.id, msg)

# --- Коллбэки ---

@bot.callback_query_handler(func=lambda call: True)
def handle_all_callbacks(call):
    if not is_admin(call.message.chat.id):
        return

    data = call.data

    # Аудит: Обновление отчета
    if data.startswith("audit_refresh:"):
        server_id = data.split(":", 1)[1]
        srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
        bot.answer_callback_query(call.id, f"Обновляю анализ ({srv['name']})...")
        handle_full_audit(call.message.chat.id, server_id)
        return

    # Аудит: График 24ч
    elif data.startswith("chart_24h:"):
        server_id = data.split(":", 1)[1]
        srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
        bot.answer_callback_query(call.id, "Формирую график...")
        if server_id == "nl":
            rows = metrics_store.get_samples(24)
            if not rows:
                safe_send_message(bot, call.message.chat.id, "История метрик пока накапливается. Попробуйте чуть позже.")
                return
            chart_buf = card_generator.generate_history_chart(rows, 24)
            safe_send_photo(bot, call.message.chat.id, chart_buf, caption=f"📈 <b>График нагрузки и трафика VPS за 24 часа ({srv['flag']} {srv['name']})</b>")
        else:
            m = remote_monitor.get_remote_system_metrics(server_id=server_id)
            if m:
                card_buf = card_generator.generate_status_card(
                    m["cpu"], m["ram_pct"], m["swap_pct"], m["disk_pct"],
                    subtitle=f"Audit: {srv['name']} ({srv['ip']})",
                    title=f"РЕСУРСЫ VPS ({srv['name'].upper()})"
                )
                safe_send_photo(bot, call.message.chat.id, card_buf, caption=f"📊 <b>Карточка ресурсов {srv['flag']} {srv['name']}</b>")
            else:
                safe_send_message(bot, call.message.chat.id, f"❌ Не удалось подключиться к серверу {srv['flag']} {srv['name']}.")
        return

    # Аудит: переход к службам
    elif data.startswith("audit_services:"):
        server_id = data.split(":", 1)[1]
        bot.answer_callback_query(call.id, "Службы сервера...")
        body = build_services_text(server_id)
        kb = make_services_inline(server_id)
        safe_send_message(bot, call.message.chat.id, body, reply_markup=kb)
        return

    # Аудит: переход к логам
    elif data.startswith("audit_logs:"):
        server_id = data.split(":", 1)[1]
        srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
        bot.answer_callback_query(call.id, "Загружаю журнал логов...")
        if not srv.get("is_local", True):
            logs = remote_monitor.get_remote_critical_logs(lines=15, server_id=server_id)
        else:
            logs = analyzer.get_critical_logs(lines=15)
        safe_logs = html.escape(logs[-3000:], quote=False)
        msg = f"📋 <b>Системные ошибки: {srv['flag']} {srv['name']}</b>\n<blockquote>Журнал критических событий за 24 часа:</blockquote>\n\n<pre>{safe_logs}</pre>"
        safe_send_message(bot, call.message.chat.id, msg)
        return

    # Службы
    elif data.startswith("srv:"):
        parts = data.split(":")
        if len(parts) == 4:
            _, server_id, action, unit = parts
        else:
            _, action, unit = parts
            server_id = "nl"

        srv_conf = config.SERVERS.get(server_id, config.SERVERS["nl"])
        bot.answer_callback_query(call.id, f"Выполняю {action} для {unit} ({srv_conf['name']})...")

        if srv_conf.get("is_local", True):
            subprocess.run(["systemctl", action, unit])
            if action in ["start", "restart"]:
                for _ in range(3):
                    time.sleep(1)
                    body = build_services_text(server_id)
                    if "🔴 down" not in body or action == "stop":
                        break
            else:
                time.sleep(1)
                body = build_services_text(server_id)
        else:
            remote_monitor.control_remote_systemd(action, unit, server_id=server_id)
            time.sleep(1.5)
            body = build_services_text(server_id)

        active_dashboard_msg["chat_id"] = call.message.chat.id
        active_dashboard_msg["message_id"] = call.message.message_id
        active_dashboard_msg["last_content"] = body
        active_dashboard_msg["server_id"] = server_id
        try:
            safe_edit_message(
                bot,
                call.message.chat.id,
                call.message.message_id,
                body,
                reply_markup=make_services_inline(server_id)
            )
        except Exception:
            pass

    elif data.startswith("refresh_services"):
        parts = data.split(":")
        server_id = parts[1] if len(parts) > 1 else "nl"
        bot.answer_callback_query(call.id, "Обновляю статусы...")
        body = build_services_text(server_id)
        active_dashboard_msg["chat_id"] = call.message.chat.id
        active_dashboard_msg["message_id"] = call.message.message_id
        active_dashboard_msg["last_content"] = body
        active_dashboard_msg["server_id"] = server_id
        try:
            safe_edit_message(
                bot,
                call.message.chat.id,
                call.message.message_id,
                body,
                reply_markup=make_services_inline(server_id)
            )
        except Exception:
            pass

    # Выбор режима Топ процессов
    elif data.startswith("procs:"):
        parts = data.split(":")
        if len(parts) == 3:
            _, server_id, mode = parts
        else:
            _, mode = parts
            server_id = "nl"

        mode_title = "CPU" if mode == "cpu" else "ОЗУ (RAM)" if mode == "ram" else "SWAP"
        bot.answer_callback_query(call.id, f"Сортировка: {mode_title}")
        text_msg, kb = build_top_procs_text_and_kb(mode=mode, server_id=server_id)
        try:
            safe_edit_message(
                bot,
                call.message.chat.id,
                call.message.message_id,
                text_msg,
                reply_markup=kb
            )
        except Exception:
            pass

    # Обновление Топ процессов
    elif data.startswith("procs_refresh:"):
        parts = data.split(":")
        if len(parts) == 3:
            _, server_id, mode = parts
        else:
            _, mode = parts
            server_id = "nl"

        bot.answer_callback_query(call.id, "Обновляю процессы...")
        text_msg, kb = build_top_procs_text_and_kb(mode=mode, server_id=server_id)
        try:
            safe_edit_message(
                bot,
                call.message.chat.id,
                call.message.message_id,
                text_msg,
                reply_markup=kb
            )
        except Exception:
            pass

    # Убийство процессов
    elif data.startswith("kill:"):
        _, pid, name = data.split(":", 2)
        if is_protected_proc(pid, name):
            bot.answer_callback_query(call.id, f"❌ Процесс {name} (PID {pid}) защищен от завершения из бота!", show_alert=True)
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
        parts = data.split(":")
        if len(parts) == 3:
            _, server_id, ip = parts
        else:
            _, ip = parts
            server_id = "nl"

        if server_id != "nl":
            res = remote_monitor.unban_remote_ip(ip, server_id=server_id)
        else:
            res = analyzer.unban_ip(ip)

        bot.answer_callback_query(call.id, "Команда отправлена")
        bot.send_message(call.message.chat.id, f"Разбан `{ip}` ({server_id.upper()}):\n{res}", parse_mode="Markdown")

    # SSL
    elif data == "renew_ssl":
        bot.answer_callback_query(call.id, "Обновляю сертификат...")
        status_msg = safe_send_message(bot, call.message.chat.id, "⏳ Обновляю сертификат Let's Encrypt...")
        res = analyzer.renew_ssl()
        if status_msg:
            safe_edit_message(bot, call.message.chat.id, status_msg.message_id, res)
        else:
            safe_send_message(bot, call.message.chat.id, res)

    # Обновление метрик в существующем сообщении с карточкой
    elif data.startswith("refresh_metrics"):
        parts = data.split(":")
        server_id = parts[1] if len(parts) > 1 else "nl"
        bot.answer_callback_query(call.id, "Обновляю метрики...")
        try:
            srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
            msg_text, cpu, ram, swap, disk, sub = format_system_text(server_id)
            photo_buf = card_generator.generate_status_card(cpu, ram, swap, disk, subtitle=sub, title=f"СТАТУС РЕСУРСОВ VPS ({srv['name'].upper()})")
            if getattr(call.message, 'content_type', None) == 'photo':
                media = types.InputMediaPhoto(photo_buf, caption='📊 <b>Инфографика ресурсов и стабильности VPS</b>', parse_mode='HTML')
                bot.edit_message_media(
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    media=media,
                    reply_markup=make_status_inline(server_id)
                )
            else:
                safe_edit_message(
                    bot,
                    call.message.chat.id,
                    call.message.message_id,
                    msg_text,
                    reply_markup=make_status_inline(server_id)
                )
        except Exception as e:
            log.warning(f"Ошибка при обновлении метрик: {e}")

    # Выгрузка SWAP
    elif data == "flush_swap":
        bot.answer_callback_query(call.id, "Запускаю выгрузку SWAP...")
        wait_msg = safe_send_message(bot, call.message.chat.id, "⏳ Выполняю безопасную выгрузку SWAP в ОЗУ (`swapoff -a && swapon -a`)...")
        res_text = analyzer.flush_swap()
        if wait_msg:
            safe_edit_message(bot, call.message.chat.id, wait_msg.message_id, res_text)
        else:
            safe_send_message(bot, call.message.chat.id, res_text)

    # График из метрик
    elif data == "show_chart_24":
        bot.answer_callback_query(call.id)
        rows = metrics_store.get_samples(24)
        if not rows:
            bot.send_message(call.message.chat.id, "История метрик пока накапливается. Попробуйте чуть позже.")
            return
        chart_buf = card_generator.generate_history_chart(rows, 24)
        safe_send_photo(bot, call.message.chat.id, photo=chart_buf, caption="📈 <b>График нагрузки и сетевого трафика VPS за 24 часа</b>")

    # Ручной бэкап
    elif data.startswith("backup:") or data == "run_manual_backup":
        if data == "backup:nl":
            bot.answer_callback_query(call.id, "Архивирую Нидерланды...")
            bot.send_message(call.message.chat.id, "⏳ Создаю и отправляю резервную копию 🇳🇱 Нидерландов...")
            success, msg = backup_manager.send_backup(bot, call.message.chat.id, target="nl")
        elif data == "backup:fin":
            bot.answer_callback_query(call.id, "Архивирую Финляндию...")
            bot.send_message(call.message.chat.id, "⏳ Создаю и отправляю резервную копию 🇫🇮 Финляндии...")
            success, msg = backup_manager.send_backup(bot, call.message.chat.id, target="fin")
        elif data == "backup:ru":
            bot.answer_callback_query(call.id, "Архивирую Россию...")
            bot.send_message(call.message.chat.id, "⏳ Создаю и отправляю резервную копию 🇷🇺 России...")
            success, msg = backup_manager.send_backup(bot, call.message.chat.id, target="ru")
        else:
            bot.answer_callback_query(call.id, "Архивирую все 3 сервера...")
            bot.send_message(call.message.chat.id, "⏳ Создаю и отправляю резервные копии всех серверов (🇳🇱 + 🇫🇮 + 🇷🇺)...")
            success, msg = backup_manager.send_backup(bot, call.message.chat.id, target="all")

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
        safe_edit_message(
            bot,
            call.message.chat.id,
            call.message.message_id,
            "# 🔔 Послужебная настройка алертов при сбоях\nНажмите на службу, чтобы включить или отключить отправку алертов при ее падении:",
            reply_markup=make_service_alerts_inline()
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
        settings_text = (
            "# ⚙️ Панель настроек мониторинга и бэкапов\n\n"
            "- **Автобэкап:** Включение/выключение и точное время отправки архива по МСК.\n"
            "- **Фильтр автообновлений ОС:** Игнорирует временные 100% всплески процессора от фоновых обновлений Ubuntu (`apt`, `unattended-upgrades`).\n"
            "- **Настройка уведомлений служб:** Позволяет точечно включить или выключить алерты о сбое для каждой службы отдельно."
        )
        safe_edit_message(
            bot,
            call.message.chat.id,
            call.message.message_id,
            settings_text,
            reply_markup=make_settings_main_inline()
        )

# --- Фоновый цикл ---

def monitoring_loop():
    global last_alert_time, last_ssl_check_day, last_backup_date_str
    high_cpu_counter = 0
    alerted_failed_services = set()
    failed_service_counts = {}
    service_alert_messages = []
    last_remote_statuses = {}
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

            # 1. Проверка служб Нидерландов
            nl_units = [srv["unit"] for srv in config.SERVERS["nl"]["monitored_services"]]
            nl_statuses = get_local_systemd_statuses(nl_units)
            for srv in config.SERVERS["nl"]["monitored_services"]:
                unit = srv["unit"]
                should_alert = alerts_map.get(unit, True)
                status = nl_statuses.get(unit, "⚪ unknown")

                if "🔴" in status:
                    failed_service_counts[("nl", unit)] = failed_service_counts.get(("nl", unit), 0) + 1
                    if failed_service_counts[("nl", unit)] >= 2:
                        if ("nl", unit) not in alerted_failed_services:
                            if should_alert:
                                newly_failed.append({"server": "🇳🇱 Нидерланды", "name": srv["name"], "unit": unit, "sid": "nl"})
                            alerted_failed_services.add(("nl", unit))
                elif "🟢" in status:
                    failed_service_counts[("nl", unit)] = 0
                    alerted_failed_services.discard(("nl", unit))

            # 2. Проверка удаленных серверов (Финляндия и Россия, раз в ~12-15 сек)
            if bg_refresh_ticks % 4 == 0:
                for r_sid in [k for k, v in config.SERVERS.items() if not v.get("is_local", True)]:
                    r_conf = config.SERVERS[r_sid]
                    r_units = [srv["unit"] for srv in r_conf.get("monitored_services", [])]
                    r_statuses = remote_monitor.get_remote_systemd_statuses(r_units, server_id=r_sid)
                    last_remote_statuses[r_sid] = r_statuses
                    r_label = f"{r_conf['flag']} {r_conf['name']}"
                    for srv in r_conf.get("monitored_services", []):
                        unit = srv["unit"]
                        should_alert = alerts_map.get(unit, True)
                        status = r_statuses.get(unit, "⚪ unknown")
                        if "🔴" in status:
                            failed_service_counts[(r_sid, unit)] = failed_service_counts.get((r_sid, unit), 0) + 1
                            if failed_service_counts[(r_sid, unit)] >= 2:
                                if (r_sid, unit) not in alerted_failed_services:
                                    if should_alert:
                                        newly_failed.append({"server": r_label, "name": srv["name"], "unit": unit, "sid": r_sid})
                                    alerted_failed_services.add((r_sid, unit))
                        elif "🟢" in status:
                            failed_service_counts[(r_sid, unit)] = 0
                            alerted_failed_services.discard((r_sid, unit))

            # Проверка восстановления упавших служб и удаление неактуальных алертов
            if service_alert_messages:
                remaining_alerts = []
                for alert in service_alert_messages:
                    all_recovered = True
                    for sid, unit in alert["units"]:
                        st = nl_statuses.get(unit, "") if sid == "nl" else last_remote_statuses.get(sid, {}).get(unit, "")
                        if "🟢" not in st:
                            all_recovered = False
                            break

                    if all_recovered:
                        for chat_id, msg_id in alert["messages"]:
                            if msg_id == active_dashboard_msg.get("message_id"):
                                continue
                            try:
                                bot.delete_message(chat_id=chat_id, message_id=msg_id)
                                log.info(f"Службы {alert['units']} восстановились. Удалено неактуальное сообщение об алерте (chat_id={chat_id}, msg_id={msg_id})")
                            except Exception as del_err:
                                log.debug(f"Не удалось удалить сообщение алертов {msg_id}: {del_err}")
                    else:
                        if now_ts - alert.get("created_at", now_ts) < 86400:
                            remaining_alerts.append(alert)
                service_alert_messages = remaining_alerts

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
                    cur_srv = active_dashboard_msg.get("server_id", "nl")
                    new_body = build_services_text(cur_srv)
                    if new_body != active_dashboard_msg["last_content"]:
                        active_dashboard_msg["last_content"] = new_body
                        safe_edit_message(
                            bot,
                            active_dashboard_msg["chat_id"],
                            active_dashboard_msg["message_id"],
                            new_body,
                            reply_markup=make_services_inline(cur_srv)
                        )
                except Exception:
                    pass

            curr_time = time.time()
            if newly_failed:
                # 1. Специализированный алерт о сбое системной службы
                markup = types.InlineKeyboardMarkup()
                if len(newly_failed) == 1:
                    s = newly_failed[0]
                    sid = s.get("sid", "nl")
                    srv_name = s.get("server", "🇳🇱 Нидерланды")
                    reason = diagnose_service_failure(sid, s["unit"], s["name"])

                    msg = (
                        f"🚨 **СБОЙ СИСТЕМНОЙ СЛУЖБЫ**\n\n"
                        f"• **Служба:** {s['name']} (`{s['unit']}`)\n"
                        f"• **Сервер:** {srv_name}\n\n"
                        f"💡 **Вероятная причина:**\n{reason}"
                    )
                    btn_start = types.InlineKeyboardButton(f"▶️ Запустить {s['name']}", callback_data=f"srv:{sid}:start:{s['unit']}")
                    btn_restart = types.InlineKeyboardButton(f"🔄 Рестарт {s['name']}", callback_data=f"srv:{sid}:restart:{s['unit']}")
                    markup.row(btn_start, btn_restart)
                else:
                    msg = f"🚨 **СБОЙ СИСТЕМНЫХ СЛУЖБ**\n\n"
                    blocks = []
                    for idx, s in enumerate(newly_failed, 1):
                        sid = s.get("sid", "nl")
                        srv_name = s.get("server", "🇳🇱 Нидерланды")
                        reason = diagnose_service_failure(sid, s["unit"], s["name"])
                        blocks.append(
                            f"{idx}️⃣ **{s['name']}** (`{s['unit']}`)\n"
                            f"• **Сервер:** {srv_name}\n"
                            f"• **Причина:** {reason}"
                        )
                        btn_start = types.InlineKeyboardButton(f"▶️ Запустить {s['name']}", callback_data=f"srv:{sid}:start:{s['unit']}")
                        btn_restart = types.InlineKeyboardButton(f"🔄 Рестарт {s['name']}", callback_data=f"srv:{sid}:restart:{s['unit']}")
                        markup.row(btn_start, btn_restart)
                    msg += "\n\n".join(blocks)

                sent_msgs = notify_admins(msg, reply_markup=markup if markup.keyboard else None)
                if sent_msgs:
                    failed_keys = {(s["sid"], s["unit"]) for s in newly_failed}
                    msg_targets = [(m.chat.id, m.message_id) for m in sent_msgs if getattr(m, "message_id", None)]
                    if msg_targets:
                        service_alert_messages.append({
                            "units": failed_keys,
                            "messages": msg_targets,
                            "created_at": curr_time
                        })

            elif trigger_alert and (curr_time - last_alert_time > config.ALERT_COOLDOWN):
                # 2. Алерт о высокой системной нагрузке (если службы не падали)
                last_alert_time = curr_time
                procs_data = get_top_cpu_data(limit=4)
                system_summary = analyzer.get_system_summary()

                msg = (
                    f"⚠️ **ВНИМАНИЕ: Высокая нагрузка VPS!**\n\n"
                    f"🚨 **Причина:**\n• " + "\n• ".join(alert_reasons) + "\n\n"
                )

                if procs_data:
                    top_lines = []
                    for item in procs_data:
                        name, pid, cpu, *_, desc = item
                        top_lines.append(f"• `{name}` (PID {pid}): **{cpu:.1f}%**\n  └ *{desc}*")
                    msg += f"📈 **Топ процессов по нагрузке:**\n" + "\n".join(top_lines) + "\n\n"

                msg += f"📊 **Сводка системы:**\n{system_summary}"
                notify_admins(msg)

        except Exception as e:
            log.exception("Ошибка в фоновом цикле мониторинга")

        time.sleep(3)

def setup_bot_commands():
    commands = [
        types.BotCommand("start", "Главное меню и клавиатура"),
        types.BotCommand("audit", "Глубокий полный анализ сервера"),
        types.BotCommand("status", "Метрики и карточка ресурсов"),
        types.BotCommand("chart", "График истории нагрузки за 24ч"),
        types.BotCommand("backup", "Сделать бэкап сервера"),
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