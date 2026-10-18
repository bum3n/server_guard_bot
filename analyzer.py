import subprocess
import shutil
import datetime
import os
import time

try:
    import config
except ImportError:
    config = None

def get_fail2ban_stats():
    """Сбор статистики активных банов Fail2Ban."""
    try:
        res = subprocess.run(["fail2ban-client", "status", "sshd"], capture_output=True, text=True, timeout=3)
        banned = 0
        total = 0
        banned_ips = []
        for line in res.stdout.splitlines():
            if "Currently banned:" in line:
                banned = line.split(":")[-1].strip()
            if "Total banned:" in line:
                total = line.split(":")[-1].strip()
            if "Banned IP list:" in line:
                raw_ips = line.split(":")[-1].strip()
                banned_ips = raw_ips.split() if raw_ips else []
        return banned, total, banned_ips
    except Exception:
        return "0", "0", []

def unban_ip(ip):
    """Разбан конкретного IP-адреса."""
    try:
        res = subprocess.run(["fail2ban-client", "set", "sshd", "unbanip", ip], capture_output=True, text=True, timeout=3)
        return "✅ IP успешно разблокирован" if "1" in res.stdout else f"Ответ Fail2Ban: {res.stdout.strip()}"
    except Exception as e:
        return f"Ошибка при разбане: {e}"

def check_ssl_expiry(cert_path=None):
    """Проверка оставшихся дней действия сертификата Let's Encrypt."""
    if not cert_path:
        domain = getattr(config, "DOMAIN", "example.com") if config else "example.com"
        candidate = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        if os.path.exists(candidate):
            cert_path = candidate
        elif os.path.exists("/root/cert/ip/fullchain.pem"):
            cert_path = "/root/cert/ip/fullchain.pem"
        else:
            cert_path = candidate

    if not os.path.exists(cert_path):
        return None, "Файл сертификата не найден"
    try:
        cmd = f"openssl x509 -enddate -noout -in {cert_path}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        raw_date = res.stdout.strip().replace("notAfter=", "")
        expire_date = datetime.datetime.strptime(raw_date, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
        return days_left, expire_date.strftime("%d.%m.%Y")
    except Exception as e:
        return None, f"Ошибка парсинга даты: {e}"

def renew_ssl():
    """Безопасный перевыпуск сертификата с гарантированным подъемом Nginx и x-ui."""
    output_log = ""
    success = False
    try:
        # 1. Останавливаем Nginx для освобождения 80 порта
        subprocess.run(["systemctl", "stop", "nginx"], check=False)
        time.sleep(1)

        # 2. Перевыпуск через acme.sh
        cmd_renew = "/root/.acme.sh/acme.sh --renew -d example.com --force"
        res_renew = subprocess.run(cmd_renew, shell=True, capture_output=True, text=True, timeout=90)
        output_log += res_renew.stdout + "\n" + res_renew.stderr

        # 3. Копирование сертификатов
        cmd_install = (
            "/root/.acme.sh/acme.sh --install-cert -d example.com "
            "--key-file /root/cert/ip/privkey.pem "
            "--fullchain-file /root/cert/ip/fullchain.pem"
        )
        res_inst = subprocess.run(cmd_install, shell=True, capture_output=True, text=True, timeout=30)
        output_log += res_inst.stdout

        days, exp = check_ssl_expiry()
        if days and days > 4:
            success = True
            msg = f"✅ **SSL-сертификат успешно обновлен!**\nНовый срок действия: до `{exp}` (`{days}` дн.)"
        else:
            msg = f"⚠️️ **Не удалось подтвердить продление сертификата.**\nЛог acme.sh:\n```text\n{output_log[-1200:]}\n```"

    except subprocess.TimeoutExpired:
        msg = "⏱ **Таймаут выполнения acme.sh (>90 сек).** Службы восстанавливаются."
    except Exception as e:
        msg = f"❌ **Ошибка при обновлении сертификата:** {e}"
    finally:
        # Гарантированно поднимаем и перезапускаем все веб- и прокси-службы
        subprocess.run(["systemctl", "restart", "x-ui"], check=False)
        subprocess.run(["systemctl", "start", "nginx"], check=False)
        time.sleep(1.5)
        # Контрольный статус
        ng_st = subprocess.run(["systemctl", "is-active", "nginx"], capture_output=True, text=True).stdout.strip()
        xui_st = subprocess.run(["systemctl", "is-active", "x-ui"], capture_output=True, text=True).stdout.strip()
        msg += f"\n\n🛠 **Статус служб после операции:**\n• Nginx: `{ng_st}`\n• 3X-UI: `{xui_st}`"

    return msg

def run_speedtest():
    """Замер скорости канала VPS."""
    try:
        tool = "speedtest-cli" if shutil.which("speedtest-cli") else None
        if not tool:
            return "❌ Утилита speedtest-cli не найдена. Установите: apt install speedtest-cli"
        
        cmd = ["speedtest-cli", "--simple"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return res.stdout.strip() if res.stdout else "Не удалось получить данные замера."
    except subprocess.TimeoutExpired:
        return "⏱ Время ожидания теста скорости истекло (>60 сек)."
    except Exception as e:
        return f"Ошибка при тесте скорости: {e}"

def get_critical_logs(lines=12):
    """Выборка реальных системных инцидентов за последние 24 часа без сетевого мусора."""
    try:
        cmd = (
            "journalctl -p err..emerg --since '24 hours ago' --no-pager "
            "| grep -vE 'TLS handshake error|unsupported SSLv2|Connection reset by peer|kex_exchange_identification' "
            f"| tail -n {lines}"
        )
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = res.stdout.strip()
        return out if out else "За последние 24 часа критических ошибок сервисов не зафиксировано."
    except Exception as e:
        return f"Ошибка чтения логов: {e}"

def get_system_summary():
    try:
        with open("/proc/loadavg", "r") as f:
            load_avg = " ".join(f.read().split()[:3])
    except Exception:
        load_avg = "н/д"
    
    banned, total, _ = get_fail2ban_stats()
    return f"• **Load Average (1/5/15 мин):** `{load_avg}`\n• **Защита SSH:** Активно: `{banned}` (Всего: `{total}`)"

def flush_swap():
    """Безопасная выгрузка SWAP в ОЗУ (swapoff -a && swapon -a)."""
    import psutil
    ram = psutil.virtual_memory()
    swap = psutil.swap_memory()

    if swap.used == 0:
        return "ℹ️ **SWAP в данный момент пуст, выгрузка не требуется.**"

    if swap.used > ram.available:
        swap_mb = swap.used // (1024 * 1024)
        ram_mb = ram.available // (1024 * 1024)
        return (
            f"⚠️ **Недостаточно свободной ОЗУ для безопасной выгрузки SWAP!**\n\n"
            f"• Занято в SWAP: `{swap_mb} MB`\n"
            f"• Доступно в ОЗУ: `{ram_mb} MB`\n\n"
            f"Операция отменена во избежание сбоя системы (OOM Killer)."
        )

    try:
        res = subprocess.run("swapoff -a && swapon -a", shell=True, capture_output=True, text=True, timeout=90)
        if res.returncode == 0:
            ram_after = psutil.virtual_memory()
            swap_after = psutil.swap_memory()
            return (
                f"✅ **SWAP успешно выгружен в ОЗУ!**\n\n"
                f"• Использовано SWAP до: `{swap.used // (1024 * 1024)} MB` ➔ после: `{swap_after.used // (1024 * 1024)} MB`\n"
                f"• Загрузка ОЗУ: `{ram_after.percent}%` ({ram_after.used // (1024 * 1024)}MB / {ram_after.total // (1024 * 1024)}MB)"
            )
        else:
            return f"❌ **Ошибка выгрузки SWAP:**\n```text\n{res.stderr.strip()}\n```"
    except subprocess.TimeoutExpired:
        return "⏱ **Время ожидания выгрузки SWAP истекло (>90 сек).**"
    except Exception as e:
        return f"❌ **Ошибка при выгрузке SWAP:** {e}"

