"""Инструменты безопасности: SSH-входы, ручной бан IP, определение страны по IP."""
import ipaddress
import re
import subprocess

import requests

_geo_cache = {}

_ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port \d+")


def is_valid_ip(value):
    """True, если строка — корректный IPv4/IPv6-адрес."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def parse_ssh_accepted(line):
    """Разбирает строку журнала sshd. Возвращает (метод, пользователь, ip) или None."""
    m = _ACCEPTED_RE.search(line or "")
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


_seen_ssh_logins = set()


def get_ssh_logins_since(since_ts):
    """Успешные SSH-входы после unix-времени since_ts: список (метод, пользователь, ip)."""
    try:
        # Берём логи с небольшим сдвигом вперед + 1 сек
        res = subprocess.run(
            ["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"@{int(since_ts) + 1}",
             "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return []
    logins = []
    for line in res.stdout.splitlines():
        parsed = parse_ssh_accepted(line)
        if parsed:
            key = (line.strip(), parsed)
            if key not in _seen_ssh_logins:
                _seen_ssh_logins.add(key)
                if len(_seen_ssh_logins) > 200:
                    _seen_ssh_logins.clear()
                logins.append(parsed)
    return logins


def geoip(ip):
    """Строка вида 'Германия, Франкфурт (Hetzner)' либо пустая строка, если определить не удалось."""
    ip = (ip or "").strip()
    if ip in _geo_cache:
        return _geo_cache[ip]
    if not is_valid_ip(ip):
        return ""
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback:
        _geo_cache[ip] = "локальная сеть"
        return _geo_cache[ip]
    result = ""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,isp", "lang": "ru"},
            timeout=3,
        )
        data = r.json()
        if data.get("status") == "success":
            parts = [p for p in (data.get("country"), data.get("city")) if p]
            result = ", ".join(parts)
            if data.get("isp"):
                result += f" ({data['isp']})"
    except Exception:
        return ""
    _geo_cache[ip] = result
    return result


def ban_ip(ip):
    """Ручной бан IP в jail sshd. Возвращает текст результата."""
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return "❌ Некорректный IP-адрес"
    try:
        res = subprocess.run(
            ["fail2ban-client", "set", "sshd", "banip", ip],
            capture_output=True, text=True, timeout=5,
        )
        out = res.stdout.strip()
        return "✅ IP заблокирован" if out in ("1", "") and res.returncode == 0 else f"Ответ Fail2Ban: {out or res.stderr.strip()}"
    except Exception as e:
        return f"Ошибка при бане: {e}"
