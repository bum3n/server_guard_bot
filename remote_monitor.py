import json
import logging
import socket
import subprocess

log = logging.getLogger(__name__)

REMOTE_HOSTS = {
    "fin": "root@201.58.188.206",
    "ru": "root@62.173.152.111",
}
REMOTE_HOST = REMOTE_HOSTS["fin"]

SSH_OPTS = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=6",
    "-o", "StrictHostKeyChecking=accept-new",
]


def _get_host(server_id="fin"):
    return REMOTE_HOSTS.get(server_id, REMOTE_HOST)


def run_remote_ssh(cmd, timeout=12, server_id="fin"):
    host = _get_host(server_id)
    try:
        full_cmd = SSH_OPTS + [host, cmd]
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        return res.returncode == 0, res.stdout, res.stderr
    except Exception as e:
        log.warning(f"Ошибка выполнения команды на {host}: {e}")
        return False, "", str(e)


def get_remote_system_metrics(server_id="fin"):
    """Возвращает метрики CPU, RAM, SWAP, Disk и Uptime для удаленного сервера (с /proc fallback)."""
    py_script = (
        "import json, os, time\n"
        "uptime = 0.0\n"
        "try:\n"
        "    with open('/proc/uptime') as f: uptime = float(f.readline().split()[0])\n"
        "except Exception: pass\n"
        "try:\n"
        "    import psutil\n"
        "    cpu = psutil.cpu_percent(0.25)\n"
        "    ram = psutil.virtual_memory()\n"
        "    swap = psutil.swap_memory()\n"
        "    disk = psutil.disk_usage('/')\n"
        "    data = {\n"
        "        'cpu': cpu, 'ram_pct': ram.percent,\n"
        "        'ram_used': ram.used // (1024*1024), 'ram_total': ram.total // (1024*1024),\n"
        "        'swap_pct': swap.percent,\n"
        "        'swap_used': swap.used // (1024*1024), 'swap_total': swap.total // (1024*1024),\n"
        "        'disk_pct': disk.percent,\n"
        "        'disk_free': disk.free // (1024*1024*1024), 'disk_total': disk.total // (1024*1024*1024),\n"
        "        'uptime': uptime\n"
        "    }\n"
        "except ImportError:\n"
        "    def _cpu_stat():\n"
        "        with open('/proc/stat') as f:\n"
        "            vals = [int(x) for x in f.readline().split()[1:]]\n"
        "        return sum(vals), vals[3] + (vals[4] if len(vals) > 4 else 0)\n"
        "    t1, i1 = _cpu_stat(); time.sleep(0.25); t2, i2 = _cpu_stat()\n"
        "    dt = max(1, t2 - t1); cpu = round((1.0 - (i2 - i1) / dt) * 100.0, 1)\n"
        "    mi = {}\n"
        "    with open('/proc/meminfo') as f:\n"
        "        for ln in f:\n"
        "            k, v = ln.split(':', 1)\n"
        "            mi[k] = int(v.strip().split()[0]) * 1024\n"
        "    ram_t = mi.get('MemTotal', 1); ram_a = mi.get('MemAvailable', mi.get('MemFree', 0))\n"
        "    ram_u = max(0, ram_t - ram_a)\n"
        "    sw_t = mi.get('SwapTotal', 0); sw_f = mi.get('SwapFree', 0); sw_u = max(0, sw_t - sw_f)\n"
        "    st = os.statvfs('/')\n"
        "    d_t = st.f_blocks * st.f_frsize; d_f = st.f_bavail * st.f_frsize; d_u = max(0, d_t - st.f_bfree * st.f_frsize)\n"
        "    data = {\n"
        "        'cpu': cpu, 'ram_pct': round(ram_u * 100.0 / max(1, ram_t), 1),\n"
        "        'ram_used': ram_u // (1024*1024), 'ram_total': ram_t // (1024*1024),\n"
        "        'swap_pct': round(sw_u * 100.0 / sw_t, 1) if sw_t else 0.0,\n"
        "        'swap_used': sw_u // (1024*1024), 'swap_total': sw_t // (1024*1024),\n"
        "        'disk_pct': round(d_u * 100.0 / max(1, d_t), 1),\n"
        "        'disk_free': d_f // (1024*1024*1024), 'disk_total': d_t // (1024*1024*1024),\n"
        "        'uptime': uptime\n"
        "    }\n"
        "print(json.dumps(data))\n"
    )
    ok, out, _ = run_remote_ssh(f"python3 - << 'EOP'\n{py_script}\nEOP", timeout=10, server_id=server_id)
    if not ok or not out.strip():
        return None
    try:
        return json.loads(out.strip())
    except Exception:
        return None


def get_remote_systemd_statuses(unit_names, server_id="fin"):
    """Возвращает словарь {unit_name: '🟢 active' | '🔴 ...'} за один SSH-запрос."""
    if not unit_names:
        return {}
    host = _get_host(server_id)
    units_arg = " ".join(unit_names)
    cmd = f"systemctl is-active {units_arg}"
    try:
        full_cmd = SSH_OPTS + [host, cmd]
        res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=10)
        lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
        result = {}
        for i, u in enumerate(unit_names):
            if i < len(lines):
                st = lines[i]
                result[u] = "🟢 active" if st == "active" else f"🔴 {st}"
            else:
                result[u] = "⚪ unknown"
        return result
    except Exception as e:
        log.warning(f"Ошибка проверки статусов служб на {host}: {e}")
        return {u: "⚪ unknown" for u in unit_names}


def get_remote_systemd_status(unit_name, server_id="fin"):
    res = get_remote_systemd_statuses([unit_name], server_id=server_id)
    return res.get(unit_name, "⚪ unknown")


def control_remote_systemd(action, unit_name, server_id="fin"):
    """start, stop, restart"""
    if action not in ("start", "stop", "restart"):
        return False, "Неверное действие"
    cmd = f"systemctl {action} {unit_name}"
    ok, out, err = run_remote_ssh(cmd, timeout=12, server_id=server_id)
    return ok, out if ok else err


def get_remote_top_procs(mode="cpu", limit=6, server_id="fin"):
    """Возвращает топ процессов с удаленного сервера (psutil или чистый /proc fallback)."""
    py_script = (
        "import json, os, time\n"
        "total_ram = 2048 * 1024 * 1024\n"
        "try:\n"
        "    with open('/proc/meminfo') as f:\n"
        "        for ln in f:\n"
        "            if ln.startswith('MemTotal:'):\n"
        "                total_ram = int(ln.split()[1]) * 1024; break\n"
        "except Exception: pass\n"
        "res = []\n"
        "try:\n"
        "    import psutil\n"
        "    procs = []\n"
        "    for p in psutil.process_iter(['pid', 'name', 'cpu_times', 'memory_info']):\n"
        "        try: p.cpu_percent(None); procs.append(p)\n"
        "        except Exception: pass\n"
        "    time.sleep(0.3)\n"
        "    for p in procs:\n"
        "        try:\n"
        "            cpu = p.cpu_percent(None)\n"
        "            mem = p.info.get('memory_info'); rss = mem.rss if mem else 0\n"
        "            t = p.info.get('cpu_times'); total_t = (t.user + t.system) if t else 0\n"
        "            cmd = []\n"
        "            try: cmd = p.cmdline()\n"
        "            except Exception: pass\n"
        "            sw = 0\n"
        "            try:\n"
        "                with open('/proc/' + str(p.info['pid']) + '/status') as sf:\n"
        "                    for sl in sf:\n"
        "                        if sl.startswith('VmSwap:'): sw = int(sl.split()[1]) * 1024; break\n"
        "            except Exception: pass\n"
        "            res.append({'pid': p.info['pid'], 'name': p.info['name'], 'cpu': cpu, 'total_time': total_t, 'rss': rss, 'swap': sw, 'cmd': cmd[:3]})\n"
        "        except Exception: pass\n"
        "except ImportError:\n"
        "    clk = os.sysconf(os.sysconf_names['SC_CLK_TCK'])\n"
        "    page = os.sysconf('SC_PAGE_SIZE')\n"
        "    def _snap():\n"
        "        d = {}\n"
        "        for pid in os.listdir('/proc'):\n"
        "            if not pid.isdigit(): continue\n"
        "            try:\n"
        "                with open(f'/proc/{pid}/stat') as f: raw = f.read()\n"
        "                rp = raw.rfind(')')\n"
        "                name = raw[raw.find('(')+1:rp]\n"
        "                rest = raw[rp+2:].split()\n"
        "                ut, st = int(rest[11]), int(rest[12])\n"
        "                d[int(pid)] = (name, (ut + st) / clk)\n"
        "            except Exception: pass\n"
        "        return d\n"
        "    s1 = _snap(); time.sleep(0.3); s2 = _snap()\n"
        "    for pid, (name, t2) in s2.items():\n"
        "        t1 = s1.get(pid, (name, t2))[1]\n"
        "        cpu = max(0.0, (t2 - t1) / 0.3 * 100.0)\n"
        "        rss = 0; sw = 0; cmd = []\n"
        "        try:\n"
        "            with open(f'/proc/{pid}/statm') as mf: rss = int(mf.read().split()[1]) * page\n"
        "        except Exception: pass\n"
        "        try:\n"
        "            with open(f'/proc/{pid}/status') as sf:\n"
        "                for sl in sf:\n"
        "                    if sl.startswith('VmSwap:'): sw = int(sl.split()[1]) * 1024; break\n"
        "        except Exception: pass\n"
        "        try:\n"
        "            with open(f'/proc/{pid}/cmdline', 'rb') as cf:\n"
        "                cmd = [c.decode('utf-8', 'ignore') for c in cf.read().split(b'\\x00') if c][:3]\n"
        "        except Exception: pass\n"
        "        res.append({'pid': pid, 'name': name, 'cpu': round(cpu, 1), 'total_time': t2, 'rss': rss, 'swap': sw, 'cmd': cmd})\n"
        "print(json.dumps({'total_ram': total_ram, 'procs': res}))\n"
    )
    ok, out, _ = run_remote_ssh(f"python3 - << 'EOF'\n{py_script}\nEOF", timeout=8, server_id=server_id)
    if not ok or not out.strip():
        return []
    try:
        payload = json.loads(out.strip())
        raw_list = payload.get("procs", []) if isinstance(payload, dict) else payload
        total_ram = payload.get("total_ram", 2048 * 1024 * 1024) if isinstance(payload, dict) else 2048 * 1024 * 1024
        results = []
        for p in raw_list:
            name = p.get("name", "unknown")
            cmd_str = " ".join(p.get("cmd", [])).lower()
            name_lower = name.lower()

            desc = "Системный процесс"
            if "realm" in name_lower or "/etc/realm" in cmd_str:
                desc = "Ретранслятор Realm Relay (RU➔NL/FI)"
            elif "adguard" in name_lower or "adguard" in cmd_str:
                desc = "Блокировщик AdGuard Home DNS"
            elif "dns_telemetry" in cmd_str or "telemetry" in cmd_str:
                desc = "Демон телеметрии DNS bbumn"
            elif "xray" in name_lower:
                desc = "Ядро прокси Xray"
            elif "x-ui" in name_lower:
                desc = "Панель 3X-UI"
            elif "nginx" in name_lower:
                desc = "Веб-сервер Nginx"
            elif "fail2ban" in name_lower or "fail2ban" in cmd_str:
                desc = "Защита от брутфорса Fail2ban"
            elif "beszel-agent" in name_lower or "beszel" in cmd_str:
                desc = "Агент мониторинга Beszel"
            elif "sshd" in name_lower:
                desc = "Служба SSH-доступа"
            elif "systemd-resolve" in name_lower:
                desc = "Системный DNS-резолвер"
            elif "unattended" in cmd_str:
                desc = "Автообновление безопасности Ubuntu"
            elif name_lower.startswith(("kworker", "rcu", "ksoftirqd", "migration")):
                desc = "Поток ядра Linux"
            elif name_lower.startswith("python"):
                desc = "Скрипт Python"

            results.append((name, p["pid"], p["cpu"], p["rss"], desc, p["total_time"], p.get("swap", 0)))

        if mode == "ram":
            results.sort(key=lambda x: x[3], reverse=True)
            return [(r[0], r[1], r[3], (r[3] / max(1, total_ram) * 100), r[4]) for r in results[:limit]]
        elif mode == "swap":
            sw_only = [(r[0], r[1], r[6], r[4]) for r in results if r[6] > 0]
            sw_only.sort(key=lambda x: x[2], reverse=True)
            return sw_only[:limit]
        else:
            results.sort(key=lambda x: (x[2], x[5]), reverse=True)
            return [(r[0], r[1], r[2], r[4]) for r in results[:limit]]
    except Exception as e:
        log.warning(f"Ошибка парсинга процессов с {server_id}: {e}")
        return []


def get_remote_fail2ban_stats(server_id="fin"):
    """Сбор статистики активных банов Fail2Ban на удаленном сервере."""
    cmd = "fail2ban-client status sshd"
    ok, out, _ = run_remote_ssh(cmd, timeout=5, server_id=server_id)
    banned = "0"
    total = "0"
    banned_ips = []
    if ok:
        for line in out.splitlines():
            if "Currently banned:" in line:
                banned = line.split(":")[-1].strip()
            if "Total banned:" in line:
                total = line.split(":")[-1].strip()
            if "Banned IP list:" in line:
                raw_ips = line.split(":")[-1].strip()
                banned_ips = raw_ips.split() if raw_ips else []
    return banned, total, banned_ips


def unban_remote_ip(ip, server_id="fin"):
    """Разбан IP на удаленном сервере."""
    cmd = f"fail2ban-client set sshd unbanip {ip}"
    ok, out, err = run_remote_ssh(cmd, timeout=5, server_id=server_id)
    return out.strip() if ok else f"Ошибка: {err}"


def get_remote_critical_logs(lines=15, server_id="fin"):
    """Выборка системных инцидентов удаленного сервера."""
    cmd = (
        "journalctl -p err..emerg --since '24 hours ago' --no-pager "
        "| grep -vE 'TLS handshake error|unsupported SSLv2|Connection reset by peer|kex_exchange_identification' "
        f"| tail -n {lines}"
    )
    ok, out, _ = run_remote_ssh(cmd, timeout=6, server_id=server_id)
    return out.strip() if ok and out.strip() else "За последние 24 часа критических ошибок сервисов не зафиксировано."


def check_remote_tcp_ports(ports, host, timeout=1.8):
    """Проверяет доступность проброшенных портов на внешнем IP ретранслятора."""
    results = []
    for item in ports:
        p = item["port"]
        name = item["name"]
        try:
            with socket.create_connection((host, int(p)), timeout=timeout):
                results.append((name, "🟢 open"))
        except Exception:
            results.append((name, "🔴 closed"))
    return results


def make_remote_backup_archive(server_id="fin"):
    """Создает архив бэкапа конфигураций на удаленном сервере (fin или ru) и возвращает его байты."""
    if server_id == "ru":
        paths = [
            "/etc/realm",
            "/usr/local/bin/realm",
            "/etc/systemd/system/realm.service",
            "/etc/sysctl.d",
            "/etc/ufw",
            "/etc/fail2ban/jail.d",
            "/etc/fail2ban/jail.local",
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d",
            "/root/.ssh/authorized_keys",
        ]
    else:
        paths = [
            "/etc/x-ui/x-ui.db",
            "/etc/systemd/system/x-ui.service",
            "/etc/nginx/nginx.conf",
            "/etc/nginx/stream_smartdns.map",
            "/etc/nginx/sites-available",
            "/etc/nginx/sites-enabled",
            "/var/www/html/dns",
            "/etc/letsencrypt/live/dns.bbumn.ru",
            "/etc/letsencrypt/archive/dns.bbumn.ru",
            "/etc/letsencrypt/renewal/dns.bbumn.ru.conf",
            "/opt/AdGuardHome/AdGuardHome.yaml",
            "/opt/AdGuardHome/data/stats.db",
            "/etc/systemd/system/AdGuardHome.service",
            "/opt/dns_telemetry/dns_telemetry.py",
            "/opt/dns_telemetry/auth.json",
            "/etc/systemd/system/dns-telemetry.service",
            "/var/lib/cloudflare-warp/conf.json",
            "/var/lib/cloudflare-warp/reg.json",
            "/var/lib/cloudflare-warp/settings.json",
            "/root/.ssh/authorized_keys",
            "/etc/fail2ban/jail.d",
            "/etc/ufw/user.rules",
            "/etc/ufw/user6.rules",
            "/etc/ufw/before.rules",
            "/etc/systemd/system/beszel-agent.service",
        ]

    paths_json = json.dumps(paths)
    py_script = (
        "import tarfile, os, tempfile, json\n"
        f"paths = {paths_json}\n"
        "existing = [p for p in paths if os.path.exists(p)]\n"
        "tmp = tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False)\n"
        "with tarfile.open(tmp.name, 'w:gz') as tar:\n"
        "    for p in existing: tar.add(p)\n"
        "print(tmp.name)\n"
    )
    ok, out, _ = run_remote_ssh(f"python3 - << 'EOF'\n{py_script}\nEOF", timeout=15, server_id=server_id)
    if not ok or not out.strip():
        return None
    remote_path = out.strip().splitlines()[-1].strip()

    host = _get_host(server_id)
    try:
        full_cmd = SSH_OPTS + [host, f"cat {remote_path} && rm -f {remote_path}"]
        res = subprocess.run(full_cmd, capture_output=True, timeout=25)
        if res.returncode == 0 and res.stdout:
            return res.stdout
    except Exception as e:
        log.warning(f"Ошибка скачивания архива с {server_id}: {e}")
    return None
