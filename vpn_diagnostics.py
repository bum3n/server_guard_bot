import time
import logging
import subprocess
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("server_guard.vpn_diag")

import config
import vpn_manager

# Состояние для отслеживания дельты трафика и отсеивания ложных срабатываний
_last_inbound_samples = {}
_strike_counts = {}

def is_local_port_listening(port, proto="tcp"):
    """Проверяет через ss, слушает ли процесс xray данный порт."""
    try:
        flag = "-tlnp" if proto == "tcp" else "-ulnp"
        res = subprocess.run(["ss", flag, f"sport = :{port}"], capture_output=True, text=True, timeout=2)
        out = res.stdout.strip()
        lines = [l for l in out.splitlines() if str(port) in l]
        return len(lines) > 0
    except Exception:
        return False

def count_active_tcp_conns(port):
    """Считает установленные TCP сессии на порту."""
    try:
        res = subprocess.run(["ss", "-tan", f"sport = :{port} or dport = :{port}"], capture_output=True, text=True, timeout=2)
        lines = [l for l in res.stdout.strip().splitlines() if "ESTAB" in l]
        return len(lines)
    except Exception:
        return 0

def check_rf_probes_dual(target_ip="62.173.152.111", timeout_sec=10):
    """
    Замеряет доступность из РФ через GlobalPing раздельно (Wi-Fi и Мобильный интернет РФ).
    Ожидает завершения замера до timeout_sec, чтобы медленные зонды не давали ложных 100% потерь.
    """
    from concurrent.futures import ThreadPoolExecutor
    headers = {"User-Agent": "ServerGuard/2.0"}
    if target_ip == "62.173.152.111":
        http_target = "bbumn.ru"
    elif target_ip == "201.58.188.206":
        http_target = "dns.bbumn.ru"
    else:
        http_target = target_ip

    mob_payload = {
        "target": http_target,
        "type": "http",
        "locations": [{"country": "RU", "asn": asn} for asn in (8359, 3216, 8402, 25513, 31133)],
        "limit": 2,
        "measurementOptions": {"request": {"method": "GET", "path": "/"}, "port": 443, "protocol": "HTTPS"},
    }
    wifi_payload = {
        "target": http_target,
        "type": "http",
        "locations": [{"country": "RU", "asn": asn} for asn in (12389, 52207, 41733)],
        "limit": 2,
        "measurementOptions": {"request": {"method": "GET", "path": "/"}, "port": 443, "protocol": "HTTPS"},
    }

    def start_m(payload):
        try:
            r = requests.post("https://api.globalping.io/v1/measurements", json=payload, headers=headers, timeout=4)
            if r.status_code in (200, 201, 202):
                return r.json().get("id")
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        mid_mob = pool.submit(start_m, mob_payload).result()
        mid_wifi = pool.submit(start_m, wifi_payload).result()

    def fetch_res(mid):
        if not mid:
            return None, "Нет активного зонда"
        deadline = time.monotonic() + max(timeout_sec, 6)
        time.sleep(1.5)
        last_results = []
        while True:
            try:
                res = requests.get(f"https://api.globalping.io/v1/measurements/{mid}", headers=headers, timeout=3.5)
                if res.status_code == 200:
                    data = res.json()
                    last_results = data.get("results", []) or []
                    finished = [r for r in last_results if (r.get("result") or {}).get("status") == "finished"]
                    if data.get("status") == "finished" or (finished and any(
                        (r.get("result") or {}).get("statusCode", 0) in (200, 301, 302, 404) for r in finished
                    )):
                        chosen = next((r for r in finished if (r.get("result") or {}).get("statusCode", 0) in (200, 301, 302, 404)), finished[0] if finished else None)
                        if chosen:
                            probe_res = chosen.get("result", {})
                            probe_info = chosen.get("probe", {})
                            ok = probe_res.get("statusCode", 0) in (200, 301, 302, 404)
                            total_ms = (probe_res.get("timings") or {}).get("total") or 0
                            return {
                                "loss": 0 if ok else 100,
                                "avg_rtt": round(total_ms, 1),
                                "city": probe_info.get("city", "RU"),
                                "isp": probe_info.get("network", "Провайдер РФ"),
                                "asn": probe_info.get("asn", ""),
                            }, ""
            except Exception as e:
                if time.monotonic() >= deadline:
                    return None, str(e)
            if time.monotonic() >= deadline:
                break
            time.sleep(1.0)
        if last_results:
            isp = (last_results[0] or {}).get("probe", {}).get("network", "зонд")
            return None, f"Зонд ({isp}) не завершил замер вовремя"
        return None, "Таймаут замера"

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_m = pool.submit(fetch_res, mid_mob)
        f_w = pool.submit(fetch_res, mid_wifi)
        mob_data, mob_err = f_m.result()
        wifi_data, wifi_err = f_w.result()

    return {"mobile": mob_data, "mobile_err": mob_err, "wifi": wifi_data, "wifi_err": wifi_err}


def check_rf_probe(target_ip="62.173.152.111", timeout_sec=10):
    """Обратная совместимость: возвращает результат зонда Wi-Fi или Мобильного."""
    res = check_rf_probes_dual(target_ip=target_ip, timeout_sec=timeout_sec)
    d = res.get("wifi") or res.get("mobile")
    if d:
        return d, ""
    return None, res.get("wifi_err") or res.get("mobile_err") or "Ошибка замера"

def get_vpn_full_report():
    """Собирает полную диагностику по всем 4 инбаундам и доступности из РФ."""
    lines = ["🩺 **Диагностика работоспособности VPN (3X-UI / Xray)**\n"]

    # 1. Онлайн клиенты
    online_clients = []
    try:
        url_onlines = vpn_manager.get_panel_url("/panel/api/clients/onlines")
        r_onl = vpn_manager.session.post(url_onlines, headers=vpn_manager.get_headers(), timeout=4)
        if r_onl.status_code == 200 and r_onl.json().get("success"):
            online_clients = r_onl.json().get("obj", [])
    except Exception as e:
        log.warning(f"Ошибка получения onlines: {e}")

    onl_count = len(online_clients)
    onl_desc = f"`{onl_count}` чел. ({', '.join(online_clients[:5])})" if onl_count > 0 else "нет активных сессий"

    # 2. Проверка зондов из РФ (раздельно Wi-Fi и Мобильный)
    probes = check_rf_probes_dual("62.173.152.111")
    lines.append("🇷🇺 **Связь из РФ (GlobalPing):**")
    
    wifi_data = probes.get("wifi")
    if wifi_data:
        loss = wifi_data["loss"]
        rtt = wifi_data["avg_rtt"]
        city = wifi_data["city"]
        isp = wifi_data["isp"]
        lines.append(f"• 🏠 Домашний Wi-Fi: {'🟢' if loss == 0 else ('🟡' if loss < 100 else '🔴')} `{loss}%` потерь (`{rtt} ms`, {city} / {isp})")
    else:
        lines.append(f"• 🏠 Домашний Wi-Fi: ⚪ Зонд недоступен ({probes.get('wifi_err')})")

    mob_data = probes.get("mobile")
    if mob_data:
        loss = mob_data["loss"]
        rtt = mob_data["avg_rtt"]
        city = mob_data["city"]
        isp = mob_data["isp"]
        lines.append(f"• 📱 Мобильный интернет: {'🟢' if loss == 0 else ('🟡' if loss < 100 else '🔴')} `{loss}%` потерь (`{rtt} ms`, {city} / {isp})")
    else:
        lines.append(f"• 📱 Мобильный интернет: ⚪ Зонд недоступен ({probes.get('mobile_err')})")

    # Проверка HTTPS шлюза
    code_200 = False
    try:
        r_gw = requests.get(f"https://{vpn_manager.DOMAIN}/", timeout=3, verify=False)
        code_200 = (r_gw.status_code == 200)
        lines.append(f"• Web шлюз / SSL (порт 443): {'🟢 200 OK' if code_200 else f'🟡 {r_gw.status_code}'}")
    except Exception:
        lines.append("• Web шлюз / SSL (порт 443): 🔴 down")

    lines.append(f"• Онлайн сейчас: {onl_desc}\n")

    # 3. Диагностика целевых инбаундов [1, 2, 3, 5]
    lines.append("⚡ **Состояние целевых инбаундов:**")
    target_names = {
        1: ("🇳🇱 Reality (Основной)", "tcp"),
        2: ("🇳🇱 Hysteria 2 (UDP)", "udp"),
        3: ("🇳🇱 Reality (Резерв)", "tcp"),
        5: ("🇳🇱 WebSocket (Резерв 2)", "tcp")
    }

    url_inbounds = vpn_manager.get_panel_url("/panel/api/inbounds/list")
    inbounds_map = {}
    try:
        r_inb = vpn_manager.session.get(url_inbounds, headers=vpn_manager.get_headers(), timeout=4)
        if r_inb.status_code == 200 and r_inb.json().get("success"):
            for item in r_inb.json().get("obj", []):
                inbounds_map[item.get("id")] = item
    except Exception as e:
        log.warning(f"Ошибка получения списка инбаундов: {e}")

    issues = []
    global _last_inbound_samples

    for i_id in vpn_manager.TARGET_INBOUND_IDS:
        default_label, default_proto = target_names.get(i_id, (f"Инбаунд {i_id}", "tcp"))
        inb = inbounds_map.get(i_id)
        if not inb:
            lines.append(f"• ID {i_id} ({default_label}): ⚪ Не найден в 3X-UI")
            continue

        port = inb.get("port")
        proto = inb.get("protocol", default_proto)
        is_udp = (proto == "hysteria" or default_proto == "udp")
        enabled = inb.get("enable", True)
        up_bytes = inb.get("up", 0)
        down_bytes = inb.get("down", 0)
        total_human = vpn_manager.format_bytes(up_bytes + down_bytes)

        # Локальное прослушивание
        check_proto = "udp" if is_udp else "tcp"
        listening = is_local_port_listening(port, proto=check_proto)

        # TCP соединения
        conns_str = ""
        if not is_udp:
            conns = count_active_tcp_conns(port)
            if conns > 0:
                conns_str = f" | Сессий: `{conns}`"

        # Дельта трафика
        prev = _last_inbound_samples.get(i_id, {})
        delta_bytes = (up_bytes + down_bytes) - prev.get("total", (up_bytes + down_bytes))
        _last_inbound_samples[i_id] = {"total": up_bytes + down_bytes, "ts": time.time()}

        # Вердикт инбаунда
        if not enabled:
            status_icon = "⚪"
            status_desc = "Отключен в панели"
        elif not listening:
            status_icon = "🔴"
            status_desc = f"Порт :{port} НЕ слушается (сбой Xray!)"
            issues.append(f"Инбаунд {i_id} ({default_label}) — закрыт порт :{port}")
        else:
            status_icon = "🟢"
            status_desc = f"Слушается (:{port}){conns_str} | Трафик: `{total_human}`"

        lines.append(f"• **{default_label}**: {status_icon} {status_desc}")

    # 4. Итоговый вердикт
    lines.append("\n💡 **Заключение:**")
    if rf_data and rf_data.get("loss", 0) == 100:
        lines.append("🚨 **ВНИМАНИЕ:** Внешний IP сервера не отвечает на пинги из РФ. Возможна блокировка IP подсети.")
    elif issues:
        lines.append("⚠️ Зафиксированы локальные неполадки: " + "; ".join(issues))
    elif onl_count > 0:
        lines.append(f"🟢 Все 4 инбаунда активны, прямо сейчас в сети {onl_count} пользователей.")
    else:
        lines.append("🟢 Все инбаунды слушают порты и готовы к подключениям. Блокировок со стороны РФ не обнаружено.")

    return "\n".join(lines)

def check_vpn_watchdog():
    """
    Легкая фоновая проверка для monitoring_loop (без тяжелых внешних вызовов).
    Возвращает список сообщений об ошибках, если инбаунд не отвечает 3 проверки подряд.
    """
    global _strike_counts
    alerts = []

    # 1. Проверяем локальные порты инбаундов
    target_ports = {
        1: (38813, "tcp", "Reality (Основной)"),
        2: (22377, "udp", "Hysteria 2"),
        3: (41840, "tcp", "Reality (Резерв)"),
        5: (8080, "tcp", "WebSocket (Резерв 2)")
    }

    for i_id, (port, proto, label) in target_ports.items():
        listening = is_local_port_listening(port, proto=proto)
        strike_key = f"inbound_{i_id}"
        if not listening:
            _strike_counts[strike_key] = _strike_counts.get(strike_key, 0) + 1
            if _strike_counts[strike_key] == 3:
                alerts.append(f"❌ **Инбаунд {i_id} ({label}) не слушает порт `{port}`** (3 проверки подряд). Возможен сбой Xray.")
        else:
            _strike_counts[strike_key] = 0

    return alerts
