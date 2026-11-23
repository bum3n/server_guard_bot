"""
Модуль комплексного аудита серверов (Нидерланды, Финляндия, Россия).
Собирает данные о ресурсах за 24 часа, службах, веб-сервисах, портах, безопасности и системных инцидентах.
Формирует богатый структурированный отчет в формате Rich Markdown с таблицами и сворачиваемыми блоками.
"""
import datetime
import subprocess
import os
import psutil
import socket
import urllib.request
import urllib.error
import time

import config
import analyzer
import card_generator
import metrics_store
import remote_monitor
import maintenance

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))


def _check_http_service(name, url, timeout=2.5):
    """Быстрая HTTP проверка доступности веб-сервиса."""
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ServerGuardAudit/2.0"},
            method="HEAD"
        )
        ctx = None
        if url.startswith("https://"):
            import ssl
            ctx = ssl._create_unverified_context()

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            rtt = round((time.time() - t0) * 1000, 1)
            code = resp.status
            if code in (200, 301, 302, 401, 403, 404, 405):
                return name, f"🟢 {code}", rtt, True
            return name, f"🟡 {code}", rtt, False
    except urllib.error.HTTPError as e:
        rtt = round((time.time() - t0) * 1000, 1)
        if e.code in (200, 301, 302, 401, 403, 404, 405):
            return name, f"🟢 {e.code}", rtt, True
        return name, f"🟡 {e.code}", rtt, False
    except Exception:
        rtt = round((time.time() - t0) * 1000, 1)
        return name, "🔴 timeout", rtt, False


def run_server_audit(server_id="nl"):
    """
    Выполняет полный аудит указанного сервера.
    Возвращает:
      - report_text: подробный текст отчета в Rich Markdown
      - photo_buf: буфер с изображением (график 24ч или статусная карточка)
      - health_score: индекс стабильности (0-100)
    """
    srv = config.SERVERS.get(server_id, config.SERVERS["nl"])
    srv_name = srv.get("name", server_id)
    srv_flag = srv.get("flag", "🌐")
    srv_ip = srv.get("ip", "unknown")
    is_local = srv.get("is_local", True)
    now_msk = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S")

    health_score = 100
    warnings = []
    critical_issues = []

    # ---------------- 1. Сбор метрик ресурсов и аптайма ----------------
    summary_24h = None
    photo_buf = None

    if is_local:
        cpu = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        uptime_sec = maintenance.get_uptime_seconds()

        try:
            with open("/proc/loadavg", "r") as f:
                load_avg = " ".join(f.read().split()[:3])
        except Exception:
            load_avg = "н/д"

        cpu_val = cpu
        ram_pct = ram.percent
        ram_used_mb = ram.used // (1024 * 1024)
        ram_total_mb = ram.total // (1024 * 1024)
        swap_pct = swap.percent
        swap_used_mb = swap.used // (1024 * 1024)
        swap_total_mb = swap.total // (1024 * 1024)
        disk_pct = disk.percent
        disk_free_gb = disk.free // (1024 * 1024 * 1024)
        disk_total_gb = disk.total // (1024 * 1024 * 1024)

        summary_24h = metrics_store.get_summary(hours=24)
        rows = metrics_store.get_samples(hours=24)
        if rows and len(rows) > 5:
            photo_buf = card_generator.generate_history_chart(rows, 24)
        else:
            photo_buf = card_generator.generate_status_card(
                cpu_val, ram_pct, swap_pct, disk_pct,
                subtitle=f"Audit: {srv_name} ({srv_ip})",
                title=f"АУДИТ РЕСУРСОВ VPS ({srv_name.upper()})"
            )
    else:
        m = remote_monitor.get_remote_system_metrics(server_id=server_id)
        if not m:
            err_msg = f"❌ Не удалось подключиться по SSH к серверу {srv_flag} {srv_name} (`{srv_ip}`). Аудит прерван."
            return err_msg, None, 0

        cpu_val = m["cpu"]
        ram_pct = m["ram_pct"]
        ram_used_mb = m["ram_used"]
        ram_total_mb = m["ram_total"]
        swap_pct = m["swap_pct"]
        swap_used_mb = m["swap_used"]
        swap_total_mb = m["swap_total"]
        disk_pct = m["disk_pct"]
        disk_free_gb = m["disk_free"]
        disk_total_gb = m["disk_total"]
        uptime_sec = m.get("uptime", 0)
        load_avg = m.get("load_avg", "н/д")

        photo_buf = card_generator.generate_status_card(
            cpu_val, ram_pct, swap_pct, disk_pct,
            subtitle=f"Audit: {srv_name} ({srv_ip})",
            title=f"АУДИТ РЕСУРСОВ VPS ({srv_name.upper()})"
        )

    uptime_str = maintenance.format_duration(uptime_sec)

    # Оценка здоровья ресурсов
    if cpu_val > config.CPU_THRESHOLD:
        health_score -= 10
        warnings.append(f"Высокая текущая нагрузка CPU: `{cpu_val}%`")
    if ram_pct > config.RAM_THRESHOLD:
        health_score -= 10
        warnings.append(f"Высокая занятость ОЗУ: `{ram_pct}%`")
    if disk_pct > config.DISK_THRESHOLD:
        health_score -= 15
        critical_issues.append(f"Критическое заполнение диска: `{disk_pct}%` (осталось {disk_free_gb} GB)")

    # ---------------- 2. Состояние служб Systemd ----------------
    monitored = srv.get("monitored_services", [])
    unit_names = [s["unit"] for s in monitored]
    if is_local:
        from main import get_local_systemd_statuses
        statuses = get_local_systemd_statuses(unit_names)
    else:
        statuses = remote_monitor.get_remote_systemd_statuses(unit_names, server_id=server_id)

    total_services = len(monitored)
    active_services = 0
    failed_services_list = []

    for s in monitored:
        st = statuses.get(s["unit"], "⚪ unknown")
        if "active" in st:
            active_services += 1
        else:
            failed_services_list.append((s["name"], s["unit"], st))
            health_score -= 15
            critical_issues.append(f"Служба остановлена: **{s['name']}** (`{s['unit']}`: {st})")

    # ---------------- 3. Сетевые проверки (HTTP / TCP) ----------------
    http_checks = srv.get("http_checks", [])
    http_results = []
    http_ok_count = 0
    for hc in http_checks:
        h_name, h_code, h_rtt, h_ok = _check_http_service(hc["name"], hc["url"])
        http_results.append((h_name, h_code, h_rtt, h_ok))
        if h_ok:
            http_ok_count += 1
        else:
            health_score -= 10
            warnings.append(f"Веб-сервис не отвечает: **{h_name}** ({h_code})")

    tcp_checks = srv.get("tcp_checks", [])
    tcp_results = []
    tcp_ok_count = 0
    if tcp_checks:
        remote_ports_res = remote_monitor.check_remote_tcp_ports(tcp_checks, srv_ip)
        for p_name, p_st in remote_ports_res:
            is_open = "open" in p_st
            tcp_results.append((p_name, p_st, is_open))
            if is_open:
                tcp_ok_count += 1
            else:
                health_score -= 8
                warnings.append(f"Порт закрыт/недоступен: **{p_name}**")

    # ---------------- 4. Безопасность и сертификаты ----------------
    if is_local:
        banned, total_banned, banned_ips = analyzer.get_fail2ban_stats()
        ssl_days, ssl_exp = analyzer.check_ssl_expiry()
    else:
        banned, total_banned, banned_ips = remote_monitor.get_remote_fail2ban_stats(server_id=server_id)
        ssl_days, ssl_exp = None, "N/A"

    if ssl_days is not None:
        if ssl_days <= 3:
            health_score -= 15
            critical_issues.append(f"Истекает срок SSL-сертификата: осталось `{ssl_days}` дн.!")
        elif ssl_days <= 10:
            health_score -= 5
            warnings.append(f"SSL-сертификат истекает через `{ssl_days}` дн. (до {ssl_exp})")

    # ---------------- 5. Журнал системных ошибок за 24ч ----------------
    if is_local:
        raw_logs = analyzer.get_critical_logs(lines=12)
    else:
        raw_logs = remote_monitor.get_remote_critical_logs(lines=12, server_id=server_id)

    has_real_errors = raw_logs and "не зафиксировано" not in raw_logs and "Ошибка" not in raw_logs
    if has_real_errors:
        err_lines = [l for l in raw_logs.splitlines() if l.strip()]
        if len(err_lines) > 5:
            health_score -= 5
            warnings.append(f"В системном журнале зафиксировано `{len(err_lines)}` инцидентов за сутки")

    # Фиксация Health Score в диапазоне 0..100
    health_score = max(0, min(100, health_score))
    if health_score >= 95:
        verdict_icon = "🟢"
        verdict_title = "Все системы функционируют штатно"
    elif health_score >= 80:
        verdict_icon = "🟢"
        verdict_title = "Сервер стабилен, есть мелкие замечания"
    elif health_score >= 60:
        verdict_icon = "⚠️"
        verdict_title = "Обнаружены отклонения в работе компонентов"
    else:
        verdict_icon = "🚨"
        verdict_title = "Зафиксированы критические сбои служб или сервисов"

    # ==================== ФОРМИРОВАНИЕ ОТЧЕТА (TELEGRAM RICH MARKDOWN) ====================
    lines = []
    lines.append(f"# 🔍 Полный аудит сервера: {srv_flag} {srv_name}\n")
    lines.append(
        f"> — 📅 {now_msk} MSK\n"
        f"> — IP: `{srv_ip}`\n"
        f"> — Аптайм: `{uptime_str}`\n"
    )

    lines.append(f"## {verdict_icon} Индекс стабильности: {health_score}% ({verdict_title})\n")

    # 1. Текущие ресурсы (Таблица)
    vcpus_str = f"{psutil.cpu_count(logical=True)} vCPU " if is_local else ""
    lines.append("### 📊 Системные ресурсы")
    lines.append("| Ресурс | Объем / Параметр | Загрузка |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **CPU** | {vcpus_str}(LA: `{load_avg}`) | `{cpu_val}%` |")
    lines.append(f"| **RAM** | `{ram_used_mb}` / `{ram_total_mb} MB` | `{ram_pct}%` |")
    lines.append(f"| **SWAP** | `{swap_used_mb}` / `{swap_total_mb} MB` | `{swap_pct}%` |")
    lines.append(f"| **Диск** | Свободно: `{disk_free_gb}` / `{disk_total_gb} GB` | `{disk_pct}%` |")

    # 2. Динамика 24ч (Таблица)
    if summary_24h:
        lines.append("\n### 📈 Динамика за последние 24 часа")
        lines.append("| Метрика | Среднее (24ч) | Пиковое (макс) |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(f"| **CPU** | `{summary_24h['cpu_avg']:.1f}%` | `{summary_24h['cpu_max']:.1f}%` |")
        lines.append(f"| **RAM** | `{summary_24h['ram_avg']:.1f}%` | `{summary_24h['ram_max']:.1f}%` |")
        lines.append(f"| **Диск** | `{summary_24h['disk_max']:.1f}%` | `{summary_24h['disk_max']:.1f}%` |")
        lines.append(f"- _Замеров в базе:_ `{summary_24h['count']:,}` точек мониторинга")

    # 3. Службы
    status_emoji = "🟢" if not failed_services_list else "🔴"
    lines.append(f"\n### ⚙️ Системные службы (systemd): `{active_services}/{total_services} active` {status_emoji}")
    if failed_services_list:
        lines.append("| Остановленная служба | Юнит | Статус |")
        lines.append("| :--- | :--- | :--- |")
        for fn, fu, fs in failed_services_list:
            lines.append(f"| **{fn}** | `{fu}` | 🔴 {fs} |")
    else:
        lines.append(f"<details><summary>Все {total_services} системные службы</summary>\n")
        lines.append("| Служба | Описание | Статус |")
        lines.append("| :--- | :--- | :--- |")
        for s in monitored:
            st = statuses.get(s["unit"], "⚪ unknown")
            lines.append(f"| **{s['name']}** | `{s['unit']}` | {st} |")
        lines.append("\n</details>")

    # 4. Веб-сервисы и порты
    if http_results or tcp_results:
        lines.append("\n### 🌐 Доступность сервисов и портов")
        lines.append("| Сервис / Порт | Протокол | Статус / RTT |")
        lines.append("| :--- | :--- | :--- |")
        if http_results:
            for h_name, h_code, h_rtt, h_ok in http_results:
                bullet = "🟢" if h_ok else "🔴"
                lines.append(f"| **{h_name}** | HTTPS | {bullet} `{h_code}` (`{h_rtt} ms`) |")
        if tcp_results:
            for p_name, p_st, is_open in tcp_results:
                bullet = "🟢" if is_open else "🔴"
                lines.append(f"| **{p_name}** | TCP | {bullet} {p_st} |")

    # 5. Безопасность и SSL
    lines.append("\n### 🛡️ Безопасность и SSL")
    if is_local and ssl_days is not None:
        ssl_icon = "🟢" if ssl_days > 10 else "🟡"
        lines.append(f"- **SSL Let's Encrypt:** {ssl_icon} `{ssl_days} дн.` (до {ssl_exp})")
    lines.append(f"- **Fail2Ban (SSH):** 🟢 Активно в бане: `{banned}` (всего отражено: `{total_banned}`)")

    # 6. Ошибки в логах
    lines.append("\n### 📋 Системные инциденты (24ч)")
    if has_real_errors:
        clean_logs = raw_logs.strip()[-1200:]
        lines.append(f"<details><summary>Записи системных инцидентов</summary>\n\n```\n{clean_logs}\n```\n</details>")
    else:
        lines.append("- 🟢 _За последние 24 часа критических сбоев не зафиксировано._")

    # 7. Вердикт
    lines.append("\n### 💡 Вердикт")
    if critical_issues:
        lines.append("> 🚨 **Обнаружены критические сбои:**\n" + "\n".join(f"> - {ci}" for ci in critical_issues))
    elif warnings:
        lines.append("> ⚠️ **Внимание:**\n" + "\n".join(f"> - {w}" for w in warnings))
    else:
        lines.append("> 🟢 **Все компоненты сервера работают безупречно.** Нагрузка в норме, демоны активны, сетевые шлюзы отвечают штатно.")

    report_text = "\n".join(lines)
    return report_text, photo_buf, health_score
