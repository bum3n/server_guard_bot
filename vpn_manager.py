import io
import datetime
import time
import uuid
import secrets
import string
import logging
import requests
import urllib3
import qrcode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("server_guard.vpn")

SERVER_IP = "1.2.3.4"
PANEL_PORT = 44506
BASE_PATH = "/3x-ui-panel"

try:
    import config as _config  # подгружает .env
except Exception:
    _config = None
import os as _os

DOMAIN = getattr(_config, "DOMAIN", "example.com") if _config else "example.com"

SERVER_IP = getattr(_config, "SERVER_IP", SERVER_IP) if _config else SERVER_IP
BASE_PATH = getattr(_config, "BASE_PATH", BASE_PATH) if _config else BASE_PATH
BASE_PATH = "/" + BASE_PATH.strip("/")

API_TOKEN = "YOUR_3XUI_API_TOKEN"
API_TOKEN = _os.environ.get("XUI_API_TOKEN", API_TOKEN)

# Базовый URL панели 3X-UI (по умолчанию локально с verify=False)
PANEL_BASE_URL = _os.environ.get("XUI_BASE_URL", f"https://127.0.0.1:{PANEL_PORT}{BASE_PATH}").rstrip("/")

SUB_PATH = _os.environ.get("XUI_SUB_PATH", "sub")
HAPP_PREFIX = f"https://{DOMAIN}/redirect_happ/?token="

TARGET_INBOUND_IDS = [1, 2, 3, 5]

session = requests.Session()
session.verify = False

def get_panel_url(endpoint=""):
    """Формирует корректный URL к панели без дублирования слешей."""
    endpoint = "/" + endpoint.lstrip("/") if endpoint else ""
    return f"{PANEL_BASE_URL}{endpoint}"

def login(username, password):
    """Авторизация по логину/паролю через POST /login (сохраняет cookies в session)."""
    url = get_panel_url("/login")
    try:
        r = session.post(url, data={"username": username, "password": password}, timeout=5)
        if r.status_code == 200 and r.json().get("success"):
            return True
        log.warning("3X-UI login failed: HTTP %s, body: %s", r.status_code, r.text[:200])
        return False
    except Exception as e:
        log.exception("3X-UI login error for %s: %s", url, e)
        return False

def get_headers():
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_TOKEN}"
    }

def format_bytes(b):
    if not b:
        return "0 MB"
    mb = b / (1024 * 1024)
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.1f} MB"

def gen_rand_str(length=16):
    chars = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def get_clients_list():
    """Считывает клиентов через официальный GET /panel/api/clients/list."""
    url = get_panel_url("/panel/api/clients/list")
    try:
        r = session.get(url, headers=get_headers(), timeout=5)
        if r.status_code != 200:
            log.error("3X-UI get_clients_list failed: HTTP %s, body: %s", r.status_code, r.text[:300])
            return []
        data = r.json()
        if not data.get("success"):
            log.warning("3X-UI get_clients_list returned success=False: %s", data.get("msg", data))
            return []

        raw_clients = data.get("obj", [])
        result = []
        for c in raw_clients:
            inb_ids = c.get("inboundIds", [])
            has_target = any(i in TARGET_INBOUND_IDS for i in inb_ids) if inb_ids else True
            if not has_target:
                continue

            traffic = c.get("traffic") or {}
            result.append({
                "email": c.get("email"),
                "uuid": c.get("uuid") or c.get("id", ""),
                "sub_id": c.get("subId", ""),
                "enable": c.get("enable", True),
                "total_gb": c.get("totalGB", 0),
                "expiry_time": c.get("expiryTime", 0),
                "inbound_ids": inb_ids,
                "up": traffic.get("up", 0),
                "down": traffic.get("down", 0)
            })
        return result
    except Exception as e:
        log.exception("3X-UI get_clients_list request exception for %s: %s", url, e)
        return []

def get_client_by_email(email):
    for c in get_clients_list():
        if c["email"] == email:
            return c
    return None

def build_links(sub_id):
    """
    Формирует:
    1. raw_sub: прямая ссылка подписки 3X-UI через домен по стандартному HTTPS (порт 443)
    2. happ_link: компактная ссылка веб-шлюза с токеном подписки (/redirect_happ/?token=...)
    """
    if not sub_id:
        return "", ""
    raw_sub = f"https://{DOMAIN}/{SUB_PATH}/{sub_id}"
    happ_link = f"https://{DOMAIN}/redirect_happ/?token={sub_id}"
    return raw_sub, happ_link

def build_happ_deeplink(sub_id):
    """Прямой deep-link протокола Happ (happ://add/<raw_sub>) по HTTPS 443."""
    if not sub_id:
        return ""
    return f"happ://add/https://{DOMAIN}/{SUB_PATH}/{sub_id}"

def generate_qr_bytes(text):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=3
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#111827", back_color="white")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)
    return buf

def create_client(email, sub_id=None, total_gb=0, days_limit=0):
    """Штатное добавление клиента через POST /panel/api/clients/add."""
    if not sub_id:
        sub_id = gen_rand_str(16)

    expiry_ts = 0
    if days_limit > 0:
        expiry_ts = int((datetime.datetime.now() + datetime.timedelta(days=days_limit)).timestamp() * 1000)

    total_bytes = int(total_gb * (1024 ** 3)) if total_gb > 0 else 0

    payload = {
        "client": {
            "email": email,
            "subId": sub_id,
            "totalGB": total_bytes,
            "expiryTime": expiry_ts,
            "flow": "xtls-rprx-vision",
            "enable": True,
            "limitIp": 0,
            "limitHwid": 0,
            "tgId": 0,
            "comment": ""
        },
        "inboundIds": TARGET_INBOUND_IDS
    }

    url = get_panel_url("/panel/api/clients/add")
    try:
        r = session.post(url, json=payload, headers=get_headers(), timeout=8)
        if r.status_code != 200:
            log.error("3X-UI create_client failed: HTTP %s, body: %s", r.status_code, r.text[:300])
            return False, f"Ошибка 3X-UI: HTTP {r.status_code}"
        res = r.json()
        if res.get("success"):
            return True, sub_id
        log.warning("3X-UI create_client returned success=False: %s", res)
        return False, res.get("msg", "Ошибка добавления на стороне 3X-UI")
    except Exception as e:
        log.exception("3X-UI create_client exception: %s", e)
        return False, str(e)

def delete_client(email):
    """Удаление клиента через POST /panel/api/clients/del/{email}?keepTraffic=0."""
    url = get_panel_url(f"/panel/api/clients/del/{email}?keepTraffic=0")
    try:
        r = session.post(url, headers=get_headers(), timeout=5)
        if r.status_code != 200:
            log.error("3X-UI delete_client failed: HTTP %s, body: %s", r.status_code, r.text[:300])
            return False
        return r.json().get("success", False)
    except Exception as e:
        log.exception("3X-UI delete_client exception: %s", e)
        return False

def update_client_limits(email, total_gb=None, days_limit=None):
    """Обновление лимитов через POST /panel/api/clients/update/{email}."""
    client = get_client_by_email(email)
    if not client:
        return False

    total_bytes = client.get("total_gb", 0)
    if total_gb is not None:
        total_bytes = int(total_gb * (1024 ** 3)) if total_gb > 0 else 0

    expiry_ts = client.get("expiry_time", 0)
    if days_limit is not None:
        if days_limit > 0:
            expiry_ts = int((datetime.datetime.now() + datetime.timedelta(days=days_limit)).timestamp() * 1000)
        else:
            expiry_ts = 0

    payload = {
        "email": email,
        "subId": client.get("sub_id"),
        "totalGB": total_bytes,
        "expiryTime": expiry_ts,
        "enable": client.get("enable", True),
        "limitIp": 0,
        "limitHwid": 0
    }

    url = get_panel_url(f"/panel/api/clients/update/{email}")
    try:
        r = session.post(url, json=payload, headers=get_headers(), timeout=5)
        if r.status_code != 200:
            log.error("3X-UI update_client_limits failed: HTTP %s, body: %s", r.status_code, r.text[:300])
            return False
        return r.json().get("success", False)
    except Exception as e:
        log.exception("3X-UI update_client_limits exception: %s", e)
        return False

def _push_update(email, client, total_bytes, expiry_ts, enable):
    """Единая отправка обновления клиента (тот же payload, что и в update_client_limits)."""
    payload = {
        "email": email,
        "subId": client.get("sub_id"),
        "totalGB": total_bytes,
        "expiryTime": expiry_ts,
        "enable": enable,
        "limitIp": 0,
        "limitHwid": 0
    }
    url = get_panel_url(f"/panel/api/clients/update/{email}")
    try:
        r = session.post(url, json=payload, headers=get_headers(), timeout=5)
        if r.status_code != 200:
            log.error("3X-UI _push_update failed: HTTP %s, body: %s", r.status_code, r.text[:300])
            return False
        return bool(r.json().get("success", False))
    except Exception as e:
        log.exception("3X-UI _push_update exception: %s", e)
        return False


def set_client_enabled(email, enabled):
    """Включает/отключает клиента без удаления."""
    client = get_client_by_email(email)
    if not client:
        return False
    return _push_update(email, client, client.get("total_gb", 0), client.get("expiry_time", 0), bool(enabled))


def extend_client(email, add_days=0, add_gb=0):
    """Продлевает срок (от текущей даты окончания или от сегодня) и/или увеличивает лимит трафика.

    Возвращает (ok, сообщение).
    """
    client = get_client_by_email(email)
    if not client:
        return False, "Клиент не найден"

    total_bytes = client.get("total_gb", 0)
    expiry_ts = client.get("expiry_time", 0)

    if add_gb and add_gb > 0:
        if total_bytes <= 0:
            return False, "У клиента безлимитный трафик — увеличивать нечего"
        total_bytes = int(total_bytes + add_gb * (1024 ** 3))

    if add_days and add_days > 0:
        now_ms = int(time.time() * 1000)
        base = expiry_ts if expiry_ts and expiry_ts > now_ms else now_ms
        expiry_ts = int(base + add_days * 86400 * 1000)

    ok = _push_update(email, client, total_bytes, expiry_ts, client.get("enable", True))
    return ok, ("Готово" if ok else "Панель 3X-UI не приняла изменения")

