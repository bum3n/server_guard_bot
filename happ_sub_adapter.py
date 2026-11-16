#!/usr/bin/env python3
import base64
import re
import ssl
import sys
import urllib.request
import urllib.parse
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

TARGET_BASE = 'https://127.0.0.1:2096'
SSL_CTX = ssl._create_unverified_context()
DUMMY_VLESS = 'vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1080?encryption=none#'

try:
    import config
    RU_RELAY_HOST = config.SERVERS.get("ru", {}).get("ip", "1.2.3.4") if hasattr(config, "SERVERS") else "1.2.3.4"
    nl_ip = config.SERVERS.get("nl", {}).get("ip", "1.2.3.4") if hasattr(config, "SERVERS") else "1.2.3.4"
    fin_ip = config.SERVERS.get("fin", {}).get("ip", "1.2.3.4") if hasattr(config, "SERVERS") else "1.2.3.4"
    RU_RELAY_ORIGINS = (f"@{nl_ip}:", f"@{fin_ip}:")
except Exception:
    import os
    RU_RELAY_HOST = os.environ.get('RU_RELAY_HOST', '1.2.3.4')
    RU_RELAY_ORIGINS = ('@1.2.3.4:',)

def route_via_ru_relay(decoded: str) -> str:
    for origin in RU_RELAY_ORIGINS:
        decoded = decoded.replace(origin, f'@{RU_RELAY_HOST}:')
    return decoded

class SubAdapterHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.proxy_request(is_head=False)

    def do_HEAD(self):
        self.proxy_request(is_head=True)

    def proxy_request(self, is_head=False):
        target_url = TARGET_BASE + self.path
        req = urllib.request.Request(target_url, method='HEAD' if is_head else 'GET')
        for key, value in self.headers.items():
            if key.lower() not in ('host', 'content-length'):
                req.add_header(key, value)
        incoming_host = self.headers.get('Host', '').split(':')[0]
        if not incoming_host or incoming_host in ('127.0.0.1', 'localhost'):
            incoming_host = 'bbumn.ru'
        req.add_header('Host', incoming_host)

        try:
            with urllib.request.urlopen(req, context=SSL_CTX) as resp:
                body = b'' if is_head else resp.read()
                status = resp.status
                resp_headers = resp.headers
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            if not is_head:
                self.wfile.write(e.read())
            return
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            if not is_head:
                self.wfile.write(f'Bad Gateway: {e}'.encode('utf-8'))
            return

        is_expired_stub = False
        if not is_head and body:
            try:
                decoded = base64.b64decode(body).decode('utf-8', errors='ignore')
                modified = False
                if 'socks://127.0.0.1:1080#' in decoded:
                    is_expired_stub = True
                    decoded = decoded.replace('socks://127.0.0.1:1080#', DUMMY_VLESS)
                    modified = True
                if '@localhost:' in decoded:
                    decoded = decoded.replace('@localhost:', f'@{incoming_host}:')
                    modified = True
                if 'support-x25519mlkem768=' in decoded:
                    decoded = re.sub(r'&support-x25519mlkem768=[^&#\r\n]*', '', decoded)
                    decoded = re.sub(r'\?support-x25519mlkem768=[^&#\r\n]*&?', lambda m: '?' if m.group(0).endswith('&') else '', decoded)
                    modified = True
                if 'sni=www.cloudflare.com' in decoded:
                    decoded = decoded.replace('sni=www.cloudflare.com', 'sni=www.swisstransfer.com')
                    modified = True
                if not is_expired_stub:
                    with_relays = route_via_ru_relay(decoded)
                    if with_relays != decoded:
                        decoded = with_relays
                        modified = True
                if modified:
                    body = base64.b64encode(decoded.encode('utf-8'))
            except Exception:
                pass

        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() in ('content-length', 'transfer-encoding', 'connection'):
                continue
            self.send_header(k, v)

        if is_expired_stub:
            self.send_header('Sub-Expire', '1')
            self.send_header('Sub-Expire-Button-Link', 'https://t.me/bum3n/')

        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()

        if not is_head and body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass

def main():
    port = 2097
    server = ThreadingHTTPServer(('127.0.0.1', port), SubAdapterHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
