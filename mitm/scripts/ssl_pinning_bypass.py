"""
Scenariusz 3: SSL Pinning Bypass
=================================
Cel: analiza mechanizmu SSL Pinning i próba obejścia przez
    podmianę certyfikatu CA (mitmproxy CA zamiast oryginalnego).

Działanie:
    mitmproxy automatycznie prezentuje własny certyfikat podpisany
    przez swoje CA. Jeśli urządzenie Android ufa CA mitmproxy
    (zainstalowany certyfikat), SSL pinning zostaje obejśty.

    Ten skrypt DODATKOWO:
    - loguje szczegóły certyfikatów w handshake
    - wykrywa próby SSL pinning (błędy TLS)
    - rejestruje wszystkie przechwycone połączenia TLS

Android 9.0 (API 28) — specyfika:
    - Aplikacje targeting API 24+ nie ufają certyfikatom użytkownika.
      Wymagana instalacja CA do system store: /system/etc/security/cacerts/
    - Network Security Config (NSC) pozwala aplikacjom pinować certyfikaty
      przez res/xml/network_security_config.xml — bypass NSC wymaga Fridy
      lub modyfikacji APK.
    - Android 9 używa TLS 1.2 (TLS 1.3 dostępne dopiero od API 29).

Uruchomienie:
    docker exec wzirni-mitm mitmweb --listen-port 8080 -s /scripts/ssl_pinning_bypass.py
"""

from mitmproxy import http, tls, ctx
from datetime import datetime

LOG_FILE = "/tmp/ssl_pinning_log.log"


def _log(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    ctx.log.warn(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


class SSLPinningBypassAddon:

    def __init__(self):
        self.intercepted_tls = 0
        self.pinning_errors  = 0

    # ------------------------------------------------------------------
    # Klient zainicjował TLS
    # ------------------------------------------------------------------
    def tls_start_client(self, tls_handshake: tls.ClientHelloData) -> None:
        self.intercepted_tls += 1
        sni = tls_handshake.context.client.sni
        _log(
            f"[TLS-CLIENT] Handshake #{self.intercepted_tls} | "
            f"SNI={sni} | "
            f"mitmproxy prezentuje własny certyfikat"
        )

    # ------------------------------------------------------------------
    # Połączenie do serwera docelowego
    # ------------------------------------------------------------------
    def tls_start_server(self, _tls_handshake: tls.TlsData) -> None:
        _log(f"[TLS-SERVER] Połączenie serwer-side TLS (mitmproxy ↔ backend)")

    # ------------------------------------------------------------------
    # Żądanie - po udanym przejściu TLS
    # ------------------------------------------------------------------
    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        _log(f"[SSL-BYPASS-OK] Przechwycono: {flow.request.method} {url}")

        # Odczyt certyfikatu serwera (jeśli dostępny)
        if flow.server_conn and flow.server_conn.certificate_list:
            cert = flow.server_conn.certificate_list[0]
            _log(
                f"[CERT-SERVER] CN={cert.cn} | "
                f"SHA256={cert.fingerprint().hex()[:16]}..."
            )

    # ------------------------------------------------------------------
    # Odpowiedź - oznaczenie przechwyconych danych
    # ------------------------------------------------------------------
    def response(self, flow: http.HTTPFlow) -> None:
        flow.response.headers["x-mitm-ssl-bypass"] = "success"
        flow.response.headers["x-mitm-cert-replaced"] = "mitmproxy-ca"

        status = flow.response.status_code
        _log(f"[RESPONSE] {flow.request.pretty_url} -> {status}")

    # ------------------------------------------------------------------
    # Obsługa błędów TLS (np. wykryto SSL pinning po stronie klienta)
    # ------------------------------------------------------------------
    def tls_failed_client(self, _context) -> None:
        self.pinning_errors += 1
        _log(
            f"[SSL-PINNING-DETECTED] TLS handshake z klientem nie powiódł się! "
            f"Możliwy SSL Pinning lub Network Security Config (API 28+). "
            f"Liczba błędów: {self.pinning_errors}"
        )

    def tls_failed_server(self, _context) -> None:
        _log(f"[TLS-SERVER-FAIL] Błąd TLS po stronie serwera")


addons = [SSLPinningBypassAddon()]
