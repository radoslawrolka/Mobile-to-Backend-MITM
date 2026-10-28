#!/usr/bin/env bash
# =============================================================
# WZIRNI Projekt – Demo porównawcze: BEZ ATAKU vs Z ATAKIEM
# Użycie: ./demo.sh [tls|tamper|pinning|all]
# =============================================================

set -uo pipefail

BACKEND_HTTPS="https://localhost:3443"
BACKEND_HTTP="http://localhost:3000"
# Adres backendu widziany Z WNĘTRZA sieci Docker (mitmproxy → backend)
BACKEND_HTTPS_DOCKER="https://172.20.0.10:3443"
BACKEND_HTTP_DOCKER="http://172.20.0.10:3000"
PROXY="http://localhost:8080"

# curl bez proxy (połączenie bezpośrednie host → backend przez port-mapping)
CURL_DIRECT="curl -sk --max-time 5"
# curl przez mitmproxy — cel musi być adresem widocznym z kontenera mitmproxy
CURL_MITM="curl -sk --max-time 5 --proxy $PROXY"
# curl przez mitmproxy z verbose (do wyciągania info o certyfikacie)
CURL_MITM_V="curl -sk --max-time 5 --proxy $PROXY -v"
CURL_DIRECT_V="curl -sk --max-time 5 -v"

# Kolory
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

sep()    { echo -e "${DIM}────────────────────────────────────────────────────${NC}"; }
header() { echo -e "\n${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"; \
           printf "${BOLD}${CYAN}║  %-52s║${NC}\n" "$1"; \
           echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"; }
label_ok()     { echo -e "${GREEN}${BOLD}[BEZ ATAKU]${NC} $1"; }
label_attack() { echo -e "${RED}${BOLD}[Z ATAKIEM]${NC} $1"; }
info()         { echo -e "${YELLOW}[INFO]${NC} $1"; }
diff_line()    { echo -e "${BOLD}$1${NC}"; }

pretty_json() {
    python3 -m json.tool 2>/dev/null || cat
}

check_services() {
    if ! $CURL_DIRECT "$BACKEND_HTTPS/api/health" &>/dev/null; then
        echo -e "${RED}BŁĄD: Backend niedostępny ($BACKEND_HTTPS). Uruchom: make up${NC}"
        exit 1
    fi
    if ! curl -s --max-time 3 --proxy "$PROXY" "http://172.20.0.10:3000/api/health" &>/dev/null; then
        echo -e "${RED}BŁĄD: mitmproxy niedostępny ($PROXY). Uruchom wybrany scenariusz np: make scenario-tls${NC}"
        exit 1
    fi
}

# =============================================================
# SCENARIUSZ 1: TLS Downgrade + HSTS
# =============================================================
demo_tls() {
    header "Scenariusz 1: TLS Downgrade + HSTS"

    echo ""
    info "Cel: pokazanie że MITM usuwa nagłówek HSTS i podmieniahttps→http w treści."
    info "Aktywuj scenariusz przed demo: make scenario-tls"
    sep

    # ---- Test 1: nagłówek HSTS ----
    diff_line "TEST 1 — Nagłówek Strict-Transport-Security"
    echo ""

    DIRECT_HEADERS=$($CURL_DIRECT -I "$BACKEND_HTTPS/api/health" || true)
    HSTS_DIRECT=$(echo "$DIRECT_HEADERS" | grep -i "strict-transport-security" | tr -d '\r' || true)
    MITM_HEADER_LINE=$($CURL_MITM -I "$BACKEND_HTTPS_DOCKER/api/health" || true)
    HSTS_MITM=$(echo "$MITM_HEADER_LINE" | grep -i "strict-transport-security" | tr -d '\r' || true)
    TLS_DOWNGRADE_HDR=$(echo "$MITM_HEADER_LINE" | grep -i "x-mitm-tls-downgrade" | tr -d '\r' || true)

    label_ok  "HSTS obecny    : ${HSTS_DIRECT:-<brak nagłówka>}"
    label_attack "HSTS usunięty  : ${HSTS_MITM:-<nagłówek USUNIĘTY przez MITM>}"
    label_attack "MITM oznaczenie: ${TLS_DOWNGRADE_HDR:-<brak>}"
    sep

    # ---- Test 2: podmiana https→http w JSON ----
    diff_line "TEST 2 — Treść odpowiedzi JSON (podmiana https:// → http://)"
    echo ""

    # Backend specjalnie zwraca pole z URL żeby pokazać downgrade
    DIRECT_BODY=$($CURL_DIRECT "$BACKEND_HTTPS/api/health" || true)
    MITM_BODY=$($CURL_MITM "$BACKEND_HTTPS_DOCKER/api/health" || true)

    echo -e "${GREEN}${BOLD}[BEZ ATAKU] /api/health:${NC}"
    echo "$DIRECT_BODY" | pretty_json
    echo ""
    echo -e "${RED}${BOLD}[Z ATAKIEM] /api/health (mitmproxy TLS Downgrade):${NC}"
    echo "$MITM_BODY" | pretty_json

    sep
    # ---- Test 3: żądanie HTTP (po downgrade klient wysyła cleartext) ----
    diff_line "TEST 3 — Żądanie cleartext HTTP (efekt downgrade)"
    echo ""
    label_ok  "HTTPS (szyfrowane): $($CURL_DIRECT "$BACKEND_HTTPS/api/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"tls={d['tls']}\")" 2>/dev/null || echo "tls=yes")"
    label_attack "HTTP (cleartext) : $($CURL_MITM "$BACKEND_HTTP_DOCKER/api/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"tls={d['tls']}\")" 2>/dev/null || echo "tls=no (NIESZYFROWANE!)")"
    sep
}

# =============================================================
# SCENARIUSZ 2: Traffic Tampering
# =============================================================
demo_tamper() {
    header "Scenariusz 2: Traffic Tampering"

    echo ""
    info "Cel: przechwytywanie credentiali + podmiana danych finansowych."
    info "Aktywuj scenariusz przed demo: make scenario-tamper"
    sep

    # ---- Test 1: POST /api/login (credential harvesting) ----
    diff_line "TEST 1 — Kradzież danych logowania POST /api/login"
    echo ""

    CREDS='{"username":"admin","password":"password123"}'

    echo -e "${GREEN}${BOLD}[BEZ ATAKU] POST /api/login:${NC}"
    $CURL_DIRECT -X POST \
        -H "Content-Type: application/json" \
        -d "$CREDS" \
        "$BACKEND_HTTPS/api/login" 2>/dev/null | pretty_json || echo "(brak odpowiedzi)"
    echo ""

    echo -e "${RED}${BOLD}[Z ATAKIEM] POST /api/login (credentials przechwycone!):${NC}"
    $CURL_MITM -X POST \
        -H "Content-Type: application/json" \
        -d "$CREDS" \
        "$BACKEND_HTTPS_DOCKER/api/login" 2>/dev/null | pretty_json || echo "(brak odpowiedzi)"
    echo ""
    label_attack "Credentials zapisane w kontenerze — sprawdź: make capture-logs"
    sep

    # ---- Test 2: GET /api/data (modyfikacja salda i tokenu) ----
    diff_line "TEST 2 — Modyfikacja danych wrażliwych GET /api/data"
    echo ""

    DIRECT_DATA=$($CURL_DIRECT "$BACKEND_HTTPS/api/data" || true)
    MITM_DATA=$($CURL_MITM "$BACKEND_HTTPS_DOCKER/api/data" || true)

    BALANCE_DIRECT=$(echo "$DIRECT_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin)['balance'])" 2>/dev/null || echo "?")
    BALANCE_MITM=$(echo "$MITM_DATA"   | python3 -c "import sys,json; print(json.load(sys.stdin)['balance'])" 2>/dev/null || echo "?")
    TOKEN_DIRECT=$(echo "$DIRECT_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_token'][:16]+'...')" 2>/dev/null || echo "?")
    TOKEN_MITM=$(echo "$MITM_DATA"     | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_token'][:16]+'...')" 2>/dev/null || echo "?")
    MITM_NOTE=$(echo "$MITM_DATA"      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('_mitm_note','<brak>'))" 2>/dev/null || echo "?")

    label_ok    "Saldo (oryginalne) : $BALANCE_DIRECT PLN"
    label_attack "Saldo (podmienione): $BALANCE_MITM PLN  ← zmodyfikowane przez MITM!"
    echo ""
    label_ok    "Token (oryginał)   : $TOKEN_DIRECT"
    label_attack "Token (podmieniony): $TOKEN_MITM"
    echo ""
    label_attack "Pole _mitm_note    : $MITM_NOTE"
    sep

    echo -e "${GREEN}${BOLD}[BEZ ATAKU] Pełna odpowiedź /api/data:${NC}"
    echo "$DIRECT_DATA" | pretty_json
    echo ""
    echo -e "${RED}${BOLD}[Z ATAKIEM] Pełna odpowiedź /api/data (ZMANIPULOWANA):${NC}"
    echo "$MITM_DATA" | pretty_json
    sep

    # ---- Test 3: curl BEZ -k (strict TLS verification) przez MITM ----
    diff_line "TEST 3 — Strict TLS verification (curl bez -k) przez mitmproxy"
    echo ""
    info "Klient z włączoną weryfikacją certyfikatu ODRZUCA certyfikat mitmproxy."
    echo ""

    STRICT_RESULT=$(curl -sS --max-time 5 --proxy "$PROXY" \
        "$BACKEND_HTTPS_DOCKER/api/data" 2>&1 || true)

    echo -e "${GREEN}${BOLD}[BEZ ATAKU]${NC} curl -s (strict) bezpośrednio do backendu:"
    STRICT_DIRECT=$(curl -s --max-time 5 "$BACKEND_HTTPS/api/data" 2>&1 || true)
    if echo "$STRICT_DIRECT" | python3 -m json.tool &>/dev/null; then
        echo "$STRICT_DIRECT" | pretty_json
    else
        echo -e "  ${RED}Błąd TLS (self-signed backend cert):${NC} $STRICT_DIRECT"
        info "Backend używa self-signed cert — klient bez -k odrzuca go tak samo."
    fi
    echo ""

    echo -e "${RED}${BOLD}[Z ATAKIEM]${NC} curl -s (strict) przez mitmproxy (BEZ zainstalowanego CA):"
    if echo "$STRICT_RESULT" | python3 -m json.tool &>/dev/null; then
        echo -e "  ${RED}UWAGA: MITM się powiódł — CA mitmproxy jest zaufany w systemie!${NC}"
        echo "$STRICT_RESULT" | pretty_json
    else
        echo -e "  ${GREEN}TLS handshake zerwany po stronie klienta (oczekiwany wynik):${NC}"
        echo "  $STRICT_RESULT"
        info "Żądanie HTTP nigdy nie dotarło do mitmproxy — w mitmweb widać tylko CONNECT lub nic."
    fi
    echo ""
    label_ok  "Strict TLS blokuje MITM — atakujący nie może zmodyfikować danych."
    label_attack "Atak działa tylko gdy: klient używa -k / ignoruje błędy cert / zainstalował CA mitmproxy."
    sep
}

# =============================================================
# SCENARIUSZ 3: SSL Pinning Bypass
# =============================================================
demo_pinning() {
    header "Scenariusz 3: SSL Pinning Bypass"

    echo ""
    info "Cel: pokazanie że mitmproxy podmienia certyfikat TLS."
    info "Aktywuj scenariusz przed demo: make scenario-pinning"
    sep

    # ---- Test 1: porównanie certyfikatów ----
    diff_line "TEST 1 — Certyfikat TLS (kto go wystawił?)"
    echo ""

    DIRECT_CERT=$($CURL_DIRECT_V "$BACKEND_HTTPS/api/health" 2>&1 | grep -E "subject:|issuer:|SSL connection using" | tr -d '\r' || true)
    MITM_CERT=$($CURL_MITM_V "$BACKEND_HTTPS_DOCKER/api/health" 2>&1 | grep -E "subject:|issuer:|SSL connection using" | tr -d '\r' || true)

    echo -e "${GREEN}${BOLD}[BEZ ATAKU] Certyfikat backendu:${NC}"
    if [ -n "$DIRECT_CERT" ]; then
        echo "$DIRECT_CERT"
    else
        # Fallback: openssl
        echo | openssl s_client -connect localhost:3443 -brief 2>/dev/null | grep -E "subject|issuer" || echo "  (uruchom: openssl s_client -connect localhost:3443 -brief)"
    fi

    echo ""
    echo -e "${RED}${BOLD}[Z ATAKIEM] Certyfikat prezentowany przez mitmproxy:${NC}"
    if [ -n "$MITM_CERT" ]; then
        echo "$MITM_CERT"
    else
        echo "  (uruchom: openssl s_client -connect localhost:3443 -proxy localhost:8080 -brief)"
    fi
    sep

    # ---- Test 2: nagłówki wskazujące na bypass ----
    diff_line "TEST 2 — Nagłówki wskazujące na SSL Pinning Bypass"
    echo ""

    DIRECT_HDRS=$($CURL_DIRECT -I "$BACKEND_HTTPS/api/health" || true)
    MITM_HDRS=$($CURL_MITM -I "$BACKEND_HTTPS_DOCKER/api/health" || true)

    BYPASS_HDR=$(echo "$MITM_HDRS" | grep -i "x-mitm-ssl-bypass" | tr -d '\r' || true)
    CERT_HDR=$(echo "$MITM_HDRS"   | grep -i "x-mitm-cert-replaced" | tr -d '\r' || true)
    BACKEND_VER_DIRECT=$(echo "$DIRECT_HDRS" | grep -i "x-backend-version" | tr -d '\r' || true)
    BACKEND_VER_MITM=$(echo "$MITM_HDRS"     | grep -i "x-backend-version" | tr -d '\r' || true)

    label_ok    "x-mitm-ssl-bypass   : <brak> (połączenie bezpośrednie)"
    label_attack "x-mitm-ssl-bypass   : ${BYPASS_HDR:-<brak — CA mitmproxy nie zainstalowane?>}"
    label_attack "x-mitm-cert-replaced: ${CERT_HDR:-<brak>}"
    echo ""
    label_ok    "$BACKEND_VER_DIRECT (nagłówek backendu — oryginał)"
    label_ok    "$BACKEND_VER_MITM   (nagłówek backendu — przez MITM)"
    sep

    # ---- Test 3: co się dzieje bez zaufanego CA mitmproxy ----
    diff_line "TEST 3 — Symulacja: co widzi klient BEZ zainstalowanego CA mitmproxy"
    echo ""
    info "Poniżej: curl bez -k (strict cert verification) przez mitmproxy:"
    STRICT_RESULT=$(curl -sS --max-time 5 --proxy "$PROXY" "$BACKEND_HTTPS_DOCKER/api/health" 2>&1 || true)
    echo -e "${RED}${BOLD}Wynik:${NC} ${STRICT_RESULT}"
    echo ""
    info "Powyższy błąd = to co widzi aplikacja z SSL Pinning (lub bez zainstalowanego CA mitmproxy)."
    info "Bypass działa tylko gdy CA mitmproxy jest zainstalowany jako zaufany (make mitm-certs + setup.sh)."
    sep
}

# =============================================================
# Main
# =============================================================
SCENARIO="${1:-all}"

echo ""
echo -e "${BOLD}${CYAN}WZIRNI Projekt — Demo MITM: BEZ ATAKU vs Z ATAKIEM${NC}"
echo -e "${DIM}Backend: $BACKEND_HTTPS | Proxy: $PROXY${NC}"

check_services

case "$SCENARIO" in
    tls)     demo_tls ;;
    tamper)  demo_tamper ;;
    pinning) demo_pinning ;;
    all)
        demo_tls
        echo ""
        demo_tamper
        echo ""
        demo_pinning
        ;;
    *)
        echo "Użycie: $0 [tls|tamper|pinning|all]"
        exit 1
        ;;
esac

echo ""
info "Demo zakończone."
info "Logi z kontenera mitmproxy : make capture-logs"
info "Wizualny podgląd ruchu     : http://localhost:8081 (mitmweb UI)"
echo ""
