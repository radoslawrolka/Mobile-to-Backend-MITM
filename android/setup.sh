#!/usr/bin/env bash
# =============================================================
# Konfiguracja emulatora Androida (macOS - Android Studio AVD)
# =============================================================
# Uruchom ten skrypt na HOŚCIE (macOS), nie w kontenerze.
# Wymaga: adb zainstalowanego (Android Studio SDK)
#
# Przed uruchomieniem:
#   1. Uruchom emulator w Android Studio (API 28 z google apis, arm64-v8a)
#   2. Uruchom kontenery: make up
#   3. Uruchom ten skrypt: bash android/setup.sh
# =============================================================

set -e

MITM_PROXY="10.0.2.2:8080"   # 10.0.2.2 = host macOS z perspektywy emulatora Androida
CERT_TMP="/tmp/mitmproxy-ca-cert.pem"

echo "============================================"
echo " WZIRNI Android Emulator Setup (macOS)"
echo " Android 9.0 / API 28"
echo "============================================"

# Czekaj na emulator
echo "[1/4] Czekam na gotowość emulatora ADB..."
adb wait-for-device
adb root
sleep 2 # Krótka pauza na restart adbd

# Android 9 (API 28): disable-verity wymagane przed remount przy verified boot
echo "      Próba wyłączenia verified boot (Android 9 / API 28)..."
if adb disable-verity 2>/dev/null | grep -q "Verity already disabled\|disabled"; then
    echo "      Verified boot wyłączony. Restartowanie..."
    adb reboot
    adb wait-for-device
    adb root
    sleep 3
elif adb disable-verity 2>/dev/null | grep -q "Now reboot"; then
    echo "      disable-verity wymaga restartu. Restartowanie..."
    adb reboot
    adb wait-for-device
    adb root
    sleep 3
fi

# Sprawdzenie czy remount jest możliwy
if adb remount 2>&1 | grep -qiE "succeeded|remount succeeded"; then
    MOUNT_OK=true
    echo "      System jest zapisywalny (remount succeeded)."
else
    MOUNT_OK=false
    echo "      UWAGA: /system jest read-only. Uruchom emulator z flagą -writable-system."
fi

# 2. Ustaw proxy (Android 9 wymaga ustawienia zarówno http_proxy jak i global_http_proxy)
echo "[2/4] Ustawienie proxy -> ${MITM_PROXY}..."
adb shell settings put global http_proxy "${MITM_PROXY}"
# Dodatkowe ustawienia proxy dla Android 9 (API 28)
adb shell settings put global global_http_proxy_host "10.0.2.2"
adb shell settings put global global_http_proxy_port "8080"
adb shell settings put global global_http_proxy_exclusion_list "localhost,127.0.0.1"
echo "      Proxy ustawione (http_proxy + global_http_proxy)."

# Eksportuj certyfikat CA mitmproxy z kontenera
echo "[3/4] Eksport certyfikatu CA z Docker..."
if ! docker cp wzirni-mitm:/root/.mitmproxy/mitmproxy-ca-cert.pem "${CERT_TMP}" 2>/dev/null; then
    echo "BŁĄD: Nie można pobrać certyfikatu z kontenera 'wzirni-mitm'."
    exit 1
fi

# 4. Instalacja certyfikatu
echo "[4/4] Instalacja certyfikatu CA..."
CERT_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "${CERT_TMP}" | head -1)
adb push "${CERT_TMP}" "/data/local/tmp/${CERT_HASH}.0"

if [ "$MOUNT_OK" = true ]; then
    # Instalacja bezpośrednio do System Store
    adb shell "cp /data/local/tmp/${CERT_HASH}.0 /system/etc/security/cacerts/"
    adb shell "chmod 644 /system/etc/security/cacerts/${CERT_HASH}.0"
    echo "      SUKCES: Certyfikat zainstalowany w System Store."
else
    echo "      BŁĄD: Nie można zapisać w /system."
    echo "      Uruchom emulator komendą: emulator @Twoja_Nazwa -writable-system"
    exit 1
fi

echo ""
echo "============================================"
echo " Setup zakończony!"
echo "============================================"
echo " Android proxy:  ${MITM_PROXY}"
echo " mitmweb UI:     http://localhost:8081"
echo " Backend HTTPS:  https://localhost:3443/api/health"
echo ""
echo " Test połączenia (otwiera przeglądarkę na emulatorze):"
echo "   adb shell am start -a android.intent.action.VIEW -d 'http://10.0.2.2:3000/api/health'"
echo ""
echo " Sprawdź przechwycony ruch w mitmweb: http://localhost:8081"
echo "============================================"
