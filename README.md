# WZIRNI Project - Mobile-to-Backend MITM Lab

An environment for analyzing HTTPS traffic with MITM attacks (TLS Downgrade, Traffic Tampering, SSL Pinning Bypass).

## Architecture

```
  macOS (host)                Docker (172.20.0.0/24)
  ┌────────────────┐          ┌─────────────┐    ┌─────────────┐
  │ Android Studio │─────────▶│  mitmproxy  │───▶│   Backend   │
  │   Emulator     │  proxy   │   (MITM)    │    │  Node.js    │
  │   (native)     │ :8080    │ 172.20.0.20 │    │ 172.20.0.10 │
  └────────────────┘          │  :8081 UI   │    │  :3443 HTTPS│
                              └─────────────┘    └─────────────┘
```

> The Android emulator runs **natively on macOS** (Android Studio).
> The backend and mitmproxy run in Docker containers.

## Requirements

- Docker + Docker Compose
- Android Studio with an installed emulator (API 28, Android 9.0, arm64-v8a, Google APIs)
- `adb` available in PATH (`which adb`)
- `openssl` (`brew install openssl`)

> **Android 9.0 (API 28) — important limitations:**
> - Apps targeting API 28+ block cleartext HTTP traffic by default (`android:usesCleartextTraffic=false`). The TLS Downgrade scenario may not work for native apps, but it works in the Chrome browser.
> - User certificates are not trusted by apps targeting API 24+. Installation into the system store (`/system/etc/security/cacerts/`) via `setup.sh` is required.
> - Network Security Configuration (NSC) lets apps define their own trust rules and certificate pinning in an XML file.

## Quick start

### 1. Start the containers

```bash
make build
make up
```

Interfaces after startup:
- **mitmweb UI**: http://localhost:8081
- **Backend HTTPS**: https://localhost:3443/api/health
- **Backend HTTP**: http://localhost:3000 (redirect → HTTPS)

### 2. Start the emulator in Android Studio

Launch an AVD with API 28 (Android 9.0, Google APIs). SSL Pinning Bypass requires root access and a writable `/system`:

```bash
# Emulator with a writable /system (required to install the CA into the system store):
EMULATOR=$(emulator -list-avds)
emulator @"$EMULATOR" -writable-system &
adb root && adb disable-verity && adb reboot
adb wait-for-device && adb root && adb remount
```

> A Google APIs image is required (not Google Play) — the Play Store blocks `adb root`.

### 3. Configure the proxy and CA certificate

```bash
bash android/setup.sh
```

The script (run on the macOS host):
1. Waits for the emulator to be ready
2. Sets the proxy → `10.0.2.2:8080` (`10.0.2.2` = the macOS host from the emulator's perspective)
3. Exports the CA certificate from the Docker container (`docker cp`)
4. Copies the CA onto the emulator (`/data/local/tmp/`) and installs it into the system store (only if root + `-writable-system`); without root — requires manual installation via `Settings > Security > Install Certificate`

### 4. Test the connection

```bash
# Opens the browser on the emulator - the request will pass through mitmproxy:
adb shell am start -a android.intent.action.VIEW -d 'http://10.0.2.2:3000/api/health'

# The intercepted traffic is visible in mitmweb: http://localhost:8081
```

---

## Attack scenarios

### 1. TLS Downgrade

```bash
make scenario-tls
```

- Removes `Strict-Transport-Security` (HSTS) headers — enabling a future downgrade
- Rewrites `https://` → `http://` links in the response body
- Logs unencrypted HTTP requests if the client sends them after the downgrade
- Observe the traffic in mitmweb: http://localhost:8081

### 2. Traffic Tampering

```bash
make scenario-tamper
```

- Captures login credentials from `POST /api/login`
- Modifies the `/api/data` response (token substitution, balance change)
- Injects JavaScript into the HTML response

Logs of captured data:
```bash
make capture-logs
```

### 3. SSL Pinning Bypass

```bash
make scenario-pinning
```

- mitmproxy presents its own certificate instead of the server's certificate
- Works when the device trusts the mitmproxy CA (installed via `setup.sh`)
- Without the CA installed → the emulator rejects the certificate (TLS handshake fail)

> Requires the emulator to be started with `-writable-system` for the system trust store.

### All scenarios at once

```bash
make scenario-all
```

---

## Analyzing the results

```bash
make capture-logs    # credentials, traffic log, SSL pinning log
make mitm-logs       # live logs of the mitmproxy container
make backend-logs    # live logs of the backend
```

---

## Managing the environment

```bash
make up              # start the containers
make down            # stop the containers
make build           # rebuild the images from scratch
make clean           # remove containers, volumes, and images
make shell-mitm      # shell in the mitmproxy container
make shell-backend   # shell in the backend container
make help            # list all commands
```
