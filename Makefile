# =========================================================
# WZIRNI Projekt - Makefile
# Zarządzanie środowiskiem laboratoryjnym
# =========================================================

.PHONY: up down build logs backend-logs mitm-logs \
        scenario-tls scenario-tamper scenario-pinning scenario-all \
        demo-tls demo-tamper demo-pinning demo-all \
        mitm-certs shell-backend shell-mitm \
        capture-logs clean

# ---------------------------------------------------------
# Podstawowe operacje
# ---------------------------------------------------------

up: ## Uruchom całe środowisko
	docker compose up -d
	@echo ""
	@echo "Środowisko uruchomione:"
	@echo "  mitmweb UI:      http://localhost:8081"
	@echo "  Backend HTTP:    http://localhost:3000"
	@echo "  Backend HTTPS:   https://localhost:3443"

down: ## Zatrzymaj środowisko
	docker compose down

build: ## Zbuduj obrazy Docker
	docker compose build --no-cache

logs: ## Logi wszystkich kontenerów
	docker compose logs -f

backend-logs: ## Logi backendu
	docker compose logs -f backend

mitm-logs: ## Logi mitmproxy
	docker compose logs -f mitm


# ---------------------------------------------------------
# Scenariusze ataków
# ---------------------------------------------------------

scenario-tls: ## Scenariusz 1: TLS Downgrade
	@echo "[*] Uruchamianie scenariusza TLS Downgrade..."
	MITM_SCRIPT=/scripts/tls_downgrade.py docker compose up -d --force-recreate mitm
	@echo "[+] TLS Downgrade aktywny. UI: http://localhost:8081"

scenario-tamper: ## Scenariusz 2: Traffic Tampering
	@echo "[*] Uruchamianie scenariusza Traffic Tampering..."
	MITM_SCRIPT=/scripts/traffic_tamper.py docker compose up -d --force-recreate mitm
	@echo "[+] Traffic Tampering aktywny. Logi: /tmp/mitm_traffic.log"

scenario-pinning: ## Scenariusz 3: SSL Pinning Bypass
	@echo "[*] Uruchamianie scenariusza SSL Pinning Bypass..."
	MITM_SCRIPT=/scripts/ssl_pinning_bypass.py docker compose up -d --force-recreate mitm
	@echo "[+] SSL Pinning Bypass aktywny."

scenario-all: ## Wszystkie scenariusze naraz
	@echo "[*] Uruchamianie wszystkich scenariuszy..."
	MITM_SCRIPT=/scripts/all_scenarios.py docker compose up -d --force-recreate mitm
	@echo "[+] Wszystkie scenariusze aktywne."

demo-tls: ## Demo porównawcze: TLS Downgrade (BEZ ATAKU vs Z ATAKIEM)
	@echo "[*] Aktywuję scenariusz TLS Downgrade..."
	MITM_SCRIPT=/scripts/tls_downgrade.py docker compose up -d --force-recreate mitm
	@echo "[*] Czekam na gotowość mitmproxy..."
	@sleep 5
	@bash demo.sh tls

demo-tamper: ## Demo porównawcze: Traffic Tampering (BEZ ATAKU vs Z ATAKIEM)
	@echo "[*] Aktywuję scenariusz Traffic Tampering..."
	MITM_SCRIPT=/scripts/traffic_tamper.py docker compose up -d --force-recreate mitm
	@echo "[*] Czekam na gotowość mitmproxy..."
	@sleep 5
	@bash demo.sh tamper

demo-pinning: ## Demo porównawcze: SSL Pinning Bypass (BEZ ATAKU vs Z ATAKIEM)
	@echo "[*] Aktywuję scenariusz SSL Pinning Bypass..."
	MITM_SCRIPT=/scripts/ssl_pinning_bypass.py docker compose up -d --force-recreate mitm
	@echo "[*] Czekam na gotowość mitmproxy..."
	@sleep 5
	@bash demo.sh pinning

demo-all: ## Demo porównawcze: wszystkie 3 scenariusze po kolei
	@echo "[*] Uruchamianie demo TLS Downgrade..."
	$(MAKE) demo-tls
	@echo ""
	@echo "[*] Uruchamianie demo Traffic Tampering..."
	$(MAKE) demo-tamper
	@echo ""
	@echo "[*] Uruchamianie demo SSL Pinning Bypass..."
	$(MAKE) demo-pinning

# ---------------------------------------------------------
# Certyfikat CA mitmproxy
# ---------------------------------------------------------

mitm-certs: ## Eksportuj certyfikat CA mitmproxy na hosta
	docker cp wzirni-mitm:/root/.mitmproxy/mitmproxy-ca-cert.pem ./mitm-ca.pem
	@echo "[+] Certyfikat CA zapisany: ./mitm-ca.pem"
	@echo "    Instalacja na emulatorze: bash android/setup.sh"

# ---------------------------------------------------------
# Dostęp do powłoki
# ---------------------------------------------------------

shell-backend: ## Shell w kontenerze backend
	docker exec -it wzirni-backend sh

shell-mitm: ## Shell w kontenerze mitm
	docker exec -it wzirni-mitm bash

# ---------------------------------------------------------
# Analiza ruchu
# ---------------------------------------------------------

capture-logs: ## Wyświetl przechwycone logi
	@echo "=== Traffic Tamper Log ==="
	docker exec wzirni-mitm cat /tmp/mitm_traffic.log 2>/dev/null || echo "(brak)"
	@echo ""
	@echo "=== Captured Credentials ==="
	docker exec wzirni-mitm cat /tmp/captured_credentials.log 2>/dev/null || echo "(brak)"
	@echo ""
	@echo "=== SSL Pinning Log ==="
	docker exec wzirni-mitm cat /tmp/ssl_pinning_log.log 2>/dev/null || echo "(brak)"

# ---------------------------------------------------------
# Czyszczenie
# ---------------------------------------------------------

clean: ## Usuń kontenery, wolumeny i obrazy
	docker compose down -v --remove-orphans
	docker image rm wzirni-backend wzirni-mitm 2>/dev/null || true

help: ## Wyświetl pomoc
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	    awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
