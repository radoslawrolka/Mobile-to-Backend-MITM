"""
Wszystkie scenariusze naraz - do pełnej analizy ruchu
=====================================================
Łączy: TLS Downgrade + Traffic Tampering + SSL Pinning Bypass

Uruchomienie:
    docker exec wzirni-mitm mitmweb --listen-port 8080 -s /scripts/all_scenarios.py
"""

# Importuj i załaduj wszystkie addony
import importlib.util

_scripts = ["tls_downgrade", "traffic_tamper", "ssl_pinning_bypass"]
addons = []

for name in _scripts:
    spec = importlib.util.spec_from_file_location(name, f"/scripts/{name}.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "addons"):
        addons.extend(mod.addons)
