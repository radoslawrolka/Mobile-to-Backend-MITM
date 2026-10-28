FROM mitmproxy/mitmproxy:10

# Kopiowanie skryptów ataków
COPY scripts/ /scripts/

# Weryfikacja instalacji (CA generuje się przy pierwszym uruchomieniu kontenera)
RUN mitmproxy --version

EXPOSE 8080 8081

# MITM_SCRIPT - opcjonalna ścieżka do skryptu addona (ustawiana przez docker compose)
ENV MITM_SCRIPT=""

# Shell form - żeby $MITM_SCRIPT był interpretowany jako zmienna środowiskowa
CMD mitmweb \
    --web-host 0.0.0.0 \
    --web-port 8081 \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set ssl_insecure=true \
    --set confdir=/root/.mitmproxy \
    --map-remote "|://10.0.2.2:|://backend:" \
    ${MITM_SCRIPT:+-s $MITM_SCRIPT}
