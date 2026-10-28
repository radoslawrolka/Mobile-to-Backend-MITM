FROM node:20-alpine

WORKDIR /app

# Instalacja openssl do generowania certyfikatów
RUN apk add --no-cache openssl

# Zależności
COPY package*.json ./
RUN npm install --omit=dev

# Kod aplikacji
COPY . .

# Generowanie self-signed certyfikatu serwera (z SAN dla SSL pinning)
RUN mkdir -p certs && \
    openssl req -x509 -newkey rsa:4096 \
      -keyout certs/server.key \
      -out certs/server.crt \
      -days 365 -nodes \
      -subj "/CN=backend/O=WZIRNI-Lab/C=PL" \
      -addext "subjectAltName=DNS:backend,DNS:localhost,IP:172.20.0.10,IP:127.0.0.1"

# Eksport publicznego klucza do SSL pinning (SHA-256 SPKI hash)
RUN openssl x509 -in certs/server.crt -pubkey -noout | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    openssl enc -base64 > certs/spki_pin.txt && \
    echo "Server SPKI pin:" && cat certs/spki_pin.txt

EXPOSE 3000 3443

CMD ["node", "server.js"]
