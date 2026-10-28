'use strict';

const express = require('express');
const https   = require('https');
const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const morgan  = require('morgan');
const crypto  = require('crypto');

// =========================================================
// Konfiguracja
// =========================================================
const HTTP_PORT  = 3000;
const HTTPS_PORT = 3443;
const CERTS_DIR  = path.join(__dirname, 'certs');

// =========================================================
// Aplikacja Express
// =========================================================
const app = express();

app.use(morgan('combined'));
app.use(express.json());

// ---------------------------------------------------------
// Nagłówki bezpieczeństwa
// ---------------------------------------------------------
app.use((req, res, next) => {
  // HSTS - wymusza HTTPS na kolejne 1 rok
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Backend-Version', '1.0.0');
  next();
});

// ---------------------------------------------------------
// Endpointy API
// ---------------------------------------------------------

/** GET /api/health  - sprawdzenie stanu serwera */
app.get('/api/health', (req, res) => {
  const host = req.headers.host || 'localhost:3443';
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    tls: req.socket.encrypted ? 'yes' : 'no',
    api_url: `https://${host}/api/data`,
    login_url: `https://${host}/api/login`
  });
});

/** GET /api/data  - wrażliwe dane (cel Traffic Tampering) */
app.get('/api/data', (req, res) => {
  res.json({
    message: 'Sensitive backend data',
    user: 'testuser',
    balance: 9999.99,
    secret_token: crypto.randomBytes(16).toString('hex')
  });
});

/** POST /api/login  - logowanie (cel przechwytywania danych) */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  console.log(`[AUTH] Login attempt: user=${username}`);

  if (username === 'admin' && password === 'password123') {
    res.json({
      success: true,
      token: 'eyJhbGciOiJIUzI1NiJ9.test_jwt_token',
      user: { id: 1, name: 'Admin', role: 'admin' }
    });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

/** GET /api/pinning-info  - informacje o SSL Pinning */
app.get('/api/pinning-info', (req, res) => {
  let spkiPin = 'unknown';
  try {
    spkiPin = fs.readFileSync(path.join(CERTS_DIR, 'spki_pin.txt'), 'utf8').trim();
  } catch {}
  res.json({ spki_sha256: spkiPin, algorithm: 'sha256/base64' });
});

// ---------------------------------------------------------
// Serwer HTTP - serwuje content bezpośrednio (cel TLS Downgrade)
// Normalnie serwer powinien tu tylko redirectować do HTTPS.
// W labie celowo serwujemy też przez HTTP żeby pokazać downgrade.
// ---------------------------------------------------------
const httpApp = express();
httpApp.use(express.json());
httpApp.use(morgan('combined'));

// API dostępne przez HTTP - pokazuje tls: no po downgrade
httpApp.use(app);

// ---------------------------------------------------------
// Serwer HTTPS
// ---------------------------------------------------------
const httpsOptions = {
  key:  fs.readFileSync(path.join(CERTS_DIR, 'server.key')),
  cert: fs.readFileSync(path.join(CERTS_DIR, 'server.crt')),
  // Minimalna wersja TLS - obrona przed TLS Downgrade
  minVersion: 'TLSv1.2',
  // Dozwolone cipher suites (tylko silne)
  ciphers: [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384'
  ].join(':'),
  honorCipherOrder: true
};

http.createServer(httpApp).listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`[HTTP]  Listening on :${HTTP_PORT} (redirects to HTTPS)`);
});

https.createServer(httpsOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
  console.log(`[HTTPS] Listening on :${HTTPS_PORT}`);
  console.log(`[TLS]   Min version: TLSv1.2 | HSTS enabled`);
  try {
    const pin = fs.readFileSync(path.join(CERTS_DIR, 'spki_pin.txt'), 'utf8').trim();
    console.log(`[PIN]   SPKI SHA256: ${pin}`);
  } catch {}
});
