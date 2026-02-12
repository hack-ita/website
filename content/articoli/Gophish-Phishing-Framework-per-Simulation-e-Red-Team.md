---
title: 'Gophish: Phishing Framework per Simulation e Red Team'
slug: gophish
description: >-
  Gophish è una piattaforma open-source per phishing simulation e red team
  engagement. Campaign management, tracking e reporting centralizzato.
image: /Gemini_Generated_Image_wfub0owfub0owfub.webp
draft: false
date: 2026-02-13T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - phising
---

Gophish è il framework open-source di riferimento per condurre campagne di [phishing](https://hackita.it/articoli/phishing) simulation durante penetration test e red team engagement. Fornisce tutto il necessario: server SMTP integration, landing page builder, email template designer e reporting dettagliato. In questa guida impari a configurare Gophish, creare campagne convincenti e catturare credenziali per dimostrare il rischio phishing ai tuoi clienti.

## Posizione nella Kill Chain

Gophish opera nelle fasi di Delivery e Initial Access:

| Fase           | Tool Precedente                                                           | Gophish                | Tool Successivo                                            |
| -------------- | ------------------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------- |
| Recon          | [TheHarvester](https://hackita.it/articoli/theharvester) email collection | → Target list creation | → Campaign launch                                          |
| Delivery       | Campaign ready                                                            | → Email delivery       | → User click                                               |
| Initial Access | User clicks                                                               | → Credential capture   | → [Evilginx2](https://hackita.it/articoli/evilginx2) proxy |
| Reporting      | Campaign complete                                                         | → Generate report      | → Client presentation                                      |

## Installazione e Setup

### Download Binary

```bash
# Scarica ultima release
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d /opt/gophish
cd /opt/gophish
chmod +x gophish
```

### Configurazione Iniziale

Modifica `config.json`:

```json
{
    "admin_server": {
        "listen_url": "0.0.0.0:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:80",
        "use_tls": false
    },
    "db_name": "sqlite3",
    "db_path": "gophish.db"
}
```

### Primo Avvio

```bash
sudo ./gophish
```

Output:

```
time="2024-01-15T10:30:00Z" level=info msg="Please login with the username admin and password: AbC123xYz"
time="2024-01-15T10:30:00Z" level=info msg="Starting admin server at https://0.0.0.0:3333"
time="2024-01-15T10:30:00Z" level=info msg="Starting phishing server at http://0.0.0.0:80"
```

Accedi a `https://YOUR_IP:3333` con le credenziali mostrate.

### Cambio Password

Al primo login, cambia la password di default.

## Configurazione SMTP

### Sending Profile

Per inviare email serve configurare SMTP. Opzioni:

**SMTP Proprio (Raccomandato per test)**

```
Name: Internal SMTP
Host: mail.yourdomain.com:25
Username: noreply@yourdomain.com
Password: smtp_password
From Address: IT Support <support@yourdomain.com>
```

**SMTP Esterno (Gmail, SendGrid)**

```
Name: SendGrid SMTP
Host: smtp.sendgrid.net:587
Username: apikey
Password: SG.xxxxx
From Address: it-security@company.com
```

### Test SMTP

Dopo configurazione, usa "Send Test Email" per verificare delivery.

## Creazione Landing Page

### Importa Sito Esistente

Gophish può clonare automaticamente pagine:

```
1. Landing Pages → New Page
2. Name: Microsoft 365 Login
3. Click "Import Site"
4. URL: https://login.microsoftonline.com
5. Check "Capture Submitted Data"
6. Check "Capture Passwords"
7. Redirect to: https://office.com
```

### Landing Page Custom

Per maggiore controllo, crea HTML custom:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Company Portal - Sign In</title>
    <style>
        body { font-family: Arial; display: flex; justify-content: center; margin-top: 100px; }
        .login-box { width: 300px; padding: 40px; border: 1px solid #ddd; }
        input { width: 100%; padding: 10px; margin: 10px 0; }
        button { width: 100%; padding: 10px; background: #0078d4; color: white; border: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Sign In</h2>
        <form method="post">
            <input type="email" name="email" placeholder="Email">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
```

## Creazione Email Template

### Template Convincente

```
Name: IT Security Alert

Subject: [Action Required] Password Expiration Notice

HTML:
```

```html
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto;">
        <img src="https://company.com/logo.png" width="150">
        <h2>Password Expiration Notice</h2>
        <p>Dear {{.FirstName}},</p>
        <p>Your corporate password will expire in <strong>24 hours</strong>.</p>
        <p>To maintain access to company resources, please update your password immediately.</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{.URL}}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px;">Update Password Now</a>
        </p>
        <p>If you did not request this change, please contact IT Support.</p>
        <hr>
        <p style="font-size: 12px; color: #666;">
            IT Security Team<br>
            This is an automated message.
        </p>
    </div>
</body>
</html>
```

### Variabili Disponibili

| Variabile          | Descrizione        |
| ------------------ | ------------------ |
| `{{.FirstName}}`   | Nome utente        |
| `{{.LastName}}`    | Cognome utente     |
| `{{.Email}}`       | Email utente       |
| `{{.Position}}`    | Posizione/ruolo    |
| `{{.URL}}`         | URL phishing unico |
| `{{.From}}`        | Mittente email     |
| `{{.TrackingURL}}` | Pixel tracking     |

## Scenari Pratici di Penetration Test

### Scenario 1: Campagna Credential Harvesting

**Timeline stimata: 2 ore setup + giorni campaign**

```bash
# COMANDO: Prepara target list (CSV)
echo "First Name,Last Name,Email,Position
John,Doe,john.doe@company.com,Manager
Jane,Smith,jane.smith@company.com,Developer" > targets.csv
```

## OUTPUT ATTESO

CSV con target importabile in Gophish

```
# Setup in Gophish UI:
1. Users & Groups → New Group → Import targets.csv
2. Landing Pages → Create Microsoft clone
3. Email Templates → Create password expiry template
4. Sending Profile → Configure SMTP
5. Campaigns → New Campaign
   - Name: Q1-2024-PasswordExpiry
   - Email Template: Password Expiration
   - Landing Page: Microsoft 365
   - URL: https://login-portal.attacker.com
   - Sending Profile: Configured SMTP
   - Groups: Target Group
   - Launch Date: Immediate
```

## OUTPUT ATTESO

```
Campaign launched successfully
Emails sent: 2
```

### COSA FARE SE FALLISCE

* **Email non arriva**: Verifica SMTP, controlla spam folder, check SPF/DKIM.
* **Link non funziona**: Verifica che phish server sia raggiungibile.
* **Tracking non funziona**: Firewall blocca immagini. Normale per alcuni client.

### Scenario 2: Spear Phishing Executive

**Timeline stimata: 3 ore**

Target: C-Level con pretesto board meeting.

```html
<!-- Template personalizzato per executive -->
Subject: Confidential: Board Meeting Materials

Dear {{.FirstName}},

The materials for tomorrow's board meeting have been uploaded to the secure portal.

Please review the Q4 financial projections before the meeting.

[Access Secure Portal]({{.URL}})

This link will expire in 24 hours for security purposes.

Best regards,
Corporate Secretary
```

### Scenario 3: Campagna Multi-Wave

**Timeline stimata: 1 settimana**

Wave 1: Generic password reset (50% targets)
Wave 2: IT maintenance notice (25% targets)\
Wave 3: Package delivery notification (25% targets)

Confronta click rate per determinare pretesti più efficaci.

### Scenario 4: Integration con Evilginx2

Per bypass 2FA, usa Gophish per delivery + Evilginx2 per landing:

```
1. In Gophish, URL della campagna punta a Evilginx2 lure
2. Evilginx2 gestisce proxy e cattura session
3. Gophish traccia open/click
4. Evilginx2 cattura credenziali e 2FA token
```

## Tecniche di Evasion

### Email Evasion

**SPF/DKIM/DMARC Compliance**

Configura record DNS corretti per il tuo sending domain:

```dns
TXT  @     "v=spf1 ip4:YOUR_IP ~all"
TXT  _dmarc "v=DMARC1; p=none"
```

**Sender Address Tricks**

```
From: IT Support <support@company.com>  # Se controlli il dominio
From: support@c0mpany.com               # Lookalike domain
From: support@company.com.attacker.com  # Subdomain trick
```

### Landing Page Evasion

**Bot Detection**

Aggiungi delay o CAPTCHA per evitare scanner automatici:

```html
<script>
setTimeout(function(){
    document.getElementById('form').style.display = 'block';
}, 2000);
</script>
```

**Geofencing**

Blocca accesso da IP non target nel server config.

## Defense Evasion

### Tecnica 1: Typosquatting Domain

Registra domini simili:

```
microsoftonline.com → microsoftonIine.com (i → I)
google.com → googIe.com
linkedin.com → linkedln.com (i → l)
```

### Tecnica 2: URL Shortener

```
1. Crea lure in Gophish
2. Accorcia con bit.ly o custom shortener
3. URL finale non mostra dominio phishing
```

### Tecnica 3: Legitimate Redirect

```html
<!-- Pagina intermedia su hosting legittimo -->
<meta http-equiv="refresh" content="0;url=https://phishing-landing.com">
```

## Integration Matrix

| Gophish +                                          | Risultato        | Workflow                            |
| -------------------------------------------------- | ---------------- | ----------------------------------- |
| [Evilginx2](https://hackita.it/articoli/evilginx2) | 2FA bypass       | Gophish delivery → Evilginx landing |
| [BeEF](https://hackita.it/articoli/beef)           | Browser hooking  | Landing include BeEF hook           |
| [Maltego](https://hackita.it/articoli/maltego)     | Target OSINT     | Maltego emails → Gophish targets    |
| [SET](https://hackita.it/articoli/set)             | Payload delivery | Gophish link → SET payload          |

## Confronto: Gophish vs Alternative

| Feature        | Gophish | King Phisher | Lucy | SET      |
| -------------- | ------- | ------------ | ---- | -------- |
| Open Source    | ✓       | ✓            | ✗    | ✓        |
| Web UI         | ✓       | ✓            | ✓    | ✗        |
| Reporting      | ✓       | ✓            | ✓    | Limitato |
| Site Clone     | ✓       | ✓            | ✓    | ✓        |
| API            | ✓       | ✓            | ✓    | ✗        |
| Learning Curve | Bassa   | Media        | Alta | Bassa    |

## Detection e Countermeasures

### Cosa Cerca il Blue Team

* Header X-Gophish-Contact
* Pattern URL con RID parameter
* Landing page clone identiche
* SMTP source analysis

### Evasion

1. **Modifica header** in source code prima di compilare
2. **Randomizza URL parameter** name
3. **Customizza landing** invece di clone diretto

## Reporting

Gophish genera report automatici:

```
Dashboard → Campaign → Export
- CSV: raw data
- PDF: executive summary
```

Metriche chiave:

* **Emails Sent**: totale inviate
* **Emails Opened**: tracking pixel loaded
* **Clicked Link**: utente ha cliccato
* **Submitted Data**: credenziali inserite

## Troubleshooting

### Email finisce in spam

```
# Verifica configurazione
1. SPF record corretto
2. DKIM signing attivo
3. Domain reputation check
4. Content non troppo "spammy"
```

### Tracking non funziona

Molti client bloccano immagini esterne. Considera:

* Click tracking più affidabile di open tracking
* Pixel tracking supplementare, non primario

### Landing page non carica

```bash
# Verifica phish server
curl -I http://YOUR_IP:80
```

Se timeout: firewall o servizio non attivo.

## Cheat Sheet

| Operazione      | Azione                                   |
| --------------- | ---------------------------------------- |
| Start Gophish   | `sudo ./gophish`                         |
| Admin Panel     | `https://IP:3333`                        |
| Default User    | `admin` (password in stdout)             |
| Import Targets  | CSV: First Name,Last Name,Email,Position |
| Clone Site      | Landing Pages → Import Site              |
| Test SMTP       | Sending Profiles → Send Test Email       |
| Launch Campaign | Campaigns → New Campaign → Launch        |
| Export Report   | Campaign → Export CSV/PDF                |

## FAQ

**Le email arrivano in spam, come risolvo?**

Configura SPF/DKIM, usa dominio con buona reputation, evita keyword spam nel contenuto.

**Posso tracciare chi apre l'email?**

Sì con tracking pixel, ma molti client bloccano immagini. Il click tracking è più affidabile.

**Come evito che IT rilevi la campagna?**

Coordina con il cliente, usa dominio plausibile, non targetizzare IT staff se non necessario.

**Gophish funziona con 2FA?**

Gophish cattura solo credenziali. Per 2FA bypass, integra con [Evilginx2](https://hackita.it/articoli/evilginx2).

**Quanto deve durare una campagna?**

Tipicamente 1-5 giorni. Più lunga = più dati, ma più rischio di rilevamento.

**È legale fare phishing simulation?**

Solo con autorizzazione scritta del cliente. Per campagne professionali, [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Gophish GitHub](https://github.com/gophish/gophish) | [Gophish Docs](https://docs.getgophish.com/)
