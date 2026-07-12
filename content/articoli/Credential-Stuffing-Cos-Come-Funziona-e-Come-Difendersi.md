---
title: 'Credential Stuffing: Cos’è, Come Funziona e Come Difendersi'
slug: credential-stuffing
description: 'Credential stuffing: scopri come funziona l’attacco con credenziali rubate, come rilevarlo e quali difese usare tra MFA, passkey e rate limiting.'
image: /credential-stuffing-attacco-riutilizzo-credenziali.webp
draft: true
date: 2026-07-19T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - credential stuffing
  - credenziali rubate
  - account takeover
  - password reuse
  - bot detection
---

# Credential Stuffing: Come Funziona, Rilevarlo e Difendersi

Il credential stuffing è un attacco automatizzato che testa coppie username/password già valide, rubate da breach di terze parti o infostealer, contro il login di un servizio diverso da quello di origine — sfrutta il riuso delle password, non una vulnerabilità tecnica.

***

Il credential stuffing sfrutta una debolezza estremamente comune: il riutilizzo della stessa combinazione email/password su servizi differenti. Nel giugno 2025 sono stati individuati circa 16 miliardi di record di autenticazione distribuiti tra numerosi dataset, in parte sovrapposti e alimentati da leak precedenti e infostealer — non un singolo nuovo breach, né necessariamente 16 miliardi di credenziali uniche.

L'analisi Verizon 2025 sui log dei provider SSO ha rilevato che il credential stuffing rappresentava una mediana del 19% dei tentativi quotidiani di autenticazione, con punte fino al 25% nelle organizzazioni enterprise. Il riutilizzo delle password è diffuso ed è la condizione fondamentale che rende possibile questo attacco, come documentano OWASP e MITRE.

> **Key Takeaway:** il credential stuffing non deve violare direttamente il sistema che attacca. Usa credenziali già valide e cerca gli account dove la stessa password è stata riutilizzata — bypassa firewall, EDR e antivirus perché non c'è nulla di "anomalo" nella singola richiesta.

Classificato da MITRE ATT\&CK come [T1110.004](https://attack.mitre.org/techniques/T1110/004/).

***

## Come Funziona

l'attaccante prende coppie username/password già associate da un breach, le automatizza contro un servizio diverso, distribuendo i tentativi su molti IP per eludere rate limiting.

```
Breach database / dark web / infostealer
    ↓
Combo list: coppie username:password già associate
    ↓
Automazione + proxy pool distribuito (residenziali, botnet)
    ↓
Test su target (login aziendale, VPN, webmail, portali SaaS, API mobile)
    ↓
Account takeover sulle credenziali riusate
    ↓
Lateral movement, data theft, BEC fraud
```

Gli attaccanti distribuiscono i tentativi su migliaia di IP tramite proxy residenziali, mimano il comportamento di utenti reali (user-agent, timing randomizzato) e adattano la configurazione al login flow specifico del target.

***

## Tooling Usato Realmente dagli Attaccanti

**Answer capsule:** in campagne reali gli attaccanti non scrivono script custom da zero — usano tool dedicati come OpenBullet, SentryMBA e Snipr, con "config" già pronte per centinaia di siti target, condivise nelle community underground.

* **OpenBullet / OpenBullet2** — il tool più diffuso, open source, basato su file di configurazione (`.loli`/`.opk`) che definiscono request, parsing della risposta e criteri di successo per un target specifico
* **SentryMBA** — uno dei primi tool dedicati al credential stuffing, con architettura simile: config per sito + combo list + proxy list
* **Snipr** — tool con interfaccia semplificata, popolare per target consumer (gaming, streaming, e-commerce)

Il workflow tipico con questi tool:

```
1. Acquisizione combo list (breach, infostealer, dark web market)
2. Ricerca o creazione di una "config" per il sito target
   (definisce endpoint di login, parametri, pattern di successo/fallimento)
3. Caricamento di una lista di proxy (spesso residenziali, per distribuire i tentativi)
4. Avvio del bot: tenta ogni coppia della combo list attraverso i proxy
5. Output: lista di "hits" (coppie valide) da monetizzare o rivendere
```

Le "config" per i tool più diffusi vengono condivise, vendute o scambiate in forum e canali Telegram dedicati — conoscerne l'esistenza aiuta a capire perché anche piattaforme di nicchia possono essere bersaglio di campagne mirate, non solo i grandi provider.

Il tasso di successo per singolo tentativo è tipicamente stimato tra lo 0,1% e il 2% su liste di buona qualità — basso in percentuale, ma su combo list da milioni di coppie produce comunque migliaia di account validi per singola campagna.

***

## Fonti delle Credenziali

* **Breach di terze parti** — database di servizi compromessi, spesso aggregati in collection più grandi
* **Infostealer** — malware che estrae credenziali da browser e le carica su C2 controllati dall'attaccante
* **Phishing** — credenziali raccolte da campagne AiTM o fake login page (vedi [credential harvesting](https://hackita.it/articoli/credential-harvesting/))
* **Dark web market** — combo list vendute come commodity

```bash
# Verifica se un'email aziendale compare in breach noti
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@company.com" \
  -H "hibp-api-key: <API_KEY>"
```

***

## Differenza con Password Spraying e Brute Force

**Answer capsule:** il credential stuffing usa coppie già valide da un breach, il password spraying prova poche password comuni su molti account, il brute force genera sistematicamente combinazioni — sono tre attacchi distinti con logiche di detection diverse.

| Tecnica                 | Credenziali usate                       | Volume     | Lockout risk                    |
| ----------------------- | --------------------------------------- | ---------- | ------------------------------- |
| **Credential stuffing** | Coppie reali già associate (da breach)  | Molto alto | Alto se non distribuito         |
| **Password spraying**   | Poche password comuni per molti account | Medio      | Basso (progettato per eluderlo) |
| **Brute force**         | Dizionario/permutazioni su un account   | Molto alto | Alto                            |

In un pentest la distinzione è sostanziale: il credential stuffing verifica se le credenziali dei dipendenti sono già compromesse e riusate; il [password spraying](https://hackita.it/articoli/password-spraying/) verifica l'efficacia delle policy password.

***

## Testare le Difese: Metodologia Corretta

**Answer capsule:** un test di credential stuffing autorizzato usa coppie username/password sintetiche e già associate tra loro, mai wordlist generiche come rockyou.txt — altrimenti si sta simulando un brute force, non un credential stuffing.

Un loop che prova molte password diverse su un solo username, o un dizionario come rockyou.txt con Hydra, simula un **brute force su singolo account**, non credential stuffing. Il credential stuffing prova coppie già accoppiate, tipicamente ottenute (in un test autorizzato) da un set sintetico creato ad hoc.

Metodologia corretta per un assessment:

1. Creare account sintetici dedicati al test
2. Generare coppie username/password sintetiche e controllate, approvate dal cliente
3. Usare un ambiente di staging quando disponibile
4. Concordare un numero massimo di tentativi
5. Definire una stop condition per evitare lockout e interruzioni di servizio
6. Misurare rate limiting, challenge presentate, tempo di alert, latenza di detection
7. Non usare mai credenziali reali trovate in leak pubblici, nemmeno in un test autorizzato

```bash
# Esempio concettuale — coppie sintetiche pre-accoppiate, non wordlist generica
# username:password già associati, creati per il test, numero limitato e concordato
cat synthetic_pairs.txt
# testuser01:Sy1nth#Pair!
# testuser02:Sy2nth#Pair!

# Test con numero di tentativi limitato e stop condition esplicita
while read -r pair; do
  user=$(echo "$pair" | cut -d: -f1)
  pass=$(echo "$pair" | cut -d: -f2)
  curl -s -o /dev/null -w "%{http_code} $user\n" \
    -X POST https://staging.target.com/login \
    -d "username=$user&password=$pass"
  sleep 1
done < synthetic_pairs.txt
```

Verifica di rate limiting: osservare se compare HTTP 429, se viene presentata una challenge adattiva, e dopo quanti tentativi — senza superare la soglia concordata con il cliente.

***

## Pwned Passwords e Controllo Preventivo

La sezione su Pwned Passwords resta valida: il servizio usa k-anonymity, riceve solo i primi 5 caratteri dell'hash SHA-1 (o NTLM), mai la password in chiaro.

```bash
hash=$(echo -n "Password123" | sha1sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')
prefix=${hash:0:5}
suffix=${hash:5}
curl "https://api.pwnedpasswords.com/range/$prefix" | grep "^$suffix"
```

Tre precisazioni importanti:

* una password trovata nel corpus va rifiutata, ma l'assenza dal corpus **non garantisce** che sia forte
* il controllo va eseguito sia in creazione che in cambio password
* il monitoring di un dominio aziendale richiede verifica del dominio e un piano commerciale adatto

NIST richiede esplicitamente che le nuove password vengano confrontate con una blocklist di valori comuni, prevedibili o già compromessi.

***

## Detection Lato Difensore

**Answer capsule:** la detection non deve mai basarsi sul confronto di password in chiaro nei log — si basa su rapporto tentativi/account, fingerprint distribuiti e pattern comportamentali, con soglie adattive e non fisse.

Un'applicazione sicura non registra le password inserite, nemmeno quelle errate — quindi la detection non può e non deve correlare "la stessa password testata su più account".

Segnali utili:

* molti username distinti provati dalla stessa sorgente o dallo stesso fingerprint
* pochi tentativi per singolo account, ma volume complessivo molto alto
* picchi nel rapporto login falliti/riusciti
* richieste da IP diversi ma con fingerprint, header o comportamento simile (indicano automazione distribuita)
* accesso riuscito da nuovo device dopo una serie di errori sullo stesso account
* accessi da geolocalizzazione o ASN incompatibili con lo storico
* login automatizzati contro API mobile, SSO, VPN, RDP o SaaS
* sequenze di errori "low and slow" distribuite nel tempo

MITRE ha pubblicato una strategia di detection dedicata, [DET0460](https://attack.mitre.org/detectionstrategies/DET0460/), che copre identity provider, SaaS, Windows, Linux, macOS, rete e container.

Le soglie vanno adattive, non fisse: un numero di tentativi "anomalo" per una piccola VPN aziendale può essere del tutto normale per una piattaforma con milioni di utenti. Vanno calibrate su baseline dello specifico endpoint, utenti unici coinvolti, rapporto failure/success, IP/ASN, storico dell'account e fascia oraria. IP residenziali, VPN e Tor sono **segnali di rischio da pesare**, non motivo automatico di blocco.

***

## Rate Limiting e Lockout: Oltre il Semplice "N per IP"

**Answer capsule:** un rate limit basato solo su IP è facilmente aggirato da un botnet distribuito; serve uno scoring combinato su più dimensioni, e il lockout rigido può diventare esso stesso un vettore di denial-of-service.

Dimensioni da combinare nello scoring:

* account
* indirizzo IP
* subnet/ASN
* device o browser fingerprint
* sessione
* endpoint
* numero di username distinti tentati
* intervallo temporale

Un lockout troppo rigido permette a un attaccante di bloccare deliberatamente migliaia di account (DoS mirato) — OWASP raccomanda cautela nella progettazione. Approccio progressivo consigliato:

1. ritardo crescente
2. challenge adattiva
3. autenticazione step-up (richiesta di secondo fattore aggiuntivo)
4. limitazione temporanea, non permanente
5. blocco solo per rischio elevato correlato
6. notifica all'utente

Nota: HTTP 423 non va usato come indicatore universale — la risposta visibile al client dovrebbe restare generica per evitare user enumeration.

***

## CAPTCHA e Bot Detection: Non Sono Sinonimi

Il CAPTCHA aumenta il costo dell'automazione ma non blocca browser automatizzati avanzati né servizi di risoluzione umana su commissione. Va usato in modo adattivo (solo su pattern sospetti, non su ogni login) e non sostituisce una difesa stratificata: da solo non impedisce l'account takeover quando l'attaccante possiede già credenziali valide.

***

## Attacchi Distribuiti e Low-and-Slow

**Answer capsule:** proxy residenziali e botnet permettono di mantenere pochi tentativi per singolo IP, rendendo inefficace un blocco basato solo sul volume per indirizzo.

Il blocco per singolo IP non basta quando l'attaccante ha migliaia di indirizzi a disposizione: ogni IP genera un volume di richieste che sembra normale, ma l'insieme rivela il pattern. La detection efficace deve correlare a livello di campagna — stesso fingerprint TLS/JA3, stesso comportamento di timing, stesso set di username target — non a livello di singolo indirizzo.

***

## Superfici di Attacco

Il credential stuffing non colpisce solo il form di login web:

* API di autenticazione dirette
* applicazioni mobile
* portali SSO
* webmail
* VPN
* RDP e servizi di accesso remoto
* piattaforme SaaS
* account consumer collegati a servizi aziendali
* endpoint di recovery e reset password (spesso meno protetti del login principale)

***

## Account Takeover dopo il Login Riuscito

**Answer capsule:** l'attacco non finisce al login riuscito — l'attaccante consolida l'accesso modificando email di recupero, MFA e credenziali, prima di monetizzare o muoversi lateralmente.

Dopo un login riuscito, i passi tipici dell'attaccante includono:

* modifica dell'email di recupero
* cambio password
* registrazione di nuovi metodi MFA
* furto di dati
* frode finanziaria
* acquisti non autorizzati
* Business Email Compromise (BEC)
* persistenza tramite token/sessioni valide
* rivendita dell'account validato sul mercato nero

***

## Incident Response dopo un Account Takeover

Checklist difensiva:

1. Revoca delle sessioni attive
2. Reset della password
3. Invalidazione dei refresh token
4. Rimozione dei metodi MFA sconosciuti registrati dall'attaccante
5. Controllo delle regole di inoltro/filtro email
6. Verifica dei nuovi dispositivi registrati
7. Analisi degli accessi successivi per movimento laterale
8. Notifica all'utente coinvolto
9. Ricerca dello stesso pattern di credenziali su altri account dell'organizzazione

***

## Metriche per il Report di Pentest

Per un assessment credibile, includere nel report:

* numero di coppie sintetiche testate
* percentuale bloccata da rate limiting/lockout
* tempo trascorso fino al primo alert generato
* percentuale di tentativi sottoposta a step-up MFA
* falsi positivi osservati
* endpoint privi di rate limiting (web vs API vs mobile)
* possibilità di enumerare utenti dalle risposte del sistema
* efficacia delle stop condition concordate

***

## Mitigazione

**Layer 1 — Credenziali**

* Controllo automatico delle password contro database breach (API Pwned Passwords) al momento di creazione/cambio
* Password manager e password uniche per servizio
* Monitoring del dark web per leak di credenziali aziendali (dominio verificato)

**Layer 2 — Autenticazione**

* **Passkey/FIDO2** — riducono radicalmente il credential stuffing perché non usano una password condivisa e riutilizzabile sul percorso normale di login. La protezione resta incompleta se il sistema mantiene fallback via password, recovery debole via email/SMS, o help desk facilmente manipolabile
* MFA su tutti gli account — riduce l'impatto anche con credenziali compromesse
* Conditional Access — blocca accesso da IP anomali, device non noti, geolocation inusuale

**Layer 3 — Bot Detection**

* Rate limiting con scoring combinato (non solo per IP)
* CAPTCHA adattivo solo su pattern sospetti
* Browser fingerprinting e JavaScript challenge
* Bot management (Akamai, Cloudflare) per identificare traffico da proxy residenziali noti

**Layer 4 — Monitoring**

* Alert su rapporto anomalo tentativi falliti/account coinvolti, non su soglia fissa
* Correlazione a livello di campagna (fingerprint, timing, target set)
* Monitoring continuo dei breach per credenziali aziendali esposte

***

## Casi Reali di Credential Stuffing e Abuso di Credenziali Rubate

**Answer capsule:** non tutti gli incidenti noti che coinvolgono credenziali rubate sono credential stuffing in senso stretto — la distinzione tra riuso automatizzato e semplice abuso di credenziali compromesse è importante per non generalizzare.

**Roku (2024)** — `Credential stuffing confermato`. Roku ha attribuito l'accesso a circa 576.000 account al credential stuffing, dichiarando di non aver trovato prove che le credenziali provenissero dai propri sistemi.

**Snowflake (2024)** — `Credenziali da infostealer`. Mandiant ha ricondotto la campagna UNC5537 a credenziali di clienti Snowflake sottratte tramite infostealer su macchine personali dei dipendenti, non a una compromissione dell'infrastruttura Snowflake né necessariamente a un riuso automatizzato in senso stretto.

**Change Healthcare (2024)** — `Valid accounts / origine non completamente documentata`. Confermato l'uso di credenziali compromesse contro un portale Citrix privo di MFA; non è pubblicamente dimostrato che quelle credenziali siano state validate tramite una campagna automatizzata di credential stuffing.

Il denominatore comune resta però lo stesso: MFA non obbligatorio e nessuna verifica preventiva delle credenziali contro database breach noti.

**Altri casi noti di credential stuffing confermato:**

* **The North Face / VF Corporation (aprile 2025)** — `Credential stuffing confermato`. Quarto incidente di questo tipo sui brand VF Corp dal 2020; esposti dati anagrafici e storico ordini, nessun dato di pagamento (gestito da processori terzi)
* **Reddit** — utenti bloccati in massa dopo un'ondata di tentativi di credential stuffing; reset password forzato per gli account coinvolti
* **TurboTax (2019)** — accesso a dichiarazioni fiscali e dati sensibili (inclusi SSN) tramite credenziali riusate
* **HSBC** — accesso non autorizzato a circa 14.000 account clienti tramite credenziali rubate, con sospensione temporanea del login online
* **Fondi pensione australiani (marzo 2026)** — tentativi coordinati di credential stuffing rilevati su più fondi (AustralianSuper, Rest Super, Hostplus, Australian Retirement Trust, Insignia Financial) nello stesso finestra temporale, segno di una campagna centralizzata contro un intero settore

***

## FAQ

**Cosa distingue il credential stuffing dal brute force?**
Il brute force genera password candidate per un account. Il credential stuffing usa coppie username/password già valide e associate, ottenute da breach — il tasso di successo è molto diverso: brute force su password forti può richiedere anni, credential stuffing ha un hit rate misurabile su liste di buona qualità.

**Il 2FA protegge dal credential stuffing?**
La maggior parte dei fattori MFA (TOTP, SMS, push) riduce drasticamente l'impatto, perché anche con credenziali valide l'attaccante deve superare il secondo fattore. Solo passkey/FIDO2, su un percorso realmente passwordless, eliminano il vettore alla radice.

**Come verifico se le credenziali aziendali sono in un breach pubblico?**
HaveIBeenPwned con Domain Search (verifica del dominio richiesta), o servizi di monitoring continuo come SpyCloud o Recorded Future.

***

## Conclusione

Il credential stuffing è tra gli attacchi con il ROI più alto per un attaccante: nessun exploit, nessuna vulnerabilità da cercare, solo automazione su coppie di credenziali già disponibili. In un pentest, testarlo correttamente significa usare coppie sintetiche pre-accoppiate — mai wordlist generiche, che simulerebbero un brute force — e misurare rate limiting, step-up MFA e latenza di detection. La difesa efficace è a strati: password uniche forzate tecnicamente, MFA robusto (idealmente passkey/FIDO2 con recovery altrettanto solido), scoring comportamentale multi-dimensionale e monitoring attivo sui breach.

***

**Risorse:**

* [MITRE ATT\&CK – T1110.004](https://attack.mitre.org/techniques/T1110/004/)
* [MITRE – DET0460 Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0460/)
* [OWASP – Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
* [OWASP – Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [Have I Been Pwned – Pwned Passwords](https://haveibeenpwned.com/Passwords)
