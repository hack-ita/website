---
title: 'Social Engineering: Cos''è, Attacchi Reali e Difese nel 2026'
slug: social
description: 'Social Engineering: framework psicologici, pretexting, vishing, impersonation, physical access, OSINT per targeting e tecniche operative. Dalla teoria all''engagement reale.'
image: /social.webp
draft: true
date: 2026-02-28T00:00:00.000Z
categories:
  - guides-resources
subcategories:
  - tecniche
tags:
  - set
  - phishing
---

# Social Engineering: Manipolazione Umana nel Pentest — Framework, Tecniche e Operazioni

> **Executive Summary** — Il social engineering è l'arte di manipolare le persone per ottenere informazioni, accesso o azioni che normalmente non concederebbero. Nel pentest, il social engineering è il vettore che bypassa ogni controllo tecnico: non importa quanto sia forte il firewall, se convinci un dipendente a darti le credenziali VPN al telefono. Il social engineering non è solo phishing (che è una sotto-categoria) — include vishing (telefono), pretexting (costruzione di identità false), impersonation (fingere di essere qualcuno), tailgating (accesso fisico), baiting (chiavette USB) e elicitation (estrazione di informazioni in conversazione). Questo articolo copre il framework psicologico, le tecniche operative e il workflow completo per un engagement di social engineering.

**TL;DR**

* Il social engineering sfrutta 6 principi psicologici (Cialdini): reciprocità, impegno, riprova sociale, autorità, simpatia, scarsità
* Il pretexting (storia credibile) è la skill più importante — senza pretext, nessuna tecnica funziona
* L’OSINT è il moltiplicatore: più conosci il target → più credibile il pretext → più successo

## Perché il Social Engineering è il Vettore più Efficace

I controlli tecnici sono migliorati enormemente: EDR avanzati, MFA diffuso, patch management automatizzato, zero trust architecture. Ma le persone restano prevedibili. Ogni organizzazione ha dipendenti che:

* Vogliono essere utili (rispondono a richieste di "colleghi")
* Rispettano l'autorità (eseguono ordini del "capo")
* Agiscono sotto pressione (urgenza → meno verifiche)
* Hanno routine prevedibili (arrivano in ufficio → badge → porta aperta per chi segue)

Nel red team, il social engineering è spesso il path of least resistance: perché spendere settimane su un perimetro hardened quando una telefonata al helpdesk può darti le credenziali in 10 minuti?

### Social Engineering vs Phishing

Il [phishing](https://hackita.it/articoli/phishing) è una sotto-categoria del social engineering — specificamente, è social engineering via email (o SMS nel caso di smishing). Il social engineering è più ampio: include canali telefonici, fisici, di persona e qualsiasi interazione umana. Il phishing usa l'infrastruttura tecnica (GoPhish, Evilginx, landing page). Il social engineering puro usa la voce, la presenza fisica e la psicologia.

```
Social Engineering (macro-categoria)
├── Phishing (email) → vedi articolo dedicato
├── Spear Phishing (email mirata)
├── Smishing (SMS)
├── Vishing (telefono)
├── Pretexting (costruzione identità falsa)
├── Impersonation (persona fisica)
├── Tailgating / Piggybacking (accesso fisico)
├── Baiting (chiavette USB, media)
├── Quid Pro Quo (scambio favori)
├── Elicitation (estrazione informazioni in conversazione)
├── Watering Hole (compromissione sito frequentato dal target)
└── Dumpster Diving (ricerca in rifiuti)
```

## 1. I 6 Principi Psicologici di Cialdini

Robert Cialdini ha identificato 6 principi che governano la persuasione. Ogni tecnica di social engineering sfrutta uno o più di questi principi. Capirli non è "teoria" — è il framework operativo che guida ogni interazione.

### Principio 1: Autorità

Le persone obbediscono a figure di autorità, anche percepita.

```
Applicazione: chiami fingendoti il CTO, il direttore IT o un auditor esterno
Esempio: "Sono il Dr. Rossi dell'audit compliance. Ho bisogno delle credenziali
         del portale fatturazione entro fine giornata per completare l'audit."
Perché funziona: il dipendente non vuole essere quello che rallenta un audit
```

### Principio 2: Urgenza / Scarsità

Quando il tempo è limitato, le persone prendono decisioni peggiori.

```
Applicazione: crei pressione temporale per impedire la verifica
Esempio: "Il server è sotto attacco in questo momento. Ho bisogno
         dell'accesso VPN immediatamente per applicare la patch."
Perché funziona: l'urgenza disabilita il pensiero critico
```

### Principio 3: Reciprocità

Se qualcuno ci fa un favore, sentiamo l'obbligo di ricambiare.

```
Applicazione: prima aiuti il target con un problema reale, poi chiedi qualcosa
Esempio: chiami il reparto vendite, li aiuti a risolvere un problema tecnico
         (che magari hai causato tu), poi chiedi l'accesso a un sistema "per verificare"
Perché funziona: il debito di gratitudine abbassa le difese
```

### Principio 4: Riprova Sociale

Le persone seguono il comportamento della maggioranza.

```
Applicazione: affermi che "tutti gli altri colleghi" hanno già fatto la cosa
Esempio: "Tutti i colleghi del reparto vendite hanno già aggiornato le credenziali.
         Lei è l'ultimo. Può procedere subito?"
Perché funziona: nessuno vuole essere l'unico a non aver fatto qualcosa
```

### Principio 5: Simpatia

Siamo più influenzabili da persone che ci piacciono o con cui ci identifichiamo.

```
Applicazione: costruisci rapport, trova interessi comuni, sii amichevole
Esempio: noti che il receptionist ha una foto del Milan sulla scrivania.
         Inizi parlando della partita di ieri. Poi chiedi di poter usare il bagno.
         Poi "ti perdi" e finisci nel data center.
Perché funziona: le persone amichevoli sono percepite come non minacciose
```

### Principio 6: Impegno e Coerenza

Una volta che una persona dice "sì" a una piccola richiesta, è più probabile che dica "sì" a richieste più grandi.

```
Applicazione: parti con una richiesta innocua, poi escala
Esempio: "Può confermarmi il nome del responsabile IT?"
         (risponde: "Sì, è Marco Bianchi")
         "Perfetto. Marco mi ha chiesto di chiamarla per il reset password.
          Può darmi il suo attuale username?"
Perché funziona: ha già iniziato a collaborare — fermarsi richiede uno sforzo
```

## 2. OSINT per il Targeting — Il Moltiplicatore

Più informazioni hai sul target, più credibile è il tuo pretext. L'OSINT (Open Source Intelligence) è il lavoro di ricognizione che precede qualsiasi interazione.

### Cosa cercare e dove

| Informazione            | Fonte                                 | Uso                                       |
| ----------------------- | ------------------------------------- | ----------------------------------------- |
| Nomi + ruoli            | LinkedIn, sito aziendale              | Scegliere chi impersonare e chi attaccare |
| Formato email           | hunter.io, phonebook.cz, Google dork  | Mandare email credibili                   |
| Struttura organizzativa | LinkedIn, report annuali              | Sapere chi è il capo di chi               |
| Tecnologie usate        | Job posting, BuiltWith, Wappalyzer    | Pretexting tecnico credibile              |
| Fornitori esterni       | Sito web, LinkedIn, comunicati stampa | Impersonare un fornitore                  |
| Eventi aziendali        | Social media, sito web, eventbrite    | Timing del pretext                        |
| Numeri di telefono      | Sito web, LinkedIn, Truecaller        | Vishing                                   |
| Abitudini personali     | Social media, Strava, Instagram       | Rapport building                          |
| Location uffici         | Google Maps, Street View              | Physical access                           |
| Badge / dress code      | Foto social, Google Images            | Impersonation fisica                      |

### OSINT operativo

```bash
# Email enumeration
theHarvester -d corp.local -b google,linkedin,hunter

# LinkedIn scraping (nomi + ruoli)
# Manuale: cerca "corp.local" su LinkedIn → People → filtra per dipartimento

# Google dorking per info interne
site:corp.local filetype:pdf "confidential"
site:corp.local filetype:xlsx "password"
"@corp.local" filetype:pdf  # Trova email in documenti pubblici
```

Per i Google dork avanzati, usa la [Google Hacking Database su Exploit-DB](https://hackita.it/articoli/exploit-db) — centinaia di dork per trovare documenti interni, credenziali esposte e informazioni sensibili.

```bash
# Metadata dai documenti pubblici (nomi utente, software, path interni)
exiftool document_scaricato.pdf
# Creator: j.smith
# Producer: Microsoft Word 2019
# Modifica path: C:\Users\j.smith\Documents\...
```

### Costruire il profilo del target

```
Target: Maria Rossi — Receptionist, Corp S.p.A.
LinkedIn: 3 anni in Corp, prima in hotel management
Social: Instagram → foto del cane, vacanze a Rimini, fan di MasterChef
Orari: pubblica su LinkedIn alle 8:30 (arriva presto)
Colleghi: riporta a Franco Neri (Office Manager)
Telefono: centralino +39 06 1234567 (interno 200 da sito web)

Pretext possibile:
Chiamo come corriere DHL con un pacco urgente per Franco Neri.
"Non riesco a trovare l'ufficio, può indicarmi dove lasciare il pacco?"
→ Ottengo informazioni sulla disposizione dell'edificio.
```

## 3. Vishing — Social Engineering Telefonico

Il vishing (voice phishing) è social engineering via telefono. È più efficace dell'email perché la voce umana crea urgenza, empatia e pressione in tempo reale — la vittima non ha tempo di verificare. In un engagement, una telefonata ben fatta al helpdesk IT può dare credenziali, reset password o accesso VPN in minuti.

### Preparazione

```
1. OSINT: identifica il target (helpdesk, receptionist, HR)
2. Numero: centralino dall'OSINT, interni dai siti aziendali
3. Caller ID spoofing: tool come SpoofCard per mostrare un numero credibile
4. Pretext: scrivi uno script (ma sii pronto a improvvisare)
5. Ambiente: stanza silenziosa, nessuna distrazione, registra (se autorizzato)
```

### Script di vishing — Esempio: Helpdesk IT

```
[Chiami il helpdesk IT]

TU: "Buongiorno, sono Marco Bianchi dal reparto vendite. Ho un problema
     urgente — sono dal cliente e non riesco ad accedere al CRM. Mi dà
     errore di password. Può aiutarmi?"

HELPDESK: "Certo, mi può dare il suo username?"

TU: "m.bianchi — come al solito. Sono davvero in difficoltà, il cliente
     sta aspettando e il mio responsabile, il Dr. Neri, mi ha detto di
     chiamare subito."

HELPDESK: "Ok, le resetto la password. La nuova password temporanea è
           Temp2026! — la cambi al primo accesso."

TU: "Grazie mille, mi ha salvato. Buona giornata!"
```

**Analisi — principi usati:**

* **Autorità**: menziona il responsabile ("Dr. Neri mi ha detto")
* **Urgenza**: "sono dal cliente", "sta aspettando"
* **Simpatia**: tono cordiale, ringraziamento
* **Impegno**: l'helpdesk ha già iniziato a collaborare (ha chiesto lo username)

### Script di vishing — Esempio: Receptionist per physical access

```
[Chiami il centralino]

TU: "Buongiorno, sono della società di manutenzione caldaie TechnoClima.
     Abbiamo un intervento programmato per oggi alle 14:00 nel vostro
     edificio. A chi mi devo rivolgere per l'accesso?"

RECEPTIONIST: "Deve parlare con il facility manager, il sig. Verdi."

TU: "Perfetto. E per entrare, serve un badge visitatore? Il mio collega
     era da voi il mese scorso e mi ha detto che bastava presentarsi
     alla reception con il documento."

RECEPTIONIST: "Sì, esatto. Si presenti alla reception con un documento
               e le diamo il badge visitatore."

TU: "Grazie. A che piano è la centrale termica?"

RECEPTIONIST: "Piano interrato, -1. Prenda l'ascensore e scenda."
```

**Cosa hai ottenuto:** nome del facility manager, procedura di accesso visitatori (solo documento), location della centrale termica (spesso vicina al server room). Tutto senza mai mettere piede nell'edificio.

### Vishing avanzato — Callback verification bypass

Alcune organizzazioni hanno la policy "ti richiamo io". Come aggirarla:

```
Tecnica 1: "Sono in mobilità, il mio interno è il 4523" 
           (interno che hai trovato nell'OSINT, magari di una sala riunioni vuota)

Tecnica 2: "Può richiamarmi al numero del mio cellulare aziendale?"
           (dai un numero VoIP che controlli)

Tecnica 3: Chiama prima la vittima da un interno legittimo (spoofato)
           così quando ti richiama, il numero corrisponde
```

## 4. Pretexting — Costruire Identità Credibili

Il pretexting è la creazione di una storia completa e coerente che giustifica le tue richieste. Non è una bugia improvvisata — è un'identità costruita con attenzione ai dettagli.

### Componenti di un pretext

```
1. CHI SEI: nome, ruolo, organizzazione
2. PERCHÉ CHIAMI/SEI QUI: il motivo della tua interazione
3. COSA VUOI: la richiesta specifica (credenziali, accesso, informazioni)
4. URGENZA: perché deve succedere ADESSO
5. CONSEGUENZA: cosa succede se non collaborano
6. PROVA: elementi che confermano la tua identità (badge, email, knowledge)
```

### Pretext comuni — con dettagli operativi

**Il tecnico IT esterno**

```
Chi: tecnico di $VENDOR (scoperto dall'OSINT — il vendor reale del target)
Perché: intervento di manutenzione programmato / aggiornamento urgente
Cosa vuoi: accesso al server room / credenziali admin / accesso remoto
Props: polo con logo (stampata), borsa con laptop, badge generico $VENDOR
Knowledge: nomi dei sistemi (dall'OSINT), nome del responsabile IT
Script: "Buongiorno, sono [nome] di [vendor]. Ho un ticket aperto con
         [responsabile IT] per l'aggiornamento del [sistema]. Mi può
         indicare dove sono i rack?"
```

**L'auditor / compliance**

```
Chi: consulente di [big4 / società di audit nota]
Perché: audit programmato (SOC2, GDPR, ISO27001)
Cosa vuoi: accesso ai sistemi, documentazione, credenziali di test
Props: vestito formale, badge con logo, laptop con presentazione
Knowledge: standard di compliance reali, terminologia corretta
Script: "Buongiorno, sono [nome] di [audit firm]. Siamo qui per la
         verifica annuale. Il Dr. [CFO name] è informato. Avrei bisogno
         di accedere al sistema [X] per verificare i log di audit."
```

**Il nuovo dipendente**

```
Chi: dipendente appena assunto nel reparto [X]
Perché: primo giorno / prima settimana, non ha ancora tutti gli accessi
Cosa vuoi: badge provvisorio, credenziali, accesso a sistemi
Script: "Ciao, sono [nome], sono nuovo nel reparto marketing. Il mio
         responsabile [nome reale dall'OSINT] mi ha detto di rivolgermi
         a voi per configurare l'accesso al portale. Non ho ancora
         ricevuto le credenziali dall'IT."
```

**Il corriere / fornitore**

```
Chi: corriere DHL/UPS/Bartolini o tecnico di manutenzione
Perché: consegna urgente / intervento programmato
Cosa vuoi: accesso all'edificio, mappatura degli spazi
Props: divisa (acquistabile online), clipboard, pacco
Script: "Ho una consegna urgente per [nome persona reale]. Deve firmare
         personalmente. A che piano si trova il suo ufficio?"
```

## 5. Physical Social Engineering — Accesso Fisico

L'accesso fisico è il livello più avanzato di social engineering. L'obiettivo è entrare negli uffici del target senza autorizzazione. Una volta dentro: installi rogue device (Raspberry Pi, LAN Turtle, WiFi Pineapple), accedi a workstation incustodite, fotografi documenti e badge, accedi al server room.

### Tailgating / Piggybacking

```
Tecnica: segui un dipendente attraverso una porta con accesso badge
Come: aspetti fuori l'edificio (zona fumatori, entrata), ti avvicini
      quando qualcuno entra. Sorridi, fai finta di cercare il badge
      in tasca. "Grazie, l'ho sempre dove non lo trovo..."
Principio: simpatia + norma sociale (è scortese chiudere la porta in faccia)
```

### Baiting — USB Drop

```
Tecnica: lasci chiavette USB "perse" nel parcheggio, reception, mensa
Contenuto: payload che chiama casa quando inserita (Rubber Ducky, Bash Bunny,
           o file .lnk che esegue PowerShell)
Label sulla USB: "Buste paga Q4 2025", "Foto licenziamenti", "Piano bonus"
Principio: curiosità
Percentuale di inserimento: 30-50% (da studi empirici)
```

### Rogue Device Placement

Una volta dentro l'edificio:

```
Device: Raspberry Pi Zero con 4G + reverse SSH
        LAN Turtle (si collega tra PC e cavo ethernet)
        WiFi Pineapple (rogue AP per credential harvest)
        
Posizionamento ideale:
- Sotto una scrivania (alimentato dalla USB del PC)
- Dietro una stampante (alimentato dalla presa della stampante)
- In una sala riunioni (meno traffico, meno controlli)
- Nel server room (accesso diretto alla rete)
```

Il rogue device ti dà accesso persistente alla rete interna. Da qui: [enumerazione servizi](https://hackita.it/articoli/porta-1433-mssql), [lateral movement AD](https://hackita.it/articoli/dcsync), [accesso a share NFS](https://hackita.it/articoli/porta-2049-nfs) o [Docker API esposto](https://hackita.it/articoli/porta-2375-docker-api).

### Dumpster Diving

```
Cosa cerchi: documenti stampati con credenziali, organigrammi, contratti,
             post-it con password, hardware dismesso (HDD non wiped)
Dove: cestini, cassonetti, area riciclaggio carta
Orario: dopo l'orario di lavoro, nei giorni di pulizie
Legale: verifica la legislazione locale — in molti paesi, i rifiuti
        abbandonati non sono più proprietà privata
```

## 6. Elicitation — Estrarre Informazioni Senza Chiedere

L'elicitation è l'arte di ottenere informazioni senza fare domande dirette. Invece di chiedere "qual è la password?", guidi la conversazione in modo che il target riveli informazioni spontaneamente.

### Tecniche di elicitation

**Affermazione deliberatamente errata:**

```
TU: "Se non sbaglio, usate SAP per la contabilità..."
TARGET: "No no, usiamo Oracle ERP, SAP lo usavamo anni fa."
→ Hai scoperto il software gestionale senza chiedere
```

**Quid pro quo (scambio):**

```
TU: "Da noi abbiamo avuto un problema con il backup la settimana scorsa.
     Usavamo Veeam ma siamo passati a Commvault. Voi come gestite i backup?"
TARGET: "Noi siamo su Veeam da anni, funziona bene. Facciamo backup
         giornalieri su NAS e settimanali su tape."
→ Hai scoperto il software di backup, la frequenza e il tipo di storage
```

**Lusinga + domanda:**

```
TU: "Complimenti per l'infrastruttura, sembra molto ben gestita.
     Come avete implementato la segmentazione di rete?"
TARGET: [spiega l'architettura di rete]
→ Information disclosure massiva mascherata da complimento professionale
```

**Uso del silenzio:**

```
TU: fai una domanda e poi taci
TARGET: il silenzio crea disagio → la persona riempie il vuoto parlando
→ Spesso rivela più di quanto intendesse
```

## 7. Scenari Pratici di Engagement

### Scenario 1: Red Team — Initial Access via vishing

**Obiettivo:** ottenere credenziali VPN per accedere alla rete interna.

**Step 1 — OSINT (1-2 giorni):**

```
- LinkedIn: identifica 5 dipendenti nel reparto vendite (spesso in trasferta)
- Sito web: trova il numero del helpdesk IT (+39 06 1234567 int. 300)
- Job posting: l'azienda usa Cisco AnyConnect VPN (dal requisito "esperienza VPN")
- LinkedIn: il responsabile IT si chiama Luca Verdi
```

**Step 2 — Pretext building:**

```
Impersono: Marco Rossi, venditore senior (persona reale trovata su LinkedIn)
Storia: sono dal cliente, non riesco a connettermi alla VPN, urgente
Knowledge: nome del responsabile IT, tipo di VPN (Cisco AnyConnect)
```

**Step 3 — Call:**

```
"Buongiorno, sono Marco Rossi delle vendite. Sono dal cliente Mediaworld
e non riesco a connettermi alla VPN. Mi dà errore di autenticazione.
Luca Verdi mi ha detto di chiamare voi per un reset rapido perché
devo accedere al CRM per chiudere l'ordine."
```

**Step 4 — Risultato:**

```
Helpdesk resetta la password → TempPass2026!
Tu: ti connetti alla VPN con m.rossi / TempPass2026!
→ Accesso alla rete interna → pentest prosegue
```

**Tempo stimato:** 2-3 ore (OSINT) + 10 minuti (call)

### Scenario 2: Physical — Rogue device in ufficio

**Obiettivo:** piazzare un Raspberry Pi nella rete interna.

**Step 1 — Recon fisico:**

```
Google Maps / Street View: entrate, parcheggio, area fumatori
Drive-by: osserva dress code, flusso persone, orari
OSINT: nome facility manager, fornitori noti
```

**Step 2 — Pretext:**

```
Impersono: tecnico di [vendor stampanti reale]
Props: polo scura, badge generico, borsa con Raspberry Pi
```

**Step 3 — Esecuzione:**

```
Arrivi alle 10:30 (non troppo presto, non in pausa pranzo)
"Buongiorno, sono di [vendor]. Ho un ticket per la stampante al terzo piano."
Receptionist: badge visitatore, indicazioni
Sali al terzo piano → trovi una stampante → colleghi il Pi alla presa ethernet
→ nascondi sotto la scrivania → esci
```

**Step 4 — Post-access:**

```
Il Pi si connette via 4G al tuo C2
SSH tunnel → sei nella rete interna
→ Enumerazione, lateral movement, compromissione
```

**Tempo stimato:** 1 giorno (recon) + 30 minuti (esecuzione)

### Scenario 3: Awareness test — campagna multi-vettore

**Obiettivo:** misurare la resilienza dell'organizzazione su più canali.

```
Settimana 1: Phishing email (GoPhish) — 500 utenti
             Pretext: "Aggiornamento password aziendale"
             Metrica: click rate, submit rate

Settimana 2: Vishing — 20 chiamate a helpdesk e dipendenti
             Pretext: vari (password reset, verifica dati, audit)
             Metrica: quanti forniscono informazioni

Settimana 3: USB drop — 10 chiavette nel parcheggio
             Label: "Buste paga Q4 2025"
             Metrica: quante vengono inserite

Settimana 4: Physical — tentativo di tailgating
             Metrica: successo/fallimento accesso
```

Per la parte phishing email, usa il workflow completo descritto nella [guida al phishing](https://hackita.it/articoli/phishing) con [GoPhish](https://hackita.it/articoli/gophish) ed [Evilginx](https://hackita.it/articoli/evilginx).

## 8. Aspetti Legali e Etici

Il social engineering nel pentest richiede attenzione particolare agli aspetti legali:

```
OBBLIGATORIO prima di qualsiasi engagement:
□ Autorizzazione scritta esplicita dal cliente
□ Scope definito (chi puoi contattare, quali tecniche, orari)
□ Limiti: non impersonare forze dell'ordine, non minacciare, non manipolare emozioni
□ Numero di emergenza del cliente (se qualcosa va storto)
□ Debriefing post-engagement (spiega ai dipendenti "ingannati" cosa è successo)
□ Reportistica anonimizzata (non nominare chi è "caduto" nel report pubblico)
```

**Cosa NON fare mai:**

* Impersonare polizia, carabinieri, vigili del fuoco o autorità giudiziaria
* Creare panico (falso allarme bomba, emergenza medica)
* Manipolare emotivamente (ricatti, minacce, vulnerabilità personali)
* Registrare conversazioni senza autorizzazione legale
* Accedere a proprietà privata senza autorizzazione scritta

## 9. Detection — Come le Organizzazioni si Difendono

| Difesa                       | Cosa blocca                                         |
| ---------------------------- | --------------------------------------------------- |
| Security awareness training  | Riconoscimento di pretext e tecniche SE             |
| Callback verification policy | Helpdesk richiama il dipendente al suo interno      |
| Badge obbligatorio visibile  | Identifica intrusi nell'edificio                    |
| Visitor management system    | Registra e verifica ogni visitatore                 |
| Clean desk policy            | Niente credenziali su post-it o documenti esposti   |
| Shredder obbligatorio        | Niente informazioni nel cestino                     |
| USB port disable             | Blocca baiting via chiavette USB                    |
| DLP (Data Loss Prevention)   | Rileva invio di dati sensibili via email            |
| Report channel facile        | I dipendenti possono segnalare interazioni sospette |

## 10. Toolchain

| Tool                                 | Funzione                                                                              |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| **GoPhish**                          | Campagne phishing email — vedi [guida phishing](https://hackita.it/articoli/phishing) |
| **Evilginx**                         | MFA bypass via reverse proxy                                                          |
| **SET (Social Engineering Toolkit)** | Quick attacks: clone site, HTA, QR                                                    |
| **theHarvester**                     | OSINT email e sottodomini                                                             |
| **Maltego**                          | OSINT grafico — relazioni tra persone, organizzazioni, infrastruttura                 |
| **SpiderFoot**                       | OSINT automatizzato                                                                   |
| **SpoofCard / SIPVicious**           | Caller ID spoofing per vishing                                                        |
| **WiFi Pineapple**                   | Rogue AP per credential harvest                                                       |
| **Rubber Ducky / Bash Bunny**        | Payload USB per baiting                                                               |
| **LAN Turtle**                       | Rogue device di rete                                                                  |
| **dnstwist**                         | Genera varianti di dominio per phishing                                               |

## 11. Cheat Sheet Finale

### Framework psicologico

| Principio       | Tecnica operativa                                          |
| --------------- | ---------------------------------------------------------- |
| Autorità        | Impersona un superiore, un auditor, un fornitore noto      |
| Urgenza         | Deadline immediata, emergenza tecnica, cliente che aspetta |
| Reciprocità     | Prima dai aiuto, poi chiedi qualcosa                       |
| Riprova sociale | "Tutti gli altri colleghi l'hanno già fatto"               |
| Simpatia        | Rapport building, interessi comuni, tono cordiale          |
| Impegno         | Parti con richieste piccole, poi escala                    |

### Checklist pre-engagement

```
□ Autorizzazione scritta con scope dettagliato
□ OSINT completato (nomi, ruoli, numeri, fornitori, tecnologie)
□ Pretext costruito e testato
□ Props pronti (badge, vestiti, device)
□ Script di vishing scritto (con varianti per risposte diverse)
□ Infrastruttura phishing pronta (se incluso) → vedi guida phishing
□ Numero di emergenza del cliente
□ Piano B se il pretext fallisce
```

### Vishing quick reference

| Fase            | Azione                                              |
| --------------- | --------------------------------------------------- |
| Apertura        | Presentati, stabilisci autorità/rapport             |
| Giustificazione | Spiega perché chiami (pretext)                      |
| Richiesta       | Chiedi quello che ti serve (inizia in piccolo)      |
| Urgenza         | Aggiungi pressione temporale se necessario          |
| Escalation      | Se rifiutano: menziona il superiore, la conseguenza |
| Chiusura        | Ringrazia, chiudi cordialmente (evita sospetti)     |

### OSINT sources

| Tipo             | Fonte                                                                        |
| ---------------- | ---------------------------------------------------------------------------- |
| Persone + ruoli  | LinkedIn, sito aziendale, annual report                                      |
| Email            | hunter.io, phonebook.cz, [GHDB dork](https://hackita.it/articoli/exploit-db) |
| Telefoni         | Sito web, LinkedIn, Truecaller, paginegialle                                 |
| Tecnologie       | Job posting, BuiltWith, Wappalyzer                                           |
| Documenti        | Google dork (`site:target filetype:pdf`)                                     |
| Immagini ufficio | Google Maps, Street View, Instagram geo-tagged                               |
| Metadata         | exiftool su documenti pubblici                                               |

### Metriche di reporting

| Metrica                    | Cosa misura                                                   |
| -------------------------- | ------------------------------------------------------------- |
| Credential disclosure rate | % di utenti che rivelano credenziali (vishing/phishing)       |
| Physical access success    | % di tentativi di accesso fisico riusciti                     |
| Information disclosure     | Quante informazioni ottenute via elicitation                  |
| USB insertion rate         | % di USB drop inserite                                        |
| Report rate                | % di dipendenti che segnalano il tentativo (metrica positiva) |
| Time to detection          | Quanto tempo prima che qualcuno segnali                       |

### OPSEC

Nelle chiamate di vishing: usa numeri VoIP usa-e-getta, non dare il tuo vero nome, non lasciare tracce digitali. Nel physical: non portare documenti personali, usa badge generici senza foto, piano di uscita rapida se scoperto. In tutte le interazioni: registra (se legalmente permesso) come prova per il report, ma informa il cliente immediatamente se un dipendente chiama le forze dell'ordine.

⚠️ **Disclaimer**

> ***Questo contenuto è fornito esclusivamente per scopi educativi e per attività di sicurezza informatica in ambienti autorizzati (pentest, red team, assessment).***\
> ***Qualsiasi utilizzo non autorizzato è illegale e non è responsabilità dell’autore.***

***

🎯 **Vuoi migliorare davvero?**\
Formazione pratica **1:1** → [https://hackita.it/servizi](https://hackita.it/servizi)

🏢 **Vuoi testare la tua azienda?**\
Simulazioni e assessment reali → [https://hackita.it/servizi](https://hackita.it/servizi)

❤️ **Supporta HackIta**\
Sostieni il progetto → [https://hackita.it/supporto](https://hackita.it/supporto)

***

Riferimento:

* Robert Cialdini — "Influence"
* Christopher Hadnagy — "Social Engineering: The Science of Human Hacking"
* MITRE ATT\&CK T1566 → [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)
* MITRE ATT\&CK T1598 → [https://attack.mitre.org/techniques/T1598/](https://attack.mitre.org/techniques/T1598/)
* PTES Social Engineering → [http://www.pentest-standard.org/index.php/Social\_Engineering](http://www.pentest-standard.org/index.php/Social_Engineering)

Uso esclusivo in ambienti autorizzati.
