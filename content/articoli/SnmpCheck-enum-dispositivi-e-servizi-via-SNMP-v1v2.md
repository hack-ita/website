---
title: 'SnmpCheck: enum dispositivi e servizi via SNMP v1/v2'
description: >-
  Snmp-check permette di estrarre informazioni da dispositivi di rete usando
  SNMP. Perfetto per attacchi low-noise, enumeration silenziosa e footprinting.
image: /snmpcheck.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - snmp
  - ''
slug: "snmpcheck"
---

# Snmpcheck (snmp-check): enumerazione SNMP facile in lab

Snmpcheck (installato su Kali Linux come pacchetto `snmpcheck` ma eseguito con il comando `snmp-check`) è uno strumento di enumerazione SNMP che formatta automaticamente l'output in un formato leggibile, organizzato per sezioni. In un ambiente di laboratorio autorizzato, se scopri il servizio SNMP in esecuzione sulla porta UDP 161, questo tool è spesso la via più rapida per trasformare i dati grezzi del protocollo in informazioni tattiche utili, come dettagli di sistema, configurazioni di rete e servizi in esecuzione.

Questa guida ti mostrerà come utilizzarlo efficacemente in tre comandi fondamentali, interpretare correttamente il suo output, generare report utili e capire quando sia più opportuno utilizzare strumenti più granulari come `snmpwalk`. Ricorda: tutte le tecniche descritte devono essere applicate esclusivamente su sistemi di cui possiedi la proprietà o per i quali hai ottenuto esplicita autorizzazione scritta.

## Cos'è snmpcheck e perché semplifica l'enumerazione SNMP

Snmp-check funziona come uno strato di astrazione sopra i classici strumenti da riga di comando SNMP. Invece di restituire una lista grezza di Object Identifiers (OID) e valori, interroga l'agente SNMP remoto e organizza le informazioni in categorie logiche e immediatamente comprensibili.

Per un tester alle prime armi o per un professionista che deve operare rapidamente, questa automazione è inestimabile. Ti permette di saltare la fase, spesso complessa e noiosa, di dover conoscere a memoria i singoli OID o di dover filtrare manualmente migliaia di righe di output. Lo strumento si concentra tipicamente sull'estrazione di: informazioni di sistema (hostname, descrizione, uptime, contatti), dettagli di rete (interfacce, indirizzi IP, tabelle di routing), e dati operativi (connessioni TCP attive, porte UDP in ascolto).

## SNMP in breve: community string, OID e le porte fondamentali

Prima di approfondire lo strumento, è cruciale comprendere i concetti base del protocollo che va a interrogare. SNMP (Simple Network Management Protocol) è un protocollo di livello applicativo utilizzato per la gestione e il monitoraggio dei dispositivi di rete.

In particolare, le versioni 1 e 2c, ancora molto diffuse, si basano su un semplice meccanismo di autenticazione basato su stringhe di testo chiamate **community string**. La stringa `public` è comunemente utilizzata per l'accesso in sola lettura, mentre `private` è spesso (e pericolosamente) usata per l'accesso in scrittura. Il protocollo opera principalmente sulla **porta UDP 161** per le query e sulla **porta UDP 162** per l'invio di trap (notifiche asincrone).

Le informazioni gestibili tramite SNMP sono organizzate in una struttura ad albero gerarchica chiamata MIB (Management Information Base). Ogni punto dati in questo albero è identificato univocamente da un OID (Object Identifier), una sequenza numerica come `1.3.6.1.2.1.1.5.0` che rappresenta il nome dell'host di sistema (`sysName`).

## Installazione e comandi fondamentali

Su una distribuzione basata su Debian come Kali Linux, l'installazione è immediata.

```
sudo apt update
sudo apt install snmpcheck -y
```

Per verificare l'installazione e visualizzare tutte le opzioni disponibili:

```
snmp-check -h
```

Il comando più basilare, che dovresti provare per primo dopo aver individuato un servizio SNMP, utilizza la community string `public` con i parametri predefiniti.

```
snmp-check 10.10.20.5 -c public
```

## Uso pratico: opzioni che fanno la differenza

Mentre il comando base è un buon punto di partenza, le opzioni avanzate di `snmp-check` sono ciò che ti permette di adattarlo a scenari reali e potenzialmente ostili.

**Gestione di timeout e ritentativi**: Il protocollo UDP non è affidabile per natura. Su reti lente o su host lenti, è essenziale aumentare i timeout e i ritentativi per evitare falsi negativi.

```
snmp-check 10.10.20.5 -c public -v 2c -t 3 -r 2
```

**Selezione della versione del protocollo**: Specificare la versione SNMP può influenzare il risultato. SNMPv2c (`-v 2c`) è generalmente preferibile perché supporta l'operazione `GETBULK`, più efficiente per recuperare grandi quantità di dati.

**Test dell'accesso in scrittura**: L'opzione `-w` esegue un test separato per verificare se la community string fornita concede privilegi di scrittura. Questo è un finding critico in un penetration test.

```
snmp-check 10.10.20.5 -c private -v 2c -w
```

**Disabilitare l'enumerazione pesante**: Su host con molte connessioni, l'enumerazione delle connessioni TCP attive può essere lenta. L'opzione `-d` (disable) salta questa fase, rendendo la scansione più rapida e meno rumorosa, concentrandosi sulle informazioni di configurazione di base.

## Interpretazione dell'output: dove cercare le informazioni cruciali

Non è necessario leggere ogni riga dell'output. Per un'analisi tattica efficiente, concentrati su tre aree chiave in quest'ordine:

1. **Identità del Sistema (Sezione "System information")**: Cerca l'hostname, la descrizione del sistema (che spesso rivela il sistema operativo e la versione), e soprattutto i campi `Contact` e `Location`. Questi ultimi sono notoriamente trascurati dagli amministratori e possono rivelare indirizzi email interni (utili per campagne di phishing) o informazioni fisiche sensibili.
2. **Mappatura della Rete (Sezioni "Network interfaces" e "Routing information")**: Queste sezioni sono fondamentali per il movimento laterale. Elencano tutti gli indirizzi IP assegnati all'host e le rotte di rete conosciute, svelando spesso subnet interne non precedentemente identificate durante la fase di scoperta iniziale.
3. **Indizi sui Servizi (Sezioni "Listening UDP ports" e "TCP connections")**: Forniscono una istantanea delle porte in ascolto e delle connessioni attive. Considera queste informazioni come *indizi* piuttosto che verità assoluta (possono cambiare rapidamente), ma sono ottimi punti di partenza per un'ulteriore enumerazione mirata con `nmap` sui servizi identificati.

## Mini-playbook operativo (stile OSCP)

Questo flusso di lavoro è progettato per essere metodico, ripetibile e a basso rumore, trasformando SNMP da una curiosità in un acceleratore per il tuo engagement.

**Step 1 — Conferma del Servizio**
Prima di qualsiasi tentativo di enumerazione, conferma la presenza del servizio SNMP sulla porta standard.

```
sudo nmap -sU -p 161 10.10.20.5 -n -Pn --open
```

**Step 2 — Enumerazione Iniziale con snmp-check**
Esegui una scansione rapida con parametri conservativi. Salva sempre l'output.

```
snmp-check 10.10.20.5 -v 2c -c public -t 2 -r 1 > snmp_initial.txt
```

**Step 3 — Analisi e Estrazione dei Dati Tattici**
Analizza il file `snmp_initial.txt` e estrai le tre categorie di informazioni chiave: Identità di Sistema, Configurazione di Rete, Indizi sui Servizi. Annotale.

**Step 4 — Enumerazione Mirata dei Servizi**
Utilizza le informazioni raccolte (ad esempio, un indirizzo IP interno o un numero di porta scoperto) per lanciare scansioni `nmap` mirate e molto più silenziose, evitando di scannerizzare l'intera superficie d'attacco in modo indiscriminato.

**Step 5 — Investigazione Avanzata (Se Necessario)**
Se l'output di `snmp-check` indica la presenza di dati interessanti ma non li espande (ad esempio, un OID specifico), passa a `snmpwalk` per un'analisi più granulare di quel sotto-albero della MIB.

## Snmpcheck vs Snmpwalk: scegliere lo strumento giusto

La scelta non è tra "meglio" e "peggio", ma tra "panoramica" e "profondità".

* **Usa `snmp-check` quando**: Hai bisogno di una **panoramica rapida e umanamente leggibile** di un host appena scoperto. È il tool ideale per la fase di triage iniziale. Vuoi categorizzare automaticamente le informazioni senza conoscere gli OID specifici.
* **Usa `snmpwalk` quando**: Hai bisogno di un **controllo assoluto e granulare** su ciò che stai interrogando. Devi enumerare uno specifico sotto-albero della MIB (ad esempio, `.1.3.6.1.4.1.77.1.2.25` per gli utenti su Windows). L'output di `snmp-check` ti ha indicato una direzione e vuoi scavare più a fondo per recuperare ogni dato disponibile in quella categoria. Per operazioni su grandi set di dati, `snmpbulkwalk` (che utilizza `GETBULK`) è più efficiente.

## Concetti controintuitivi per un uso efficace

1. **Il silenzio UDP è ambiguo**: Un timeout o l'assenza di risposta sulla porta 161/UDP **non equivale a un servizio chiuso**. L'agente SNMP può semplicemente ignorare le query che utilizzano una community string errata o una versione del protocollo non supportata. Sperimenta con diverse combinazioni di `-v` e `-c` prima di dichiarare il servizio inaccessibile.
2. **Più output non significa più valore**: `snmp-check` può generare molte righe di output, specialmente su server ricchi di servizi. Il tuo obiettivo non è leggerle tutte, ma filtrare strategicamente per le tre categorie di informazioni chiave (Identità, Rete, Servizi). Il vero valore sta nel trasformare quei dati in azioni successive.
3. **Disabilitare può essere un vantaggio**: L'opzione `-d` (disable TCP enum) non è un limite, ma uno strumento tattico. Su un target critico o molto attivo, ottenere rapidamente le informazioni di sistema e di rete saltando l'enumerazione TCP lunga e rumorosa può essere la scelta più intelligente.
4. **L'accesso in scrittura (-w) è un campanello d'allarme, non un exploit**: Trovare una community string con privilegi di scrittura è un grave problema di configurazione. Tuttavia, non concede un controllo immediato del dispositivo. Segnalalo come un finding ad alto rischio, ma la tua prossima mossa dovrebbe essere investigare *come* questo accesso possa essere sfruttato in modo specifico nel contesto del target (es. modificare le route di rete, alterare la configurazione).

## Checklist operativa e promemoria

Per garantire un approccio metodico in laboratorio o durante un esame, segui questa checklist:

* Confermata la porta 161/UDP aperta con `nmap -sU`.
* Eseguito `snmp-check` con `-v 2c` e community comuni (`public`, `private`).
* Aggiustati parametri di timeout/retry in caso di fallimenti iniziali.
* Salvato l'output completo in un file per il report.
* Estratti e annotati: Hostname/OS, Interfacce di rete/IP, Porte/Servizi interessanti.
* Avviata enumerazione mirata con `nmap` basata sui dati SNMP raccolti.
* Considerato l'uso di `snmpwalk` per investigare ulteriormente OID promettenti.

## FAQ su Snmpcheck

**snmpcheck e snmp-check sono la stessa cosa?**
Sì. Su Kali Linux, il pacchetto Debian si chiama `snmpcheck`, ma il comando binario che si invoca da terminale è `snmp-check`.

**Qual è il primo comando da provare?**
`snmp-check 10.10.20.5 -c public`. Se fallisce, prova `-v 2c` e aumenta `-t`.

**Perché ottengo solo timeout?**
Le cause tipiche sono: community string errata, versione SNMP sbagliata (`-v`), firewall che blocca UDP/161, o un agente SNMP molto lento. Modifica un parametro alla volta per diagnosticare il problema.

**A cosa serve esattamente il flag `-w`?**
Esegue un test specifico e separato per determinare se la community string fornita concede privilegi di scrittura (ad esempio, per impostare valori OID). È un test distinto dall'enumerazione standard in sola lettura.

**SNMP è sempre in esecuzione sulla porta 161?**
Nella stragrande maggioranza dei casi, sì. In scenari di laboratorio particolarmente creativi o in ambienti personalizzati, potrebbe essere stato spostato. In questi rari casi, utilizza l'opzione `-p <porta>` per specificarne una diversa.

## Note Legali e Etiche Finali

**Ricorda**: Le tecniche e gli strumenti descritti in questa guida, incluso `snmp-check`, sono potenti e devono essere utilizzati in modo responsabile. Il loro impiego è giustificato **esclusivamente** in uno dei seguenti contesti:

1. Su sistemi e reti di tua esclusiva proprietà.
2. Come parte di un penetration test o di un'attività di Red Team per la quale possiedi un'autorizzazione scritta, esplicita e vincolante dal proprietario del sistema target.
3. In ambienti di laboratorio isolati e controllati, come quelli di Hackita, progettati per l'apprendimento e la sperimentazione.

L'uso non autorizzato di questi strumenti per accedere o modificare sistemi informatici altrui costituisce un reato ed è contrario all'etica professionale della comunità della sicurezza informatica.

Formati. Sperimenta in modo Etico. Previeni.

Hackita - Excellence in Offensive Security
Link utili

Documentazione SNMP
[https://www.net-snmp.org/docs/](https://www.net-snmp.org/docs/)

OID reference
[https://oid-info.com/](https://oid-info.com/)

**Supporto e formazione**

*Supporta HackITA
[https://hackita.it/supporto/](https://hackita.it/supporto/)*

*Formazione e servizi Red Team
[https://hackita.it/servizi/](https://hackita.it/servizi/)*
