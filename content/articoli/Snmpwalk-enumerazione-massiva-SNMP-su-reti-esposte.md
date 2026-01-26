---
title: 'Snmpwalk: enumerazione massiva SNMP su reti esposte'
description: >-
  Snmpwalk è il tool ideale per interrogare agent SNMP e raccogliere info
  dettagliate su dispositivi di rete. Usato per recon low-noise e attacchi
  mirati.
image: /snmpwalk.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - snmpwalk
  - snmp
slug: "snmpwalk"
---

##

# **Cos'è snmpwalk?**

Snmpwalk è uno strumento da riga di comando della suite Net-SNMP. Il suo scopo è interrogare in modo sequenziale un agente SNMP remoto, recuperando tutti i valori disponibili a partire da un punto specifico nell'albero gerarchico dei dati (MIB). È lo strumento principe per un'**enumerazione approfondita e completa**.

**Cosa fa concretamente?**
Invia una serie di richieste SNMP GETNEXT (o GETBULK con `snmpbulkwalk`) per "camminare" attraverso un sotto-albero di OID (Object Identifiers). Restituisce una lista grezza di tutte le coppie OID-valore esposte dall'agente. A differenza di tool come `snmp-check`, non formatta l'output in sezioni, ma offre il **massimo dettaglio possibile**.

**A cosa serve per un attaccante?**
Trasforma un servizio SNMP mal configurato in una **miniera di intelligence**. Serve a:

* Identificare il sistema operativo, la versione e i contatti amministrativi.
* Mappare la rete scoprendo interfacce, indirizzi IP e, soprattutto, la **tabella ARP** per individuare altri host.
* Enumerare processi e servizi in esecuzione attraverso OID specifici.
  La sua forza è la **completezza**: estrae (quasi) tutto ciò che l'agente è configurato a condividere.

**Filosofia del tool.**
Opera a basso livello, esponendo la complessità del protocollo SNMP per dare all'operatore il controllo totale. Per un Red Teamer, padroneggiarlo significa saper estrarre ogni dato esposto da una configurazione negligente.

## Setup e Primi Passi

Snmpwalk è di solito preinstallato su Kali Linux. Verifica o installa con:

```
sudo apt update && sudo apt install snmp -y
```

**Configurazione base per il lab.**
Non serve configurazione client. L'unico prerequisito è la connettività verso la porta **161/UDP** del target. Conferma prima il servizio:

```
sudo nmap -sU -p 161 --open 10.10.20.5 -n
```

Ricorda: "open|filtered" su UDP è un risultato comune e normale.

## Tecniche Offensive Dettagliate

### Tecnica 1: Scoprire l'Identità del Sistema

```
snmpwalk -v2c -c public 10.10.20.5 .1.3.6.1.2.1.1
```

**Spiegazione offensiva:**
Questo comando interroga il gruppo `system` (OID .1.3.6.1.2.1.1), la base. Cerca questi valori nell'output:

* `sysDescr.0`: Rivela sistema operativo e versione. Fondamentale per la ricerca di exploit.
* `sysName.0`: L'hostname o FQDN del target.
* `sysContact.0` e `sysLocation.0`: Spesso contengono **informazioni sensibili** come email di amministratori o ubicazione fisica, utili per phishing o comprensione dell'ambiente.

### Tecnica 2: Mappare la Rete e Scoprire Altri Host

```
snmpwalk -v2c -c public -Oq 10.10.20.5 .1.3.6.1.2.1.2.2.1.2
snmpwalk -v2c -c public 10.10.20.5 .1.3.6.1.2.1.3.1.1.2
```

**Spiegazione offensiva:**
Il primo comando enumera le descrizioni delle interfacce di rete (`ifDescr`). Il secondo interroga la **tabella ARP**, uno dei trofei più preziosi.
La tabella ARP mostra gli indirizzi IP e MAC degli host con cui il target ha comunicato di recente. Questo permette di:

* **Scoprire host attivi** nella stessa sottorete senza lanciare scansioni attive e rumorose.
* Identificare potenziali obiettivi per il **movimento laterale**.
  È intelligence di rete pura e stealth.

### Tecnica 3: Enumerare Processi e Servizi

```
snmpwalk -v2c -c public 10.10.20.5 .1.3.6.1.2.1.25.4.2.1.2
```

**Spiegazione offensiva:**
Questo OID (.1.3.6.1.2.1.25.4.2.1.2) appartiene alla HOST-RESOURCES-MIB e restituisce i nomi dei processi in esecuzione (`hrSWRunName`). Filtra l'output per servizi critici:

```
... | grep -iE "(ssh|apache|nginx|mysql|postgres|java|tomcat)"
```

Trovare `sshd`, `apache2` o `mysqld` fornisce target immediati per attacchi successivi (brute-force, exploit web, query al DB). Su host Windows, OID specifici possono enumerare utenti locali.

### Tecnica 4: Ottimizzare l'Output per l'Analisi

L'output grezzo può essere enorme. Ecco come renderlo gestibile:

```
snmpbulkwalk -v2c -c public -Cn0 -Cr50 10.10.20.5 .1.3.6.1.2.1.2
snmpwalk -v2c -c public -Oqv 10.10.20.5 .1.3.6.1.2.1.1.0 > system_info.txt
snmpwalk -v2c -c public -On 10.10.20.5 .1.3.6.1.2.1.1.1.0
```

**Spiegazione offensiva:**

* `snmpbulkwalk`: Usa l'operazione GETBULK (più efficiente di GETNEXT) per tabelle grandi. `-Cn0 -Cr50` ottimizza il recupero.
* `-Oqv`: Produce output "solo valori", perfetto per il piping in `grep`, `awk` o per script.
* `-On`: Forza l'output numerico, essenziale se i file MIB non sono installati o causano errori.
  Questi comandi trasformano il dato grezzo in **intelligence analizzabile**.

### Tecnica 5: Affrontare SNMPv3

SNMPv3 introduce autenticazione e cifratura basate su utente.

```
snmpwalk -v3 -l noAuthNoPriv -u snmp_user 10.10.20.5 .1.3.6.1.2.1.1
snmpwalk -v3 -l authPriv -u snmp_admin -a SHA -A "AuthPass123!" -x AES -X "PrivPass456!" 10.10.20.5 .1.3.6.1.2.1.1
```

**Spiegazione offensiva:**
Il parametro `-l` definisce il **livello di sicurezza**:

* `noAuthNoPriv`: Solo username (nessuna sicurezza reale).
* `authNoPriv`: Autenticazione (con `-a` e `-A`) ma dati in chiaro.
* `authPriv`: Autenticazione e cifratura (con `-x` e `-X`).
  In un test autorizzato, queste credenziali potrebbero essere trovate in file di configurazione, backup o tramite altri vettori.

## Scenario di Attacco Completo

**Contesto:** Test su rete autorizzata. Il router di confine (`10.10.100.1`) ha SNMP attivo.

1. **Step 1 - Ricognizione:**
   `snmpwalk -v2c -c public 10.10.100.1 .1.3.6.1.2.1.1`
   *Trovi:* OS "Cisco IOS", contatto "[noc@corp.com](mailto:noc@corp.com)".
2. **Step 2 - Scoperta Rete Interna:**
   `snmpwalk -v2c -c public 10.10.100.1 .1.3.6.1.2.1.3.1.1.2`
   *Trovi:* Host attivi in `192.168.10.0/24`, incluso `192.168.10.25`.
3. **Step 3 - Pivot e Sfruttamento:**
   Scopri che la community `private` offre accesso in scrittura. Con `snmpset`, modifichi temporaneamente una route sul router per reindirizzare il traffico verso `192.168.10.25` attraverso una macchina da te controllata, creando un tunnel per il movimento laterale.
4. **Step 4 - Compromissione:**
   Raggiunto `192.168.10.25`, una nuova enumerazione SNMP rivela (tramite HOST-RESOURCES-MIB) un servizio di database vecchio e vulnerabile. Lo sfruttamento porta alla compromissione.

**Risultato Finale:** Partendo dall'enumerazione SNMP di un router, attraverso la mappatura della rete interna e lo sfruttamento di privilegi di scrittura SNMP, hai ottenuto l'accesso a un server interno. Questo dimostra come **SNMP mal configurato possa essere il ponte che collega segmenti di rete isolati**.

## Considerazioni Finali per l'Operatore

1. **Lezione Fondamentale:** Considera ogni agente SNMPv1/v2c accessibile come un **database di configurazione remoto**. Il tuo compito è collegare i punti (contatti, rete, servizi) per ricostruire l'architettura del target e trovare il percorso di attacco.
2. **Quando Usarlo vs Altri Tool:**
   * Usa **`snmpwalk`/`snmpbulkwalk`** per l'enumerazione completa e approfondita.
   * Usa **`snmp-check`** per una panoramica rapida e formattata in fase di triage iniziale.
   * Usa **`snmpget`** per interrogare singoli OID noti.
   * Integra **sempre** i dati SNMP con i risultati di `nmap` e altri strumenti.
3. **Limiti Realistici:**
   * La sua efficacia dipende totalmente dalla **configurazione dell'agente**. SNMPv3 con autenticazione forte e view restrittive lo neutralizzano.
   * È **intrinsecamente rumoroso**: molte query consecutive sono facilmente rilevabili da un SIEM o IDS attento.
4. **Integrazione con Altri Strumenti:**
   L'output di snmpwalk è **il carburante per l'automazione offensiva**.
   * Gli IP dalla tabella ARP alimentano liste per scansioni `nmap` mirate.
   * I nomi dei processi vengono confrontati con database di exploit.
   * Le versioni OS guidano la ricerca di vulnerabilità.
     Snmpwalk non è la fine, ma **l'inizio di un processo di targeting estremamente preciso**.

### Pronto a Portare le Tue Competenze Offensive al Livello Successivo?

Hackita offre formazione pratica e avanzata per Red Teamer e appassionati di sicurezza. Esplora i nostri percorsi formativi, come corsi di Red Teaming e laboratori accessibili 24/7, per approfondire le tecniche descritte in scenari complessi e realistici.
Visita la nostra pagina dei servizi per maggiori dettagli: [https://hackita.it/servizi](https://hackita.it/servizi)

### Supporta la Comunità della Sicurezza Italiana

Crediamo in una comunità di sicurezza forte e condivisa. I nostri contenuti gratuiti sono resi possibili anche dal tuo supporto. Un tuo contributo ci aiuta a mantenere i laboratori, produrre nuove guide e organizzare eventi.
Se trovi valore nel nostro lavoro, considera una donazione: [https://hackita.it/supporto](https://hackita.it/supporto)

### Note Legali e Etiche

**RICORDA:** Le tecniche descritte devono essere utilizzate esclusivamente in ambienti che possiedi o per i quali hai **autorizzazione scritta esplicita**. Il loro uso non autorizzato è illegale e non etico.
**Formati. Sperimenta in modo Etico. Previeni.**

Due eccellenti riferimenti esterni per la guida su `snmpwalk`.

**1. SnmpWalk.exe (SNMPSoft Tools)**

* **Cosa trovi:** La documentazione ufficiale dello strumento a riga di comando `SnmpWalk.exe`. Contiene l'elenco completo di **tutti i parametri** con descrizioni dettagliate (es. `-v:version`, `-ap:auth_proto`, `-os:start_oid`), i formati di output (CSV) e diversi esempi di sintassi per SNMPv1/v2c e SNMPv3 .
* **Perché è utile per il lab:** È un riferimento tecnico essenziale per costruire comandi complessi, soprattutto per SNMPv3 con autenticazione e cifratura, o per eseguire walk parziali partendo da OID specifici.
* **Link:** [https://ezfive.com/snmpsoft-tools/snmp-walk/](https://ezfive.com/snmpsoft-tools/snmp-walk/)

**2. Guida "How to execute SNMPWALK" (OpsRamp)**

* **Cosa trovi:** Una guida operativa chiara, organizzata per versioni SNMP (v1, v2c, v3). Fornisce **esempi pratici immediatamente utilizzabili** per "full walk", "system walk", "enterprise walk", ecc. Spiega anche parametri utili per ambienti di lab come timeout (`-t`) e ritentativi (`-r`) .
* **Perché è utile per il lab:** È perfetta per il playbook OSCP-style, permettendo di copiare e adattare rapidamente la sintassi per diversi tipi di enumerazione senza perdere tempo con la sperimentazione.
* **Link:** [https://docs.opsramp.com/solutions/monitors/snmp-monitors/how-to-execute-snmpwalk/](https://docs.opsramp.com/solutions/monitors/snmp-monitors/how-to-execute-snmpwalk/)
