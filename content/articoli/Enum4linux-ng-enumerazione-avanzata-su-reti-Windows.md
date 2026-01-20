---
title: 'Enum4linux-ng: enumerazione avanzata su reti Windows'
description: >-
  Scopri come usare enum4linux-ng per estrarre utenti, gruppi, condivisioni e
  SID da sistemi Windows. Strumento essenziale per ogni fase di information
  gathering.
image: /enum4linux.webp
draft: true
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - enum4linux-ng
featured: true
---

# Enum4linux-ng: La Lente d'Ingrandimento per il Cuore di Windows e Samba

Report Red Team | Ambiente Controllato Autorizzato

## 1. Introduzione

**Cos'è il tool?** Enum4linux-ng è la riscrittura in Python del classico enum4linux, uno strumento progettato per enumerare informazioni da sistemi Windows e Samba. Non è un exploit, ma un **potentissimo aggregatore di intelligence**. Incapsula e automatizza l'uso di strumenti Samba come `rpcclient`, `smbclient`, `net` e `nmblookup` per fornire una visione organizzata del target.

**Cosa fa concretamente?** Interroga i servizi SMB e LDAP di un host per estrarre in modo strutturato informazioni critiche: utenti, gruppi, membership, share di rete, policy password, informazioni sul sistema operativo e sul dominio. La sua caratteristica distintiva è la capacità di esportare tutti i risultati in formati strutturati come **JSON e YAML**, rendendo i dati pronti per l'analisi successiva o l'integrazione in pipeline automatizzate.

**A cosa serve per un attaccante?** Serve a **rispondere a domande fondamentali** subito dopo aver scoperto una porta 445 aperta. Chi è su questa macchina? A quale dominio appartiene? Ci sono share accessibili? Qual è la policy delle password? In un attacco reale, specialmente in ambienti Active Directory, queste risposte sono il carburante per il movimento laterale e l'escalation dei privilegi. È il tool che trasforma un "SMB open" in una mappa di opportunità attaccabili.

**Filosofia del tool:** La sua potenza risiede nell'**automazione intelligente ("smart enumeration")**. Prima verifica quali servizi (SMB/LDAP) sono accessibili, poi adatta dinamicamente i suoi test, saltando quelli inutili. Inoltre, se non riesce a stabilire una sessione SMB, si ferma, evitando di farti perdere tempo con errori rumorosi. È pensato per professionisti della sicurezza e giocatori di CTF, dove l'efficienza e la chiarezza dei dati contano.

## 2. Setup e Primi Passi

L'installazione su Kali Linux è immediata. Il tool è disponibile nei repository ufficiali.

```
sudo apt update && sudo apt install enum4linux-ng -y
```

Per verificare l'installazione e vedere tutte le opzioni:

```
enum4linux-ng -h
```

**Configurazione base per il lab:** Non è richiesta alcuna configurazione. Il tool dipende da Python3 e dai toolkit Samba comuni, già installati di default su Kali. L'unica premessa è avere un target con i servizi SMB (porte 139/445) o LDAP accessibili.

## 3. Tecniche Offensive Dettagliate

### Tecnica 1: La Baseline Tattica – Scansione "All-in-One"

```
enum4linux-ng -A 10.10.20.5
```

**Spiegazione offensiva:** La flag `-A` (Do all simple enumeration) è il tuo **primo colpo di sonar**. Senza autenticazione, cerca di raccogliere tutto il possibile: utenti, gruppi, share, policy password e info sull'OS. Anche se con credenziali NULL potresti vedere solo utenti e gruppi predefiniti, scoprire la policy delle password (es. "lunghezza minima: 7") è già un intel prezioso per dirigere attacchi di brute-force o password spraying.

### Tecnica 2: L'Upgrade con Credenziali – Sbloccare l'Accesso Reale

```
enum4linux-ng -A -u 'jdoe' -p 'Password123!' -w LAB.LOCAL 10.10.20.5
```

**Spiegazione offensiva:** Questo è il salto di qualità. Molte informazioni sensibili in SMB/RPC sono protette dall'accesso anonimo. Con credenziali valide, **la lista degli utenti diventa completa** e, soprattutto, puoi enumerare le **appartenenze ai gruppi**. Scoprire che un account è membro di gruppi privilegiati come "Backup Operators" identifica immediatamente un target ad alto valore per l'escalation.

### Tecnica 3: RID Cycling – L'Enumerazione Forzata Quando il Server Tace

```
enum4linux-ng -R -r 1000-1100 10.10.20.5
```

**Spiegazione offensiva:** Il RID (Relative Identifier) è la parte finale di un SID (Security Identifier) di Windows. Il RID cycling prova in sequenza un range di RID (es. 1000-1100) per **indovinare oggetti esistenti**. È una tecnica più rumorosa ma potente quando l'enumerazione pulita fallisce, permettendoti di scoprire account non elencati altrimenti, come account di servizio nascosti.

### Tecnica 4: L'Esportazione per la Persistenza – JSON/YAML

```
enum4linux-ng -A -u 'jdoe' -p 'Password123!' -oA loot_dc01 10.10.20.5
```

**Spiegazione offensiva:** Questa è la feature killer di enum4linux-ng. L'opzione `-oA` **salva tutto lo stato dell'enumerazione** in file JSON e YAML. Offensivamente, ti permette di archiviare l'intel per un engagement lungo, elaborare i dati automaticamente (es. estrarre tutti gli username per un attacco di password spraying) e generare evidenze chiare per il report finale.

## 4. Scenario di Attacco Completo

**Contesto:** Penetrazione iniziale su una workstation (10.10.20.10). Hai ottenuto shell e dumpato gli hash locali, trovando le credenziali dell'utente di dominio `jdoe`.

1. **Step 1 – Ricognizione sul Controller di Dominio:**

```
enum4linux-ng -As -u 'jdoe' -p 'Password123!' -w LAB.LOCAL 10.10.20.5 | tee initial_scan.txt
```

**Trovi:** Una lista di utenti e l'appartenenza di un account `svc_backup` al gruppo "Backup Operators".

1. **Step 2 – Ricerca di Punti d'Appoggio:**

Esplori le share enumerate e trovi credenziali in chiaro per un utente `db_admin` in uno script.

1. **Step 3 – Escalation con Nuove Credenziali:**

```
enum4linux-ng -A -u 'db_admin' -p 'DB@Pass!2024' -w LAB.LOCAL -oJ domain_loot.json 10.10.20.5
```

**Risultato:** Il file JSON contiene una mappatura completa. L'analisi rivela che `db_admin` è membro del gruppo **"Server Operators"**, concedendo potenziali privilegi amministrativi.

1. **Step 4 – Pivot Finale:**

Utilizzando le informazioni su share e permessi, localizzi e comprometti un server di sviluppo, per poi mirare al Domain Controller finale.

**Risultato Finale:** Partendo da un semplice hash locale, l'uso strategico di enum4linux-ng per enumerare utenti, gruppi e permessi ha guidato una catena di movimenti laterali ed escalation dei privilegi.

## 5. Considerazioni Finali per l'Operatore

1. **Lezione Fondamentale: È un Generatore di Ipotesi Attaccabili.** Enum4linux-ng non sfrutta direttamente le vulnerabilità; **trasforma la configurazione di sistema in obiettivi tattici**. La vera abilità sta nel collegare un utente enumerato a un gruppo, quel gruppo a una permissione, e quella permissione a un'azione concreta.
2. **Quando Usarlo vs Altri Tool:** Usalo come **strumento di enumerazione primaria su SMB/LDAP** quando hai bisogno di output strutturato. Per l'esecuzione di comandi su grandi reti, **NetExec (ex CrackMapExec)** è più adatto. Per la visualizzazione grafica delle relazioni AD, **BloodHound** è insostituibile. Enum4linux-ng si colloca perfettamente nella fase di raccolta dati strutturati.
3. **Limiti Realistici:** È **rumoroso**. Le interrogazioni RPC e SMB vengono registrate nei log di Windows. La sua efficacia è legata ai permessi delle credenziali fornite e alla configurazione del server target.
4. **Integrazione con Altri Strumenti:** Il suo output JSON è il **ponte perfetto per l'automazione**. Le liste utenti possono essere passate a tool come Kerbrute per password spraying. Le informazioni sui gruppi possono alimentare script di PowerView per l'analisi delle ACL.

### Pronto a Portare le Tue Competenze Offensive al Livello Successivo?

La padronanza di strumenti di enumerazione come enum4linux-ng è fondamentale, ma sapere come integrarli in un flusso di attacco coordinato contro un Active Directory enterprise è ciò che separa un principiante da un professionista.

[Hackita offre formazione pratica](https://hackita.it/servizi) e avanzata pensata per i Red Teamer. Scopri i nostri servizi formativi .

### Supporta la Comunità della Sicurezza Italiana

Crediamo in una comunità di sicurezza forte, condivisa e indipendente. Il nostro materiale formativo, gli articoli tecnici e i laboratori sono progettati per alzare il livello di tutti.

Supportaci con una [donazione](https://hackita.it/supporto) cliccandoci sopra.

### Note Legali

**RICORDA:** Le tecniche descritte devono essere utilizzate esclusivamente in ambienti che possiedi o per i quali hai **autorizzazione scritta esplicita**. Il loro uso non autorizzato è illegale e non etico.

**Formati. Sperimenta. Previeni.**
