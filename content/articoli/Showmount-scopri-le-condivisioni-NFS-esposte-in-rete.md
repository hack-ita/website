---
title: 'Showmount: scopri le condivisioni NFS esposte in rete'
slug: showmount
description: >-
  Showmount è il tool perfetto per enumerare condivisioni NFS. Usato nei recon
  per identificare risorse accessibili e punti d’ingresso in ambienti
  Unix/Linux.
image: /showmount.webp
draft: false
date: 2026-01-25T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - showmount
  - nfs
---

# Showmount: Scopri le Condivisioni NFS Esposte in Rete

Se `showmount -e` ti dà timeout o “Program not registered”, qui capisci subito se è un problema di NFSv4-only, `rpcbind/mountd`, o firewall, e ottieni un risultato verificabile in lab.

## Intro

`showmount` è un tool che interroga il mount daemon (MNT service) di un server NFS per ottenere informazioni su export e mount attivi.

In un workflow offensivo “da lab”, ti serve per scoprire rapidamente directory esportate (potenziale leakage), capire se l’host espone MNT service e correlare la superficie d’attacco RPC/NFS prima di passare a mount e verifica permessi.

Cosa farai:

* Identificare export NFS con `showmount -e`
* Capire cosa significa (e cosa NON significa) l’output
* Risolvere gli errori più comuni (RPC, versioni, firewall)
* Applicare detection e hardening essenziali

Nota etica: usa queste tecniche solo su lab/CTF/HTB/PG/VM personali o sistemi esplicitamente autorizzati.

## Cos’è showmount e dove si incastra nel workflow NFS

> **In breve:** `showmount` interroga il servizio MNT (`rpc.mountd`) di un server NFS per ottenere export e informazioni sui mount, ma su server “NFSv4-only” può non funzionare anche se NFS è attivo.

Nel recon, `showmount` è il “quick check” per capire se un server NFS sta esponendo export e come li annuncia via MNT service.

Perché: ti evita di andare “alla cieca” su mount e ti dà segnali immediati su configurazione e superficie RPC.

Cosa aspettarti: un elenco di export (con `-e`) o di client che stanno montando (senza opzioni / con `-a/-d`).

Comando:

```bash
showmount -h
```

Interpretazione: se vedi opzioni `-e`, `-a`, `-d`, stai usando la versione “classica” di `showmount` (nfs-utils/nfs-common lato client).

Quando NON usarlo: se sai che il target è NFSv4-only (MNT service non esposto) o se l’ambiente blocca RPC/portmap; in quel caso devi passare a metodi alternativi (vedi sezione “Alternative”).

## Installazione e sanity check in Kali/Debian

> **In breve:** su Kali/Debian, `showmount` arriva tipicamente con il pacchetto client NFS (`nfs-common`); verifica che esista e che risponda localmente.

Perché: molti errori “misteriosi” sono solo “tool non installato” o PATH sbagliato.

Cosa aspettarti: un path valido e un help funzionante.

Comando:

```bash
which showmount
```

Esempio di output (può variare):

```text
/usr/sbin/showmount
```

Interpretazione: se `which` non stampa nulla, installa i client NFS o usa `command -v showmount`.

Errore comune + fix: `which: no showmount in (...)` → installa `nfs-common` o equivalente distro.

Comando:

```bash
sudo apt update && sudo apt install -y nfs-common
```

Cosa aspettarti: installazione di utility NFS client (incluso `showmount` su molte distro).

## Sintassi base: i 3 pattern che userai sempre

> **In breve:** `showmount -e` per export, `showmount` (senza opzioni) per client che montano, `showmount -a` per “chi monta cosa” (ma non affidabile al 100%).

### Pattern 1 — Export discovery (`-e`)

Perché: scoprire rapidamente quali directory vengono esportate.

Cosa aspettarti: lista di export + ACL/host autorizzati (se configurati).

Comando:

```bash
showmount -e 10.10.10.10
```

Esempio di output (può variare):

```text
Export list for 10.10.10.10:
/srv/nfs/public   *
/srv/nfs/backup   10.10.10.0/24
```

Interpretazione: `*` indica che l’export è “wide” (non necessariamente scrivibile), mentre una subnet/host limita i mount.

Errore comune + fix: `clnt_create: RPC: Port mapper failure - Timed out` → RPC/111 bloccato o `rpcbind` non raggiungibile; vedi troubleshooting.

### Pattern 2 — Client list (senza opzioni)

Perché: capire chi sta montando dal server (utile in lab per capire “attività” e rumore).

Cosa aspettarti: elenco di client (hostname/IP).

Comando:

```bash
showmount 10.10.10.10
```

Esempio di output (può variare):

```text
Hosts on 10.10.10.10:
10.10.10.20
10.10.10.30
```

Interpretazione: ti dice “chi risulta montare”, ma dipende da come il server registra i mount.

Errore comune + fix: output vuoto non significa “nessun mount” (può essere logging disabilitato o info non affidabile).

### Pattern 3 — Host:dir (`-a`) e dirs (`-d`)

Perché: correlare client e directory, oppure vedere solo directory montate.

Cosa aspettarti: `-a` mostra `host:dir`, ma questa informazione può non essere affidabile (dipende dai file di stato del server).

Comando:

```bash
showmount -a 10.10.10.10
```

Esempio di output (può variare):

```text
All mount points on 10.10.10.10:
10.10.10.20:/srv/nfs/public
10.10.10.30:/srv/nfs/backup
```

Interpretazione: utile come indizio in lab, non come verità assoluta.

Errore comune + fix: se vedi hostnames “strani” o duplicati, ricordati che il server può normalizzare/sortare i record.

## Enumerazione NFS “da lab”: cosa ti dice showmount (e cosa no)

> **In breve:** `showmount` ti dice cosa il server pubblica via MNT service, non necessariamente tutto ciò che NFS rende accessibile (specialmente con NFSv4-only).

Workflow minimo (in lab):

1. Conferma reachability host (ICMP o ARP in LAN).
2. Controlla che RPC/portmap e MNT siano esposti.
3. Lancia `showmount -e` e interpreta ACL.

Prima di `showmount`, la reachability “basic” la ottieni con [Ping e tecniche ICMP per il recon](/articoli/ping/) in modo coerente col tuo contesto (LAN vs HTB).

Perché: se l’host non risponde o la rete filtra, `showmount` ti darà solo timeout e perdi tempo.

Cosa aspettarti: risultati coerenti con servizi aperti (RPC/111, NFS/2049, MNT dinamica).

Per correlare rapidamente i servizi RPC (program number/porte) usa [rpcinfo per enumerare servizi RPC](/articoli/rpcinfo/) prima di “fidarti” di `showmount -e`.

Quando NON usarlo: se `rpcinfo` mostra NFS ma non MNT, o se il server è NFSv4-only (MNT non esposto). In quel caso l’assenza di export in `showmount` non è conclusiva.

## Casi d’uso offensivi “da lab”: export leakage e validazione permessi

> **In breve:** un export “wide” (`*`) o troppo permissivo può esporre file sensibili o permettere scrittura in directory condivise; valida sempre con un mount controllato in lab e chiudi con mitigazioni.

Caso tipico in lab: `showmount -e` rivela `/srv/nfs/public *`. Questo è un segnale, non un exploit.

Perché: l’export è spesso usato per share di team, backup, staging; se misconfigurato può contenere chiavi, config, dump, script.

Cosa aspettarti: potresti trovare file leggibili da “anon” o permessi di scrittura inattesi.

Comando:

```bash
showmount -e 10.10.10.10
```

Esempio di output (può variare):

```text
Export list for 10.10.10.10:
/srv/nfs/public   *
```

Interpretazione: “\*” indica che il server consente mount da qualunque client (salvo firewall). Ora devi validare accesso e permessi lato filesystem.

Validazione in lab (montare e verificare):
Perché: verificare se l’export è `ro` o `rw` e quali permessi reali hai.

Cosa aspettarti: mount riuscito e directory visibile sotto `/mnt/nfs`.

Comando:

```bash
sudo mkdir -p /mnt/nfs && sudo mount -t nfs -o vers=3 10.10.10.10:/srv/nfs/public /mnt/nfs
```

Interpretazione: output vuoto spesso significa “OK”. Verifica con `mount | grep nfs` e prova lettura/scrittura controllata su file di test.

Errore comune + fix: `mount.nfs: access denied by server` → ACL export non ti include, o stai usando vers errata; prova `vers=4` o controlla export/`/etc/exports` (se sei tu il difensore).

Abuso tipico (solo lab) e cosa guardare:

* Leakage: file di backup, `.env`, config, script di deploy.
* Scrittura: upload di file “innocui” (marker) per validare `rw` senza fare danni.

Detection (segnali): mount request anomale da subnet non prevista, pattern di accesso a directory “backup”, picchi su `rpc.mountd`/NFS in journald/syslog.

Hardening (mitigazioni): restringi gli host autorizzati, evita `*`, mantieni `root_squash`, usa `ro` dove possibile, filtra 111/2049 e la porta di `mountd`, segmenta la rete.

## Errori comuni e troubleshooting (RPC, firewall, NFSv4-only)

> **In breve:** la maggior parte dei fallimenti è dovuta a RPC/111 filtrato, `rpc.mountd` non esposto, o server NFSv4-only senza MNT service pubblica.

### Errore: “RPC: Port mapper failure - Timed out”

Perché: `showmount` passa dal portmapper (`rpcbind`) per scoprire dove parla MNT service.

Cosa aspettarti: timeout se 111 è bloccata o l’host non risponde.

Comando:

```bash
showmount -e 10.10.10.10
```

Esempio di output (può variare):

```text
clnt_create: RPC: Port mapper failure - Timed out
```

Interpretazione: non stai raggiungendo `rpcbind` (porta 111) o la rete filtra UDP/TCP.

Errore comune + fix: testare solo TCP e ignorare UDP (o viceversa) → verifica entrambe le direzioni con un check rapido.

Per test “al volo” reachability su 111/2049, un check pragmatico lo fai anche con [Netcat](/articoli/netcat/) (ricorda: NC ti dice “porta aperta”, non che RPC funzioni).

### Errore: “Program not registered”

Perché: MNT service (mountd) non è registrato su rpcbind, o non esposto ai client.

Cosa aspettarti: `rpcbind` risponde ma non annuncia mountd.

Comando:

```bash
showmount -e 10.10.10.10
```

Esempio di output (può variare):

```text
clnt_create: RPC: Program not registered
```

Interpretazione: tipico su server NFSv4-only o su configurazioni dove `rpc.mountd` è disabilitato/non pubblicato.

Errore comune + fix: concludere “non esiste NFS” → falso. Potrebbe esistere NFSv4 senza MNT service.

### Debug “wire-level” (quando vuoi capire cosa succede davvero)

Perché: vedere se stai contattando 111, se ricevi risposte, e dove va il traffico.

Cosa aspettarti: pacchetti RPC/NFS mentre lanci `showmount`.

Comando:

```bash
sudo tcpdump -ni any host 10.10.10.10 and \( port 111 or port 2049 \)
```

Interpretazione: se non vedi traffico o vedi solo SYN senza SYN/ACK, è filtering. Se vedi risposta su 111 ma poi nulla per mountd, è probabile “MNT non esposto”.

Se preferisci analisi con GUI e filtri, puoi passare a [Wireshark per analisi traffico](/articoli/wireshark/) separando il debugging dal recon.

## Alternative e tool correlati (quando preferirli)

> **In breve:** se `showmount` fallisce o non è conclusivo, usa alternative che non dipendono dal MNT service o che correlano meglio RPC/NFS.

Alternative pratiche in lab:

* `rpcinfo -p <host>` per vedere program/porte RPC e capire se esiste mountd/nfsd.
* `nmap` con script NFS (es. “showmount”) per un check automatizzato (utile se stai già facendo scanning controllato).
* `mount -t nfs -o vers=4 ...` per validare NFSv4 quando MNT non c’è (solo su host autorizzati).
* `nfsstat`/`exportfs` lato server (difensore) per audit reale.

Quando NON usarlo: se stai lavorando in ambienti dove RPC è pesantemente filtrato o se l’obiettivo è NFSv4-only, `showmount` è spesso più “rumore” che segnale.

## Hardening & detection (difesa, log, regole)

> **In breve:** la difesa efficace su NFS è: limitare chi può montare, ridurre i servizi RPC esposti, loggare e monitorare mount anomali.

Hardening “minimo vitale”:

* Evita export a `*` se non strettamente necessario.
* Preferisci ACL su IP/subnet dedicate e segmentazione di rete.
* Mantieni `root_squash` e limita `rw` solo dove serve.
* Firewall: controlla 111/2049 e la porta di `mountd` (oltre a servizi RPC correlati).
* Verifica periodica di `/etc/exports` e applica cambi con `exportfs -ra` (lato server).

Detection (segnali utili):

* Picchi di richieste RPC/portmapper da host non attesi.
* Mount request ripetute (enumerazione) su molte directory in poco tempo.
* Accessi a path “backup”, “home”, “keys” subito dopo un mount.

Perché: questi pattern sono tipici del recon offensivo (anche in lab) e sono ottimi indicatori in produzione.

Cosa aspettarti: eventi in syslog/journal legati a `rpc.mountd`, NFS server e firewall.

***

## Scenario pratico: showmount su una macchina HTB/PG

> **In breve:** in un lab, userai `showmount` per scoprire export NFS su `10.10.10.10`, validare reachability RPC e ottenere un risultato concreto (lista export + decisione successiva).

Ambiente: target `10.10.10.10` (VM HTB/PG), attacker Kali.

Obiettivo: scoprire export NFS e capire se MNT service è esposto.

Perché: vuoi una lista export affidabile prima di tentare mount e analisi permessi.

Cosa aspettarti: output “Export list …” oppure errore RPC che indirizza il troubleshooting.

Comando:

```bash
showmount -e 10.10.10.10
```

Esempio di output (può variare):

```text
Export list for 10.10.10.10:
/srv/nfs/public   *
/srv/nfs/backup   10.10.10.0/24
```

Interpretazione: `public` è potenzialmente montabile da chiunque; `backup` è limitato alla subnet. La prossima azione è validare in lab (mount controllato) e verificare permessi reali.

Comando:

```bash
rpcinfo -p 10.10.10.10 | egrep 'portmapper|mountd|nfs'
```

Esempio di output (può variare):

```text
100000  4   tcp 111  portmapper
100005  3   tcp 20048 mountd
100003  3   tcp 2049 nfs
```

Interpretazione: se vedi `mountd` (100005) e `nfs` (100003), `showmount` ha basi tecniche per funzionare. Se manca `mountd`, sospetta NFSv4-only o MNT non esposto.

Detection + hardening: in difesa, logga richieste a `rpcbind/mountd`, filtra 111/2049 da subnet non autorizzate e rimuovi export “wide” non necessari.

## Playbook 10 minuti: showmount in un lab

> **In breve:** sequenza rapida e ripetibile per passare da “ip trovato” a “export NFS interpretati”, con fallback immediati se `showmount` fallisce.

### Step 1 – Conferma reachability del target

Perché: evita timeout “falsi” dovuti a rete/filtri.

Comando:

```bash
ping -c 1 10.10.10.10
```

### Step 2 – Verifica se RPC/NFS sono plausibili

Perché: `showmount` dipende da RPC per trovare MNT service.

Comando:

```bash
rpcinfo -p 10.10.10.10
```

### Step 3 – Enumerazione export con showmount

Perché: ottenere la lista export e ACL.

Comando:

```bash
showmount -e 10.10.10.10
```

### Step 4 – Se fallisce, interpreta l’errore e scegli il fallback

Perché: “timeout” e “program not registered” portano a cause diverse.

Comando:

```bash
showmount -e 10.10.10.10
```

### Step 5 – Debug rapido di rete (se necessario)

Perché: capire se è firewall o servizio assente.

Comando:

```bash
sudo tcpdump -ni any host 10.10.10.10 and \( port 111 or port 2049 \)
```

### Step 6 – Validazione controllata (solo se autorizzato)

Perché: l’export in lista non implica automaticamente accesso utile.

Comando:

```bash
sudo mount -t nfs -o vers=3 10.10.10.10:/srv/nfs/public /mnt/nfs
```

## Checklist operativa

> **In breve:** se spunti questi punti, riduci quasi a zero i falsi negativi e gli errori “banali” in enumerazione NFS con showmount.

* Hai confermato reachability del target (ICMP/ARP secondo il contesto).
* Hai verificato che `showmount` sia installato e in PATH.
* Hai controllato `rpcinfo -p` per vedere se esiste `mountd` (100005).
* Hai provato `showmount -e` prima di qualsiasi mount.
* Hai interpretato ACL in output (host/subnet vs `*`).
* Hai considerato scenario NFSv4-only se `mountd` non è esposto.
* Hai distinto timeout (rete/firewall) da “program not registered” (servizio).
* Hai fatto debug “wire-level” se i sintomi non tornavano.
* Hai validato accesso reale con mount controllato solo se autorizzato.
* Hai verificato permessi reali lato filesystem (non solo export).
* Hai annotato detection/hardening come parte del report lab.
* Hai evitato conclusioni assolute basate su `-a`/mount list (info non affidabile).

## Riassunto 80/20

> **In breve:** queste azioni coprono la maggior parte dei casi reali in lab.

| Obiettivo               | Azione pratica                   | Comando/Strumento     |
| ----------------------- | -------------------------------- | --------------------- |
| Scoprire export NFS     | Enumerare export via MNT service | `showmount -e <host>` |
| Vedere chi monta        | Lista client che montano         | `showmount <host>`    |
| Correlare client e dir  | Vista host:dir (indicativa)      | `showmount -a <host>` |
| Capire se è RPC issue   | Verifica program/porte           | `rpcinfo -p <host>`   |
| Identificare NFSv4-only | Se manca `mountd`                | `rpcinfo -p <host>`   |
| Capire se è firewall    | Sniff porte 111/2049             | `tcpdump`             |
| Validare accesso reale  | Mount controllato (autorizzato)  | `mount -t nfs`        |

## Concetti controintuitivi

> **In breve:** sono errori frequenti che fanno perdere tempo anche a chi “sa già” usare showmount.

* **“Se showmount non mostra export, allora NFS non c’è.”**
  Falso: su server NFSv4-only il MNT service può non essere esposto; valida con `rpcinfo` e metodi NFSv4 in lab.
* **“`showmount -a` mi dice esattamente chi monta cosa.”**
  Non sempre: la lista può dipendere da file di stato e può essere incompleta o imprecisa; usala come indizio.
* **“Export `*` significa scrittura garantita.”**
  No: l’ACL export è solo una parte; i permessi reali dipendono dal filesystem e dalle opzioni (es. `ro/rw`, squash).
* **“Basta che 2049 sia aperta per far funzionare showmount.”**
  Non basta: `showmount` passa da RPC/111 e MNT service; 2049 aperta non implica `mountd` raggiungibile.

## FAQ

> **In breve:** risposte rapide ai dubbi più comuni quando showmount “non torna”.

D: `showmount -e` va in timeout, ma io vedo 2049 aperta. Perché?

R: Perché `showmount` dipende da `rpcbind` (111) e dal MNT service (`mountd`). Se 111 o `mountd` sono filtrati/non esposti, `showmount` fallisce anche con NFS attivo.

D: “Program not registered” significa che il server non ha NFS?

R: No. Significa che `mountd` non è registrato/esposto via RPC. Può essere NFSv4-only o configurazione che non pubblica MNT service.

D: Se vedo un export con `*`, posso montarlo sempre?

R: Non necessariamente: firewall, opzioni export e policy di rete possono bloccare comunque. In lab, valida sempre con mount controllato.

D: `showmount` mostra `/srv/nfs/backup 10.10.10.0/24` ma io sono fuori subnet. È finita?

R: Per quell’export, sì: l’ACL ti esclude. In lab, verifica se esistono altri export o se stai lavorando da un pivot interno autorizzato.

D: È “normale” che `showmount` non funzioni su alcuni server moderni?

R: Sì: su server NFSv4-only il MNT service può non essere esposto. Usa alternative e validazioni NFSv4 in contesto autorizzato.

D: Come faccio a capire se è un problema di firewall o di servizio?

R: `rpcinfo -p` e sniffing mirato su 111/2049 ti danno la risposta: se vedi richieste senza risposte è filtering; se manca `mountd` è servizio/registrazione.

## Link utili su HackIta.it

> **In breve:** articoli correlati che ti aiutano a completare il cluster (recon host → RPC → verifica porte → debug traffico).

* [rpcinfo per enumerare servizi RPC](/articoli/rpcinfo/)
* [Ping e tecniche ICMP per il recon](/articoli/ping/)
* [Netdiscover: scopri dispositivi e IP in LAN](/articoli/netdiscover/)
* [ARP-Scan per host discovery e pivoting interno](/articoli/arp-scan/)
* [Netcat: coltellino svizzero di rete](/articoli/netcat/)
* [Tcpdump: analizzare traffico da terminale](/articoli/tcpdump/)

Pagine istituzionali:

* /supporto/
* /contatto/
* /articoli/
* /servizi/
* /about/
* /categorie/

## Riferimenti autorevoli

> **In breve:** fonti primarie per opzioni e comportamento reale di showmount e delle export NFS.

* [https://man7.org/linux/man-pages/man8/showmount.8.html](https://man7.org/linux/man-pages/man8/showmount.8.html)
* [https://man7.org/linux/man-pages/man5/exports.5.html](https://man7.org/linux/man-pages/man5/exports.5.html)

## CTA finale HackITA

Se questo contenuto ti è utile e vuoi supportare il progetto, trovi tutto qui: /supporto/.

Per formazione 1:1 (lab guidati, metodologia OSCP/PG/HTB, workflow reali), guarda i percorsi su /servizi/.

Se invece sei un’azienda e vuoi assessment, hardening o simulazioni controllate (sempre nel perimetro legale), trovi i servizi su /servizi/.
