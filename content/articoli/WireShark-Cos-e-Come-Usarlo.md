---
title: WireShark Cos'è e Come Usarlo
description: >
  Guida operativa a Wireshark per hacker etici in lab. Cos’è, come usarlo su
  Kali, filtri per isolare traffico target, estrarre password e file. Tutorial
  pratico per CTF, HTB e ambienti autorizzati.
image: /WIRESHARK.webp
draft: false
date: 2026-01-20T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - Wireshark
featured: true
---

<!--
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "Wireshark Cos'è e Come Usarlo - Guida Hacking per Lab",
  "description": "Scopri cos'è Wireshark e come usarlo in pentesting. Guida pratica con comandi per Kali Linux, filtri, estrazione dati e analisi traffico in lab CTF e HTB.",
  "author": {
    "@type": "Organization",
    "name": "HackIta"
  },
  "publisher": {
    "@type": "Organization",
    "name": "HackIta"
  },
  "about": "Wireshark, packet sniffing, analisi traffico di rete, ethical hacking, Kali Linux, TCP, HTTP, FTP, DNS, tcpdump, tshark, PCAP, lab autorizzati"
}
</script>
-->

# Wireshark Cos'è e Come Usarlo

**Wireshark è lo strumento che ti permette di vedere tutto il traffico di rete, pacchetto per pacchetto.** Per un hacker in lab, è come avere i superpoteri: vedi password in chiaro, file trasferiti, e persino come gli exploit viaggiano sulla rete. In questa guida imparerai cos'è, come configurarlo su Kali Linux, e una manciata di comandi pratici per usarlo subito in ambienti come HackTheBox (HTB) o Proving Grounds (PG). Alla fine, saprai aprire una cattura, filtrare il traffico del tuo target, e trovare le informazioni che servono per compromettere un sistema in un lab autorizzato.

## Cos'è Esattamente Wireshark (e Cosa NON È)

**Wireshark è un analizzatore di protocolli di rete (packet sniffer), non un tool di attacco attivo.** Non lanci exploit, ma ti mostra cosa succede quando un exploit viene lanciato. In lab, lo usi per fare intelligence: capire come un servizio comunica, trovare dati sensibili che viaggiano senza cifratura, o debugare i tuoi stessi script.

Il trucco è questo: **tutto ciò che fa il tuo computer in rete (e tutto ciò che riceve) può essere catturato e ispezionato.** Wireshark organizza questo caos in una tabella leggibile, dove ogni riga è un pacchetto e puoi vedere indirizzi IP, porte, protocolli e il contenuto grezzo. Su Kali, è preinstallato. Apri il terminale e digita `wireshark` per avviarlo.

## Configurazione Rapida per il Lab (Kali Linux)

**Il primo errore è avviare Wireshark senza i permessi giusti, ritrovandosi senza pacchetti o con interfacce inattive.** Devi dare al tuo utente normale la capacità di catturare pacchetti.

Apri un terminale e dai questo comando:

```bash
sudo dpkg-reconfigure wireshark-common
```

Quando ti chiede "Should non-superusers be able to capture packets?", seleziona **YES**. Poi, aggiungi il tuo utente al gruppo `wireshark` e applica i cambiamenti:

```bash
sudo usermod -a -G wireshark $USER
newgrp wireshark
```

Ora, **riconnessione obbligatoria.** Esci dalla sessione grafica di Kali e rientra. Dopo il login, avvia Wireshark senza `sudo`:

```bash
wireshark
```

Vedrai la lista delle interfacce. In un lab come HTB, la tua interfaccia di lavoro è quasi sempre `tun0` (la VPN). Cliccaci sopra per iniziare a catturare. Premi il tasto rosso di stop dopo qualche secondo per analizzare.

## La Prima Cattura: Isolare il Tuo Target

**Appena avvi una cattura, sei sommerso da centinaia di pacchetti al secondo. Il filtro display è il tuo migliore amico.** Nella barra in alto, puoi scrivere delle regole per vedere solo quello che ti interessa.

Il filtro più utile in assoluto in un lab è questo: `ip.addr == 10.10.10.10`. Sostituisci l'IP con quello della tua macchina target (es. su HTB). Scrivilo e premi Invio. Ora Wireshark mostra solo i pacchetti dove l'IP sorgente O destinazione è il tuo target.

Altri filtri base salvavita:

```bash
http                    # Solo traffico HTTP
tcp.port == 21          # Solo traffico sulla porta FTP (21)
ftp                     # Solo protocollo FTP
!arp                    # Esclude tutto il rumore ARP della rete locale
```

**Se non vedi nulla dopo aver applicato un filtro, controlla due cose:** 1) Hai scritto il filtro giusto? 2) Stai davvero generando traffico verso il target? Fai un ping veloce (`ping -c 1 10.10.10.10`) e dovresti vedere apparire pacchetti ICMP.

## Playbook 10 Minuti: Dal Caos alla Pista Giusta

Quando ti danno un file `.pcap` in una CTF o vuoi analizzare una cattura live, segui questi step. Ti portano dritto al punto.

**Step 1: Apri e Filtra per Protocollo.** Apri il file in Wireshark. Applica subito un filtro generico per un protocollo comune di applicazione: `http` o `ftp`. Questo scarta il 90% del rumore di basso livello (TCP handshake, ARP, etc.).

**Step 2: Stringi sul Target Specifico.** Guarda le colonne `Source` e `Destination`. Identifica l'IP del server (spesso quello che "risponde" su porte come 80 o 21). Aggiungi un filtro combinato: `http and ip.addr == 10.10.10.10`.

**Step 3: Isola Conversazioni Rilevanti.** Clicca con il tasto destro su un pacchetto interessante (es. una richiesta `POST`). Seleziona **Conversation Filter > TCP**. Wireshark creerà un filtro (es. `tcp.stream eq 12`) che isola *tutta* quella singola conversazione tra client e server.

**Step 4: Segui lo Stream ed Estrai.** Sempre col tasto destro sul pacchetto, vai su **Follow > TCP Stream**. Si apre una finestra che ricostruisce l'intera conversazione in testo leggibile. Qui **cerchi password, comandi, o nomi di file**. Per estrarre un file trasferito (es. un'immagine), usa il menu **File > Export Objects > HTTP...**.

**Step 5: Next Move - Lo Strumento Giusto Dopo.** Se hai trovato credenziali FTP/HTTP, passa a `hydra` per fare brute force su altri servizi. Se hai trovato un dominio (es. `dc01.lab.local`), fanculo `nmap`, aggiungilo al tuo `/etc/hosts` e inizia a enumerare i servizi su quella macchina.

## Caccia alle Credenziali e ai File Nascosti

**Nei lab, i servizi insicuri (FTP, HTTP senza TLS, Telnet) sono una miniera.** Wireshark ti lascia prendere ciò che viaggia in chiaro.

**Per catturare una password FTP live:**

1. Avvia una cattura su `tun0` (o `eth0` se la VM è in rete NAT).
2. Filtra: `ftp`.
3. Da un altro terminale, connettiti al servizio FTP del target e fai login.
4. In Wireshark, cerca un pacchetto con `Request: PASS` nella colonna Info. Cliccaci sopra e guarda nel pannello centrale, espandi `FTP > Frame`. Vedrai la password in chiaro.

**Per estrarre un file da una cattura HTTP:**
Dopo aver filtrato il traffico del target (`ip.addr == 10.10.10.10 and http`), usa la funzione automatica:

```
File -> Export Objects -> HTTP...
```

Una lista di tutti i file trasferiti (immagini, zip, txt) appare. Selezionalo e clicca "Save". Molte CTF nascondono la flag in un file così.

## Automazione da Terminale con TShark (Il Fratello Cattivo)

**Quando lavori via SSH o devi analizzare molti file, Wireshark grafico è lento. Usa TShark, la versione a riga di comando.** È già installato su Kali.

Comando per estrarre tutte le password FTP da un file `.pcap`:

```bash
tshark -r cattura.pcap -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg
```

* `-r` legge il file.
* `-Y` è il filtro display (come nella barra di Wireshark).
* `-T fields` formatta l'output.
* `-e` specifica il campo da estrarre (in questo caso l'argomento del comando PASS).

Comando per listare tutti gli host con cui ha parlato il target `10.10.10.10`:

```bash
tshark -r cattura.pcap -Y "ip.addr == 10.10.10.10" -T fields -e ip.dst | sort -u
```

Questo ti dà una mappa delle connessioni, utile per il movimento laterale.

## Errori Comuni e Perché Non Funziona

**1. "Non vedo l'interfaccia `tun0`."**
**Perché non funziona:** Non hai avviato la VPN di HackTheBox o Proving Grounds. La `tun0` viene creata dal client OpenVPN.
**Fix:** Vai nella directory dove hai il file `.ovpn` e lancia `sudo openvpn nome-lab.ovpn`. Aspetta che dica "Initialization Sequence Completed". Poi riavvia Wireshark.

**2. "Filtro applicato, zero risultati. Ma so che c'è traffico."**
**Perché non funziona:** Probabilmente il filtro è sbagliato. `ip.src == 10.10.10.10` mostra solo traffico *da* quel target, non *verso* di lui. Se il target ti risponde, lo vedi. Se sei tu che lo stai scansionando, non lo vedi.
**Fix:** Usa `ip.addr == 10.10.10.10` che cattura entrambe le direzioni.

**3. "Vedo solo traffico TLS/SSL, tutto cifrato."**
**Perché non funziona:** Su HTTPS (porta 443), i dati dell'applicazione sono cifrati. Wireshark non può leggerli senza la chiave privata del server.
**Fix:** Nel lab, a volte puoi fare un attacco MITT con `mitmproxy` e farti dare il traffico in chiaro. Altrimenti, concentrati sui metadati: indirizzi, tempi, dimensioni dei pacchetti. Una grossa quantità di dati uscente da un server dopo un comando potrebbe essere un'indicazione.

## Checklist Operativa per il Pentester

Prima di chiudere una sessione di Wireshark in un lab, controlla questa lista:

* Ho filtrato il traffico per l'IP del mio target (`ip.addr == <IP>`)?
* Ho controllato i protocolli in chiaro (HTTP, FTP, Telnet) con il filtro `http or ftp or telnet`?
* Per ogni conversazione HTTP/FTP sospetta, ho fatto **Follow TCP Stream**?
* Ho esportato gli oggetti HTTP dal menu `File > Export Objects`?
* Ho guardato le **Statistiche > Conversations** per vedere quali host comunicano di più?
* Ho cercato stringhe come "pass", "key", "user", "login" nella ricerca dei pacchetti (Ctrl+F)?
* Ho salvato i pacchetti filtrati rilevanti per il report (`File > Export Specified Packets...`)?

## Tabella 80/20: Le Azioni che Danno Risultati Subito

| Obiettivo                     | Azione pratica                              | Comando/Strumento                                                    |
| :---------------------------- | :------------------------------------------ | :------------------------------------------------------------------- |
| Isolare il target             | Filtrare tutto il traffico da e verso un IP | Filtro: `ip.addr == 10.10.10.10`                                     |
| Trovare login web             | Catturare richieste HTTP POST               | Filtro: `http.request.method == POST`                                |
| Sniffare password FTP         | Filtrare comandi FTP di login               | Filtro: `ftp.request.command == USER or ftp.request.command == PASS` |
| Vedere le query DNS           | Scoprire domini risolti dal target          | Filtro: `dns`                                                        |
| Estrarre un file              | Esportare oggetti trasferiti via HTTP       | Menu: `File > Export Objects > HTTP...`                              |
| Capire una connessione        | Vedere l'intero scambio client-server       | Tasto destro > `Follow > TCP Stream`                                 |
| Analizzare velocemente da CLI | Usare TShark per estrarre dati              | `tshark -r file.pcap -Y "filtro" -T fields -e campo`                 |

## Concetti Controintuitivi

**1. "Promiscuous Mode" non è magico.** Attivarla (è il default in Wireshark) non significa che puoi vedere il traffico di *tutti* nella tua rete di lab. Su reti switched moderne, vedi solo il traffico diretto al tuo MAC address, ai broadcast e ai multicast. Per vedere il traffico di altri, servono tecniche come ARP spoofing (in lab autorizzati!).

**2. I pacchetti che vedi non sono sempre "veri".** Wireshark mostra ciò che la tua scheda di rete riceve. Se un pacchetto è corrotto, te lo mostra corrotto. Se il tuo sistema operativo o hypervisor modifica il traffico (es. per il NAT), vedrai quello. Non è una vista "divina" della rete.

**3. Wireshark può cadere.** Se catturi traffico ad altissima velocità su un PC lento, perderà pacchetti. Vedrai un `[TCP Previous segment not captured]`. In un lab di pochi host non è un problema, ma sappi che non è infallibile. Per catture pesanti, usa filtri di cattura (`Capture > Options`) prima di iniziare.

## FAQ su WIRESHARK

**D: Posso usare Wireshark per decifrare HTTPS?**
R: No, non senza la chiave privata del server. In un lab *se controlli il server*, puoi farlo inserendo la chiave in `Edit > Preferences > Protocols > TLS`. Nel mondo reale, è quasi impossibile.

**D: Qual è la differenza tra un filtro "display" e un filtro "capture"?**
R: Il **filtro display** (barra in alto) nasconde i pacchetti dalla vista dopo che sono stati catturati. Il **filtro capture** (`Capture > Options > Capture Filter`) decide *prima* quali pacchetti vengono salvati in memoria. Usa i secondi per evitare di riempire la RAM in reti molto trafficate.

**D: Come salvo solo i pacchetti che mi interessano?**
R: Applica il tuo filtro display (es. `http`). Poi vai su `File > Export Specified Packets...`. Seleziona "Displayed" e salva con un nuovo nome. Hai un file .pcap più piccolo e pulito.

**D: Wireshark o tcpdump?**
R: **tcpdump** è fantastico per catture veloci da CLI e scripting. **Wireshark** è insostituibile per l'analisi visiva interattiva e il debug. Il flusso è: cattura con `tcpdump -i tun0 -w cattura.pcap`, analizza con Wireshark.

**D: Cosa significa "\[TCP Out-Of-Order]" o "\[TCP Retransmission]"?**
R: Significa che i pacchetti sono arrivati in ordine sbagliato o che uno è stato perso e rinviato. In un lab, può essere un segno di congestione di rete, ma anche di un firewall che interferisce o di uno scan troppo aggressivo che fa cadere i servizi.

**D: Come faccio a catturare il traffico di una macchina Windows in lab?**
R: Il modo più pulito è installare Wireshark/TSHARK sulla macchina Windows compromessa (se hai i permessi) e catturare lì. In alternativa, se controlli il router/switch virtuale del lab, puoi configurare il port mirroring (SPAN).

## Link utili su HackIta

* Approfondisci le tecniche di Red Teaming con i nostri [Corsi di Formazione Pratica](https://hackita.it/servizi/).
* Consulta tutti gli altri tutorial nella sezione [Articoli Tecnici HackIta](https://hackita.it/articoli/).
* Esplora tutte le aree tematiche nella pagina [Categorie HackIta](https://hackita.it/categorie/).
* Sostieni il progetto e la community dalla pagina [Supporta HackIta](https://hackita.it/supporto/).
* Scopri missione e visione del progetto nella sezione [About HackIta](https://hackita.it/about/).

Per approfondire la sintassi completa dei filtri display, fai riferimento alla documentazione ufficiale Wireshark:
[https://www.wireshark.org/docs/man-pages/wireshark-filter.html](https://www.wireshark.org/docs/man-pages/wireshark-filter.html)
