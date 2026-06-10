---
title: 'Tool Penetration Testing: Guida Completa per Fase di Attacco"'
slug: tool-penetration-testing
description: 'Tutti i tool offensivi per il penetration testing organizzati per fase di attacco: recon, exploitation, post-exploitation, pivoting, AD. Con attack chain reali per CTF, OSCP, OSEP e red team.'
image: /tool-penetration-testing.webp
draft: false
date: 2026-06-10T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - Hacking-Tools
  - Post-Exploitation
  - Active-Directory
---

Questa guida raccoglie tutti i tool offensivi usati nel penetration testing, organizzati per fase di attacco — non in ordine alfabetico. Dalla recon OSINT all'exploitation, dal lateral movement AD al pivoting su reti segmentate. Ogni tool ha il suo contesto, il suo momento, il suo caso d'uso reale.
Ogni fase di un penetration test ha i suoi strumenti. Nmap non serve a nulla se non sai leggere l'output. Mimikatz non funziona senza i privilegi giusti. BloodHound è inutile se non hai prima enumerato il dominio. La scelta del tool sbagliato nel momento sbagliato è la causa principale di engagement falliti e lab non completati.

Il riferimento operativo per chi prepara OSCP, OSEP, lavora su HTB o esegue red team engagement. Per i servizi esposti su ogni porta e i relativi vettori, consulta la [Guida Completa alle Porte TCP/UDP nel Penetration Testing](https://hackita.it/articoli/porte-tcp-udp-pentest/).

```
Recon → Scanning → Enumeration → Exploitation → Post-Exploitation → Pivoting → Exfiltration
```

***

## Top Offensive Toolkit 80/20

Se stai iniziando o prepari OSCP, questi sono i 10 tool che coprono l'80% dei casi reali. Imparali prima di tutto il resto.

| #  | Tool                                                  | Perché è essenziale                                        |
| -- | ----------------------------------------------------- | ---------------------------------------------------------- |
| 1  | [Nmap](https://hackita.it/articoli/nmap/)             | Port scan, version detection, NSE — tutto parte da qui     |
| 2  | [Burp Suite](https://hackita.it/articoli/burp-suite/) | Intercept e test vulnerabilità web — insostituibile        |
| 3  | [BloodHound](https://hackita.it/articoli/bloodhound/) | Attack path AD — ti mostra il percorso verso Domain Admin  |
| 4  | [NetExec](https://hackita.it/articoli/netexec/)       | Enumerazione e lateral movement Windows — standard attuale |
| 5  | [Impacket](https://hackita.it/articoli/impacket/)     | Toolkit Python AD — SMB, Kerberos, DCSync, WMI             |
| 6  | [Responder](https://hackita.it/articoli/responder/)   | NTLM hash capture automatico su LAN — instant win          |
| 7  | [FFUF](https://hackita.it/articoli/ffuf/)             | Web fuzzing veloce — directory, parametri, vhost           |
| 8  | [Mimikatz](https://hackita.it/articoli/mimikatz/)     | Dump credenziali Windows — NTLM, Kerberos, DPAPI           |
| 9  | [LinPEAS](https://hackita.it/articoli/linpeas/)       | Enumera tutto su Linux — privesc in automatico             |
| 10 | [Hydra](https://hackita.it/articoli/hydra/)           | Brute force multi-protocollo — SSH, FTP, HTTP, SMB         |

> **NetExec vs CrackMapExec:** NetExec è il fork attivo di CrackMapExec, sviluppato dalla community dopo l'abbandono del progetto originale. Stessa sintassi base, ma NetExec è più aggiornato. Usa NetExec per nuovi engagement, CME se segui documentazione che lo referenzia.

***

## Indice

* [Recon & OSINT](#recon--osint)
* [Network Scanning & Discovery](#network-scanning--discovery)
* [Web Application Testing](#web-application-testing)
* [Exploitation](#exploitation)
* [Brute Force & Credenziali](#brute-force--credenziali)
* [Active Directory & Windows](#active-directory--windows)
* [Linux Post-Exploitation & PrivEsc](#linux-post-exploitation--privesc)
* [Pivoting & Tunneling](#pivoting--tunneling)
* [Sniffing & MITM](#sniffing--mitm)
* [Social Engineering & Phishing](#social-engineering--phishing)
* [Cloud & Infrastructure](#cloud--infrastructure)
* [LOLBins & Tool Nativi Windows](#lolbins--tool-nativi-windows)
* [Attack Chains Reali](#attack-chains-reali)
* [Hub correlati](#hub-correlati)

***

## Recon & OSINT

Prima di toccare il target, raccogli tutto quello che puoi da fonti pubbliche. Subdomini, email, tecnologie, dipendenti, infrastruttura cloud — tutto quello che riduce il rumore nella fase successiva e aumenta la tua attack surface conosciuta.

| Tool         | Cosa fa nel pentest                                           | Guida                                                     |
| ------------ | ------------------------------------------------------------- | --------------------------------------------------------- |
| Amass        | Enumerazione subdomini passiva e attiva, ASN mapping          | [Amass](https://hackita.it/articoli/amass/)               |
| Aquatone     | Screenshot automatico di tutti i subdomini trovati            | [Aquatone](https://hackita.it/articoli/aquatone/)         |
| Assetfinder  | Discovery rapido subdomini da fonti OSINT                     | [Assetfinder](https://hackita.it/articoli/assetfinder/)   |
| Eyewitness   | Screenshot + report visivo di servizi web e RDP               | [Eyewitness](https://hackita.it/articoli/eyewitness/)     |
| FOCA         | Metadati da documenti pubblici, info su dominio e utenti      | [FOCA](https://hackita.it/articoli/foca/)                 |
| Gitrob       | Ricerca segreti e credenziali in repository GitHub pubblici   | [Gitrob](https://hackita.it/articoli/gitrob/)             |
| HostRecon    | Recon rapido su host singolo, tecnologie e servizi            | [HostRecon](https://hackita.it/articoli/hostrecon/)       |
| HTTPX        | Probe HTTP veloce su lista di host, status code e tech stack  | [HTTPX](https://hackita.it/articoli/httpx/)               |
| Maltego      | Grafo OSINT visuale — relazioni tra entità, email, IP, domini | [Maltego](https://hackita.it/articoli/maltego/)           |
| Recon-ng     | Framework OSINT modulare, simile a Metasploit per la recon    | [Recon-ng](https://hackita.it/articoli/reconng/)          |
| ReconSpider  | OSINT automatizzato multi-fonte su target specifico           | [ReconSpider](https://hackita.it/articoli/reconspider/)   |
| Shodan       | Motore di ricerca per device esposti — IoT, ICS, servizi      | [Shodan](https://hackita.it/articoli/shodan/)             |
| SpiderFoot   | OSINT automatizzato, scanning passivo su dominio/IP           | [SpiderFoot](https://hackita.it/articoli/spiderfoot/)     |
| Subfinder    | Discovery subdomini veloce con certificate transparency       | [Subfinder](https://hackita.it/articoli/subfinder/)       |
| theHarvester | Email, subdomini, nomi da motori di ricerca e OSINT           | [theHarvester](https://hackita.it/articoli/theharvester/) |
| Wappalyzer   | Identificazione tecnologie web — CMS, framework, librerie     | [Wappalyzer](https://hackita.it/articoli/wappalyzer/)     |
| WaybackURLs  | URL storici da Wayback Machine — endpoint nascosti, parametri | [WaybackURLs](https://hackita.it/articoli/waybackurls/)   |
| WhatWeb      | Fingerprinting tecnologie web da CLI                          | [WhatWeb](https://hackita.it/articoli/whatweb/)           |

***

## Network Scanning & Discovery

Identificato il perimetro OSINT, mappi l'infrastruttura. L'obiettivo è trovare tutti gli host attivi, tutte le porte aperte, tutti i servizi esposti. Nmap è il centro — gli altri lo affiancano per velocità o protocolli specifici.

| Tool        | Cosa fa nel pentest                                          | Guida                                                   |
| ----------- | ------------------------------------------------------------ | ------------------------------------------------------- |
| Nmap        | Port scan, version detection, NSE scripts — lo standard      | [Nmap](https://hackita.it/articoli/nmap/)               |
| Masscan     | Port scan ad alta velocità su subnet grandi                  | [Masscan](https://hackita.it/articoli/masscan/)         |
| Arp-scan    | Discovery host su LAN via ARP — più affidabile di ping sweep | [Arp-scan](https://hackita.it/articoli/arp-scan/)       |
| Netdiscover | Host discovery ARP passivo e attivo su rete locale           | [Netdiscover](https://hackita.it/articoli/netdiscover/) |
| Ping        | ICMP echo — host discovery base, TTL fingerprinting OS       | [Ping](https://hackita.it/articoli/ping/)               |
| Nbtscan     | Scan NetBIOS su rete — hostname, dominio, MAC address        | [Nbtscan](https://hackita.it/articoli/nbtscan/)         |
| NBTSScan    | Alternativa nbtscan per enumeration NetBIOS                  | [NBTSScan](https://hackita.it/articoli/nbtsscan/)       |
| RPCinfo     | Enumera servizi RPC registrati — NFS, NIS, portmapper        | [RPCinfo](https://hackita.it/articoli/rpcinfo/)         |
| Showmount   | Lista NFS share esportati — prerequisito per mount anonimo   | [Showmount](https://hackita.it/articoli/showmount/)     |
| SNMP-check  | Enumera info SNMP — utenti, processi, routing table          | [SNMP-check](https://hackita.it/articoli/snmp-check/)   |
| SNMPwalk    | Dump completo MIB via SNMP — config device, credenziali      | [SNMPwalk](https://hackita.it/articoli/snmpwalk/)       |

***

## Web Application Testing

Trovati i servizi web, testi ogni superficie: directory nascoste, parametri vulnerabili, injection points, autenticazione debole. Il combo FFUF + Burp Suite copre il 90% dei casi.

| Tool         | Cosa fa nel pentest                                            | Guida                                                     |
| ------------ | -------------------------------------------------------------- | --------------------------------------------------------- |
| Burp Suite   | Proxy intercept, scanner vuln web, fuzzer — il centrale        | [Burp Suite](https://hackita.it/articoli/burp-suite/)     |
| FFUF         | Fuzzing web veloce — directory, parametri, vhost, LFI          | [FFUF](https://hackita.it/articoli/ffuf/)                 |
| Feroxbuster  | Directory brute force ricorsivo con multi-threading            | [Feroxbuster](https://hackita.it/articoli/feroxbuster/)   |
| Gobuster     | Directory e DNS brute force — veloce su target singolo         | [Gobuster](https://hackita.it/articoli/gobuster/)         |
| Dirsearch    | Directory scan con wordlist, filtri su status code             | [Dirsearch](https://hackita.it/articoli/dirsearch/)       |
| Nikto        | Web server scan automatico — misconfig, header, CVE noti       | [Nikto](https://hackita.it/articoli/nikto/)               |
| OWASP ZAP    | Scanner DAST open source, alternativa a Burp Suite             | [OWASP ZAP](https://hackita.it/articoli/owasp-zap/)       |
| Nuclei       | Template-based vulnerability scanner — CVE, misconfiguration   | [Nuclei](https://hackita.it/articoli/nuclei/)             |
| Arjun        | Parameter discovery — trova parametri GET/POST nascosti        | [Arjun](https://hackita.it/articoli/arjun/)               |
| Commix       | Command injection automatizzato — trova e sfrutta OS injection | [Commix](https://hackita.it/articoli/commix/)             |
| SQLmap       | SQL injection automatizzata — dump DB, OS shell, file read     | [SQLmap](https://hackita.it/articoli/sqlmap/)             |
| SearchSploit | Ricerca exploit in ExploitDB locale — offline, veloce          | [SearchSploit](https://hackita.it/articoli/searchsploit/) |
| JWT          | Analisi e attacco JSON Web Token — alg:none, weak secret       | [JWT](https://hackita.it/articoli/jwt/)                   |

***

## Exploitation

Identificata la vulnerabilità, passi all'exploitation. Metasploit gestisce i casi standardizzati. Per vulnerabilità custom o ambienti hardened, combini SearchSploit con exploit manuali e PoC pubblici.

| Tool                       | Cosa fa nel pentest                                             | Guida                                                                                 |
| -------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Metasploit                 | Framework exploitation — moduli per centinaia di CVE            | [Metasploit](https://hackita.it/articoli/metasploit/)                                 |
| msfconsole                 | Interfaccia CLI di Metasploit — uso operativo quotidiano        | [msfconsole](https://hackita.it/articoli/msfconsole/)                                 |
| ExploitDB                  | Database exploit pubblici — PoC e reference per CVE             | [ExploitDB](https://hackita.it/articoli/exploitdb/)                                   |
| RouterSploit               | Framework exploitation per dispositivi embedded e router        | [RouterSploit](https://hackita.it/articoli/routersploit/)                             |
| Weevely3                   | Webshell PHP stealth con canale cifrato — post-exploitation web | [Weevely3](https://hackita.it/articoli/weevely3/)                                     |
| Vulnerability Exploitation | Metodologia e approccio all'exploitation manuale                | [Vulnerability Exploitation](https://hackita.it/articoli/vulnerability-exploitation/) |

***

## Brute Force & Credenziali

Quando non hai exploit disponibili, le credenziali deboli sono spesso la via. Hydra copre quasi tutti i protocolli in modalità online. Hashcat è per il cracking offline degli hash catturati.

| Tool    | Cosa fa nel pentest                                        | Guida                                           |
| ------- | ---------------------------------------------------------- | ----------------------------------------------- |
| Hydra   | Brute force online — SSH, FTP, HTTP, SMB, RDP, mail, DB    | [Hydra](https://hackita.it/articoli/hydra/)     |
| Medusa  | Brute force parallelo multi-host — alternativa a Hydra     | [Medusa](https://hackita.it/articoli/medusa/)   |
| Hashcat | Password cracking offline — NTLM, NTLMv2, Kerberos, MD5    | [Hashcat](https://hackita.it/articoli/hashcat/) |
| Patator | Brute force modulare — più flessibile su protocolli custom | [Patator](https://hackita.it/articoli/patator/) |

***

## Active Directory & Windows

Il cluster più denso. In un AD engagement usi questi tool in sequenza: enumeri con BloodHound e Enum4linux, attacchi Kerberos con Rubeus, fai lateral movement con NetExec e Impacket, dumpi credenziali con Mimikatz.

| Tool                | Cosa fa nel pentest                                                | Guida                                                                  |
| ------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| BloodHound          | Mappa attack path AD — percorso più corto verso Domain Admin       | [BloodHound](https://hackita.it/articoli/bloodhound/)                  |
| NetExec             | Enumerazione AD, password spray, exec comandi su Windows           | [NetExec](https://hackita.it/articoli/netexec/)                        |
| CrackMapExec        | Enumerazione e lateral movement su rete Windows                    | [CrackMapExec](https://hackita.it/articoli/crackmapexec/)              |
| Impacket            | Toolkit Python — SMB, Kerberos, MSSQL, WMI, DCSync, RPC            | [Impacket](https://hackita.it/articoli/impacket/)                      |
| Rubeus              | Attacchi Kerberos — AS-REP Roasting, Kerberoasting, ticket forge   | [Rubeus](https://hackita.it/articoli/rubeus/)                          |
| Mimikatz            | Dump LSASS, NTLM hash, Kerberos ticket, DPAPI secrets              | [Mimikatz](https://hackita.it/articoli/mimikatz/)                      |
| SafetyKatz          | Mimikatz .NET port — bypass AV, in-memory execution                | [SafetyKatz](https://hackita.it/articoli/safetykatz/)                  |
| Evil-WinRM          | Shell su WinRM (5985/5986) — lateral movement e file transfer      | [Evil-WinRM](https://hackita.it/articoli/evilwinrm/)                   |
| Enum4linux-ng       | Enumerazione SMB/LDAP — utenti, share, policy, gruppi              | [Enum4linux-ng](https://hackita.it/articoli/enum4linux-ng/)            |
| LDAPsearch          | Query LDAP raw — dump utenti, gruppi, GPO, computer                | [LDAPsearch](https://hackita.it/articoli/ldapsearch/)                  |
| rpcclient           | Shell RPC — enumera utenti, SID, policy via null session           | [rpcclient](https://hackita.it/articoli/rpcclient/)                    |
| SMBclient           | Accesso share SMB — lista, download, upload file                   | [SMBclient](https://hackita.it/articoli/smbclient/)                    |
| SMBmap              | Enumera share SMB — permessi, contenuto, drive mapping             | [SMBmap](https://hackita.it/articoli/smbmap/)                          |
| SMBexec             | Esecuzione comandi via SMB senza toccare disco                     | [SMBexec](https://hackita.it/articoli/smbexec/)                        |
| WMIexec             | Esecuzione comandi via WMI — agentless, basso rumore               | [WMIexec](https://hackita.it/articoli/wmiexec/)                        |
| PsExec              | Esecuzione remota via SMB — crea servizio temporaneo               | [PsExec](https://hackita.it/articoli/psexec/)                          |
| AdFind              | Enumerazione AD via LDAP — alternativa a BloodHound collector      | [AdFind](https://hackita.it/articoli/adfind/)                          |
| Seatbelt            | Enumera configurazione host Windows — privesc, difese, credenziali | [Seatbelt](https://hackita.it/articoli/seatbelt/)                      |
| SharpUp             | Individua misconfiguration Windows per privilege escalation        | [SharpUp](https://hackita.it/articoli/sharpup/)                        |
| SharpDPAPI          | Dump segreti DPAPI — credenziali browser, password manager         | [SharpDPAPI](https://hackita.it/articoli/sharpdpapi/)                  |
| SharpChrome         | Dump credenziali e cookie Chrome via DPAPI                         | [SharpChrome](https://hackita.it/articoli/sharpchrome/)                |
| Sherlock            | Trova CVE locali per privilege escalation su Windows               | [Sherlock](https://hackita.it/articoli/sherlock/)                      |
| Inveigh             | Responder .NET — LLMNR/NBT-NS poisoning da Windows                 | [Inveigh](https://hackita.it/articoli/inveigh/)                        |
| KeyThief            | Estrae chiavi KeePass dalla memoria — credential theft             | [KeyThief](https://hackita.it/articoli/keethief/)                      |
| LaZagne             | Dump credenziali da browser, mail client, tool vari                | [LaZagne](https://hackita.it/articoli/lazagne/)                        |
| Invoke-Manipulation | Bypass AMSI e PowerShell logging — evasion difese                  | [Invoke-Manipulation](https://hackita.it/articoli/invokemanipulation/) |
| WMIC                | LOLBin Windows — exec comandi, query WMI, lateral movement         | [WMIC](https://hackita.it/articoli/wmic/)                              |
| Pass-the-Hash       | Usa NTLM hash senza crackarlo per autenticarsi                     | [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/)            |

***

## Linux Post-Exploitation & PrivEsc

Ottenuta una shell su Linux, l'obiettivo è diventare root. LinPEAS automatizza la ricerca di vettori, GTFOBins ti dice come sfruttarli. Pspy monitora i processi in tempo reale senza root — spesso è il modo per scoprire cron job con privilegi elevati.

| Tool               | Cosa fa nel pentest                                               | Guida                                                                 |
| ------------------ | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| LinPEAS            | Enumera automaticamente tutto — privesc, credenziali, config      | [LinPEAS](https://hackita.it/articoli/linpeas/)                       |
| LinEnum            | Script bash per privilege escalation check — legacy ma affidabile | [LinEnum](https://hackita.it/articoli/linenum/)                       |
| LSE                | Linux Smart Enumeration — output graduato per priorità            | [LSE](https://hackita.it/articoli/lse/)                               |
| Lynis              | Audit sistema Linux — trova misconfiguration e hardening gap      | [Lynis](https://hackita.it/articoli/lynis/)                           |
| GTFOBins           | Riferimento binari Linux per privesc, bypass, shell — essenziale  | [GTFOBins](https://hackita.it/articoli/gtfobins/)                     |
| Getcap             | Lista capabilities Linux — vettore di privesc spesso ignorato     | [Getcap](https://hackita.it/articoli/getcap/)                         |
| Pspy               | Monitora processi in tempo reale senza root — trova cron job      | [Pspy](https://hackita.it/articoli/pspy/)                             |
| JAWS               | PowerShell script per privesc Windows — analogo di LinPEAS        | [JAWS](https://hackita.it/articoli/jaws/)                             |
| WinPEAS            | Enumerazione automatica Windows per privilege escalation          | [WinPEAS](https://hackita.it/articoli/winpeas/)                       |
| WinEnum            | Enumera configurazione Windows — servizi, task, permessi          | [WinEnum](https://hackita.it/articoli/winenum/)                       |
| Unix-PrivEsc-Check | Script Perl per sistemi Unix legacy — compatibile con sh          | [Unix-PrivEsc-Check](https://hackita.it/articoli/unix-privesc-check/) |
| MimiPenguin        | Dump credenziali da memoria su Linux — gnome-keyring, SSH         | [MimiPenguin](https://hackita.it/articoli/mimipenguin/)               |
| Chkrootkit         | Individua rootkit installati su sistema Linux                     | [Chkrootkit](https://hackita.it/articoli/chkrootkit/)                 |
| Osquery            | Query SQL su sistema operativo — processi, rete, file, utenti     | [Osquery](https://hackita.it/articoli/osquery/)                       |

***

## Pivoting & Tunneling

Dentro la rete, devi raggiungere segmenti non direttamente accessibili. Chisel e socat sono i più usati nei lab HTB. SSHuttle è il più trasparente in ambienti reali. ProxyChains instrada tool esistenti attraverso il tunnel senza modificarli.

| Tool        | Cosa fa nel pentest                                              | Guida                                                   |
| ----------- | ---------------------------------------------------------------- | ------------------------------------------------------- |
| Chisel      | TCP/UDP tunneling via HTTP — funziona anche attraverso proxy     | [Chisel](https://hackita.it/articoli/chisel/)           |
| Socat       | Relay TCP/UDP multi-uso — port forward, bind/reverse shell       | [Socat](https://hackita.it/articoli/socat/)             |
| SSHuttle    | VPN via SSH — instrada tutto il traffico senza client aggiuntivo | [SSHuttle](https://hackita.it/articoli/sshuttle/)       |
| ProxyChains | Instrada tool attraverso SOCKS/HTTP proxy — pivoting trasparente | [ProxyChains](https://hackita.it/articoli/proxychains/) |
| Plink       | PuTTY CLI — SSH tunneling da Windows senza installazioni         | [Plink](https://hackita.it/articoli/plink/)             |
| RevSocks    | Reverse SOCKS proxy — utile quando il target è dietro NAT        | [RevSocks](https://hackita.it/articoli/revsocks/)       |
| Netcat      | TCP/UDP relay, bind/reverse shell, file transfer base            | [Netcat](https://hackita.it/articoli/netcat/)           |
| nc          | Netcat — varianti e sintassi su sistemi diversi                  | [nc](https://hackita.it/articoli/nc/)                   |

***

## Sniffing & MITM

Sulla LAN, il traffico non cifrato è immediata fonte di credenziali. Responder avvelena la rete e cattura NTLM hash in automatico. Wireshark e tcpdump analizzano il traffico. Ettercap e Bettercap gestiscono attacchi MITM completi con modifica dei pacchetti in tempo reale.

| Tool      | Cosa fa nel pentest                                           | Guida                                               |
| --------- | ------------------------------------------------------------- | --------------------------------------------------- |
| Wireshark | Analisi traffico GUI — filtra, decodifica, segue stream TCP   | [Wireshark](https://hackita.it/articoli/wireshark/) |
| Tcpdump   | Packet capture CLI — cattura, filtra, esporta .pcap           | [Tcpdump](https://hackita.it/articoli/tcpdump/)     |
| Tshark    | Wireshark CLI — analisi offline di file pcap, scriptabile     | [Tshark](https://hackita.it/articoli/tshark/)       |
| Responder | LLMNR/NBT-NS/MDNS poisoning — cattura NTLM hash in automatico | [Responder](https://hackita.it/articoli/responder/) |
| Ettercap  | ARP poisoning + MITM — intercetta e modifica traffico LAN     | [Ettercap](https://hackita.it/articoli/ettercap/)   |
| Bettercap | MITM framework moderno — ARP, DNS, HTTPS downgrade            | [Bettercap](https://hackita.it/articoli/bettercap/) |
| MITMProxy | Proxy HTTP/HTTPS interattivo — ispeziona e modifica richieste | [MITMProxy](https://hackita.it/articoli/mitmproxy/) |

***

## Social Engineering & Phishing

Quando non ci sono vulnerabilità tecniche sfruttabili, l'attacco passa per le persone. GoPhish gestisce campagne phishing complete con tracking. EvilGinx2 cattura credenziali e session cookie bypassando MFA.

| Tool                    | Cosa fa nel pentest                                              | Guida                                                                  |
| ----------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------- |
| GoPhish                 | Framework phishing — campagne email, landing page, tracking      | [GoPhish](https://hackita.it/articoli/gophish/)                        |
| EvilGinx2               | Reverse proxy phishing — cattura credenziali e cookie MFA bypass | [EvilGinx2](https://hackita.it/articoli/evilginx2/)                    |
| BeEF                    | Browser Exploitation Framework — hook browser via XSS stored     | [BeEF](https://hackita.it/articoli/beef/)                              |
| Social Engineer Toolkit | Framework SE — phishing, vishing, pretexting automatizzato       | [Social Engineer Toolkit](https://hackita.it/articoli/socialengineer/) |

***

## Cloud & Infrastructure

Ambienti cloud mal configurati espongono bucket S3 pubblici, ruoli IAM con privilegi eccessivi, API senza autenticazione. Questi tool automatizzano la ricerca di questi vettori su AWS, Azure e GCP.

| Tool                     | Cosa fa nel pentest                                | Guida                                                                             |
| ------------------------ | -------------------------------------------------- | --------------------------------------------------------------------------------- |
| CloudEnum                | Enumera risorse cloud pubbliche — AWS, Azure, GCP  | [CloudEnum](https://hackita.it/articoli/cloudenum/)                               |
| S3Scanner                | Trova e testa bucket S3 pubblici o mal configurati | [S3Scanner](https://hackita.it/articoli/s3scanner/)                               |
| AWS Privilege Escalation | Tecniche e tool per privesc su AWS IAM             | [AWS Privilege Escalation](https://hackita.it/articoli/aws-privilege-escalation/) |

***

## LOLBins & Tool Nativi Windows

I tool nativi di Windows sono i più stealth: già presenti sul sistema, firmati Microsoft, raramente bloccati da AV/EDR. Usali sempre prima di scaricare tool esterni sul target — meno rumore, meno tracce, meno detection.

| Tool           | Cosa fa nel pentest                                               | Guida                                                         |
| -------------- | ----------------------------------------------------------------- | ------------------------------------------------------------- |
| CertUtil.exe   | Download file, encode/decode base64, verifica certificati         | [CertUtil](https://hackita.it/articoli/certutilexe/)          |
| WMIC           | Query WMI, exec processi, lateral movement — LOLBin potente       | [WMIC](https://hackita.it/articoli/wmic/)                     |
| Scheduled Task | Persistenza e privesc via task scheduler Windows                  | [Scheduled Task](https://hackita.it/articoli/scheduled-task/) |
| Crontab        | Persistenza su Linux via cron — vettore classico di privesc       | [Crontab](https://hackita.it/articoli/crontab/)               |
| RSH            | Remote shell legacy Unix — accesso senza password via .rhosts     | [RSH](https://hackita.it/articoli/rsh/)                       |
| Telnet         | Connessione servizi in chiaro, banner grab, test porta            | [Telnet](https://hackita.it/articoli/telnet/)                 |
| SSH-Audit      | Audit configurazione SSH — algoritmi deboli, versioni vulnerabili | [SSH-Audit](https://hackita.it/articoli/ssh-audit/)           |
| SSH-KeyHunter  | Cerca chiavi SSH private nel filesystem — post-exploitation       | [SSH-KeyHunter](https://hackita.it/articoli/ssh-keyhunter/)   |
| Empire         | C2 framework PowerShell/Python — post-exploitation avanzato       | [Empire](https://hackita.it/articoli/empire/)                 |
| Fail2ban       | Analisi log difensiva — capire i rate limit prima di bruteforce   | [Fail2ban](https://hackita.it/articoli/fail2ban/)             |

***

## Attack Chains Reali

I tool non si usano in isolamento. Queste sono le chain più comuni che incontri in ambienti reali, ProLab HTB e assessment OSCP.

### Chain 1 — External Recon → Web RCE

```
Amass / Subfinder     →  Enumerazione subdomini
HTTPX                 →  Probe HTTP su tutti i subdomini trovati
Nmap                  →  Port scan + version detection sui target vivi
Nikto / Nuclei        →  Scan automatico vulnerabilità web note
FFUF                  →  Directory brute force, parameter fuzzing
Burp Suite            →  Analisi manuale, intercept, injection test
SQLmap / Commix       →  Exploitation — dump DB o OS shell
Weevely3              →  Webshell persistente per post-exploitation
```

### Chain 2 — AD Attack Chain (da rete LAN)

```
Nmap                  →  Identifica DC, host Windows, porte AD aperte
Enum4linux-ng         →  Null session — utenti, share, policy dominio
Responder             →  LLMNR/NBT-NS poisoning → cattura NTLMv2 hash
Hashcat               →  Crack hash offline con wordlist
NetExec               →  Valida credenziali, password spray, enumera rete
BloodHound            →  Mappa attack path — trova percorso verso DA
Rubeus                →  Kerberoasting → hash account servizio
Hashcat               →  Crack hash Kerberos offline
Impacket secretsdump  →  DCSync → dump tutti gli hash del dominio
Mimikatz              →  Golden Ticket / credenziali da LSASS
Domain Admin          ✅
```

### Chain 3 — Linux Post-Exploitation

```
Shell iniziale        →  whoami, id, uname -a, ip a
LinPEAS               →  Enumera tutto — SUID, cron, sudo, capability
Pspy                  →  Monitora processi — trova cron job root
GTFOBins              →  Identifica binario sfruttabile per privesc
Getcap                →  Controlla capabilities — python3, perl, openssl
Root                  ✅
MimiPenguin           →  Dump credenziali da memoria
Chisel + ProxyChains  →  Pivoting verso subnet interna
```

### Chain 4 — Internal Windows Lateral Movement

```
Nmap                  →  Mappa rete interna — host Windows attivi
CrackMapExec          →  Verifica accesso su tutti gli host
SMBmap / SMBclient    →  Enumera share — cerca file con credenziali
Pass-the-Hash         →  Usa NTLM hash senza password in chiaro
Evil-WinRM            →  Shell su host via WinRM (5985)
WinPEAS / Seatbelt    →  Enumera privesc locale
SharpDPAPI            →  Dump credenziali salvate — browser, Windows
Mimikatz              →  Dump LSASS — NTLM hash e ticket Kerberos
BloodHound            →  Aggiorna attack path con nuove credenziali
Lateral movement      →  Ripeti fino a Domain Admin ✅
```

***

## Hub correlati

| Hub                                                                                               | Cosa copre                                                                          |
| ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [Porte TCP/UDP nel Penetration Testing](https://hackita.it/articoli/porte-tcp-udp-pentest/)       | Tutte le porte per scenario offensivo — AD, web, database, mail, DevOps, protocolli |
| [Web Vulnerabilities & Attack Techniques](https://hackita.it/articoli/attacchi-applicazioni-web/) | SQL injection, XSS, SSRF, SSTI, LFI e tutto il web hacking                          |

*Per penetration test professionali su infrastrutture reali, [scopri i servizi di HackIta](https://hackita.it/servizi/).*
