---
title: 'CrackMapExec vs NetExec: Comandi CME e Migrazione a NXC'
slug: crackmapexec
description: 'Guida alla migrazione da CrackMapExec (cme) a NetExec (nxc) : traduci comandi CME in NXC, gestisci Kerberos, moduli, file transfer e scopri cosa cambia oggi.'
image: /Gemini_Generated_Image_9aprd09aprd09apr.webp
draft: false
date: 2026-01-30T00:00:00.000Z
lastmod: 2026-09-19T00:00:00.000Z
categories:
  - tools
subcategories:
  - recon
tags:
  - cme
  - crackmapexec
---

# CrackMapExec (CME): Comandi Legacy e Traduzione verso NetExec

CrackMapExec (CME) è stato per anni il tool di riferimento per validare credenziali, enumerare SMB/AD e muoversi lateralmente in una rete Windows con un solo binario. Il repository originale è **archiviato dal 6 dicembre 2023** e non riceve più fix. Il successore mantenuto dalla community è [NetExec](https://hackita.it/articoli/netexec/) (binario `nxc`), stessa filosofia, protocolli e moduli aggiornati.

Questa pagina non è una seconda guida NetExec: esiste per chi arriva da una vecchia cheat sheet, un vecchio corso o un vecchio walkthrough scritto in sintassi `crackmapexec` e deve tradurla in comandi che funzionano davvero oggi. Per l'uso operativo completo vai dritto alla [guida NetExec](https://hackita.it/articoli/netexec/).

## CrackMapExec È Ancora Utilizzabile?

Tecnicamente puoi ancora installarlo (`pipx install crackmapexec`), ma è una scelta sbagliata per qualsiasi lavoro nuovo:

* non riceve correzioni né compatibilità con Python/librerie recenti;
* i moduli sono congelati alla release in cui il progetto è stato archiviato;
* comandi trovati in guide storiche possono non esistere più nella build che riesci a installare;
* i controlli contro versioni recenti di Windows possono dare falsi negativi.

Mantieni CME solo dentro una VM congelata quando devi riprodurre esattamente un vecchio laboratorio o una write-up che lo richiede esplicitamente. Per tutto il resto, [NetExec](https://hackita.it/articoli/netexec/).

## Traduzione Comandi: da CrackMapExec a NetExec

| Cosa cercavi in CME                                   | Comando NetExec da usare oggi                                      | Nota                                                                            |
| ----------------------------------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `crackmapexec smb 10.10.10.0/24`                      | `nxc smb 10.10.10.0/24`                                            | Solo il nome del binario cambia                                                 |
| `crackmapexec smb TARGET -u john -p Pass123`          | `nxc smb TARGET -u john -p Pass123`                                | Sintassi base identica                                                          |
| `crackmapexec smb TARGET -u john -p Pass123 --shares` | `nxc smb TARGET -u john -p Pass123 --shares`                       | Flag conservato                                                                 |
| `crackmapexec smb TARGET -u users.txt -p Pass123`     | `nxc smb TARGET -u users.txt -p Pass123`                           | Password spraying, stessa forma                                                 |
| `crackmapexec smb TARGET -u Administrator -H NTHASH`  | `nxc smb TARGET -u Administrator -H NTHASH`                        | Pass-the-Hash conservato                                                        |
| `crackmapexec smb TARGET -u john --kerberos`          | `nxc smb TARGET -d DOMINIO -u john -p PASS -k`                     | `--kerberos` non è più la sintassi valida: serve `-k` con credenziali esplicite |
| Ticket Kerberos passato implicitamente                | `export KRB5CCNAME=/path/ccache` poi `nxc smb TARGET --use-kcache` | NetExec richiede il flag esplicito `--use-kcache`                               |
| `crackmapexec smb TARGET --sam`                       | `nxc smb TARGET --local-auth --sam`                                | Stesso concetto, verifica sempre `--local-auth` per account locali              |
| `crackmapexec smb TARGET -M mimikatz`                 | `nxc smb TARGET -M lsassy` (o `-M nanodump`)                       | Il modulo `mimikatz` è deprecato in NetExec                                     |
| `crackmapexec smb TARGET --output file.csv`           | `nxc --log file.txt smb TARGET ...` oppure `... \| tee file.txt`   | `--output` non esiste più: usa `--log`                                          |
| `crackmapexec smb TARGET --put-file dest src`         | `nxc smb TARGET --put-file locale remoto`                          | **Ordine dei path cambiato**: locale prima, remoto dopo                         |
| `crackmapexec smb TARGET --get-file src dest`         | `nxc smb TARGET --get-file remoto locale`                          | Stesso avviso, ordine invertito rispetto a molte guide vecchie                  |
| `crackmapexec smb TARGET -M Zerologon`                | `nxc smb -L` per vedere il nome corrente, poi `-M <nome_trovato>`  | I nomi modulo cambiano tra release: non fidarti del nome in una guida vecchia   |
| `crackmapexec ldap TARGET --users`                    | `nxc ldap TARGET -d DOMINIO -u USER -p PASS --users`               | Stessa forma, verifica il dominio esplicito                                     |
| `crackmapexec smb TARGET -x whoami`                   | `nxc smb TARGET -u ADMIN -p PASS -x 'whoami'`                      | Command execution conservata, metodo sotto può cambiare fallback                |

## Le 3 Trappole Più Comuni Migrando da CME

**1. `--kerberos` non esiste più così.** Nelle guide CME vecchie basta il flag da solo con lo username. In NetExec serve `-k` insieme a credenziali esplicite (password o hash) oppure `--use-kcache` con una ccache già pronta in `KRB5CCNAME`.

**2. `--put-file` e `--get-file` hanno ordine dei parametri diverso.** Copiare un comando vecchio alla lettera può far scrivere o leggere il file sbagliato. Verifica sempre con `nxc smb --help` prima di eseguire.

**3. I moduli non sono garantiti identici.** `mimikatz` come modulo è deprecato, `Zerologon`/`PetitPotam` come nomi possono non corrispondere più a un modulo reale nella build installata. Prima di lanciare qualsiasi `-M <nome>` copiato da una guida vecchia, controlla `nxc smb -L`.

## FAQ

**CrackMapExec è ancora mantenuto?**
No, il repository è archiviato dal 6 dicembre 2023. Non riceve fix né nuovi moduli.

**Posso sostituire sempre `crackmapexec` con `nxc`?**
Per la sintassi base sì. Kerberos, moduli, file transfer e output hanno flag e comportamento diversi — controllali uno per uno prima di fidarti di una guida vecchia.

**Perché non trovo un comando CME nella guida NetExec?**
Perché la guida NetExec è scritta per l'uso attuale, non per la retrocompatibilità con la sintassi CME. Questa pagina esiste apposta per colmare quel salto.

**Devo installare CrackMapExec per imparare il tool?**
No. Installa direttamente [NetExec](https://hackita.it/articoli/netexec/): la curva di apprendimento è la stessa, ma lavori con un tool che riceve ancora aggiornamenti.

***

Per il workflow operativo completo — enumerazione, password spraying, Pass-the-Hash, Kerberos, dump credenziali, lateral movement — vai alla [guida NetExec](https://hackita.it/articoli/netexec/). Usa questi strumenti esclusivamente su sistemi di tua proprietà o in ambienti autorizzati.
