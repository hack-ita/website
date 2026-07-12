---
title: 'lookupsid.py: Enumera Utenti e SID via RID Cycling SMB'
slug: lookupsid
description: 'Guida a impacket-lookupsid per enumerare utenti, gruppi e SID tramite MS-LSAT su SMB, usando password, hash NTLM, Kerberos o sessioni anonime quando consentite.'
image: /lookupsid-py-rid-cycling-smb.webp
draft: true
date: 2026-07-26T00:00:00.000Z
categories:
  - tools
subcategories:
  - enum
tags:
  - impacket
  - active-directory
  - rid-cycling
  - ms-lsat
  - lookupsid
---

# lookupsid.py — RID Cycling e Enumerazione Utenti via SMB con Impacket

`lookupsid` enumera utenti e gruppi Windows iterando i RID via MS-LSAT su porta 445 — senza toccare LDAP. Funziona con credenziali valide, account Guest o in certi casi null session. Ottimo quando la porta 389 è filtrata o non hai credenziali di dominio.

`lookupsid.py` fa parte di [Impacket](https://hackita.it/articoli/impacket/) e sfrutta il protocollo MS-LSAT (Local Security Authority) via [SMB](https://hackita.it/articoli/smb/) per risolvere SID in nomi account. La tecnica si chiama **RID cycling**: parte dal SID del dominio, aggiunge incrementalmente il RID (500, 501, 502...) e chiede al sistema di risolverlo in un nome.

Riferimento ufficiale: [fortra/impacket — lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)

Approfondimento tecnico RID cycling: [The Hacker Recipes — SID/RID Enumeration](https://www.thehacker.recipes/ad/recon/ms-rpc)

***

## Concetto: RID cycling

Ogni account in Windows ha un SID con questo formato:

```

S-1-5-21-XXXXXXX-YYYYYYY-ZZZZZZZ-RID

│         └──────────────────────┘  └─ Relativo all'account

│              SID del dominio

└─ Prefisso fisso Windows NT

```

I RID fissi che conosci già:

\| RID | Account |

\|-----|---------|

\| 500 | Administrator |

\| 501 | Guest |

\| 502 | krbtgt (solo DC) |

\| 512 | Domain Admins |

\| 513 | Domain Users |

\| 514 | Domain Guests |

\| 515 | Domain Computers |

\| 516 | Domain Controllers |

\| 518 | Schema Admins |

\| 519 | Enterprise Admins |

\| 1000+ | Account utente/computer creati |

`lookupsid.py` parte da RID 1 e arriva fino al `maxRid` specificato (default 4000), chiedendo al sistema di risolvere ogni SID — e stampando il nome quando trova un account valido.

***

## Sintassi e opzioni

```bash

impacket-lookupsid [opzioni] [[dominio/]utente[:password]@]target [maxRid]

```

\| Opzione | Descrizione |

\|---------|-------------|

\| `maxRid` | RID massimo da testare (default: **4000**) |

\| `-domain-sids` | Enumera SID di dominio (interroga il DC) |

\| `-target-ip IP` | IP del target (se il nome non risolve) |

\| `-port PORT` | Porta SMB (default: 445) |

\| `-hashes LM:NT` | Pass-the-Hash |

\| `-k` | Kerberos |

\| `-no-pass` | Non chiedere password (per guest/null) |

\| `-debug` | Output verbose |

\| `-ts` | Aggiunge timestamp all'output |

***

## Utilizzo pratico

### Con credenziali di dominio

```bash

impacket-lookupsid corp.local/user:Password123@10.10.10.5



# Con maxRid aumentato per domini grandi

impacket-lookupsid corp.local/user:Password123@10.10.10.5 10000



# Pass-the-Hash

impacket-lookupsid -hashes :NThash corp.local/user@10.10.10.5

```

### Null session / Guest account — senza password

Questo è il vantaggio principale su [GetADUsers.py](https://hackita.it/articoli/getadusers/) e [samrdump.py](https://hackita.it/articoli/samrdump/): in certi ambienti legacy o con account Guest abilitato, puoi enumerare utenti **senza nessuna credenziale**.

```bash

# Null session (ambienti legacy, Samba)

impacket-lookupsid ''@10.10.10.5



# Guest account — molto comune su HTB e alcuni ambienti reali

impacket-lookupsid 'corp.local/guest'@10.10.10.5 -no-pass



# Senza dominio (autenticazione locale)

impacket-lookupsid 'guest'@10.10.10.5 -no-pass



# Con maxRid esplicito

impacket-lookupsid corp.local/guest@10.10.10.5 -no-pass 5000

```

### Target IP separato dal nome

```bash

impacket-lookupsid corp.local/user:pass@DC01 -target-ip 10.10.10.5

```

### Kerberos

```bash

export KRB5CCNAME=/path/to/ticket.ccache

impacket-lookupsid -k -no-pass corp.local/user@DC01.corp.local

```

***

## Output e come leggerlo

```

[*] Brute forcing SIDs at 10.10.10.5

[*] StringBinding ncacn_np:10.10.10.5[\pipe\lsarpc]

[*] Domain SID is: S-1-5-21-2725560159-1428537661-1240357446



500: CORP\Administrator (SidTypeUser)

501: CORP\Guest (SidTypeUser)

502: CORP\krbtgt (SidTypeUser)

512: CORP\Domain Admins (SidTypeGroup)

513: CORP\Domain Users (SidTypeGroup)

514: CORP\Domain Guests (SidTypeGroup)

515: CORP\Domain Computers (SidTypeGroup)

519: CORP\Enterprise Admins (SidTypeGroup)

1000: CORP\DC01$ (SidTypeUser)

1101: CORP\john.doe (SidTypeUser)

1102: CORP\svc_sql (SidTypeUser)

1103: CORP\helpdesk (SidTypeUser)

1104: CORP\WS01$ (SidTypeUser)

```

**SidType principali:**

\| SidType | Cosa indica |

\|---------|------------|

\| `SidTypeUser` | Account utente o computer (`$`) |

\| `SidTypeGroup` | Gruppo globale (Domain Admins, ecc.) |

\| `SidTypeAlias` | Gruppo locale builtin (Administrators, Backup Operators) |

\| `SidTypeWellKnownGroup` | Gruppo predefinito noto (Everyone, SYSTEM) |

\| `SidTypeDomain` | Il dominio stesso |

***

## Estrai il SID del dominio

Il SID del dominio è la prima cosa che stampa lookupsid — ed è un valore fondamentale per costruire ticket Kerberos (Golden Ticket, Silver Ticket).

```bash

# Estrai solo il SID del dominio dall'output

impacket-lookupsid corp.local/user:pass@10.10.10.5 | grep "Domain SID"

# [*] Domain SID is: S-1-5-21-2725560159-1428537661-1240357446



# Salva il SID per usarlo dopo

DOMAIN_SID=$(impacket-lookupsid corp.local/user:pass@10.10.10.5 2>/dev/null | \

  grep "Domain SID" | awk '{print $NF}')

echo $DOMAIN_SID

```

Poi usi il SID in combinazione con il hash di krbtgt per il [Golden Ticket](https://hackita.it/articoli/golden-ticket/).

***

## Estrai solo gli username per wordlist

```bash

# Salva tutto l'output

impacket-lookupsid corp.local/guest@10.10.10.5 -no-pass > /tmp/lookupsid_raw.txt



# Filtra solo utenti reali (SidTypeUser, escludi computer account con $)

grep "SidTypeUser" /tmp/lookupsid_raw.txt | grep -v '\$' | \

  awk -F'\' '{print $2}' | awk '{print $1}' > /tmp/userlist.txt



cat /tmp/userlist.txt

# Administrator

# Guest

# john.doe

# svc_sql

# helpdesk



# Estrai anche i computer account separatamente

grep "SidTypeUser" /tmp/lookupsid_raw.txt | grep '\$' | \

  awk -F'\' '{print $2}' | awk '{print $1}' > /tmp/computerlist.txt

```

***

## Workflow tipico in un pentest

```

1. Scopri porta 445 aperta → prova null/guest session prima

   impacket-lookupsid ''@TARGET -no-pass 2>/dev/null | head -5

   → se stampa utenti → hai enumerazione anonima



2. Con credenziali low-priv → esegui su DC per lista completa

   impacket-lookupsid corp.local/user:pass@DC_IP > raw.txt



3. Estrai:

   - Domain SID → per Golden/Silver Ticket

   - Username list → per password spraying

   - Gruppi privilegiati → chi è in Domain Admins?



4. Usa la lista per attacchi successivi

   → /articoli/password-spraying → spray con username trovati

   → /articoli/getnpusers → testa ogni utente per AS-REP Roasting

```

***

## Confronto con strumenti equivalenti

\| Tool | Protocollo | Null/Guest | Mostra SID dominio | Account locali |

\|------|-----------|-----------|-------------------|----------------|

\| `lookupsid.py` | MS-LSAT/SMB 445 | ✅ Spesso | ✅ Sì | ✅ Sì |

\| [samrdump.py](https://hackita.it/articoli/samrdump/) | SAMR/SMB 445 | ❌ Win10+ | ❌ No | ✅ Sì |

\| [GetADUsers.py](https://hackita.it/articoli/getadusers/) | LDAP 389 | ❌ No | ❌ No | ❌ No |

\| [rpcclient](https://hackita.it/articoli/rpcclient/) | RPC/SMB 445 | ✅ Legacy | ✅ Sì | ✅ Sì |

\| `nxc smb --users` | SMB/SAMR | ✅ Legacy | ❌ No | ✅ Sì |

**Quando preferire lookupsid:**

* Non hai credenziali ma l'account Guest è abilitato
* Hai bisogno del SID del dominio esatto
* LDAP 389 è filtrato o non disponibile
* Vuoi enumerare account locali **e** di dominio in un colpo solo

***

## Errori comuni

\| Errore | Causa | Soluzione |

\|--------|-------|-----------|

\| `STATUS_LOGON_FAILURE` | Credenziali errate | Verifica user:pass |

\| `STATUS_ACCESS_DENIED` | Account senza accesso LSARPC | Prova con account più privilegiato |

\| Nessun output dopo Domain SID | maxRid troppo basso | Aumenta a 10000 per domini grandi |

\| `Connection refused` | Porta 445 chiusa | Verifica SMB aperto |

\| Guest account bloccato | Guest disabilitato (default Win10+) | Usa credenziali valide |

***

## Cheat Sheet

```bash

# Base con credenziali

impacket-lookupsid corp.local/user:pass@TARGET



# Null session (legacy/Samba)

impacket-lookupsid ''@TARGET -no-pass



# Guest account (HTB, ambienti legacy)

impacket-lookupsid corp.local/guest@TARGET -no-pass



# maxRid aumentato per domini grandi

impacket-lookupsid corp.local/user:pass@TARGET 10000



# Pass-the-Hash

impacket-lookupsid -hashes :NThash corp.local/user@TARGET



# Estrai Domain SID

impacket-lookupsid corp.local/user:pass@TARGET | grep "Domain SID"



# Estrai username list (no computer account)

impacket-lookupsid corp.local/guest@TARGET -no-pass | \

  grep "SidTypeUser" | grep -v '\$' | \

  awk -F'\' '{print $2}' | awk '{print $1}' > userlist.txt



# Via Kerberos

export KRB5CCNAME=ticket.ccache

impacket-lookupsid -k -no-pass corp.local/user@TARGET.FQDN

```

**Articoli correlati:**

* [Impacket: suite completa](https://hackita.it/articoli/impacket/)
* [SMB — porta 445 e attacchi](https://hackita.it/articoli/smb/)
* [samrdump.py — enumerazione via SAMR](https://hackita.it/articoli/samrdump/)
* [GetADUsers.py — enumerazione via LDAP](https://hackita.it/articoli/getadusers/)
* [rpcdump.py — endpoint RPC e named pipe](https://hackita.it/articoli/rpcdump/)
* [rpcclient — shell RPC interattiva](https://hackita.it/articoli/rpcclient/)
* [Golden Ticket — usa il SID del dominio](https://hackita.it/articoli/golden-ticket/)
* [BloodHound — mappa l'AD](https://hackita.it/articoli/bloodhound/)
* [Active Directory: guida all'exploitation](https://hackita.it/articoli/active-directory/)

> Uso esclusivo in ambienti autorizzati.
