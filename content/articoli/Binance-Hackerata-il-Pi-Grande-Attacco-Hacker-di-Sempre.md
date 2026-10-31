---
title: 'Binance Hackerata: il Più Grande Attacco Hacker di Sempre'
slug: binance-hacked
description: 'Binance è stata hackerata: 6,3 miliardi rubati su 10 blockchain. L''attacco con EIP-7702, il gruppo nordcoreano dietro, fondi congelati e rischi per gli utenti.'
image: /binance-hacked-crypto-exchange-2026-hackita.webp
draft: false
date: 2026-10-31T09:28:20.503Z
categories:
  - guides-resources
subcategories:
  - risorse
tags:
  - Binance
  - TraderTraitor
  - EIP-7702
  - Furto crypto
---

# Binance Hacked 2026: Come Hanno Rubato 6,3 Miliardi su Dieci Blockchain

Binance è stata hackerata il 29 ottobre 2026: l'attacco hacker a Binance (Binance hacked, o Binance hack, come lo chiamano i media internazionali) ha portato via circa 6,3 miliardi di dollari da wallet dell'exchange su dieci blockchain. È il più grande furto crypto mai registrato, circa quattro volte il record precedente di Bybit (1,5 miliardi, febbraio 2025). Secondo [TRM Labs](https://www.trmlabs.com/resources/blog/north-korea-steals-usd-6-36-billion-from-binance-in-the-largest-hack-in-history), su Ethereum è stato usato EIP-7702 e, nel complesso, l'attaccante ha probabilmente compromesso il sistema che firma i prelievi. TRM e Chainalysis attribuiscono l'attacco al gruppo nordcoreano TraderTraitor. Binance dichiara che coprirà tutte le perdite.

| Dato                                | Risultato                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ |
| Data dell'attacco                   | 29 ottobre 2026 (sera, UTC)                                                                      |
| Exchange hackerato                  | Binance (Binance hacked)                                                                         |
| Furto stimato                       | Circa 6,3 miliardi $ (Binance), 6,36 miliardi $ (TRM)                                            |
| Blockchain coinvolte                | 10                                                                                               |
| Fondi congelati                     | Circa 3 miliardi $ (Binance), circa 2,7 miliardi $ (TRM, 30 ottobre ore 00:30 UTC)               |
| Fondi ancora in mano all'attaccante | Circa 2,4 miliardi $ (TRM)                                                                       |
| Gruppo attribuito                   | TraderTraitor (TRM: alta fiducia; Chainalysis: probabile)                                        |
| Tecnica su Ethereum                 | EIP-7702, con 50 autorizzazioni firmate in anticipo                                              |
| Prelievi / depositi                 | Prelievi sospesi, ripristino graduale; depositi operativi (aggiornamento Binance del 30 ottobre) |
| Root cause ufficiale                | Non ancora pubblicato                                                                            |

**Come leggere questo articolo.** Sulla vicenda di Binance hackerata circolano già molte cifre e ipotesi diverse, quindi tengo separati tre livelli: i *fatti dichiarati da Binance*, la *ricostruzione on-chain di TRM Labs* e le *ipotesi ancora da verificare*. L'accesso iniziale, la compromissione del sistema di firma e l'identità degli attaccanti sono attribuiti alle rispettive fonti e non sono una conferma indipendente del root cause.

**Aggiornamenti.**

* 31 ottobre 2026: pubblicazione, con l'avviso ufficiale di Binance del 30 ottobre (depositi operativi, prelievi graduali, Proof of Reserves entro il 2 novembre).
* Prossimo aggiornamento: il post-mortem tecnico di Binance e i risultati del Proof of Reserves, appena pubblicati.

## Binance hackerata: cosa è successo, in ordine

Nella sera del 29 ottobre, miliardi di dollari in crypto hanno cominciato a lasciare i wallet di Binance. In pochi minuti i wallet dell'exchange su XRP Ledger, Ethereum, Bitcoin, Tron, Solana e altre quattro reti hanno inviato i loro saldi a indirizzi controllati da un unico attaccante. Una seconda ondata ha colpito Avalanche e Polygon poco dopo le 23:05 UTC.

Binance ha confermato l'incidente di sicurezza e ha bloccato i prelievi. Ecco la cronologia dell'attacco hacker, ricostruita da TRM Labs:

![Binance hack timeline October 28-30 2026](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgODAwIDYwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHdpZHRoPSI4MDAiIGhlaWdodD0iNjAwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDAiIHk9IjQyIiBmb250LXNpemU9IjIyIiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIj5CaW5hbmNlIGhhY2sgdGltZWxpbmUgKFVUQyk8L3RleHQ+CiAgPHRleHQgeD0iNDAiIHk9IjY0IiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5PY3RvYmVyIDI4LTMwLCAyMDI2IC0gYWJvdXQgNi4zNkIgVVNEIG1vdmVkIGFjcm9zcyAxMCBibG9ja2NoYWluczwvdGV4dD4KICA8bGluZSB4MT0iMTcwIiB5MT0iOTIiIHgyPSIxNzAiIHkyPSI1MjAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMTUwIiB5PSIxMDUiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJlbmQiPk9jdCAyOCwgbW9ybmluZzwvdGV4dD4KICA8cmVjdCB4PSIxNjMiIHk9IjkzIiB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHJ4PSI3IiBmaWxsPSIjZmYwMTAzIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjE5MCIgeT0iMTA1IiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5PcGVyYXRvciB3YWxsZXQgZnVuZGVkIHZpYSAzIHNtYWxsIFRvcm5hZG8gQ2FzaCB3aXRoZHJhd2FsczwvdGV4dD4KICA8dGV4dCB4PSIxNTAiIHk9IjE1NyIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9ImVuZCI+T2N0IDI5LCBlYXJseTwvdGV4dD4KICA8cmVjdCB4PSIxNjMiIHk9IjE0NSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiByeD0iNyIgZmlsbD0iI2ZmMDEwMyIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIxOTAiIHk9IjE1NyIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+QXR0YWNrIGNvZGUgdGVzdGVkIG9uIDIgd2FsbGV0cywgcmVoZWFyc2VkIG9uIGEgM3JkPC90ZXh0PgogIDx0ZXh0IHg9IjE1MCIgeT0iMjA5IiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0iZW5kIj40aCBhZnRlciByZWhlYXJzYWw8L3RleHQ+CiAgPHJlY3QgeD0iMTYzIiB5PSIxOTciIHdpZHRoPSIxNCIgaGVpZ2h0PSIxNCIgcng9IjciIGZpbGw9IiNmZjAxMDMiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMTkwIiB5PSIyMDkiIGZvbnQtc2l6ZT0iMTUiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPlNhbWUgY29kZSBpbnN0YWxsZWQgb24gYSBCaW5hbmNlIGhvdCB3YWxsZXQ8L3RleHQ+CiAgPHRleHQgeD0iMTUwIiB5PSIyNjEiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJlbmQiPjIwOjA1IC0gMjA6MDk8L3RleHQ+CiAgPHJlY3QgeD0iMTYzIiB5PSIyNDkiIHdpZHRoPSIxNCIgaGVpZ2h0PSIxNCIgcng9IjciIGZpbGw9IiNmZjAxMDMiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMTkwIiB5PSIyNjEiIGZvbnQtc2l6ZT0iMTUiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPlhSUCBMZWRnZXI6IDIzMy40Nk0gWFJQIHN3ZXB0IGZyb20gNSB3YWxsZXRzPC90ZXh0PgogIDx0ZXh0IHg9IjE1MCIgeT0iMzEzIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0iZW5kIj4yMDoyMDwvdGV4dD4KICA8cmVjdCB4PSIxNjMiIHk9IjMwMSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiByeD0iNyIgZmlsbD0iI2ZmMDEwMyIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIxOTAiIHk9IjMxMyIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+MTgsMjcwIEJUQyBtb3ZlZCwgNTAgRUlQLTc3MDIgYXV0aG9yaXphdGlvbnMgc3VibWl0dGVkPC90ZXh0PgogIDx0ZXh0IHg9IjE1MCIgeT0iMzY1IiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0iZW5kIj4yMDoyNCBhcHByb3g8L3RleHQ+CiAgPHJlY3QgeD0iMTYzIiB5PSIzNTMiIHdpZHRoPSIxNCIgaGVpZ2h0PSIxNCIgcng9IjciIGZpbGw9IiNmZjAxMDMiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIi8+CiAgPHRleHQgeD0iMTkwIiB5PSIzNjUiIGZvbnQtc2l6ZT0iMTUiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPkVUSCBob3Qgd2FsbGV0IGRyYWluZWQ6IDE2Nyw0NjQgRVRIIGFuZCAxLjYxNUIgVVNEVDwvdGV4dD4KICA8dGV4dCB4PSIxNTAiIHk9IjQxNyIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9ImVuZCI+MjE6MDEgLSAyMjoxMDwvdGV4dD4KICA8cmVjdCB4PSIxNjMiIHk9IjQwNSIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiByeD0iNyIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjMiLz4KICA8dGV4dCB4PSIxOTAiIHk9IjQxNyIgZm9udC1zaXplPSIxNSIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+VGV0aGVyLCBDaXJjbGUsIFJpcHBsZSwgV29ybGQgTGliZXJ0eSBmcmVlemUgZnVuZHM8L3RleHQ+CiAgPHRleHQgeD0iMTUwIiB5PSI0NjkiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJlbmQiPjIzOjA1PC90ZXh0PgogIDxyZWN0IHg9IjE2MyIgeT0iNDU3IiB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHJ4PSI3IiBmaWxsPSIjZmYwMTAzIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIvPgogIDx0ZXh0IHg9IjE5MCIgeT0iNDY5IiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5TZWNvbmQgd2F2ZTogQXZhbGFuY2hlIGFuZCBQb2x5Z29uIHdhbGxldHM8L3RleHQ+CiAgPHRleHQgeD0iMTUwIiB5PSI1MjEiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJlbmQiPjAwOjA4IChPY3QgMzApPC90ZXh0PgogIDxyZWN0IHg9IjE2MyIgeT0iNTA5IiB3aWR0aD0iMTQiIGhlaWdodD0iMTQiIHJ4PSI3IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMyIvPgogIDx0ZXh0IHg9IjE5MCIgeT0iNTIxIiBmb250LXNpemU9IjE1IiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5BcmJpdHJ1bSBTZWN1cml0eSBDb3VuY2lsIGZyZWV6ZXMgRVRIIGFuZCBBUkI8L3RleHQ+CiAgPHJlY3QgeD0iNTMiIHk9IjU1MyIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiByeD0iNyIgZmlsbD0iI2ZmMDEwMyIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSI3NiIgeT0iNTY1IiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIj5BdHRhY2tlciBhY3Rpdml0eTwvdGV4dD4KICA8cmVjdCB4PSIyMTMiIHk9IjU1MyIgd2lkdGg9IjE0IiBoZWlnaHQ9IjE0IiByeD0iNyIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjMiLz4KICA8dGV4dCB4PSIyMzYiIHk9IjU2NSIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+RGVmZW5zaXZlIHJlc3BvbnNlPC90ZXh0PgogIDx0ZXh0IHg9Ijc2MCIgeT0iNTY1IiBmb250LXNpemU9IjEyIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0iZW5kIj5Tb3VyY2U6IFRSTSBMYWJzIC0gaGFja2l0YS5pdDwvdGV4dD4KPC9zdmc+Cg==)

Il dettaglio più importante non è nella sera dell'attacco, ma nelle 36 ore prima: l'attaccante ha preparato, testato e provato il codice su altri wallet prima di installarlo su un wallet di Binance. Non è stato un colpo improvvisato: è stata un'operazione pianificata, con prova generale inclusa.

## Furto crypto a Binance: quanto è stato rubato e quanto è stato congelato

TRM valuta ogni trasferimento al prezzo del momento e arriva a circa 6,36 miliardi. Ai prezzi attuali gli stessi asset valgono circa 6,23 miliardi. Binance parla di circa 6,3 miliardi. Ecco la ripartizione per rete:

| Rete                               | Importo approssimativo |
| ---------------------------------- | ---------------------- |
| Ethereum                           | 3,79 miliardi $        |
| Bitcoin (18.270 BTC)               | 1,47 miliardi $        |
| Tron                               | 628 milioni $          |
| XRP Ledger (233,46 milioni di XRP) | 296 milioni $          |
| Solana                             | 96 milioni $           |
| Arbitrum, Optimism, Base           | 39 milioni $           |
| Avalanche                          | 28 milioni $           |
| Polygon                            | 10 milioni $           |

I fondi congelati hanno due numeri, e non vanno confusi. TRM conta circa 2,7 miliardi *on-chain*, aggiornati alle 00:30 UTC del 30 ottobre. Binance, in un aggiornamento successivo, parla di circa 3 miliardi. Sono stime fatte in momenti diversi con metodi diversi, e nessuna delle due significa fondi già restituiti. Il dettaglio di TRM:

* **Tether:** circa 1,77 miliardi di USDT.
* **Circle:** circa 825 milioni di USDC, congelati in coordinamento con le forze dell'ordine.
* **Ripple:** 40,5 milioni di RLUSD.
* **World Liberty Financial:** 27,8 milioni di USD1.
* **Security Council di Arbitrum:** circa 30 milioni di dollari in ETH e ARB.

Il dato che pesa di più è l'altro: l'attaccante controlla ancora circa 2,4 miliardi di dollari in ETH e BTC, fuori dalla portata di qualsiasi emittente. Anche dopo i congelamenti, quella cifra da sola supera qualsiasi furto crypto precedente. Per questo il furto crypto a Binance è già il più grande furto di criptovalute di sempre, il più grande hack crypto della storia (the largest crypto hack ever).

## Binance hackerata: l'ultimo aggiornamento ufficiale (30 ottobre)

Nell'avviso del 30 ottobre, riportato da [CyberInsider](https://cyberinsider.com/binance-security-incident-6-3-billion/) e da [Bloomingbit](https://en.bloomingbit.io/feed/news/123338), Binance dichiara:

* di aver messo da parte oltre 6,34 miliardi di dollari di fondi aziendali per coprire le perdite, insieme al fondo SAFU;
* di aver già sostituito circa l'80% degli asset rubati con le stesse monete, e di comprare il resto sul mercato e via OTC; circa 5 miliardi sono già disponibili negli stessi asset sottratti;
* che i **depositi e i servizi non coinvolti funzionano normalmente**, mentre i **prelievi restano sospesi** finché controlli e modifiche di sistema non sono completati; il ripristino sarà graduale, a partire da circa 31 ottobre–1° novembre (Bloomberg riporta la co-fondatrice Yi He che indica domenica);
* che un nuovo Proof of Reserves sarà pubblicato entro il 2 novembre;
* che l'ingresso iniziale potrebbe essere stato un laptop, ma che la violazione ha coinvolto più percorsi, e che non c'è evidenza di chiavi private compromesse;
* che pubblicherà un post-mortem tecnico dettagliato, senza una data.

Non ho potuto aprire direttamente la pagina ufficiale di Binance: controlla sempre gli annunci originali sui suoi canali.

## Come hanno hackerato Binance (spiegato semplice)

Un exchange tiene la maggior parte dei fondi in wallet offline (cold wallet) e una parte in wallet collegati a internet, gli hot wallet, che servono a pagare i prelievi dei clienti. Pensa alla cassaforte nel retro e alla cassa del negozio.

Qui nessuno ha forzato la cassaforte. Secondo l'analisi di TRM, l'attaccante ha ottenuto la capacità di far firmare al sistema di Binance le transazioni che voleva lui, su più blockchain contemporaneamente. Un wallet su ogni rete ha mandato fondi all'attaccante con firme perfettamente valide: per la blockchain erano prelievi legittimi.

Nelle prime ore Binance aveva parlato di un laptop compromesso di un ingegnere DevOps, che avrebbe permesso all'attaccante di raggiungere un container di servizio e inviare prelievi non autorizzati. Il co-CEO Richard Teng ha poi precisato che l'attacco è stato un processo più complesso e non il semplice abuso dei permessi di una persona. Binance ha anche detto di non aver trovato evidenze di una fuga di chiavi private. Le due cose sono compatibili: far firmare al sistema richieste scelte dall'attaccante non richiede di rubare la chiave.

## Binance e EIP-7702: le 50 autorizzazioni che hanno svuotato l'hot wallet

Su Ethereum l'attacco hacker a Binance ha un meccanismo preciso. [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702), introdotto con l'aggiornamento Pectra di maggio 2025, permette a un wallet normale di far eseguire a uno smart contract il proprio comportamento, firmando una *autorizzazione*. Da quel momento ogni chiamata al wallet esegue il codice di quel contratto, finché il wallet non firma una nuova autorizzazione.

Ogni autorizzazione vale solo a un preciso nonce, cioè al contatore di transazioni del wallet in quel momento. L'hot wallet di Binance processa prelievi di continuo, quindi il suo nonce avanza sempre. L'attaccante ha risolto il problema in modo brutale: ha preparato in anticipo 50 autorizzazioni firmate su nonce consecutivi, certo che una sarebbe stata quella giusta al momento dell'esecuzione. È come provare 50 numeri di una combinazione sapendo che solo uno sarà valido in quell'istante.

Alle 20:20 UTC la transazione con le 50 autorizzazioni è stata inviata e una è andata a buon fine. Il wallet ha cominciato a eseguire un contratto "sweeper" che accettava ordini solo dall'operatore. Tre minuti e 24 secondi dopo, un'unica transazione ha spostato 167.464 ETH e 63 token, tra cui 1,615 miliardi di USDT.

La delega è rimasta attiva, e per questo ogni nuovo deposito arrivato sul wallet è stato svuotato di nuovo, più volte, fino alle 23:56 UTC. Binance ha dichiarato di aver revocato le autorizzazioni degli indirizzi coinvolti.

## Perché EIP-7702 non spiega da solo tutto l'attacco

Questo è il punto che molte ricostruzioni sbagliano. EIP-7702 spiega **come è stato svuotato un wallet Ethereum**. Non spiega le altre nove blockchain, dove non esiste nessuna delega: i wallet Binance su XRP Ledger, Bitcoin, Tron, Solana, Arbitrum, Avalanche, Optimism, Base e Polygon hanno inviato fondi con normali trasferimenti firmati. Anche un secondo hot wallet su Ethereum ha mandato 28.006 ETH, 55,7 milioni di USDT e 25,9 milioni di RLUSD senza alcuna delega.

L'ipotesi iniziale, autorizzazioni ottenute con phishing, copre solo Ethereum. Nella stessa mezz'ora, wallet con tipi di chiave e schemi di firma diversi hanno prodotto firme valide per l'attaccante. Per TRM la spiegazione più probabile è una sola: chi attacca ha messo le mani sul sistema che firma i prelievi degli hot wallet. Binance non ha confermato questo punto, e non c'è ancora una prova pubblica di quale componente sia stato compromesso per primo.

![Binance hack reconstructed attack path](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgODAwIDYyMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmZmZmZiIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2ZmMDEwMyIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgogIDxyZWN0IHdpZHRoPSI4MDAiIGhlaWdodD0iNjIwIiBmaWxsPSIjNmIwMDAxIi8+CiAgPHRleHQgeD0iNDAwIiB5PSIzNCIgZm9udC1zaXplPSIyMSIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+QmluYW5jZSBoYWNrOiByZWNvbnN0cnVjdGVkIGF0dGFjayBwYXRoPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iNTUiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkRhc2hlZCA9IGh5cG90aGVzaXMgb3IgYXNzZXNzbWVudCwgbm90IGEgY29uZmlybWVkIHJvb3QgY2F1c2U8L3RleHQ+CiAgPHJlY3QgeD0iMTAwIiB5PSI3MCIgd2lkdGg9IjYwMCIgaGVpZ2h0PSI1NiIgcng9IjYiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIzIiBzdHJva2UtZGFzaGFycmF5PSI2LDQiLz4KICA8dGV4dCB4PSI0MDAiIHk9Ijk0IiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5EZXZPcHMgZW5naW5lZXIgbGFwdG9wIGNvbXByb21pc2VkPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iMTEzIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5CaW5hbmNlOiBpbml0aWFsIGh5cG90aGVzaXMsIGVudHJ5IG1heSBpbnZvbHZlIG11bHRpcGxlIHJvdXRlczwvdGV4dD4KICA8bGluZSB4MT0iNDAwIiB5MT0iMTI2IiB4Mj0iNDAwIiB5Mj0iMTUyIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KICA8cmVjdCB4PSIxMDAiIHk9IjE1NCIgd2lkdGg9IjYwMCIgaGVpZ2h0PSI1NiIgcng9IjYiIGZpbGw9IiMwMDAwMDAiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIzIiBzdHJva2UtZGFzaGFycmF5PSI2LDQiLz4KICA8dGV4dCB4PSI0MDAiIHk9IjE3OCIgZm9udC1zaXplPSIxNyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+QWNjZXNzIHRvIGEgc2VydmljZSBjb250YWluZXI8L3RleHQ+CiAgPHRleHQgeD0iNDAwIiB5PSIxOTciIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPkJpbmFuY2U6IHVuYXV0aG9yaXplZCB3aXRoZHJhd2FscyB3ZXJlIHN1Ym1pdHRlZCBmcm9tIGl0PC90ZXh0PgogIDxsaW5lIHgxPSI0MDAiIHkxPSIyMTAiIHgyPSI0MDAiIHkyPSIyMzYiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDxyZWN0IHg9IjEwMCIgeT0iMjM4IiB3aWR0aD0iNjAwIiBoZWlnaHQ9IjU2IiByeD0iNiIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1kYXNoYXJyYXk9IjYsNCIvPgogIDx0ZXh0IHg9IjQwMCIgeT0iMjYyIiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5Ib3Qgd2FsbGV0IHNpZ25pbmcgaW5mcmFzdHJ1Y3R1cmUgYWJ1c2VkPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iMjgxIiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5UUk06IG1vc3QgbGlrZWx5IGV4cGxhbmF0aW9uLCBvZmZpY2lhbCByb290IGNhdXNlIG5vdCBwdWJsaXNoZWQ8L3RleHQ+CiAgPGxpbmUgeDE9IjQwMCIgeTE9IjI5NCIgeDI9IjQwMCIgeTI9IjMyMCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3cpIi8+CiAgPHJlY3QgeD0iMTAwIiB5PSIzMjIiIHdpZHRoPSI2MDAiIGhlaWdodD0iNTYiIHJ4PSI2IiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZjAxMDMiIHN0cm9rZS13aWR0aD0iMyIvPgogIDx0ZXh0IHg9IjQwMCIgeT0iMzQ2IiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5WYWxpZCBzaWduYXR1cmVzIG9uIDEwIGJsb2NrY2hhaW5zPC90ZXh0PgogIDx0ZXh0IHg9IjQwMCIgeT0iMzY1IiBmb250LXNpemU9IjEzIiBmb250LXdlaWdodD0iNDAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5PYnNlcnZlZCBvbi1jaGFpbjogZGlmZmVyZW50IGtleSB0eXBlcyBhbmQgc2lnbmluZyBzY2hlbWVzPC90ZXh0PgogIDxsaW5lIHgxPSI0MDAiIHkxPSIzNzgiIHgyPSI0MDAiIHkyPSI0MDQiIHN0cm9rZT0iI2ZmZmZmZiIgc3Ryb2tlLXdpZHRoPSIyIiBtYXJrZXItZW5kPSJ1cmwoI2Fycm93KSIvPgogIDxyZWN0IHg9IjEwMCIgeT0iNDA2IiB3aWR0aD0iNjAwIiBoZWlnaHQ9IjU2IiByeD0iNiIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjMiLz4KICA8dGV4dCB4PSI0MDAiIHk9IjQzMCIgZm9udC1zaXplPSIxNyIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2ZmZmZmZiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+SG90IHdhbGxldHMgc3dlcHQ8L3RleHQ+CiAgPHRleHQgeD0iNDAwIiB5PSI0NDkiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPk9ic2VydmVkOiBhYm91dCA2LjM2QiBVU0Qgb3V0LCBtb3N0IG9mIGl0IGluIGFib3V0IDIwIG1pbnV0ZXM8L3RleHQ+CiAgPGxpbmUgeDE9IjQwMCIgeTE9IjQ2MiIgeDI9IjQwMCIgeTI9IjQ4OCIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIG1hcmtlci1lbmQ9InVybCgjYXJyb3cpIi8+CiAgPHJlY3QgeD0iMTAwIiB5PSI0OTAiIHdpZHRoPSI2MDAiIGhlaWdodD0iNTYiIHJ4PSI2IiBmaWxsPSIjZmYwMTAzIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMyIvPgogIDx0ZXh0IHg9IjQwMCIgeT0iNTE0IiBmb250LXNpemU9IjE3IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZmZmZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5BdHRhY2tlciBjb250cm9sbGVkIHdhbGxldHM8L3RleHQ+CiAgPHRleHQgeD0iNDAwIiB5PSI1MzMiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJtaWRkbGUiPlRSTTogYWJvdXQgMi43QiBVU0QgZnJvemVuLCBhYm91dCAyLjRCIFVTRCBzdGlsbCBoZWxkPC90ZXh0PgogIDxyZWN0IHg9IjEwMCIgeT0iNTgwIiB3aWR0aD0iMjIiIGhlaWdodD0iMTQiIHJ4PSIzIiBmaWxsPSIjMDAwMDAwIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWRhc2hhcnJheT0iNiw0Ii8+CiAgPHRleHQgeD0iMTMwIiB5PSI1OTIiIGZvbnQtc2l6ZT0iMTMiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiPkh5cG90aGVzaXMgb3IgYXNzZXNzbWVudDwvdGV4dD4KICA8cmVjdCB4PSIzMDAiIHk9IjU4MCIgd2lkdGg9IjIyIiBoZWlnaHQ9IjE0IiByeD0iMyIgZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSIjZmYwMTAzIiBzdHJva2Utd2lkdGg9IjIiLz4KICA8dGV4dCB4PSIzMzAiIHk9IjU5MiIgZm9udC1zaXplPSIxMyIgZm9udC13ZWlnaHQ9IjQwMCIgZmlsbD0iI2ZmZmZmZiI+T2JzZXJ2ZWQgb24tY2hhaW48L3RleHQ+CiAgPHRleHQgeD0iNzAwIiB5PSI1OTIiIGZvbnQtc2l6ZT0iMTIiIGZvbnQtd2VpZ2h0PSI0MDAiIGZpbGw9IiNmZmZmZmYiIHRleHQtYW5jaG9yPSJlbmQiPlNvdXJjZXM6IEJpbmFuY2UsIFRSTSBMYWJzIC0gaGFja2l0YS5pdDwvdGV4dD4KPC9zdmc+Cg==)

Se leggi questo con l'occhio del red team, la sequenza ricalca la [Cyber Kill Chain](https://hackita.it/articoli/cyber-kill-chain/): preparazione lunga, un ingresso probabile da un endpoint DevOps, un passaggio verso un container (un [container escape](https://hackita.it/articoli/container-escape/) o un abuso di permessi, da capire dal post-mortem), poi [lateral movement](https://hackita.it/articoli/lateral-movement/) fino ai sistemi di firma e infine l'azione sull'obiettivo in un'unica raffica.

## Chi ha hackerato Binance: il gruppo TraderTraitor

Per il furto crypto a Binance, TRM attribuisce l'attacco a TraderTraitor con alta fiducia, e Chainalysis è sulla stessa linea parlando di attacco probabilmente opera di questo gruppo. È lo stesso gruppo che l'FBI ha indicato come responsabile dell'hack di Bybit del 2025. Al momento in cui scriviamo, l'attribuzione di questo attacco arriva da società private di analisi blockchain. TraderTraitor è un gruppo di hacker della Corea del Nord, noto nell'intelligence anche con altri nomi (come Jade Sleet e UNC4899) e spesso ricondotto all'ecosistema Lazarus Group.

Gli indizi in comune con i colpi nordcoreani precedenti sono tre: piccoli prelievi da Tornado Cash per finanziare il wallet dell'operatore, una preparazione iniziata molto prima del furto e firme ottenute in anticipo ed eseguite in un'unica raffica. Cambia invece il riciclaggio: dopo Bybit si usarono molto i bridge cross-chain, qui si vedono grandi swap con market maker e protocolli di lending.

## Dove sono finiti i soldi rubati a Binance

Per battere i congelamenti, l'attaccante ha venduto in fretta stablecoin che sapeva di poter perdere. Circa 325 milioni di USDT sono stati ceduti a market maker tramite UniswapX per circa 122.300 ETH, con uno sconto superiore al 10% rispetto al prezzo di mercato. Un secondo wallet ha depositato 60 milioni di USDT su Aave e ha preso in prestito circa 19.760 ETH, dopodiché Aave ha congelato i mercati interessati.

I 18.270 BTC sono entrati in una peel chain: lo stesso importo viene spezzato in pezzi tondi da 1.000 e 100 BTC per rendere il tracciamento più difficile. Dopo altri colpi simili, il passo successivo tipico sono bridge, servizi di swap e broker OTC: è lì che i team di compliance degli exchange devono guardare nei prossimi giorni.

## Binance hackerata: i miei soldi sono al sicuro?

Anche se Binance è stata hackerata, l'exchange dice che i fondi degli utenti sono al sicuro e che coprirà tutte le perdite con il fondo SAFU e con fondi aziendali. Un analista di Fundstrat citato da [CNBC](https://www.cnbc.com/2026/10/30/billions-in-crypto-frozen-in-binance-hack-heres-what-happens-next-.html) non vede al momento un rischio significativo per la solvibilità dell'exchange. I depositi sono operativi, i prelievi sono sospesi e saranno riattivati per fasi. Sul mercato, Bitcoin è sceso di oltre il 4% dopo la notizia.

Quello che devi fare tu, concretamente:

* Fidati solo dei canali ufficiali di Binance. Dopo un evento del genere partono sempre campagne di [phishing](https://hackita.it/articoli/phishing-techniques-red-team/) con finti rimborsi, finti "moduli di compensazione" e finto supporto, anche al telefono.
* Non cliccare link ricevuti via email o SMS su questo tema: apri l'app o digita tu l'indirizzo.
* Attiva una chiave hardware o una passkey e la whitelist degli indirizzi di prelievo, se non l'hai già fatto.
* Nessun servizio legittimo ti chiede mai le chiavi private o la frase di recupero.

## Binance hackerata: cosa ha gestito bene e cosa no

**Gestito bene.** Binance ha riconosciuto l'incidente in poche ore, pubblicamente su X, senza nascondersi dietro a una "manutenzione programmata". Ha bloccato i prelievi subito, ha mantenuto i depositi attivi, si è impegnata a coprire le perdite con cifre concrete e ha promesso un post-mortem tecnico quando i fatti saranno verificati. Il coordinamento con Tether, Circle, Ripple, World Liberty Financial e il Security Council di Arbitrum ha permesso di congelare circa 2,7 miliardi in poche ore, un risultato che in un furto del genere non è scontato.

**Gestito meno bene.** La prima versione pubblica, un laptop compromesso, è stata poi inquadrata dal co-CEO come un quadro più complesso del solo abuso dei permessi di una persona. Dire che non risultano chiavi private rubate non rassicura molto se il problema è il sistema che firma i prelievi. E, valutazione nostra finché non arriva il post-mortem, sembra mancato un freno automatico efficace: venti minuti sono bastati per portare via la parte più grande dei fondi, su dieci blockchain.

## Cosa insegna questo furto crypto ai team di sicurezza

La lezione utile per chi difende non è "Binance ha sbagliato", è che una firma valida non prova che la richiesta sia legittima. Le contromisure indicate da TRM per i team di tesoreria sono concrete:

* Monitorare i wallet con deleghe EIP-7702, che compaiono come codice a un indirizzo che dovrebbe averne zero, e allertare subito se compare su un wallet di tesoreria.
* Rifiutare per policy le autorizzazioni EIP-7702 non previste e trattare una richiesta con molte autorizzazioni su nonce consecutivi come indicatore di compromissione.
* Avere pronto e testato un metodo di firma per revocare la delega.
* Separare infrastruttura di firma e percorsi di approvazione per chain e per livello di wallet: qui un solo attore ha ottenuto firme valide su dieci chain in poche ore.

Nella sezione tecnica qui sotto trovi come verificarlo nella pratica.

## In sintesi: cosa sappiamo su Binance hackerata

* Binance è stata hackerata il 29 ottobre 2026: circa 6,3 miliardi di dollari rubati da wallet su dieci blockchain, il più grande furto crypto mai registrato.
* Su Ethereum l'attaccante ha usato EIP-7702 con 50 autorizzazioni; secondo TRM il sistema che firma i prelievi è stato probabilmente compromesso (non confermato da Binance).
* TRM e Chainalysis attribuiscono l'attacco a TraderTraitor, il gruppo nordcoreano già dietro l'hack di Bybit.
* Circa 2,7 miliardi (TRM) o 3 miliardi (Binance) risultano congelati; l'attaccante ne controlla ancora circa 2,4 miliardi.
* Binance copre le perdite con il fondo SAFU e con fondi aziendali: depositi operativi, prelievi sospesi con ripristino graduale.

## Glossario rapido: hot wallet, nonce, SAFU e Proof of Reserves

* **Hot wallet:** wallet collegato a internet che un exchange usa per pagare i prelievi dei clienti. Più è pieno, più vale per un attaccante.
* **Nonce:** contatore delle transazioni di un wallet. Con EIP-7702 un'autorizzazione vale solo al nonce per cui è stata firmata.
* **Sweeper contract:** contratto che svuota un wallet mandando tutto a un indirizzo scelto da chi lo controlla.
* **Peel chain:** tecnica di riciclaggio in cui una somma grande viene spezzata in pezzi sempre più piccoli e spostata a catena, per rendere difficile il tracciamento.
* **SAFU:** il fondo di emergenza di Binance per coprire le perdite degli utenti.
* **Proof of Reserves:** prova pubblicata dall'exchange per mostrare che gli asset dei clienti sono coperti da riserve.

## Domande frequenti su Binance hackerata (Binance hacked)

### Binance è stata davvero hackerata (Binance hacked)?

Sì. Binance ha confermato un incidente di sicurezza il 29 ottobre 2026 e ha stimato un impatto di circa 6,3 miliardi di dollari.

### Quanto hanno rubato a Binance?

Circa 6,3 miliardi di dollari secondo Binance, circa 6,36 miliardi secondo TRM Labs, su dieci blockchain.

### Chi ha hackerato Binance?

TRM Labs e Chainalysis attribuiscono l'attacco al gruppo nordcoreano TraderTraitor, lo stesso indicato per il furto di Bybit del 2025. L'attribuzione arriva da società di analisi blockchain.

### Che cos'è TraderTraitor?

È un gruppo di hacker della Corea del Nord, indicato da TRM e Chainalysis come autore dell'attacco a Binance e dall'FBI come responsabile dell'hack di Bybit del 2025. È spesso ricondotto all'ecosistema Lazarus Group.

### Come hanno hackerato Binance?

Binance ha parlato di un laptop DevOps compromesso che avrebbe dato accesso a un container di servizio, specificando che i percorsi sono stati più di uno. Secondo TRM i segnali puntano alla compromissione dell'infrastruttura di firma dei prelievi. Su Ethereum l'attaccante ha usato EIP-7702 con 50 autorizzazioni preparate in anticipo. Il root cause ufficiale non è ancora stato pubblicato.

### Che cos'è EIP-7702 e che ruolo ha avuto nell'attacco?

EIP-7702 è una funzione di Ethereum che permette a un wallet normale di delegare il proprio comportamento a uno smart contract tramite un'autorizzazione firmata. Su Ethereum l'attaccante l'ha usata per trasformare un hot wallet di Binance in uno "sweeper" controllato da lui. Non spiega però gli altri nove trasferimenti su blockchain diverse.

### I fondi degli utenti sono al sicuro?

Binance dice di sì e promette di coprire tutte le perdite con il fondo SAFU e con fondi aziendali, oltre 6,34 miliardi di dollari predisposti. Un nuovo Proof of Reserves è atteso entro il 2 novembre.

### Binance ha sospeso anche i depositi dopo l'hack?

All'inizio le notizie parlavano di depositi e prelievi sospesi. Nell'aggiornamento del 30 ottobre Binance precisa che i depositi e gli altri servizi non coinvolti funzionano normalmente, mentre i prelievi restano sospesi e riprenderanno per fasi.

### Binance rimborserà gli utenti?

Binance ha dichiarato che nessun utente subirà perdite: copertura tramite fondo SAFU e fondi aziendali, con circa l'80% degli asset rubati già sostituito.

### Quando riaprono i prelievi su Binance?

Binance ha detto che il ripristino sarà graduale e subordinato ai controlli di sicurezza. Le stime riportate dai media indicano il periodo tra il 31 ottobre e il 1° novembre (Bloomberg cita la co-fondatrice Yi He, che parlava di domenica), ma non è una data garantita: controlla gli annunci ufficiali di Binance.

### Binance rischia il fallimento dopo essere stata hackerata?

Al momento no, secondo le analisi riportate. Un analista di Fundstrat citato da CNBC non vede un rischio significativo per la solvibilità, e Binance dichiara oltre 6,34 miliardi di dollari predisposti per coprire le perdite. Il nuovo Proof of Reserves, atteso entro il 2 novembre, sarà il primo dato verificabile da guardare.

### Quanto è stato congelato?

Circa 2,7 miliardi di dollari secondo TRM (stima on-chain delle 00:30 UTC del 30 ottobre) e circa 3 miliardi secondo Binance. Congelato non significa restituito.

### Qual è la differenza tra l'hack di Binance e quello di Bybit?

L'hack di Binance vale circa 6,36 miliardi di dollari contro gli 1,5 miliardi di Bybit del febbraio 2025, circa quattro volte tanto. Entrambi sono attribuiti a TraderTraitor, il secondo dall'FBI e il primo da TRM e Chainalysis. Cambia anche il riciclaggio: swap e lending invece di bridge.

### Si possono recuperare i soldi rubati?

In parte: circa 2,7 miliardi sono già congelati. I circa 2,4 miliardi rimasti in ETH e BTC sono sotto il controllo dell'attaccante e vengono tracciati.

## Lato tecnico: EIP-7702, nonce e rilevamento

Questa parte è per chi vuole capire il meccanismo e costruire controlli. Tutto ciò che riguarda il sistema di firma di Binance resta un'ipotesi finché non esce il post-mortem.

### EIP-7702 sotto il cofano

Le specifiche sono nell'[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702). I punti che servono per capire l'attacco:

* **Transazione di tipo `0x04`.** Contiene una lista di autorizzazioni. Ogni voce è una tupla `[chain_id, address, nonce, y_parity, r, s]`.
* **Cosa viene firmato.** Chi autorizza (l'*authority*) firma un hash che comprende `chain_id`, l'indirizzo del contratto a cui delega e il nonce. La firma è fatta con la chiave del wallet che delega.
* **Chi la invia.** La transazione può essere inviata da un account qualsiasi, che paga il gas. Per questo un "operatore" può inviare autorizzazioni firmate da un altro wallet.
* **Cosa succede dopo.** Se la firma e il nonce sono validi, il codice del wallet diventa un indicatore `0xef0100` seguito dai 20 byte dell'indirizzo del contratto delegato. Da lì ogni chiamata al wallet esegue quel codice.
* **Il nonce.** L'autorizzazione è valida solo se il nonce firmato coincide con quello attuale del wallet, che poi aumenta di uno.
* **`chain_id` a zero.** Un'autorizzazione con chain id 0 è valida su qualsiasi rete che supporti EIP-7702; con un chain id preciso vale solo su quella.
* **Persistenza.** La delega resta finché non ne viene firmata un'altra. Delegare all'indirizzo zero la cancella.

### Perché 50 autorizzazioni e non una

Se il wallet fosse fermo basterebbe un'autorizzazione. Un hot wallet di un exchange invece firma prelievi di continuo, quindi il suo nonce cambia tra il momento in cui prepari la firma e quello in cui la transazione viene inclusa in un blocco. Preparare 50 autorizzazioni su nonce consecutivi è una scommessa sul nonce di quel momento, e basta che una vinca.

C'è un'implicazione che spesso sfugge, e che qui indichiamo come analisi nostra: ogni autorizzazione deve essere firmata con la chiave del wallet che delega. Per un wallet istituzionale non è un banale "clic su un sito di phishing", è una firma prodotta dal sistema di custodia. TRM dice che le firme sono state prodotte in anticipo, in batch. È uno dei motivi per cui l'ipotesi del solo phishing convince poco.

### Come verificare se un indirizzo ha una delega

Il controllo è una chiamata RPC `eth_getCode`. Un wallet normale restituisce `0x`; un wallet delegato restituisce `0xef0100` seguito dall'indirizzo del contratto. L'esempio usa l'indirizzo che gli explorer etichettano come Binance 14 (verifica l'etichetta su Etherscan prima di citarlo):

```bash
# Check whether an Ethereum address has an EIP-7702 delegation set
# "result":"0x"                          -> plain wallet, no delegation
# "result":"0xef0100<20-byte address>"   -> wallet delegates to that contract
curl -s -X POST https://ethereum-rpc.publicnode.com \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x28C6c06298d514Db089934071355E5743bf21d60","latest"]}'
```

Due avvertenze. Primo: con `latest` vedi lo **stato attuale**, non quello dell'attacco. Binance dice di aver revocato le autorizzazioni, quindi un risultato `0x` oggi non dimostra che il wallet non fosse delegato il 29 ottobre. Per vedere lo stato di allora serve il numero di blocco della transazione di delega e un nodo archive. Secondo: un RPC pubblico va bene per studiare, non per un allarme di produzione.

### Un monitor minimale per i wallet di tesoreria

Questo script controlla ogni 12 secondi un indirizzo e avvisa se compare una delega. Richiede `curl` e `jq`:

```bash
#!/usr/bin/env bash
# Poll an Ethereum address every 12 seconds and alert if it becomes delegated (EIP-7702)
RPC="https://ethereum-rpc.publicnode.com"
WATCHED="0x28C6c06298d514Db089934071355E5743bf21d60"

while true; do
  code=$(curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$WATCHED\",\"latest\"]}" | jq -r .result)
  case "$code" in
    0xef0100*) echo "$(date -u +%FT%TZ) ALERT: $WATCHED delegates to 0x${code:8:40}" ;;
    0x)        echo "$(date -u +%FT%TZ) ok: no delegation" ;;
    *)         echo "$(date -u +%FT%TZ) unexpected response: ${code:0:20}" ;;
  esac
  sleep 12
done
```

In produzione la stessa logica va fatta su un nodo proprio e va affiancata a un controllo sulle transazioni di tipo `0x04` che nominano i tuoi indirizzi come authority.

### La superficie d'attacco lato infrastruttura

Binance ha parlato di un laptop DevOps e di un container di servizio. Non sappiamo come sia stato compromesso il laptop, che privilegi avesse il container o quale controllo di approvazione sia stato aggirato. Sono le tre domande a cui il post-mortem deve rispondere. Intanto, su qualsiasi host che esegue container con accesso a secrets o a servizi di firma, questo comando elenca container privilegiati, rete host e mount sensibili:

```bash
# List running containers with privileged flag, network mode and mounts (look for docker.sock)
docker ps -q | xargs -r docker inspect \
  --format '{{.Name}} privileged={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}'
```

Un container con `privileged=true`, rete host o il socket `/var/run/docker.sock` montato è un ponte facile verso l'host. Se l'API Docker è esposta in rete, il rischio cresce ancora: vedi l'articolo sulla [porta 2375 e l'API Docker](https://hackita.it/articoli/porta-2375-docker-api/).

### Controlli che avrebbero cambiato la dinamica

| Controllo                                                                                                                     | Cosa cambia                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Policy engine separato dal firmatario                                                                                         | Un attaccante che compromette il servizio non può far firmare qualsiasi richiesta: la destinazione e l'importo vengono controllati da un sistema indipendente |
| Whitelist di destinazioni e limiti per transazione e per finestra di tempo                                                    | Svuotare dieci wallet in venti minuti diventa molto più difficile                                                                                             |
| Tetto ai saldi degli hot wallet con sweep automatico verso il cold                                                            | Anche un hot wallet compromesso vale meno                                                                                                                     |
| Firmatari separati per chain e per livello di wallet                                                                          | Una sola compromissione non produce firme valide su dieci reti                                                                                                |
| Rifiuto per policy delle autorizzazioni EIP-7702 sui wallet di tesoreria, o uso di wallet a smart contract con regole proprie | Chiude il percorso della delega a uno sweeper                                                                                                                 |
| Monitoraggio delle deleghe e allarme con revoca già pronta                                                                    | Riduce il tempo tra prima delega e svuotamento                                                                                                                |
| Workstation amministrative dedicate, nessun accesso persistente alla produzione da laptop di sviluppo                         | Un laptop compromesso non basta per arrivare ai sistemi di firma                                                                                              |

### Cosa deve chiarire il post-mortem

* Come è stato compromesso il laptop, e se il vettore è stato malware, supply chain o ingegneria sociale.
* Con quali privilegi girava il container e se poteva raggiungere il sistema di firma.
* Quale controllo di approvazione dei prelievi è stato aggirato o non ha scattato.
* Come sono state ottenute in anticipo le 50 autorizzazioni firmate.
* Perché i limiti di importo e velocità non hanno fermato i prelievi in venti minuti.

Fonti: [TRM Labs](https://www.trmlabs.com/resources/blog/north-korea-steals-usd-6-36-billion-from-binance-in-the-largest-hack-in-history), [CNBC](https://www.cnbc.com/2026/10/30/billions-in-crypto-frozen-in-binance-hack-heres-what-happens-next-.html), [CyberInsider](https://cyberinsider.com/binance-security-incident-6-3-billion/), [Bloomingbit](https://en.bloomingbit.io/feed/news/123338) e le specifiche [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702).

**Autore:** Canio Campaniello, fondatore di HackITA.it, il primo blog italiano dedicato esclusivamente all'offensive security (oltre 500 articoli). Lavora su Active Directory, web application security ed exploit development, ha esperienza di bug bounty e di laboratori di attacco, e sta seguendo il percorso OSCE3. [Profilo LinkedIn](https://www.linkedin.com/in/canio-campaniello-525152407).
