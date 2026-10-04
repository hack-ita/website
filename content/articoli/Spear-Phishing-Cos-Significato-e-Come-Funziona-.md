---
title: 'Spear Phishing: Cos''è ,Significato e Come Funziona '
slug: spear-phishing
description: 'Spear phishing: significato, cos''è, come funziona un attacco mirato e differenze dal phishing di massa, whaling e BEC, con un caso reale da 46 milioni.'
image: /spear-phishing-email-mirato-social-engineering.webp
draft: true
date: 2026-10-21T00:03:32.727Z
lastmod: 2026-10-21T00:03:33.955Z
categories:
  - guides-resources
subcategories:
  - concetti
tags:
  - Spear Phishing
  - Phishing Mirato
  - Social Engineering
  - OSINT
  - Email Phishing
---

# Spear Phishing: Come Funziona, Esempi e Come Difendersi

Lo **spear phishing** è una forma mirata di [phishing](https://hackita.it/articoli/phishing/): invece di inviare lo stesso messaggio generico a milioni di destinatari, l'attaccante studia una persona o un'organizzazione specifica e costruisce un messaggio su misura, usando dettagli reali per renderlo credibile. Il nome viene dalla pesca: non si lancia una rete (il phishing di massa), si colpisce un bersaglio preciso con un arpione.

È una tecnica a basso volume ma ad alto impatto: in un'analisi di Barracuda pubblicata nel 2023, le email di spear phishing rappresentavano meno dello **0,1%** del totale degli attacchi via email analizzati, ma risultavano collegate a circa il **66%** delle violazioni osservate nel campione studiato.

## Phishing e spear phishing: qual è la differenza?

Il phishing di massa punta sul volume: lo stesso messaggio a moltissime persone, sperando che una piccola percentuale abbocchi. Lo spear phishing punta sulla precisione: un messaggio costruito su misura per un bersaglio specifico, usando informazioni reali su di lui.

|                       | **Phishing di massa**                             | **Spear phishing**                             |
| --------------------- | ------------------------------------------------- | ---------------------------------------------- |
| **Destinatari**       | Migliaia o milioni, lo stesso messaggio per tutti | Una persona o un piccolo gruppo specifico      |
| **Personalizzazione** | Minima o assente                                  | Alta: nome, ruolo, azienda, contesto reale     |
| **Preparazione**      | Bassa                                             | Richiede ricognizione preventiva sul bersaglio |
| **Obiettivo tipico**  | Credenziali generiche, piccole somme              | Accessi mirati, grandi somme, dati sensibili   |

La differenza non è il canale o il contenuto in sé, ma lo **sforzo di ricognizione** che precede l'attacco.

## Come funziona un attacco di spear phishing

1. **Ricognizione (OSINT)**: l'attaccante raccoglie informazioni pubbliche sul bersaglio tramite LinkedIn, il sito aziendale, comunicati stampa, social network e, quando possibile, email trapelate in precedenti [data breach](https://hackita.it/articoli/data-breach/).
2. **Selezione del pretesto**: sceglie un contesto plausibile basato su ciò che ha scoperto: un progetto in corso, un fornitore reale, un evento aziendale, una relazione professionale.
3. **Costruzione del messaggio**: scrive un'email (o un messaggio su altro canale) che imita lo stile, il linguaggio e le informazioni che il bersaglio si aspetterebbe da quel mittente.
4. **Consegna**: invia il messaggio, spesso con un senso di urgenza o un'autorità percepita (un capo, un cliente, un collega fidato).
5. **Sfruttamento**: il click porta a un sito di raccolta credenziali, un allegato con malware, oppure il messaggio stesso chiede direttamente un'azione, come nel [Business Email Compromise](https://hackita.it/articoli/business-email-compromise/).

## Spear phishing, whaling e BEC: come si collegano

Questi tre termini vengono spesso confusi perché sono strettamente imparentati:

| Tipo                                                                                    | Bersaglio                                                       | Relazione con lo spear phishing                                                                              |
| --------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Spear phishing**                                                                      | Individui o ruoli specifici                                     | Il termine generale per qualsiasi phishing mirato                                                            |
| **Whaling**                                                                             | Dirigenti e membri del consiglio di amministrazione (*C-suite*) | Un sottoinsieme di spear phishing: stesso principio, bersagli di altissimo livello                           |
| **[Business Email Compromise](https://hackita.it/articoli/business-email-compromise/)** | Team finanziari, contabilità fornitori                          | Spesso usa lo spear phishing come vettore iniziale, ma punta specificamente a manipolare pagamenti aziendali |

In pratica: lo spear phishing è la tecnica, whaling e BEC sono applicazioni specifiche di quella tecnica verso bersagli o obiettivi particolari.

|                       | **Phishing**    | **Spear phishing** | **Whaling**                    | **BEC**                                      |
| --------------------- | --------------- | ------------------ | ------------------------------ | -------------------------------------------- |
| **Target**            | Ampio, generico | Specifico          | Dirigenti e C-suite            | Aziende, processi finanziari                 |
| **Personalizzazione** | Bassa           | Alta               | Alta                           | Alta                                         |
| **Categoria**         | Tecnica base    | Tecnica mirata     | Sottotipo dello spear phishing | Categoria di frode, può usare spear phishing |

## Perché lo spear phishing funziona così bene

* **Credibilità**: dettagli reali (nomi di colleghi, progetti in corso, eventi aziendali) abbassano le difese naturali della vittima.
* **Autorità percepita**: fingersi un superiore o un cliente importante riduce la propensione a mettere in discussione la richiesta.
* **Urgenza mirata**: a differenza di un'email di massa generica, il pretesto è calibrato sul contesto reale del bersaglio, quindi sembra più plausibile.
* **Bypassa i filtri tecnici**: un messaggio scritto ad hoc, senza pattern ripetuti su larga scala, è più difficile da intercettare per i sistemi antispam basati su firme o volumi.

I team finanziari e contabili risultano colpiti con una frequenza significativamente più alta rispetto ad altri reparti, proprio perché hanno l'autorità per autorizzare pagamenti: un bersaglio ad alto valore per chi punta a un guadagno economico diretto.

## Spear phishing e intelligenza artificiale

L'IA generativa ha cambiato l'economia dello spear phishing. Uno studio accademico di Heiding, Schneier e Vishwanath (2024), condotto su 101 partecipanti, ha confrontato diversi approcci:

| Gruppo testato                                  | Tasso di click |
| ----------------------------------------------- | -------------- |
| Phishing generico (controllo)                   | 12%            |
| Email scritte da esperti umani                  | 54%            |
| Email generate interamente da IA                | 54%            |
| IA con supervisione umana (*human-in-the-loop*) | 56%            |

Il dato interessante non è solo l'efficacia, pari a quella di un esperto umano, ma il **costo**: generare contenuti personalizzati su larga scala, un tempo compito di un operatore dedicato per ogni bersaglio, oggi richiede una frazione del tempo e del lavoro umano. È bene ricordare che si tratta di uno studio sperimentale su un campione specifico, non di un tasso medio universale valido per ogni campagna reale di spear phishing.

Questo significa che la barriera d'ingresso per campagne un tempo riservate a gruppi molto organizzati si è abbassata: ricognizione automatizzata dai profili social, generazione del testo, persino cloni vocali per rafforzare la credibilità in un secondo contatto telefonico (una tecnica che si intreccia con il [vishing](https://hackita.it/articoli/vishing/)).

## Un caso reale: Ubiquiti Networks, 46,7 milioni di dollari

Un esempio noto di quanto possa essere costosa l'impersonificazione mirata riguarda **Ubiquiti Networks**, azienda statunitense di networking: secondo quanto l'azienda ha dichiarato nei suoi documenti depositati presso la SEC, una frode per impersonificazione (classificata come *business email compromise*) ha portato dipendenti del reparto finanziario a trasferire fondi verso conti esteri controllati dai criminali, per un totale di circa **46,7 milioni di dollari**. Il caso mostra bene il punto chiave di un attacco mirato ben costruito: non è servito nessun malware sofisticato, solo ricognizione accurata e messaggi credibili verso le persone giuste.

## Come riconoscere un tentativo di spear phishing

| Segnale                                        | Perché deve insospettire                                                               |
| ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Richiesta insolita per il contesto**         | Anche se il mittente sembra legittimo, un'azione fuori dalla norma merita una verifica |
| **Urgenza abbinata a dettagli specifici**      | L'uso di informazioni reali non garantisce l'autenticità del messaggio                 |
| **Canale di risposta diverso dall'originale**  | "Rispondimi qui" con un indirizzo leggermente diverso da quello abituale               |
| **Pressione a bypassare le procedure normali** | "Non serve l'approvazione del tuo responsabile per questa volta"                       |
| **Dominio del mittente quasi identico**        | Un carattere diverso, un'estensione diversa, una lettera scambiata                     |

## Come difendersi dallo spear phishing

**A livello individuale:**

* verifica richieste insolite su un canale diverso da quello con cui sono arrivate (una telefonata a un numero noto, non quello nel messaggio);
* controlla sempre l'indirizzo email esatto del mittente, non solo il nome visualizzato;
* diffida di messaggi che spingono a bypassare procedure normali, anche se sembrano urgenti.

**A livello aziendale:**

* **autenticazione email** (SPF, DKIM, DMARC) per ridurre lo spoofing del dominio aziendale;
* **MFA** su tutti gli account, specialmente quelli con accesso a sistemi finanziari;
* **procedure a doppia approvazione** per bonifici e cambi di coordinate bancarie;
* **simulazioni mirate**, non solo formazione generica: testare scenari realistici su reparti ad alto rischio come finanza e contabilità;
* **limitare l'esposizione pubblica di informazioni sensibili** su organigrammi, ruoli e progetti in corso, che alimentano la ricognizione degli attaccanti.

## Domande frequenti sullo spear phishing

### Cos'è lo spear phishing?

Una forma di phishing mirata verso una persona o un'organizzazione specifica, costruita con dettagli reali raccolti in anticipo per renderla più credibile di un phishing generico.

### Qual è la differenza tra phishing e spear phishing?

Il phishing di massa invia lo stesso messaggio a molti destinatari sperando in pochi click. Lo spear phishing colpisce un bersaglio preciso con un messaggio personalizzato, con un tasso di successo molto più alto.

### Cos'è il whaling?

Una variante dello spear phishing che prende di mira specificamente dirigenti e membri del consiglio di amministrazione di un'azienda.

### Qual è la differenza tra spear phishing e BEC?

Il Business Email Compromise spesso usa lo spear phishing come tecnica iniziale, ma è specificamente orientato a manipolare pagamenti o processi aziendali, non solo a rubare credenziali.

### Perché lo spear phishing ha un tasso di successo così alto?

Perché usa dettagli reali sul bersaglio, raccolti in anticipo, che abbassano le difese naturali e rendono il messaggio molto più credibile rispetto a un'email generica.

### L'intelligenza artificiale ha reso lo spear phishing più pericoloso?

Sì. Uno studio accademico ha misurato un tasso di click del 54% per email di spear phishing generate da IA, alla pari con quelle scritte da esperti umani ma a una frazione del costo e del tempo.

### Chi viene preso di mira più spesso dallo spear phishing?

I team finanziari e contabili, gli esecutivi e chiunque abbia accesso a sistemi sensibili o autorità per approvare pagamenti.

### Come posso proteggermi dallo spear phishing?

Verifica le richieste insolite su un canale diverso da quello con cui sono arrivate, controlla sempre l'indirizzo email esatto del mittente, e nelle aziende usa MFA, autenticazione email e procedure a doppia approvazione per i pagamenti.

### Un messaggio personalizzato è sempre spear phishing?

No. La semplice personalizzazione non basta: lo spear phishing implica il targeting mirato di un bersaglio specifico e l'uso di informazioni contestuali reali per aumentare la credibilità dell'attacco, non solo l'inserimento di un nome in un modello di email.
