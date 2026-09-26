---
title: 'OAuth 2.0: Token, Scope e Rischi dei Tool Terzi | HackITA'
slug: oauth-security
description: 'Come funziona OAuth 2.0, cosa sono scope e access token, e come proteggere gli account social aziendali dal furto di token nei tool di terze parti.'
image: /oauth-2-0-token-scope-rischi.webp
draft: false
date: 2026-09-21T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - OAuth
  - Access Token
  - API Security
  - Autenticazione
  - Social Engineering
---

# OAuth 2.0: Come Funzionano Token, Scope e Rischi

OAuth 2.0 è il protocollo che entra in gioco ogni volta che colleghi un tool esterno al tuo account LinkedIn, Facebook o Instagram. Autorizzarlo è molto più che un semplice click di conferma: stai concedendo un access token che, a seconda dei permessi richiesti, può consentire operazioni sensibili sull'account — spesso senza dover ripetere l'autenticazione ogni volta.

**In breve**: OAuth 2.0 permette a un'applicazione di ottenere accesso delegato alle risorse di un utente senza conoscerne la password. L'access token rappresenta questa autorizzazione, e il suo potere reale dipende da scope, durata e controlli applicati dal sistema che lo emette e dalle API che lo accettano.

## Cos'è OAuth 2.0?

OAuth 2.0 è il protocollo standard che permette a un'applicazione di terze parti di accedere a risorse per conto di un utente, senza che l'utente condivida direttamente la propria password con quell'applicazione. Invece della password, l'app riceve un **access token** con uno scope (permessi) definito.

## Come funziona OAuth con i social network?

Il flusso tipico è:

`Utente → autorizza l'app → Authorization Server (es. LinkedIn/Meta) → Access Token → chiamate API`

| Elemento             | Funzione                                  |
| -------------------- | ----------------------------------------- |
| Resource Owner       | L'utente che concede l'accesso            |
| Client               | Il tool di terze parti                    |
| Authorization Server | La piattaforma (LinkedIn, Facebook, ecc.) |
| Access Token         | La credenziale usata per le chiamate API  |
| Scope                | I permessi effettivamente concessi        |

## Cosa sono gli OAuth Scope?

Gli scope definiscono esattamente quali operazioni un'app può compiere per conto dell'utente: lettura profilo, lettura post, pubblicazione, gestione pagine, lettura messaggi. Concettualmente: `read_profile`, `publish_posts`, `manage_pages` (i nomi reali variano da piattaforma a piattaforma).

In generale, più privilegi vengono concessi a un access token, maggiore può essere l'impatto di una sua compromissione. Le capacità effettivamente disponibili dipendono comunque dalle API e dai permessi specifici della piattaforma: OAuth 2.0 definisce il meccanismo di delega, non un insieme universale di scope come `publish_posts` o `manage_pages`.

## Perché i tool di terze parti rappresentano un rischio?

I tool di social media management e content automation uniscono spesso due fattori: **permessi di pubblicazione ampi** e **connessione a più account/piattaforme contemporaneamente** da un'unica dashboard. Questo li rende un bersaglio interessante — comprometterne uno può significare accesso a molteplici canali aziendali in un colpo solo.

Un esempio di categoria sono i tool AI per la generazione di contenuti social, come i [generatori di carousel per LinkedIn](https://predis.ai/use-cases/linkedin-carousel-maker/): strumenti che, a seconda dell'integrazione, richiedono permessi di pubblicazione sulla pagina aziendale collegata.

## Cosa succede se un access token viene rubato?

Qui serve precisione tecnica: **un access token non equivale automaticamente alla password**. Il suo impatto reale dipende dagli scope concessi, dalla durata di validità, dalla possibilità di revoca e dalle API a cui dà accesso.

| Scope compromesso | Possibile impatto                       |
| ----------------- | --------------------------------------- |
| Lettura profilo   | Furto informazioni                      |
| Lettura dati      | Data exposure                           |
| Pubblicazione     | Post malevoli a nome dell'azienda       |
| Messaggi          | Phishing lanciato dall'account          |
| Gestione pagine   | Compromissione della presenza aziendale |

## Come può essere compromesso un OAuth token?

| Vettore                      | Cosa succede                                                                                                                                                                             |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Token leakage                | Il token finisce in log, URL o storage non protetto                                                                                                                                      |
| Consent phishing             | L'utente autorizza un'applicazione malevola pensando sia legittima                                                                                                                       |
| Redirect URI mal configurata | Facilita il furto dell'authorization code/token                                                                                                                                          |
| Compromissione del client    | L'attaccante ottiene accesso al sistema che gestisce i token, scenario vicino a un classico [session hijacking](https://hackita.it/articoli/session-hijacking/) applicato ai token OAuth |
| Supply chain                 | Il fornitore del tool stesso viene compromesso                                                                                                                                           |

Per i meccanismi di attacco specifici al protocollo, li abbiamo trattati in dettaglio nel nostro [approfondimento su OAuth Attack](https://hackita.it/articoli/oauth-attack/).

## OAuth token vs password: qual è la differenza?

| Credenziale        | Caratteristica                                           |
| ------------------ | -------------------------------------------------------- |
| Password           | Autentica direttamente l'utente                          |
| API key            | Identifica/autorizza un'applicazione                     |
| OAuth access token | Concede accesso delegato e limitato a risorse specifiche |

OAuth non serve a "dare la password a un'app" — serve a delegare un accesso limitato senza condividerla mai.

## Scenario di compromissione

```
ADMIN
  │ autorizza
  ▼
TOOL DI TERZE PARTI
  │ riceve access token
  ▼
LINKEDIN / META (API)
  │
  ▼
POST / MESSAGGI / DATI ESPOSTI
```

1. L'amministratore collega il tool al proprio account social
2. Il tool riceve un access token con scope definiti
3. Il sistema che conserva il token viene compromesso (malware, breach lato fornitore, credenziali rubate)
4. L'attaccante usa il token per interagire con le API entro gli scope concessi
5. L'azienda si accorge dell'anomalia, revoca il token e rimuove l'integrazione

Questo tipo di scenario riguarda in generale qualunque strumento con accesso diretto ad account social e pubblicazione automatica, come un [generatore di post social](https://predis.ai/ai-social-media-post-generator/) collegato a più piattaforme. Il punto non è evitare questi strumenti, che restano utili, ma trattare l'autorizzazione come un accesso da monitorare nel tempo — non diversamente da come si tratterebbe un tentativo di [phishing](https://hackita.it/articoli/phishing-techniques-red-team/) mirato all'account aziendale.

## Come proteggere gli account aziendali

Checklist rapida se gestisci account aziendali collegati a tool OAuth:

* **Verifica periodicamente le app collegate**: LinkedIn (Impostazioni → App connesse), Facebook Business Settings → Integrazioni
* **Revoca gli accessi ai tool non più in uso**: un token dimenticato è un token che nessuno controlla
* **Limita gli scope in fase di collegamento**, quando la piattaforma lo consente
* **Usa account dedicati** per i tool di terze parti, separati dall'account amministratore principale
* **Attiva l'MFA sull'account principale** e monitora eventuali attività anomale

## OAuth Security: best practice

1. Principio del minimo privilegio sugli scope richiesti
2. Revoca periodica dei token inutilizzati
3. Rotazione dei token dove applicabile
4. Protezione dei refresh token
5. Uso di PKCE nei flussi pubblici (app senza client secret)
6. Redirect URI configurate in modo preciso, mai wildcard
7. Monitoraggio costante delle applicazioni autorizzate

Queste raccomandazioni seguono le linee guida della RFC 9700 dell'IETF (gennaio 2025), il riferimento tecnico più aggiornato sulla sicurezza dei flussi OAuth 2.0.

## FAQ: OAuth e Access Token

**Cos'è un OAuth token?**
Un access token OAuth è una credenziale che consente a un'applicazione di accedere a determinate risorse per conto dell'utente, entro i privilegi (scope) concessi.

**Un OAuth token è come una password?**
Non esattamente. Il token concede accesso senza rivelare la password, ma se rubato può essere usato entro i privilegi e la durata previsti dal token stesso.

**OAuth bypassa l'MFA?**
Non propriamente. Un token già valido può permettere richieste API senza ripetere l'autenticazione, perché login e consenso sono già avvenuti durante il flusso OAuth iniziale — l'MFA non viene "bypassata", semplicemente non serve rifarla per ogni chiamata successiva al token.

**Cosa succede se un access token viene rubato?**
L'impatto dipende dagli scope concessi e dalle risorse a cui il token permette di accedere — non è un impatto uniforme o automaticamente totale.

**Come posso proteggere i miei OAuth token?**
Limitando gli scope richiesti, revocando le autorizzazioni inutilizzate, e monitorando periodicamente le app collegate ai tuoi account social.
