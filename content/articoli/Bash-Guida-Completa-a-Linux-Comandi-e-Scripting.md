---
title: 'Bash: Guida Completa a Linux, Comandi e Scripting'
slug: bash
description: >-
  Cos'è Bash e come funziona? Scopri comandi, variabili, pipe, permessi e
  scripting Bash con una guida pratica da zero, pensata per Linux e
  cybersecurity.
image: /bash-linux-guida-completa.webp
draft: false
date: 2026-09-14T00:00:00.000Z
categories:
  - linux
subcategories:
  - filesystem
tags:
  - bash
  - shell
  - linux
  - terminale
  - sysadmin
---

# Bash: Guida Completa a Comandi e Scripting Linux

Bash è la shell che interpreta ed esegue i comandi digitati nel terminale su Linux e sistemi Unix-like. Permette di navigare nel filesystem, gestire file e processi, usare variabili, concatenare comandi e automatizzare attività attraverso script. È una delle competenze base per amministrazione di sistema, DevOps e sicurezza informatica.

Questa guida ti porta da zero a un livello solido: sintassi, scripting, gestione degli errori, e perché chi fa ethical hacking non può farne a meno.

**In questa guida**

1. Bash, shell e terminale: la differenza
2. Bash vs sh, Zsh, Fish
3. Il prompt
4. Comandi base
5. Variabili
6. Quoting
7. Redirezione, pipe e stdin/stdout/stderr
8. Operatori di controllo: `&&`, `||`, `;`
9. Permessi dei file
10. Condizionali
11. Cicli
12. Funzioni
13. Scrivere ed eseguire uno script
14. Exit code e gestione degli errori
15. `trap`
16. Best practice per gli script Bash
17. Bash e cybersecurity
18. FAQ
19. Come continuare a studiare

## Bash, shell e terminale: la differenza

Sono tre livelli distinti, e confonderli è l'errore più comune per chi inizia.

```text
Tu
 ↓
Terminale (interfaccia)
 ↓
Bash (shell/interprete)
 ↓
Kernel Linux
 ↓
Hardware
```

* **Terminale**: la finestra dove digiti. È solo l'interfaccia grafica (terminal emulator).
* **Shell**: il programma che interpreta i comandi che scrivi. Bash è una shell tra le tante.
* **Bash**: sta per Bourne Again SHell. Fa da intermediario tra te e il sistema operativo: tu scrivi testo, lei lo interpreta e la esegue chiamando il kernel.

## Bash vs sh, Zsh, Fish

Bash non è sinonimo di Linux, ed è una delle shell disponibili, non l'unica.

| Shell | Caratteristica principale                                             |
| ----- | --------------------------------------------------------------------- |
| sh    | Shell Unix storica, base dello standard POSIX                         |
| Bash  | Ampia compatibilità, diffusione e scripting maturo                    |
| Zsh   | Interattività avanzata e personalizzazione (default su macOS moderno) |
| Fish  | Sintassi moderna orientata alla facilità d'uso                        |

Bash resta una delle shell più diffuse nell'ecosistema Linux ed è stata a lungo la scelta predefinita in molte distribuzioni, ma quale shell è attiva di default dipende dalla distribuzione e dalla configurazione del sistema — non va data per scontata.

## Il prompt: come leggerlo

Quando apri un terminale vedi qualcosa tipo:

```bash
utente@hackita:~$
```

Si legge: `utente@nomehost:cartella-corrente$`. Il `$` finale indica un utente normale. Se vedi `#` al posto di `$`, sei root, l'amministratore con pieni poteri sul sistema.

## Comandi base

Un comando Bash ha questa struttura:

```bash
comando [opzioni] [argomenti]
```

Esempio:

```bash
ls -la /home
```

* `ls` è il comando (lista file e cartelle)
* `-la` sono le opzioni (mostra tutto, formato lungo)
* `/home` è l'argomento (dove guardare)

Comandi che userai ogni giorno:

```bash
pwd              # mostra la cartella in cui ti trovi
cd cartella      # entra in una cartella
ls               # elenca file e cartelle
cat file.txt     # mostra il contenuto di un file
mkdir nuova      # crea una cartella
rm file.txt      # elimina un file
cp a.txt b.txt   # copia
mv a.txt b.txt   # sposta/rinomina
```

Bash non insegna da sola i comandi: li interpreta. Una volta capita la logica delle pipe e della composizione, sequenze come questa diventano naturali:

```bash
grep "error" logfile.txt | sort | uniq -c
find /var/log -type f -name "*.log"
```

Il modello mentale Unix è sempre lo stesso: tanti piccoli strumenti, combinati con `|`, per ottenere un risultato complesso. Per l'elenco completo dei comandi più usati vedi [top 100 comandi Linux](https://hackita.it/articoli/top-100-comandi-linux/).

## Variabili

Si assegnano senza spazi intorno al segno `=`:

```bash
nome="Hackita"
echo $nome
```

Il `$` davanti al nome serve per **leggere** il valore. Senza `$` stai solo nominando la variabile.

Bash ha anche variabili d'ambiente già pronte:

```bash
echo $HOME    # la tua cartella home
echo $PATH    # dove Bash cerca gli eseguibili
echo $USER    # il tuo nome utente
```

`$PATH` è la lista di cartelle in cui Bash cerca un binario quando digiti un comando. Se scrivi `nmap` e funziona, è perché l'eseguibile si trova in una delle cartelle elencate in `$PATH`.

## Quoting: virgolette singole, doppie e niente

Punto su cui quasi tutti inciampano all'inizio.

```bash
nome="Hackita"
echo "Ciao $nome"     # Ciao Hackita -> la variabile viene espansa
echo 'Ciao $nome'     # Ciao $nome -> testo letterale, niente espansione
echo Ciao $nome       # funziona ma è rischioso con spazi/caratteri speciali
```

Regola pratica: usa sempre `"$variabile"` con le doppie virgolette, specialmente con percorsi o input esterno. Lasciare una variabile senza quoting è una delle cause più comuni di script che si rompono su spazi o caratteri speciali — o che, nel peggiore dei casi, eseguono un comando diverso da quello previsto.

## Redirezione, pipe e stdin/stdout/stderr

Ogni processo Bash ha tre canali di comunicazione, identificati da un numero:

```text
stdin  → 0  (input)
stdout → 1  (output normale)
stderr → 2  (output di errore)
```

Comandi di redirezione:

```bash
ls > lista.txt        # salva stdout in un file (sovrascrive)
ls >> lista.txt        # aggiunge stdout alla fine del file
cat < lista.txt         # legge il file come input (stdin)
comando1 | comando2     # passa stdout di comando1 come stdin a comando2
```

Puoi anche gestire i canali separatamente:

```bash
comando > output.txt          # solo stdout nel file
comando 2> errori.txt          # solo stderr nel file
comando > output.txt 2>&1      # sia stdout che stderr nello stesso file
comando 2>/dev/null             # scarta gli errori
```

Esempio pratico:

```bash
cat /etc/passwd | grep bash
```

Si legge: "mostrami il contenuto di /etc/passwd, poi filtra solo le righe che contengono 'bash'".

## Operatori di controllo: `&&`, `||`, `;`

Servono a concatenare comandi in base al loro esito:

```bash
comando1 && comando2   # esegue comando2 solo se comando1 ha successo
comando1 || comando2   # esegue comando2 solo se comando1 fallisce
comando1 ; comando2    # esegue entrambi, indipendentemente dal risultato del primo
```

Questi operatori si collegano direttamente al concetto di exit code, spiegato più avanti.

## Permessi dei file

Ogni file in Linux ha permessi di lettura (r), scrittura (w) ed esecuzione (x), assegnati a proprietario, gruppo e altri utenti.

```bash
ls -l file.sh
-rwxr-xr-- 1 utente utente 220 set 13 10:00 file.sh
```

Si legge: proprietario può leggere/scrivere/eseguire, gruppo può leggere/eseguire, altri solo leggere.

Per modificarli:

```bash
chmod +x script.sh            # rendi eseguibile
chmod 750 script.sh            # permessi numerici precisi
chown utente:gruppo file.sh    # cambia proprietario
```

I permessi non sono un dettaglio burocratico: una configurazione troppo permissiva su uno script eseguito da root è una delle porte d'ingresso più comuni per l'escalation di privilegi. Guida completa: [privilege escalation Linux](https://hackita.it/articoli/linux-privesc/).

## Condizionali

```bash
if [[ -f "$file" ]]; then
    echo "Il file esiste"
else
    echo "Il file non esiste"
fi
```

Test comuni: `-f` (è un file), `-d` (è una cartella), `-x` (è eseguibile), `-z` (stringa vuota), `-eq`/`-ne` (uguale/diverso tra numeri).

Nota su `[[ ]]` vs `[ ]`: `[ ]` è il test POSIX classico, `[[ ]]` è un'estensione di Bash con sintassi più robusta (niente problemi di quoting con variabili vuote, supporto a `&&`/`||` interni). Negli script Bash, preferisci `[[ ]]`.

## Cicli

```bash
for i in 1 2 3; do
    echo "Numero: $i"
done
```

```bash
while [[ $contatore -lt 5 ]]; do
    echo $contatore
    contatore=$((contatore + 1))
done
```

## Funzioni

```bash
saluta() {
    local nome="$1"
    echo "Ciao $nome"
}

saluta "Hackita"
```

`$1` è il primo argomento passato alla funzione, `$2`/`$3` seguono la stessa logica, `$@` rappresenta tutti gli argomenti insieme. `local` limita la variabile allo scope della funzione, evitando che sporchi l'ambiente globale dello script.

## Scrivere ed eseguire uno script

Uno script è un file di testo, tipicamente con estensione `.sh`, che contiene una sequenza di comandi.

```bash
#!/usr/bin/env bash
# Questo script stampa la data e i file nella cartella corrente

echo "Oggi è: $(date)"
ls
```

La prima riga (`#!/usr/bin/env bash`) è lo **shebang**: dice al sistema quale interprete usare per eseguire il file.

Per lanciarlo:

```bash
chmod +x mioscript.sh
./mioscript.sh
```

## Exit code e gestione degli errori

Ogni processo, quando termina, restituisce uno status di uscita: convenzionalmente `0` indica successo, un valore diverso da `0` indica una condizione di errore o comunque un esito non riuscito secondo il programma.

```bash
ls /cartella/inesistente
echo $?
```

`$?` mostra l'exit code dell'ultimo comando eseguito. È utile non solo per debug, ma per far reagire lo script a un fallimento:

```bash
if ! cp "$origine" "$destinazione"; then
    echo "Errore durante la copia" >&2
    exit 1
fi
```

Molto più utile del semplice controllo manuale di `$?` dopo ogni comando.

## `trap`

`trap` esegue un'azione quando lo script riceve un segnale o termina, utile per pulire file temporanei o gestire un'interruzione forzata (es. Ctrl+C):

```bash
cleanup() {
    rm -f "$tmpfile"
}

trap cleanup EXIT
```

## Best practice per gli script Bash

Qualche accorgimento che alza parecchio l'affidabilità di uno script:

```bash
#!/usr/bin/env bash
set -euo pipefail
```

* `set -e`: interrompe lo script al primo comando che fallisce
* `set -u`: interrompe lo script se usi una variabile non definita
* `set -o pipefail`: fa fallire una pipe se fallisce un qualsiasi comando al suo interno, non solo l'ultimo

Altri accorgimenti:

```bash
readonly COSTANTE="valore"   # variabile non modificabile
local variabile              # variabile locale a una funzione

if [[ $# -lt 1 ]]; then
    echo "Uso: $0 <file>"
    exit 1
fi
```

E, come già detto: quota sempre le variabili con `"$variabile"`.

Prima di considerare uno script pronto, vale la pena passarlo attraverso [ShellCheck](https://www.shellcheck.net/), un analizzatore statico che individua automaticamente errori di quoting, variabili non usate e altre insidie comuni negli script Bash.

## Bash e cybersecurity

Bash non è solo comodità per sysadmin. In un contesto offensivo — sempre su lab autorizzati come HackTheBox o ambienti di test per cui si ha un'autorizzazione esplicita — Bash entra in gioco in diversi momenti:

**Automazione dell'enumerazione.** Script Bash per lanciare in sequenza scansioni, raccogliere output e filtrarlo automaticamente, invece di ripetere comandi a mano.

**Analisi di file e log.** Pipe con `grep`, `sort`, `uniq`, `awk` per estrarre informazioni utili da log e file di configurazione durante un'analisi post-exploitation.

**Gestione di processi e permessi.** Capire permessi e proprietà dei file è alla base della ricerca di vettori di privilege escalation.

**LOLBins e binari con permessi elevati.** Molti binari che invocano una shell al loro interno, se eseguiti con privilegi elevati (es. via sudo o SUID), permettono di ottenere una shell privilegiata. Esempi concreti su [GTFOBins](https://gtfobins.org/).

**Cron job mal configurati.** Script Bash lanciati da root via cron, con variabili non quotate o path relativi, sono una fonte concreta di vulnerabilità reali. Approfondimento su [crontab](https://hackita.it/articoli/crontab/).

**Reverse shell.** Diverse reverse shell one-liner sfruttano la redirezione dei file descriptor di Bash per aprire una connessione verso una macchina attaccante.

Le tecniche di command execution e reverse shell vanno utilizzate esclusivamente su sistemi propri o su ambienti per i quali si dispone di un'autorizzazione esplicita.

## FAQ su Bash

**Bash è un linguaggio di programmazione?**
Bash è principalmente una shell, ma include funzionalità — variabili, condizioni, cicli, funzioni, gestione degli errori — che permettono di scrivere veri e propri script.

**Bash è uguale al terminale?**
No. Il terminale è l'interfaccia attraverso cui interagisci con una shell. Bash è una delle shell che puoi eseguire all'interno del terminale.

**Bash funziona solo su Linux?**
No. È disponibile su diversi sistemi Unix-like e può essere usata anche su macOS e, tramite ambienti dedicati, su Windows.

**A cosa serve Bash?**
A eseguire comandi, amministrare sistemi, manipolare file, automatizzare attività e scrivere script.

**Bash è difficile da imparare?**
I comandi fondamentali sono relativamente semplici. La parte più complessa arriva con quoting, redirezione, gestione dei processi ed errori, e scripting avanzato.

**Bash serve per l'ethical hacking?**
Sì, soprattutto per automazione, enumerazione e scripting durante attività di sicurezza autorizzate.

## Come continuare a studiare

```text
Terminale
   ↓
File e directory
   ↓
Pipe e redirezione
   ↓
Variabili e quoting
   ↓
Condizioni e cicli
   ↓
Funzioni
   ↓
Exit code e gestione errori
   ↓
Scripting avanzato
   ↓
Bash e sicurezza
```

Da qui, i passi naturali sono approfondire i [100 comandi Linux più usati](https://hackita.it/articoli/top-100-comandi-linux/), capire come [privilege escalation Linux](https://hackita.it/articoli/linux-privesc/) sfrutta spesso proprio script e permessi mal configurati, e studiare [GTFOBins](https://hackita.it/articoli/gtfobins/) e [crontab](https://hackita.it/articoli/crontab/) per vedere Bash applicata concretamente in un contesto offensivo.
