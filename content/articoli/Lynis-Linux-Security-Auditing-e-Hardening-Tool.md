---
title: 'Lynis: Linux Security Auditing e Hardening Tool'
slug: lynis
description: 'Lynis è uno strumento di auditing per sistemi Unix/Linux che analizza configurazioni, permessi, patch e hardening. Ideale per penetration tester e blue team.'
image: /Gemini_Generated_Image_yzklspyzklspyzkl.webp
draft: true
date: 2026-02-17T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - system-hardening
---

## Introduzione

Lynis è un tool di security auditing per sistemi Unix/Linux che analizza la configurazione del sistema operativo, identifica misconfiguration, suggerisce hardening e verifica compliance. Nel penetration testing lo usi in due contesti: post-exploitation per mappare le debolezze di un host compromesso e trovare path di privilege escalation, oppure in assessment di tipo white-box dove hai accesso legittimo al sistema.

Lynis controlla centinaia di test: permessi file, configurazione [SSH](https://hackita.it/articoli/ssh), firewall, kernel parameters, servizi in esecuzione, account policy, crittografia e molto altro. L'output è un hardening index (0-100) e una lista di finding categorizzati per severità.

Kill chain: **Discovery / Privilege Escalation** (MITRE ATT\&CK T1082).

***

## 1️⃣ Setup e Installazione

```bash
sudo apt install lynis
```

O da repository ufficiale:

```bash
git clone https://github.com/CISOfy/lynis.git
cd lynis
./lynis audit system
```

Verifica: `lynis --version`. Versione: 3.1.1.

***

## 2️⃣ Uso Base

```bash
sudo lynis audit system
```

Output (estratto):

```
[+] Boot and services
  - Checking presence GRUB2                       [ FOUND ]
  - Checking UEFI boot                            [ ENABLED ]

[+] Kernel
  - Checking default runlevel                     [ RUNLEVEL 5 ]
  - Checking kernel version and release           [ DONE ]

[+] Users, Groups and Authentication
  - Checking user password aging                  [ CONFIGURED ]
  - Query accounts without password               [ NONE ]
  - Checking sudo configuration file              [ FOUND ]

[+] SSH Support
  - Checking SSH configuration                    [ FOUND ]
  - SSH option: PermitRootLogin                   [ NO ]
  - SSH option: StrictModes                       [ YES ]

Hardening index : 72 [##############      ]
Tests performed : 283
```

**Quick audit:**

```bash
sudo lynis audit system --quick
```

Salta i prompt interattivi.

***

## 3️⃣ Tecniche Operative

### Audit di profilo specifico

```bash
sudo lynis audit system --profile custom.prf
```

### Report dettagliato

```bash
sudo lynis audit system --report-file /tmp/lynis_report.dat
cat /tmp/lynis_report.dat | grep "warning\|suggestion"
```

### Solo check specifici

```bash
sudo lynis audit system --tests-from-group "firewalls kernel ssh"
```

### Audit remoto (via SSH)

```bash
ssh root@target "cd /opt/lynis && ./lynis audit system --quick --no-colors" > remote_audit.txt
```

***

## 4️⃣ Tecniche Avanzate

### Post-exploitation — Trovare privilege escalation vectors

Dopo aver ottenuto shell:

```bash
./lynis audit system --quick 2>/dev/null | grep -E "WARNING|SUGGESTION|SUID"
```

Focus su: SUID binary insoliti, sudo misconfiguration, servizi con permessi eccessivi, kernel vulnerabile.

### Custom test plugins

Lynis supporta plugin custom in `/usr/share/lynis/plugins/`. Scrivi test specifici per l'ambiente target.

***

## 5️⃣ Scenari Pratici di Pentest

### Scenario 1: White-box audit di un server

```bash
sudo lynis audit system --quick
```

**Output atteso:** hardening index, warning e suggestion. **Timeline:** 1-2 minuti.

### Scenario 2: Post-exploitation privesc recon

```bash
curl -sO https://raw.githubusercontent.com/CISOfy/lynis/master/lynis
chmod +x lynis
./lynis audit system --quick --no-colors 2>/dev/null | grep -i "warning"
```

### Scenario 3: Compliance check

```bash
sudo lynis audit system --profile /etc/lynis/default.prf
```

***

## 6️⃣ Toolchain Integration

**Flusso post-exploitation:** Shell → **Lynis (system audit)** → linPEAS (privesc enum) → Exploit privesc

| Tool                                                 | System audit  | Privesc hints | Compliance | Agentless |
| ---------------------------------------------------- | ------------- | ------------- | ---------- | --------- |
| Lynis                                                | Sì (completo) | Sì            | Sì         | Sì        |
| [linPEAS](https://hackita.it/articoli/linpeas)       | Limitato      | Sì (focus)    | No         | Sì        |
| [Chkrootkit](https://hackita.it/articoli/chkrootkit) | Rootkit only  | No            | No         | Sì        |
| OpenSCAP                                             | Sì            | Limitato      | Sì (SCAP)  | No        |

***

## 7️⃣ Attack Chain Completa

**Fase 1:** Shell come www-data → upload Lynis (30 sec). **Fase 2:** Lynis trova SUID su custom binary (2 min). **Fase 3:** Exploit SUID → root (5 min). **Timeline:** \~8 min.

***

## 8️⃣ Detection & Evasion

**Blue Team:** process monitoring vede `lynis` in esecuzione. File access audit. **Evasion:** rinomina binary, esegui da /tmp, rimuovi dopo.

***

## 9️⃣ Performance & Scaling

Single host: 1-2 minuti. Consumo: \<50MB RAM.

***

## 🔟 Tabelle Tecniche

| Flag                 | Descrizione      |
| -------------------- | ---------------- |
| `audit system`       | Audit completo   |
| `--quick`            | No prompt        |
| `--profile file`     | Profilo custom   |
| `--report-file`      | Report output    |
| `--tests-from-group` | Gruppi specifici |
| `--no-colors`        | Output plain     |

***

## 11️⃣ Troubleshooting

| Problema          | Fix                      |
| ----------------- | ------------------------ |
| Permission denied | Esegui come root/sudo    |
| Test skipped      | Dipendenze tool mancanti |

***

## 12️⃣ FAQ

**Lynis trova privesc?** Indirettamente — segnala misconfiguration che possono essere exploitate.

**Funziona su macOS?** Sì, parzialmente.

***

## 13️⃣ Cheat Sheet

| Azione          | Comando                                                   |
| --------------- | --------------------------------------------------------- |
| Audit rapido    | `sudo lynis audit system --quick`                         |
| Con report      | `sudo lynis audit system --report-file report.dat`        |
| Solo SSH/kernel | `sudo lynis audit system --tests-from-group "ssh kernel"` |
| Remoto          | `ssh target "lynis audit system --quick --no-colors"`     |

***

**Disclaimer:** Lynis per security assessment autorizzato. Repository: [github.com/CISOfy/lynis](https://github.com/CISOfy/lynis).

***

Vuoi supportare HackIta? Visita [hackita.it/supporto](https://hackita.it/supporto) per donazioni. Per penetration test professionali e formazione 1:1, scopri [hackita.it/servizi](https://hackita.it/servizi).
