# Top opportunities (P0 + P1)

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

`current position` / `impressions`: DATA NOT AVAILABLE for every row (no GSC/SERP access here).

## P0 — critical (9)

Correctness issues with direct SERP impact. Fix first.

| Article | Intent (inferred) | Primary keyword (inferred) | Weaknesses | Action | Priority |
| --- | --- | --- | --- | --- | --- |
| `/articoli/cache-poisoning/` | informational/educational | Web Cache Poisoning | thin-intro, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/hackita/` | informational/educational | HackIta | title-too-long, brand-duplicated-in-title, first-heading-near-title, no-external-citations, no-contextual-inbound-links, links-to-unpublished-article | Remove the duplicated brand token from the source title | P0 |
| `/articoli/injection-attacks-guida-completa/` | informational/definition | Injection Attack | first-heading-near-title, links-to-unpublished-article, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/lazagne/` | tool-oriented/how-to | LaZagne | links-to-unpublished-article, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/ldapsearch/` | tool-oriented/how-to | ldapsearch | thin-intro, no-external-citations, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/mitmproxy/` | tool-oriented/how-to | Mitmproxy | title-too-long, thin-intro, links-to-unpublished-article, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/oauth-security/` | informational/educational | OAuth 2.0 | brand-duplicated-in-title, first-heading-near-title, no-contextual-inbound-links | Remove the duplicated brand token from the source title | P0 |
| `/articoli/smbexec/` | tool-oriented/how-to | SMBExec | links-to-unpublished-article, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| `/articoli/sshuttle/` | informational/educational | Sshuttle | title-too-long, duplicate-slug-cannibalization | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |


## P1 — high (91)

Over-long title combined with a thin intro or missing citations — surgical, high-upside.

| Article | Intent (inferred) | Primary keyword (inferred) | Weaknesses | Action | Priority |
| --- | --- | --- | --- | --- | --- |
| `/articoli/adcs-eku-oid-offensive/` | informational/definition | EKU OID in ADCS | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/api-modern-web-attacks-guida-completa/` | informational/definition | API Security | title-too-long, thin-intro, topic-not-in-first-100-words | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/api-rate-limit-bypass/` | informational/educational | API Rate Limit Bypass | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/api-versioning-attacck/` | informational/educational | API Versioning Attack | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/arbitrary-file-read/` | informational/definition | Arbitrary File Read | title-too-long, first-heading-near-title, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/attacchi-applicazioni-web/` | informational/definition | Attacchi alle Applicazioni Web | title-too-long, topic-not-in-first-100-words, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/aws-privilege-escalation/` | informational/educational | AWS Privilege Escalation | title-too-long, no-external-citations, no-related-block | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/blind-sql-injection/` | informational/definition | Blind SQL Injection | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/brute-force/` | informational/educational | Brute Force Attack | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/copy-fail/` | vulnerability/CVE | CVE-2026-31431 | title-too-long, first-heading-repeats-title, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/crontab/` | informational/educational | Crontab Backdoor | title-too-long, first-heading-repeats-title, thin-intro, no-related-block | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/dcsync/` | informational/educational | DCSync | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/deserialization-attack/` | informational/service-enumeration | Deserialization Attack | title-too-long, thin-intro, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/dom-xss/` | tutorial/how-to | DOM XSS | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/esc4-adcs/` | informational/educational | ESC4 ADCS Privilege Escalation | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/esc9-adcs/` | informational/educational | ESC9 ADCS | title-too-long, thin-intro, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/ettercap/` | tool-oriented/how-to | Ettercap | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/exploitdb/` | informational/educational | Exploit-DB | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/expression-language-injection/` | informational/educational | Expression Language Injection | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/fail2ban/` | informational/educational | Fail2Ban Privilege Escalation | title-too-long, first-heading-near-title, thin-intro, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/feroxbuster/` | informational/educational | Feroxbuster | title-too-long, first-heading-near-title, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/getcap/` | informational/educational | Getcap | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/ics-ot-entesting/` | informational/definition | ICS/OT pentesting | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/idor/` | tutorial/how-to | IDOR | title-too-long, thin-intro, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/jtag/` | tutorial/how-to | JTAG | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/jwt/` | informational/definition | 10 Attacchi JWT per Ethical Hacker | title-too-long, first-heading-repeats-title, thin-intro, topic-not-in-first-100-words, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/kerberoasting/` | informational/definition | Kerberoasting | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/kerberos/` | informational/educational | Kerberos Attacchi Active Directory | title-too-long, thin-intro, topic-not-in-first-100-words, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/ldap-injection/` | informational/educational | LDAP Injection | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/lfi/` | informational/educational | LFI | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/logon-type-windows/` | informational/definition | Logon Type Windows | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/lolbins/` | informational/definition | LOLBins, GTFOBins e LOOBins | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/mimipenguin/` | informational/educational | Mimipenguin | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/misc-infra-attacks-guida-completa/` | informational/definition | Misc & Infrastructure Attacks | title-too-long, topic-not-in-first-100-words, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/nikto/` | informational/educational | Nikto | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/nosql-injection/` | informational/definition | NoSQL Injection | title-too-long, first-heading-near-title, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/ntlm/` | informational/educational | NTLM | title-too-long, thin-intro, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/nuclei/` | informational/educational | Nuclei | title-too-long, thin-intro, meta-description-short | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/open-redirect/` | tutorial/how-to | Open Redirect | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/os-command-injection/` | informational/definition | OS Command Injection | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/osquery/` | tool-oriented/how-to | Osquery | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/pass-the-hash/` | informational/educational | Pass-the-Hash Windows | title-too-long, first-heading-near-title, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/path-traversal/` | informational/definition | Path Traversal | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/pivoting/` | informational/definition | Pivoting nel Pentest | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-1025-ms-rpc/` | informational/service-enumeration | Porta 1025 MS RPC | title-too-long, topic-not-in-first-100-words, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-16010-hbase/` | informational/service-enumeration | Porta 16010 HBase | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-1604-citrix-ica/` | informational/service-enumeration | Porta 1604 Citrix ICA | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-162-snmptrap/` | informational/service-enumeration | Porta 162 SNMP Trap | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-179-bgp/` | informational/service-enumeration | Porta 179 BGP | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-199-smux/` | informational/service-enumeration | Porta 199 SMUX | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-27018-mongodb-cluster/` | informational/service-enumeration | Porta 27018 MongoDB Cluster | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-28017-mongodb-http/` | informational/service-enumeration | Porta 28017 MongoDB HTTP | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-3128-squid-proxy/` | informational/service-enumeration | Porta 3128 Squid Proxy | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-3306-mysql/` | informational/service-enumeration | MySQL Porta 3306 | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-3389-rdp/` | informational/service-enumeration | Porta 3389 RDP | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-389-ldap/` | informational/service-enumeration | LDAP 389 | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-443-https/` | informational/service-enumeration | Porta 443 HTTPS | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-465-smtps/` | informational/service-enumeration | Porta 465 SMTPS | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-50000-sap/` | informational/service-enumeration | Porta 50000 SAP NetWeaver | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-50070-hadoop-namenode/` | informational/service-enumeration | Porta 50070 Hadoop NameNode | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-513-rlogin/` | informational/service-enumeration | Porta 513 Rlogin | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-8080-tomcat/` | informational/service-enumeration | Porta 8080 TCP | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-90-pointcast/` | informational/service-enumeration | Porta 90 PointCast | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-9418-git/` | informational/service-enumeration | Porta 9418 Git Daemon | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-95-supdup/` | informational/service-enumeration | Porta 95 SUPDUP | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-989-ftps-data/` | informational/service-enumeration | Porta 989 FTPS-Data | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porta-9999-abyss-dev/` | vulnerability/CVE | Porta 9999 Pentest | title-too-long, topic-not-in-first-100-words, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/porte-tcp-udp-pentest/` | informational/definition | Porte TCP/UDP nel Penetration Testing | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/privilege-escalation-web/` | informational/educational | Privilege Escalation Web | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/race-condition/` | informational/educational | Race Condition Web | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/reflected-xss/` | tutorial/how-to | Reflected XSS | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/rfi/` | informational/educational | Remote File Inclusion | title-too-long, topic-not-in-first-100-words, no-external-citations, meta-description-short, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/s3scanner/` | informational/educational | S3Scanner | title-too-long, thin-intro, meta-description-short | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/seassignprimarytokenprivilege/` | informational/educational | SeAssignPrimaryTokenPrivilege | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/semanagevolumeprivilege/` | informational/educational | SeManageVolumePrivilege | title-too-long, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/silver-ticket/` | tutorial/how-to | Silver Ticket Attack | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/smb/` | informational/service-enumeration | SMB porta 445 | title-too-long, thin-intro, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/source-code-disclosure/` | informational/educational | Source Code Disclosure | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/sql-injection-api-rest/` | informational/definition | SQL Injection su API REST e GraphQL | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/sql-injection-classica/` | informational/definition | SQL Injection Classica | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/ssh-pentesting-guide/` | informational/educational | SSH Pentesting Guide | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/subdomain-takeover/` | informational/educational | Subdomain Takeover | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/tool-penetration-testing/` | informational/definition | Tool Penetration Testing | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/vulnerability-exploitation/` | informational/educational | Vulnerability Exploitation | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/web-shell/` | informational/educational | Web Shell PHP | title-too-long, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/websocket-hijacking/` | informational/educational | WebSocket Hijacking | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/weevely3/` | tool-oriented/how-to | Weevely3 | title-too-long, first-heading-repeats-title, thin-intro | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/wmic/` | tool-oriented/how-to | WMIC | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/wmiexec/` | informational/definition | WMIExec | title-too-long, no-external-citations | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/xmlrpc/` | informational/definition | WordPress xmlrpc.php | title-too-long, thin-intro, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/zip-slip/` | informational/educational | Zip Slip Vulnerability | title-too-long, topic-not-in-first-100-words, no-external-citations, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P1 |
