# Internal linking recommendations

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

The whole site graph was built; every article is reachable within 2 clicks of the home page (template
links + related blocks), so there are **no true orphans**. The opportunity is **contextual in-body links**,
which carry more weight than template blocks.

## Articles with no contextual inbound links (40)

They rely only on the template "related" block. Add in-body links to them from topically adjacent articles,
using descriptive Italian anchors (the article's primary keyword), placed where the concept is first mentioned.

| Article | Intent (inferred) | Primary keyword (inferred) | Weaknesses | Action | Priority |
| --- | --- | --- | --- | --- | --- |
| `/articoli/copy-fail/` | vulnerability/CVE | CVE-2026-31431 | title-too-long, first-heading-repeats-title, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/cve-2026-20079-cisco-fmc-auth-bypass/` | vulnerability/CVE | CVE-2026-20079 | thin-intro, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/cve-2026-82329/` | vulnerability/CVE | CVE-2026-82329 | title-too-long, first-heading-near-title, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/dark-web/` | tutorial/how-to | Dark Web | thin-intro, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/hackita/` | informational/educational | HackIta | title-too-long, brand-duplicated-in-title, first-heading-near-title, no-external-citations, no-contextual-inbound-links, links-to-unpublished-article | Remove the duplicated brand token from the source title | P0 |
| `/articoli/htb-eighteen-badsuccessor-dmsa-walkthrough/` | walkthrough/writeup | HTB Eighteen Walkthrough | first-heading-near-title, topic-not-in-first-100-words, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-falafel-walkthrough/` | walkthrough/writeup | HTB Falafel Walkthrough | first-heading-repeats-title, thin-intro, topic-not-in-first-100-words, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-giddy-walkthrough/` | vulnerability/CVE | HTB Giddy Walkthrough | first-heading-near-title, thin-intro, topic-not-in-first-100-words, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-hator-walktrough/` | walkthrough/writeup | HTB Hathor Walkthrough ITA | title-too-long, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/htb-help-walkthrough/` | walkthrough/writeup | HTB Help Walkthrough | first-heading-near-title, topic-not-in-first-100-words, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-love-walkthrough/` | walkthrough/writeup | HTB Love Walkthrough | thin-intro, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-monitors-walkthrough/` | walkthrough/writeup | HTB Monitors Walkthrough | first-heading-near-title, topic-not-in-first-100-words, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-proloab-dante/` | walkthrough/writeup | HTB ProLab Dante | first-heading-near-title, no-contextual-inbound-links | Add in-body links to this article from related articles | P2 |
| `/articoli/htb-scepter-walkthrough/` | walkthrough/writeup | HTB Scepter Walkthrough | thin-intro, no-external-citations, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-schooled-walkthrough/` | walkthrough/writeup | HTB Schooled | first-heading-near-title, topic-not-in-first-100-words, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-scrambled-walkthrough/` | walkthrough/writeup | HTB Scrambled Walkthrough | title-too-long, topic-not-in-first-100-words, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/htb-search-walkthrough/` | walkthrough/writeup | HTB Search Walktrough | topic-not-in-first-100-words, no-external-citations, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-sekhmet-walktrough/` | walkthrough/writeup | HTB Sekhmet Walkthrough | title-too-long, topic-not-in-first-100-words, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/htb-shibuya-walkthrough/` | walkthrough/writeup | HTB Shibuya Walkthrough | first-heading-near-title, topic-not-in-first-100-words, no-external-citations, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-sink-walkthrough/` | walkthrough/writeup | HTB Sink Walkthrough | first-heading-near-title, no-contextual-inbound-links | Add in-body links to this article from related articles | P2 |
| `/articoli/htb-unattended-walkthrough/` | walkthrough/writeup | HTB Unattended Walkthrough | first-heading-repeats-title, topic-not-in-first-100-words, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/htb-voleur-walkthrough/` | walkthrough/writeup | Voleur HTB | first-heading-near-title, thin-intro, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/ics-ot-entesting/` | informational/definition | ICS/OT pentesting | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/jtag/` | tutorial/how-to | JTAG | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/kubernetes-privilege-escalation/` | informational/educational | Kubernetes Pentesting | first-heading-near-title, no-contextual-inbound-links, links-to-unpublished-article | Add in-body links to this article from related articles | P2 |
| `/articoli/linpeas-privesc-guide/` | informational/educational | LinPEAS | title-too-long, first-heading-repeats-title, no-contextual-inbound-links, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/linux-persistence/` | informational/educational | Linux Persistence | thin-intro, no-contextual-inbound-links, links-to-unpublished-article | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/ntlm-information-disclosure/` | informational/educational | NTLM Information Disclosure | title-too-long, no-contextual-inbound-links, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/oauth-security/` | informational/educational | OAuth 2.0 | brand-duplicated-in-title, first-heading-near-title, no-contextual-inbound-links | Remove the duplicated brand token from the source title | P0 |
| `/articoli/openssl/` | tool-oriented/how-to | OpenSSL | first-heading-near-title, no-contextual-inbound-links, links-to-unpublished-article | Add in-body links to this article from related articles | P2 |
| `/articoli/pth-net/` | informational/definition | pth-net | first-heading-near-title, no-contextual-inbound-links, links-to-unpublished-article | Add in-body links to this article from related articles | P2 |
| `/articoli/renamemachine/` | tool-oriented/how-to | renameMachine.py | thin-intro, no-external-citations, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/revolut-data-breach-richiesta-governativa-falsa/` | informational/educational | Revolut hackerata? Data breach | thin-intro, topic-not-in-first-100-words, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/rsync/` | informational/service-enumeration | Rsync Port 873 | first-heading-near-title, topic-not-in-first-100-words, no-external-citations, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/ssh-pentesting-guide/` | informational/educational | SSH Pentesting Guide | title-too-long, thin-intro, no-contextual-inbound-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/svg-xss-xxe/` | informational/educational | SVG XSS e XXE | thin-intro, no-contextual-inbound-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/thm-bolt-walkthrough/` | walkthrough/writeup | TryHackMe Bolt | first-heading-near-title, no-contextual-inbound-links | Add in-body links to this article from related articles | P2 |
| `/articoli/thomson-reuters-ctrack-data-breach-tribunali/` | informational/educational | Thomson Reuters | first-heading-near-title, no-contextual-inbound-links | Add in-body links to this article from related articles | P2 |
| `/articoli/vodafone-7415-punti-truffa/` | informational/educational | Truffa Vodafone | first-heading-near-title, no-contextual-inbound-links | Add in-body links to this article from related articles | P2 |
| `/articoli/windowsprivilegeescalation/` | informational/definition | Windows Privilege Escalation 2026 | title-too-long, first-heading-repeats-title, topic-not-in-first-100-words, no-contextual-inbound-links, links-to-unpublished-article | Shorten title to ~60 chars, primary keyword first | P2 |


...and 0 more in `article-audit.csv` (filter `contextual_inbound == 0`).

## Articles with no in-body outbound links (6)

| Article | Intent (inferred) | Primary keyword (inferred) | Weaknesses | Action | Priority |
| --- | --- | --- | --- | --- | --- |
| `/articoli/deserialization-attack/` | informational/service-enumeration | Deserialization Attack | title-too-long, thin-intro, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/esc9-adcs/` | informational/educational | ESC9 ADCS | title-too-long, thin-intro, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P1 |
| `/articoli/netdiscover/` | tool-oriented/how-to | Netdiscover | first-heading-repeats-title, thin-intro, no-outbound-contextual-links | Add a 2-3 sentence answer-first lead naming the entity | P2 |
| `/articoli/porta-111-rpcbind/` | informational/service-enumeration | Porta 111 RPCbind | title-too-long, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/powerview/` | tool-oriented/how-to | PowerView | title-too-long, first-heading-near-title, no-outbound-contextual-links | Shorten title to ~60 chars, primary keyword first | P2 |
| `/articoli/scapy/` | informational/educational | Scapy Python | first-heading-near-title, no-outbound-contextual-links | Make the first body heading a real section (not a title echo) | P3 |


## Method for implementers

For each target article T: find 3-5 articles that mention T's primary entity, and add one contextual link
to T at the first natural mention, anchor = T's primary keyword. Avoid exact-match anchor repetition across
many pages; vary the anchor. Do not link to unpublished articles (see the `links-to-unpublished-article` flag).
