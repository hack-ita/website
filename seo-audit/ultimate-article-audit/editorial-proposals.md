# Editorial proposals (implementation-ready, NOT applied)

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

These are concrete, reviewable proposals for the highest-value, well-defined cases. They are **proposals in
this report only** — the articles are unchanged. Full per-article title/intro rewriting across the corpus is
deliberately NOT done here (the brief forbids mass-rewriting and fabrication); use the rules below with an
editor or a supervised batch.

## 1. Double-brand titles (correctness — safe to apply as-is)

- **`/articoli/hackita/`**
  - Current `<title>`: `HackIta: il blog italiano di Ethical Hacking, Pentesting e Offensive Security | Hackita`
  - Issue: brand appears twice (the source title already ends with a brand, the template appends `| Hackita`).
  - Proposed: remove the in-title brand from the source `title` front-matter; keep the template suffix only.
  - Purpose: clean SERP title, no wasted pixels on a repeated brand.
- **`/articoli/oauth-security/`**
  - Current `<title>`: `OAuth 2.0: Token, Scope e Rischi dei Tool Terzi | HackITA | Hackita`
  - Issue: brand appears twice (the source title already ends with a brand, the template appends `| Hackita`).
  - Proposed: remove the in-title brand from the source `title` front-matter; keep the template suffix only.
  - Purpose: clean SERP title, no wasted pixels on a repeated brand.

## 2. Over-long titles — the shortening rule (apply per title, reviewed)

Goal ~60 characters, **primary keyword first**, drop filler ("Guida Completa a", "Tutti i"), keep the
distinctive qualifier, keep natural Italian. Do not stuff. Examples (current → shape to aim for; final
wording is the editor's):

- `/articoli/adcs-esc1-esc16/` (110 chars)
  - Current: `AD CS Privilege Escalation: Tutte le Tecniche ESC1–ESC16 con Certipy (Active Directory Attack Guide) | Hackita`
  - Keyword to lead with: **AD CS Privilege Escalation**; trim to ~60 chars keeping the distinctive part.
- `/articoli/seassignprimarytokenprivilege/` (102 chars)
  - Current: `SeAssignPrimaryTokenPrivilege: il bypass ai Potato Attack anche senza SeImpersonatePrivilege | Hackita`
  - Keyword to lead with: **SeAssignPrimaryTokenPrivilege**; trim to ~60 chars keeping the distinctive part.
- `/articoli/porta-912-apex-mesh/` (101 chars)
  - Current: `Porta 912 Apex Mesh / MeshCentral: server RMM, agent remoti e compromissione centralizzata. | Hackita`
  - Keyword to lead with: **Porta 912 Apex Mesh / MeshCentral**; trim to ~60 chars keeping the distinctive part.
- `/articoli/wifi-802-11/` (101 chars)
  - Current: `Wi-Fi 802.11: Frame, WPA2/WPA3, Deauth ed Evil Twin — Guida Completa agli Attacchi Wireless | Hackita`
  - Keyword to lead with: **Wi-Fi 802.11**; trim to ~60 chars keeping the distinctive part.
- `/articoli/api-modern-web-attacks-guida-completa/` (99 chars)
  - Current: `API Security: Guida Completa agli API Attacks e al Pentesting (SSRF, GraphQL, BOLA, CORS) | Hackita`
  - Keyword to lead with: **API Security**; trim to ~60 chars keeping the distinctive part.
- `/articoli/chkrootkit/` (99 chars)
  - Current: `Chkrootkit: Rootkit Detection su Linux per Incident Response e Post-Exploitation Analysis | Hackita`
  - Keyword to lead with: **Chkrootkit**; trim to ~60 chars keeping the distinctive part.
- `/articoli/tcp/` (99 chars)
  - Current: `TCP (Transmission Control Protocol): cos'è, come funziona e come sfruttarlo in un pentest | Hackita`
  - Keyword to lead with: **TCP**; trim to ~60 chars keeping the distinctive part.
- `/articoli/active-directory/` (98 chars)
  - Current: `Active Directory Pentesting 2026: Guida Completa a Kerberos, NTLM e Privilege Escalation | Hackita`
  - Keyword to lead with: **Active Directory Pentesting 2026**; trim to ~60 chars keeping the distinctive part.
- `/articoli/man-in-the-middle/` (98 chars)
  - Current: `Man in the Middle (MITM): Cos'è e tecniche reali per intercettare traffico e credenziali | Hackita`
  - Keyword to lead with: **Man in the Middle**; trim to ~60 chars keeping the distinctive part.
- `/articoli/arp/` (97 chars)
  - Current: `ARP (Address Resolution Protocol): Cos’è, Come Funziona e Come Sfruttarlo in un Pentest | Hackita`
  - Keyword to lead with: **ARP**; trim to ~60 chars keeping the distinctive part.
- `/articoli/porta-138-netbios-datagram/` (97 chars)
  - Current: `Porta 138 NetBIOS Datagram: Guida al Penetration Testing del Servizio Broadcast Windows | Hackita`
  - Keyword to lead with: **Porta 138 NetBIOS Datagram**; trim to ~60 chars keeping the distinctive part.
- `/articoli/sedelegatesessionuserimpersonateprivilege/` (97 chars)
  - Current: `SeDelegateSessionUserImpersonatePrivilege: Token Stealing Cross-Session su RDS e Citrix | Hackita`
  - Keyword to lead with: **SeDelegateSessionUserImpersonatePrivilege**; trim to ~60 chars keeping the distinctive part.

## 3. Answer-first lead — the pattern for thin intros

For the 119 thin-intro articles, add 2-3 sentences before the first `<h2>` that state, from
facts already in the article: **what it is**, **what it does / why it matters in a pentest**, **what the
reader will be able to do** after reading. Keep the offensive-security framing and lab context. No new
claims, no invented numbers. This is the single biggest AEO / AI-Overview lever in the corpus.

## 4. First-heading echo — the fix

For the 136 articles whose body starts with a heading repeating the title: either
delete that leading markdown `#` line (the template H1 already covers it) or replace it with a real first
section heading phrased as the question the section answers (e.g. "Come funziona X", "A cosa serve X") —
which also opens a featured-snippet opportunity.

> Every per-article datum behind these proposals is in `article-audit.csv` / `article-audit.json`.
