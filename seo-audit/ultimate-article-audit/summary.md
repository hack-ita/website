# Executive summary — HackITA article SEO audit

For Canio and Mudassir. Audit-only; nothing on the site was changed.

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

## The 18 questions, answered

1. **Articles audited:** 536 (every published article; no sampling).
2. **Strong SEO foundation (no major action):** 62. All 536 share a sound technical base (one H1, unique title/description, self canonical, valid schema); 62 additionally have no on-page weakness worth acting on.
3. **Title problems:** 269 over-long (will truncate in SERP) + 2 with a duplicated brand.
4. **Meta problems:** 6 too short; 0 missing, 0 duplicated.
5. **Intro problems:** 119 thin (<40 words before the first section); 100 do not name the topic in the first 100 words.
6. **Heading problems:** 136 bodies open with a heading that echoes the title; 0 missing/duplicate H1.
7. **Cannibalization risks:** 7 hard slug collisions + a handful of near-identical title pairs (see `cannibalization.md`).
8. **Weak internal linking:** 40 with no contextual inbound links; 6 with no in-body outbound links.
9. **Missing AEO opportunities:** the 119 thin-intro articles are the primary answer-first/featured-snippet opportunities.
10. **AI/LLM retrieval opportunities:** strongest where a clear definition + self-contained sections exist; the thin-intro and no-citation sets are where retrievability is weakest.
11. **Need major editorial work:** 100 (P0+P1). See `big-opportunities.md`.
12. **Quick wins:** 277 title/description surgical edits (see `quick-wins.md`).
13. **Strongest clusters (lowest share of P0/P1):** walkthroughs (0%), tools (10%), networking (15%).
14. **Weakest clusters (highest share of P0/P1):** web-hacking (37%), cve (25%), windows (19%).
15. **Greatest upside pages:** the P0 set (slug collisions + double-brand titles) then the P1 set; listed in `top-opportunities.md`.
16. **Top 20 actions:** see the table below and `top-opportunities.md`.
17. **Fix first:** the 7 slug collisions (one article silently disappears per build) and the 2 double-brand titles — correctness issues with direct SERP impact.
18. **Do NOT touch (already correct):** H1 architecture (536/536), canonicals, indexability strategy, Article schema, sitemap coherence, breadcrumbs. These were fixed in earlier commits and verified.

## Corpus health

- Priorities: **P0 9**, **P1 91**, **P2 335**, **P3 101**.
- Clusters (articles / share P0+P1): networking (173/15%); tools (109/10%); web-hacking (103/37%); windows (72/19%); guides-resources (31/19%); walkthroughs (23/0%); linux (21/19%); cve (4/25%)

## Top 20 priority actions

| # | Article | Intent (inferred) | Biggest issue | Action | Priority |
| --- | --- | --- | --- | --- | --- |
| 1 | `/articoli/cache-poisoning/` | informational/educational | thin-intro | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 2 | `/articoli/hackita/` | informational/educational | title-too-long | Remove the duplicated brand token from the source title | P0 |
| 3 | `/articoli/injection-attacks-guida-completa/` | informational/definition | first-heading-near-title | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 4 | `/articoli/lazagne/` | tool-oriented/how-to | links-to-unpublished-article | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 5 | `/articoli/ldapsearch/` | tool-oriented/how-to | thin-intro | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 6 | `/articoli/mitmproxy/` | tool-oriented/how-to | title-too-long | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 7 | `/articoli/oauth-security/` | informational/educational | brand-duplicated-in-title | Remove the duplicated brand token from the source title | P0 |
| 8 | `/articoli/smbexec/` | tool-oriented/how-to | links-to-unpublished-article | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 9 | `/articoli/sshuttle/` | informational/educational | title-too-long | Resolve slug collision editorially (pick canonical, reslug/redirect the other) | P0 |
| 10 | `/articoli/adcs-eku-oid-offensive/` | informational/definition | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 11 | `/articoli/api-modern-web-attacks-guida-completa/` | informational/definition | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 12 | `/articoli/api-rate-limit-bypass/` | informational/educational | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 13 | `/articoli/api-versioning-attacck/` | informational/educational | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 14 | `/articoli/arbitrary-file-read/` | informational/definition | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 15 | `/articoli/attacchi-applicazioni-web/` | informational/definition | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 16 | `/articoli/aws-privilege-escalation/` | informational/educational | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 17 | `/articoli/blind-sql-injection/` | informational/definition | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 18 | `/articoli/brute-force/` | informational/educational | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 19 | `/articoli/copy-fail/` | vulnerability/CVE | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |
| 20 | `/articoli/crontab/` | informational/educational | title-too-long | Shorten title to ~60 chars, primary keyword first | P1 |

## What this audit can and cannot claim

It measures on-page and site-graph quality precisely, and infers intent from content. It does **not**
include live rankings, impressions or competitor data (not available here), so it cannot prove an article
is behind a specific competitor or quantify traffic upside. Those require Search Console + live SERP pulls
(method in `serp-analysis.md`). No ranking is guaranteed; the actions aim at relevance, intent alignment,
extractability and CTR.
