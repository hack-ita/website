# HackITA — Ultimate full-corpus article SEO audit

Audit-only deliverable. **No existing site file was modified**; everything here is new, under
`seo-audit/ultimate-article-audit/`. Branch `claude-review-hackita`.

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

## What is here

| File | Contents |
| --- | --- |
| `article-audit.json` | One object per article (536): on-page facts, inferred intent, strengths, weaknesses, recommended action, priority. Machine-readable, complete. |
| `article-audit.csv` | Same, one row per article, for spreadsheets. |
| `summary.md` | Executive summary; answers the 18 required questions. |
| `top-opportunities.md` | Highest-upside articles (P0/P1) with the exact action. |
| `quick-wins.md` | Low-risk, low-effort changes. |
| `big-opportunities.md` | Articles needing larger editorial work. |
| `cannibalization.md` | Keyword/article conflicts and the recommended resolution per pair. |
| `internal-linking.md` | Concrete internal-link recommendations. |
| `serp-analysis.md` | SERP/GSC methodology; what to pull and how (live data not available here). |
| `editorial-proposals.md` | Worked, implementation-ready proposals for the top items + the rules for the rest. |
| `implementation-roadmap.md` | Recommended order of operations. |

## Method

- **Corpus:** every published article was built with Hugo 0.152.2 extended and parsed from rendered HTML; 536 URLs (543 source files; 7 share a slug).
- **Signals measured per article:** title + length, rendered H1 (count + text), meta description + length, first-content-heading vs title similarity, intro word-count before the first `<h2>`, whether the primary topic appears in the first 100 words, word count, in-body internal links out, contextual inbound links from other articles, external citations, related-block presence, click-depth from the home page, JSON-LD validity and fields, category/subcategory/tags.
- **Inferred (labelled as such):** search intent, proposed primary keyword. These are derived from on-page content and site structure, **not** from live SERP or volume data.
- **Priority rule (transparent):** P0 = slug cannibalization or duplicated brand in title; P1 = over-long title combined with a thin intro or no citations; P2 = any single high-impact on-page weakness; P3 = none (NO MAJOR ACTION REQUIRED).

## Headline findings

- Technical foundation is already sound: **536/536 articles have exactly one `<h1>`**, 0 missing/duplicate titles/descriptions/canonicals, 0 noindex, valid Article schema on every article (the `b44bf1c` commit added `mainEntityOfPage` + `inLanguage`).
- The upside is **editorial/on-page**, not technical: 269 over-long titles, 119 thin intros, 100 articles without external citations, 136 bodies whose first heading echoes the title, and 7 slug collisions.
