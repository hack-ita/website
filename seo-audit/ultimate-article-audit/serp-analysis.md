# SERP / GSC analysis — method and status

## Status: DATA NOT AVAILABLE

This environment has no Google Search Console access and no reliable live-SERP pull for Italian cybersecurity
queries. Per the brief, **no SERP positions, impressions, CTR, search volumes or competitor metrics were
invented.** Everything ranking-related below is a method to run with real access, not a result.

## What to pull (Search Console, last 3-6 months)

1. Pages ranking **positions 4-15** with high impressions and low CTR → surgical title/meta/intro wins.
2. Pages ranking for **unintended queries** → intent mismatch; the on-page intent in `article-audit.csv` (`search_intent_inferred`) is the starting hypothesis to confirm.
3. Pages with **many adjacent queries** on one URL → candidates for a section/FAQ targeting the secondary query.
4. **Zero-impression** published pages → indexing/relevance problem; cross-check with the `no-contextual-inbound-links` flag.

## How to join GSC to this dataset

`article-audit.csv` keys every row by `url`. Export the GSC "Pages" report, join on URL, and fill the
`gsc_impressions`, `gsc_position`, `gsc_ctr` columns. Then re-rank priority with real demand data; the
current priority is on-page-quality only.

## Competitor analysis (method)

For each P0/P1 primary keyword, pull the top 10 IT results and compare on: answer-first lead, definition
clarity, command/output presence, depth, internal links, citations, freshness, schema. Record the specific
structural advantage the competitor has. **Not done here** — requires live SERP access.
