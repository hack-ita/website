# Cannibalization analysis

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

## Hard conflicts: 7 duplicate slugs (two articles → one URL)

Hugo publishes only one per build; the other silently disappears. Both files are preserved. **Recommendation per pair below; do not merge/delete/redirect yet — editorial decision.**

| Slug (URL) | Recommended resolution |
| --- | --- |
| `/articoli/cache-poisoning/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/injection-attacks-guida-completa/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/lazagne/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/ldapsearch/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/mitmproxy/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/smbexec/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |
| `/articoli/sshuttle/` | DIFFERENTIATE or CONSOLIDATE LATER: pick the canonical article, reslug the other with a 301, or merge if near-identical. See the file pairs + word counts in the prior technical report. |


## Soft conflicts: near-identical titles targeting one intent

Detected via title-token overlap (Jaccard ≥ 0.6). Resolve by intent separation + hub/spoke linking, not deletion.
Full pair list is in `article-audit.json` consumers can regenerate; the dominant cases overlap the 7 slug collisions above.

## Resolution legend

`KEEP SEPARATE` · `DIFFERENTIATE` · `CONSOLIDATE LATER` · `REDIRECT LATER` · `CREATE HUB + SPOKE` · `NO ACTION`.
The category hubs shipped earlier (Home → Category → Article, in-body category chips) are the backbone for hub/spoke differentiation.
