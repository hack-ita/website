# Implementation roadmap

> **Data honesty.** Live Google SERP positions, Search Console impressions/CTR, keyword search volumes, and competitor metrics were **not available** in this environment and are marked `DATA NOT AVAILABLE`. Everything else is measured from the rendered HTML, the markdown source and the full site link-graph of the review branch, or clearly labelled *inferred*. No ranking is promised.

Recommended order. Every step is a separate, reviewable change; nothing here is applied yet.

## Phase 0 — correctness (P0, do first)
1. Resolve the **7 duplicate slugs** editorially (pick canonical, reslug + 301 the other, or merge the near-identical pairs). This stops an article silently disappearing per build.
2. Fix the **2 double-brand titles** (`oauth-security`, `hackita`).
3. **Before any production merge:** regenerate `tina/tina-lock.json` locally (`npx tinacms build`) — still outstanding from the earlier audit; the Netlify build can fail at the Tina step otherwise.

## Phase 1 — high-upside surgical (P1)
4. Shorten the 269 over-long titles to ~60 chars, keyword-first. Batch, reviewed per title.
5. Add answer-first leads to the 119 thin-intro articles (facts already in the article).
6. Add primary-source citations to the highest-traffic of the 100 uncited articles (prioritise with GSC once available).

## Phase 2 — structure & linking (P2)
7. Replace the 136 title-echo first headings with real section headings.
8. Add contextual inbound links to the 40 weakly-linked articles.
9. Add FAQ / comparison / definition blocks where the intent is `informational/definition` and a featured-snippet gap exists.

## Phase 3 — depth & authority (P2/P3)
10. Fill topical-cluster gaps (pillar/spoke) identified per category.
11. Extend the 6 short descriptions.

## Guardrails
- Apply in small reviewed batches; rebuild and re-run the QA scripts after each.
- Preserve URLs; any slug change needs a 301.
- Do not mass-generate copy; keep HackITA's practical, offensive-security voice.
