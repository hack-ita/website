#!/usr/bin/env node
/*
 * check-duplicate-slugs.mjs — guard against NEW duplicate article slugs.
 *
 * Two published articles that resolve to the same /articoli/<slug>/ URL are a
 * silent data-loss risk: Hugo keeps only one (the winner changes per build) and
 * the other article disappears from that URL. This scans content/articoli/*.md,
 * computes each file's effective slug, and fails when two files collide.
 *
 * Pre-existing collisions awaiting an editorial decision are listed in
 * scripts/known-duplicate-slugs.json and treated as accepted, so this passes on
 * the current repo but fails loudly the moment a NEW collision is introduced.
 *
 * No dependencies (Node stdlib only). Exit 0 = clean, exit 1 = new collision.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ARTICLES_DIR = path.join(ROOT, "content", "articoli");
const BASELINE_FILE = path.join(ROOT, "scripts", "known-duplicate-slugs.json");

function slugify(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, "")
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

// Minimal front-matter reader: only the keys we need (slug, url, draft, title).
function frontMatter(content) {
  const m = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!m) return {};
  const fm = {};
  for (const line of m[1].split("\n")) {
    const kv = line.match(/^([A-Za-z_]+):\s*(.*)$/);
    if (!kv) continue;
    let v = kv[2].trim().replace(/^["']|["']$/g, "");
    fm[kv[1]] = v;
  }
  return fm;
}

// Effective published slug: an explicit `url:` wins (its last path segment),
// else `slug:`, else Hugo's default (slugified filename).
function effectiveSlug(file, fm) {
  if (fm.url) {
    const seg = fm.url.replace(/\/+$/, "").split("/").filter(Boolean).pop();
    if (seg) return slugify(seg);
  }
  if (fm.slug) return slugify(fm.slug);
  return slugify(path.basename(file, ".md"));
}

const baseline = new Set(JSON.parse(fs.readFileSync(BASELINE_FILE, "utf8")).known);

const bySlug = new Map();
for (const name of fs.readdirSync(ARTICLES_DIR)) {
  if (!name.endsWith(".md") || name === "_index.md") continue;
  const file = path.join(ARTICLES_DIR, name);
  const fm = frontMatter(fs.readFileSync(file, "utf8"));
  if (String(fm.draft).toLowerCase() === "true") continue; // drafts are not published
  const slug = effectiveSlug(name, fm);
  if (!slug) continue;
  if (!bySlug.has(slug)) bySlug.set(slug, []);
  bySlug.get(slug).push(name);
}

const duplicates = [...bySlug.entries()].filter(([, files]) => files.length > 1);
const unexpected = duplicates.filter(([slug]) => !baseline.has(slug));
const staleBaseline = [...baseline].filter((slug) => (bySlug.get(slug) || []).length <= 1);

if (duplicates.length) {
  console.log("Duplicate article slugs found:");
  for (const [slug, files] of duplicates.sort((a, b) => a[0].localeCompare(b[0]))) {
    const tag = baseline.has(slug) ? "known" : "NEW";
    console.log(`  [${tag}] /articoli/${slug}/`);
    for (const f of files) console.log(`      - content/articoli/${f}`);
  }
}

if (staleBaseline.length) {
  console.log(
    `\nNote: these baseline slugs are no longer duplicated and can be removed ` +
      `from scripts/known-duplicate-slugs.json: ${staleBaseline.join(", ")}`
  );
}

if (unexpected.length) {
  console.error(
    `\n::error::${unexpected.length} NEW duplicate article slug(s) would ship: ` +
      unexpected.map(([s]) => s).join(", ") + "."
  );
  console.error(
    "::error::Two articles share one /articoli/<slug>/ URL; one silently disappears. " +
      "Give one a distinct slug. If the collision is genuinely intentional, add the " +
      "slug to scripts/known-duplicate-slugs.json."
  );
  process.exit(1);
}

console.log(
  `\nOK — no new duplicate slugs (${bySlug.size} unique slugs, ` +
    `${duplicates.length} known/accepted collision${duplicates.length === 1 ? "" : "s"}).`
);
