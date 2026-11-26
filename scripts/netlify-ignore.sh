#!/usr/bin/env bash
# Netlify "ignore" command (netlify.toml → [build] ignore). Exit 0 = skip this build, exit 1 = build.
#
# A production deploy costs 15 credits. This skips only the builds that cannot change the published site:
#   - draft posts (front matter "draft: true") that were already drafts or new: saving a draft in TinaCMS no longer
#     rebuilds the whole site; it goes live with the scheduled publication or the next real change;
#   - files Netlify never builds: GitHub workflows and hooks, README.
# Anything else, any doubt, any error → build (fail-safe). Build hooks and "Clear cache and deploy" always build
# when nothing changed since the last build.
set -u

base="${CACHED_COMMIT_REF:-}"
head="${COMMIT_REF:-HEAD}"
if [ -z "$base" ] || [ "$base" = "$head" ]; then
  exit 1
fi
changed="$(git diff --name-only "$base" "$head" 2>/dev/null)" || exit 1
[ -n "$changed" ] || exit 1

is_draft() {  # reads front matter only (between the first two --- lines)
  awk 'NR==1 && $0!="---" {exit 1} NR>1 && $0=="---" {exit} NR>1 && /^draft:[[:space:]]*true[[:space:]]*$/ {found=1}
       END {exit found ? 0 : 1}'
}

while IFS= read -r file; do
  case "$file" in
    .github/*|.githooks/*|README*) ;;
    content/*.md)
      [ -f "$file" ] || exit 1                                    # deleted: the page must disappear
      is_draft < "$file" || exit 1                                # visible content changed
      if git cat-file -e "$base:$file" 2>/dev/null; then          # a published post turned into a draft
        git show "$base:$file" | is_draft || exit 1
      fi
      ;;
    *) exit 1 ;;
  esac
done <<< "$changed"

echo "Only draft posts or repository files changed since the last build: production build skipped (15 credits saved)."
exit 0
