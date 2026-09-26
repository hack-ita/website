# Git hooks

## pre-push — stale-content guard

Prevents pushing a stale local checkout that would silently delete published
articles still present on `origin/main` (the root cause of pages that suddenly
started returning 404). It fetches `origin/main`, compares the article files,
and blocks the push if more than 3 are missing locally.

Enable it once per clone:

```
git config core.hooksPath .githooks
```

Bypass for a deliberate bulk delete:

```
git push --no-verify
```

A matching server-side alarm runs in CI (`.github/workflows/content-guard.yaml`)
in case the hook isn't installed on a given machine.
