# AI Development Guide

This file transfers project-specific decisions between AI coding sessions and
future developers.

## Verify Before Assuming

- The backend uses `http.server`, not Flask.
- The current branch is `main` and pushes auto-deploy to Render.
- Inspect the current README before copying external feedback; some feedback
  may describe an older revision.
- Never publish local database counts as production traction.

## Required Change Loop

1. Read the relevant handler, frontend control and documentation.
2. Reproduce the bug locally.
3. Implement the smallest behaviorally complete fix.
4. Add an automated regression test.
5. Run Python, JavaScript and whitespace checks.
6. Verify important frontend behavior in the in-app browser.
7. Update architecture, security or performance notes when a reusable pattern
   was learned.
8. Commit, push and verify the live Render endpoint.

Do not report the Python `trace` summary without `--missing`; that mode counts
only observed lines and produces a misleading 100% result.

## Export Pattern

- Generate bytes on the server.
- Validate ownership through the signed session.
- Return a safe attachment filename.
- Use client-side `fetch` so JSON errors become visible feedback.
- Keep anonymous storage bounded to the latest report.

## Safety

Do not commit secrets, execute uploaded repository code, add offensive payload
automation or expose local/private files through the static server.
