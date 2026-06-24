# GitHub Issues Backlog

The Codex GitHub integration could not create issues because the installed app
does not currently have repository Issues write permission. Use this backlog to
copy the items manually or recreate them once the permission is enabled.

## Launch checklist: Product Hunt screenshots and demo flow

Labels: `growth`, `launch`

Prepare the public launch assets before submitting OSINTPRO to Product Hunt.

- Capture dashboard, Domain Intel, Repository Audit, Wallet OSINT and Entity Graph screenshots.
- Record a short 30-60 second demo.
- Verify all README and docs links return HTTP 200.
- Confirm signup, login, exports and billing links work on the live Render deployment.

Reference: `docs/PRODUCT_HUNT_LAUNCH.md`

## Increase backend coverage toward 70% without fake tests

Labels: `testing`, `backend`

Current standard-library trace coverage is 57.27% on the monolithic `server.py`
with 31 tests.

Useful next coverage targets:

- Monitoring route edge cases.
- Admin backup restore/download flows.
- API key rate limiting and deletion paths.
- Network and wallet error paths with mocked upstream failures.
- Backend modularization so coverage work is maintainable.

Do not add empty assertion tests just to inflate the percentage.

## Expand dependency advisory rules for Repository Audit Lab

Labels: `repository-audit`, `security`

The first offline dependency advisory layer checks common npm, pip, Cargo and
Composer manifests.

Next steps:

- Add ecosystem-specific lockfile parsing.
- Add framework-aware rules for Django, Flask, Express, Laravel and Next.js.
- Add severity/source references in the UI.
- Keep scanning passive: no install, no build scripts, no dependency execution.

## Improve Free-to-Pro conversion metrics dashboard

Labels: `growth`, `analytics`

OSINTPRO now exposes account metrics, admin growth metrics and plan feature
flags.

Next steps:

- Add an admin UI panel for conversion funnel events.
- Track which module triggers upgrade intent most often.
- Compare Free tier variants A/B/C over real signup cohorts.
- Keep metrics first-party and privacy-conscious.
