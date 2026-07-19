# OSINTPRO Distribution Action Log

This file tracks real distribution work only. Do not record simulated traffic,
paid engagement, fake accounts, inflated metrics or unconfirmed outreach.

## Completed In-Product Growth Work

- Added share-ready SEO metadata to the live app:
  - canonical URL
  - Open Graph title, description, URL and image
  - Twitter summary card
  - hreflang alternates for English, Italian, Spanish, French, German and Portuguese
  - SoftwareApplication structured data with Free, Pro and Agency pricing
- Kept the public safety positioning intact: passive OSINT, no exploits, no brute force.
- Preserved Product Hunt screenshot assets for social previews.

## Completed External Distribution Actions

- Product Hunt product page is live:
  - https://www.producthunt.com/products/osintpro
  - Verified on 2026-07-11 with website and GitHub links present.
- Published a Product Hunt product forum update from Leo's existing logged-in
  account:
  - https://www.producthunt.com/p/osintpro/osintpro-update-cleaner-mobile-ui-and-multilingual-polish
  - Angle: mobile UI cleanup, multilingual polish, language selector fix,
    share metadata and passive-only positioning.
  - Screenshot archive:
    `assets/ph-launch/live-producthunt/forum-update-2026-07-11.png`
- Opened GitHub PRs to relevant awesome lists:
  - `jivoi/awesome-osint`: https://github.com/jivoi/awesome-osint/pull/1042
    - Fit: general OSINT tools; added one neutral entry under Other Tools.
  - `mickygough/Awesome-Security-Tools`: https://github.com/mickygough/Awesome-Security-Tools/pull/2
    - Fit: Passive Recon section; added URL and repository link.
  - `hslatman/awesome-threat-intelligence`: https://github.com/hslatman/awesome-threat-intelligence/pull/402
    - Fit: Tools section includes OSINT artifact collection/enrichment tools.
  - Each PR includes disclosure that Leo is related to OSINTPRO.
- GitHub repository metadata refreshed on 2026-07-19:
  - Description updated to mention investigations, repository audit, wallet tracing,
    APIs, webhooks and graph exports.
  - Topics refreshed within GitHub's 20-topic limit to include `i18n`, `sarif`,
    `dependency-scanning`, `repository-audit`, `entity-graph` and `game-security`.
  - Numeric claims used: none.
- Reddit r/OSINT post submitted on 2026-07-19 from the existing logged-in account
  `u/Wooden_Durian7470`:
  - URL: https://www.reddit.com/r/OSINT/comments/1v0zpz7/built_a_passive_osint_workspace_for_clientready/
  - Status: submitted, then removed by subreddit moderation/filter shortly after
    posting. Do not count this as live traffic.
  - Angle: passive-only OSINT workspace, request for community feedback on safe
    risk explanations.
  - Numeric claims used: none.

## External Channel Status Checks

- Awesome-list PR status checked on 2026-07-19:
  - `jivoi/awesome-osint`: https://github.com/jivoi/awesome-osint/pull/1042
    - Status: closed without merge on 2026-07-14.
    - Maintainer comments or requested changes: none visible.
  - `mickygough/Awesome-Security-Tools`: https://github.com/mickygough/Awesome-Security-Tools/pull/2
    - Status: open.
    - Maintainer comments or requested changes: none visible.
  - `hslatman/awesome-threat-intelligence`: https://github.com/hslatman/awesome-threat-intelligence/pull/402
    - Status: open.
    - Maintainer comments or requested changes: none visible.
- Self-serve directory review on 2026-07-19:
  - 10015 Product Finder looked like a URL-only form, but submitting the URL opened
    a required Sign In / Register modal. No account was created.
  - Twelve Tools has a public free submission form, but requires adding a
    `twelve.tools` backlink or badge to the product homepage/footer before
    publication. No backlink was added.
  - SaaSHub, AlternativeTo and StackShare were not submitted because current
    public guidance indicates account creation or sign-in is required.
- Tier 2 account checks on 2026-07-19:
  - Hacker News `/submit` is not logged in and shows login/create account fields.
  - Indie Hackers is not logged in and shows a Join flow.
  - No HN or Indie Hackers account was created.

## Self-Serve Submissions To Do

These are allowed when the form is public and does not require creating a new
personal account for Leo.

| Surface | Fit | Suggested angle | Status |
| --- | --- | --- | --- |
| Product Hunt | Strong | Passive OSINT workspace for consultants | Live product page + forum update published |
| GitHub repository profile | Strong | Passive OSINT, investigation graph, client-ready reports | Active |
| Open-source directories | Medium | Security tool with passive-only boundary | Three GitHub awesome-list PRs opened |
| Startup/demo directories | Medium | Freemium security SaaS for consultants and investigators | Initial review done; 10015 and Twelve Tools blocked by login/backlink requirements |

## GitHub PR Targets To Research

Only open a PR when the list explicitly accepts tools like OSINTPRO and the entry
does not read as spam.

| Candidate list type | Fit criteria | Entry copy |
| --- | --- | --- |
| awesome-osint | Accepts passive OSINT tools and SaaS/web apps | PR opened: https://github.com/jivoi/awesome-osint/pull/1042 |
| awesome-security-tools | Accepts defensive web/security review tools | PR opened: https://github.com/mickygough/Awesome-Security-Tools/pull/2 |
| awesome-threat-intelligence | Accepts domain/posture/intel tools | PR opened: https://github.com/hslatman/awesome-threat-intelligence/pull/402 |

## Ready Copy

### Short Technical Blurb

```text
OSINTPRO is a passive OSINT workspace for consultants, investigators and fraud
analysts. It turns public domain, username, repository and wallet evidence into
client-ready findings, graph exports and reports without running exploits,
brute force or invasive scans.

Live demo: https://osintpro-48j4.onrender.com/
GitHub: https://github.com/haizen1312/osintpro
```

### Directory Summary

```text
Passive OSINT SaaS for client-ready domain intelligence, username checks,
repository audit leads, wallet tracing, monitoring and investigation graphs.
```

### Safety Boundary

```text
OSINTPRO is passive-only. It uses public signals and defensive review workflows.
It does not automate exploitation, credential attacks, bypasses or brute force.
```

## Requires Leo Confirmation

These actions must not be performed without explicit approval at action time:

- Creating a new account in Leo's identity.
- Sending a direct message to a real identified person.
- Posting from a personal social profile that is not already logged in and ready.

### Ready Tier 2 Copy

Use this only after Leo explicitly approves account creation or confirms an
existing logged-in account.

#### Hacker News

Title:

```text
Show HN: OSINTPRO - passive OSINT workspace for client-ready reports
```

URL:

```text
https://osintpro-48j4.onrender.com/
```

Optional first comment:

```text
I built OSINTPRO as a passive-only OSINT workspace for consultants and
investigators who need client-ready evidence packages instead of raw lookup
screens.

The boundary is intentionally conservative: no exploits, no brute force, no
credential attacks, no invasive scanning and no wallet movement. The current
modules cover domain OSINT, social username checks, public wallet tracing,
repository audit leads with SARIF export, dependency advisory checks, graph
exports and PDF/CSV reporting.

The technical question I am still working through is how to explain risk in a
useful way without drifting into offensive procedure. Feedback on that boundary
would be especially useful.
```

#### Indie Hackers

Title:

```text
I built a passive OSINT SaaS and the hardest part is explaining risk safely
```

Body:

```text
I am building OSINTPRO, a freemium passive OSINT workspace for consultants,
investigators and small security-minded teams.

The first version tried to collect useful public evidence: domains, usernames,
wallets, repository audit leads and graph exports. The newer work is more about
delivery: translated findings, client-ready reports, webhook/API workflows and
owner-readable risk explanations.

The product deliberately does not run exploits, brute force, credential attacks
or invasive scans. That makes the positioning cleaner, but it also creates a
copy/product challenge: users still need to understand how a weakness could be
abused, without the app turning into an offensive guide.

Current pricing is Free / Pro / Agency. I am not sharing MRR or conversion
numbers yet because usage is still too early and I do not want to invent
traction.

What would you expect to see before trusting a small security SaaS in a client
workflow?

Live demo: https://osintpro-48j4.onrender.com/
GitHub: https://github.com/haizen1312/osintpro
```
