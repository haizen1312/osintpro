# Product Hunt Launch Plan

This document keeps the launch work repeatable. Do not publish until the live
demo, exports, auth and billing paths have been tested end to end on Render.

## Pre-Launch Checklist

- Verify the live demo: `https://osintpro-48j4.onrender.com/`
- Confirm GitHub README links return HTTP 200.
- Test signup, login, logout and password change.
- Test Domain Intel PDF/CSV exports.
- Test Repository Audit JSON and SARIF export with a Pro/Admin account.
- Test Wallet OSINT and Entity Graph export.
- Prepare 3-5 screenshots: dashboard, domain report, repo audit, wallet graph, billing.
- Prepare one 30-60 second screen recording.
- Update README traction honestly; do not invent signups, revenue or MRR.

## Launch Copy

Full copy-paste launch assets are in [`PRODUCT_HUNT_COPY.md`](PRODUCT_HUNT_COPY.md):
Product Hunt post, FAQ, social posts, demo GIF script, launch-day timeline,
positioning variants and objection handling.

Headline:

```text
OSINTPRO - Passive OSINT for security consultants and investigators
```

Tagline:

```text
Turn public evidence into client-ready investigation graphs without aggressive scans.
```

Short description:

```text
OSINTPRO helps small security teams and investigators turn public evidence from
domains, repositories, usernames and blockchain wallets into readable reports
and relationship graphs. It is passive-only: no exploits, brute force or
invasive scanning.
```

## Launch Day

- Publish Product Hunt post early in the US day.
- Share the live demo and GitHub repository on LinkedIn.
- Post a technical Show HN thread focused on passive OSINT and client reporting.
- Ask for feedback in relevant cybersecurity and OSINT communities without spam.
- Reply to every comment with specifics and humility.
- Track signups, checkout clicks, paywall hits and feedback themes.

## Success Metrics

- 50+ signups from launch traffic.
- 5+ useful feedback threads.
- 1+ Pro conversion or serious agency conversation.
- 20+ GitHub stars.
- Clear top-3 product objections captured in ROADMAP.md or GitHub issues.

## FAQ

### Is OSINTPRO like Maltego?

OSINTPRO is lighter and focused on small-team delivery. Maltego is a broad
enterprise investigation platform. OSINTPRO emphasizes passive evidence,
readable reports and exports.

### Is it an offensive scanner?

No. OSINTPRO does not run exploits, brute force, credential attacks, invasive
scans or unauthorized packet capture.

### Can agencies integrate it?

The current API key MVP is limited to Agency/Admin workflows. Public API selling
should wait for persistent storage, stronger metering and production support.

### What makes it useful if the data is public?

The value is normalization, prioritization, relationship mapping and client
delivery. Public data is easy to collect badly and slow to explain well.
