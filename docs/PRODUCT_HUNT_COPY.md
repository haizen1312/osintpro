# OSINTPRO Product Hunt Launch Copy

This document is copy-paste ready for Product Hunt, social launch posts, FAQ answers and launch-day comment handling.

## 1. Product Hunt Post

### Headline

OSINTPRO — Passive OSINT for security consultants

### Tagline

Turn public evidence into client-ready investigation graphs. No exploits, no BS. €19/mo.

### Description

I built OSINTPRO because a lot of small security consultants and investigators have the same problem: the investigation is not always the slowest part. The reporting is.

You can spend hours collecting public evidence from DNS records, certificates, headers, social profiles, public repositories and blockchain explorers, then spend just as long turning that evidence into something a client can actually understand. Raw findings are useful to us. Clients need a clear story, a graph, a timeline and a report they can act on.

The existing tools are strong, but many of them are built for a different job. Maltego is powerful, but it can be too much for a small agency or solo consultant. Shodan is useful, but it is centered on internet-exposed services and port intelligence. A lot of recon tooling also moves quickly toward aggressive scanning, exploitation or workflows that are not appropriate unless you have explicit authorization.

OSINTPRO is deliberately different. It is passive-only. It works from public evidence and defensive review workflows, then turns that evidence into readable findings, investigation graphs, exports and monitors.

The goal is simple: point OSINTPRO at a domain, username, wallet or repository, review the evidence, connect the entities, export the report and move on. It is built for consultants, fraud analysts, investigators and technical founders who need useful intelligence without turning every engagement into a custom research project.

What OSINTPRO does today:

- Domain intelligence: DNS, IP resolution, HTTPS certificates, security headers, email authentication posture, public web exposure and risk findings.
- Investigation graph: connect domains, findings, wallets, usernames and evidence into a graph that can be exported for case work.
- Client-ready exports: PDF reports, CSV exports, JSON-LD, DOT for Graphviz and graph-ready evidence formats.
- Monitoring: track domain changes and receive monitor events through the app or webhooks.
- Repository Audit Lab: passive source review for common security leads, SARIF export and dependency advisory checks without executing uploaded code.
- Wallet OSINT: public wallet balance, movement summaries, counterparties, tags, notes and case timeline support for fraud reconstruction.
- Web Audit Lab and Network Traffic Lab: beginner-friendly defensive workflows that explain technical concepts instead of just dumping raw output.

How it compares honestly:

Maltego is excellent when you need a mature enterprise graph platform. OSINTPRO is for smaller teams that want faster client delivery, simpler workflows and lower cost.

Shodan is excellent when you need internet-exposed service intelligence. OSINTPRO is not a port scanner and does not try to be one. It focuses on passive public evidence, reporting and relationship mapping.

VirusTotal and SecurityTrails are useful sources for threat and domain intelligence. OSINTPRO is closer to a workspace around the evidence: normalize it, explain it, connect it, export it and monitor it.

Pricing:

- Free: 5 reports/month, 1 monitor, no credit card required.
- Pro: €19/month, unlimited reports, 5 monitors, Pro exports and webhooks.
- Agency: €79/month, agency workflows, higher monitor limits and client delivery features.

The product is early, but it is live and usable. Webhooks are live, the public API is available with Bearer tokens, monitoring is implemented and the roadmap is open on GitHub.

Try it here:
https://osintpro-48j4.onrender.com/

GitHub:
https://github.com/haizen1312/osintpro

I would love feedback from security consultants, investigators, fraud analysts and technical founders. The most useful question for us right now is: what would make this easier to use in a real client investigation?

## 2. FAQ

**Q: How is OSINTPRO different from Maltego?**  
A: Maltego is a mature enterprise graph platform. OSINTPRO is lighter, cheaper and focused on passive evidence collection, readable findings and client-ready delivery for small teams.

**Q: Can you scan my company's infrastructure?**  
A: No. OSINTPRO is passive-only, which means it works from public records, public web responses, public repositories and authorized defensive workflows without port scanning, exploitation or brute force.

**Q: Is this legal?**  
A: OSINTPRO is designed around public evidence and defensive review. It does not bypass authentication, run exploits, move wallets, brute force accounts or perform invasive scanning.

**Q: Why €19/month and not $19/month?**  
A: We are EU-based, so EUR is the default pricing currency. Stripe handles card payments and currency conversion for users outside the Eurozone.

**Q: What payment methods do you accept?**  
A: Payments are handled through Stripe. Depending on your country and device, Stripe can support cards, Apple Pay, Google Pay and other local payment methods.

**Q: Can I use this for penetration testing?**  
A: OSINTPRO is not a penetration testing or exploitation tool. It can be useful for pre-engagement passive reconnaissance and client reporting, but it is not built for active testing.

**Q: Do you have an API?**  
A: Yes. OSINTPRO has a public API with Bearer token authentication and plan-based access controls for API workflows.

**Q: Can I export data?**  
A: Yes. OSINTPRO supports PDF, CSV, JSON-LD, DOT for Graphviz and SARIF for repository audit findings.

**Q: Do you have webhooks?**  
A: Yes. Pro and Agency users can configure webhooks for monitor and report events, so OSINTPRO can trigger external alerts or workflows.

**Q: What about privacy?**  
A: OSINTPRO is built around first-party product usage, not ad tracking or data resale. The roadmap is public, and the export formats are based on open standards.

**Q: How much does it cost to self-host?**  
A: The code is public on GitHub, but official self-hosting support is not the main product yet. Right now, the hosted SaaS is the recommended path.

**Q: What happens if I hit my monitor limit?**  
A: You can upgrade to a higher plan when you need more monitors. Your existing reports and workspace stay attached to your account.

**Q: Is there a free tier?**  
A: Yes. The free tier includes 5 reports per month and 1 monitor, with no credit card required.

**Q: Does OSINTPRO replace human investigation?**  
A: No. It helps collect, normalize and explain passive evidence, but the analyst still decides what matters and what should go into the client story.

**Q: Does OSINTPRO store uploaded source code?**  
A: Repository Audit Lab is designed for defensive review and redacted findings. The product does not execute uploaded code or install dependencies during review.

## 3. Positioning Statement

For security consultants, investigators and fraud analysts under time pressure, OSINTPRO is a passive OSINT workspace that turns public evidence into readable findings, investigation graphs and client-ready exports. Unlike Maltego, which is a broader enterprise graph platform, or Shodan, which is focused on exposed services, OSINTPRO is built for smaller teams that need deliverables, monitoring and clear evidence without aggressive scanning. We are honest about the boundary: passive-only, no exploits, no brute force, no hacking workflows. The focus is simple: evidence in, graph out, client report ready.

## 4. Launch Social Copy

### Twitter/X Post

Built OSINTPRO because consultants waste too much time turning OSINT into client reports.

Passive OSINT. Investigation graphs. PDF/CSV exports. Webhooks. Free tier.

Live on Product Hunt:
https://osintpro-48j4.onrender.com/

### LinkedIn Post

Security consultants often do not lose time because they cannot find public evidence.

They lose time because turning that evidence into a client-ready report takes too long.

That is why we built OSINTPRO: a passive OSINT workspace for consultants, investigators, fraud analysts and technical founders who need fast, readable intelligence from public sources.

OSINTPRO helps with:

- Domain intelligence: DNS, certificates, headers and email security posture.
- Investigation graphs: connect domains, findings, usernames, wallets and evidence.
- Client-ready exports: PDF, CSV, JSON-LD and DOT.
- Repository Audit Lab: defensive source review with SARIF export.
- Wallet OSINT: public wallet movement, counterparties, labels and notes.
- Monitoring and webhooks: track drift and send events into your workflow.

The boundary is intentional: passive-only. No exploits, no brute force, no invasive scanning.

Pricing is simple:

- Free: 5 reports/month and 1 monitor.
- Pro: €19/month.
- Agency: €79/month.

The product is early, live and open to feedback.

Try it here:
https://osintpro-48j4.onrender.com/

GitHub:
https://github.com/haizen1312/osintpro

If you are a security consultant, investigator or fraud analyst, I would love to know what would make this more useful in a real client case.

### Reddit r/cybersecurity Post

**Title:** [Discussion] Built OSINTPRO - Passive OSINT for consultants (free tier available)

Hey r/cybersecurity,

I built OSINTPRO because a recurring pain point from small security consultants is not just finding public evidence. It is turning that evidence into something a client can understand quickly.

OSINTPRO is a passive-only OSINT workspace. It does not run exploits, brute force, port scan or try to replace proper authorization. The goal is to collect public evidence, normalize it, explain it, connect it in a graph and export it for reporting.

Current features:

- Domain OSINT: DNS, IP, HTTPS certificates, headers, email security posture.
- Entity graph: connect domains, findings, wallets, usernames and evidence.
- Exports: PDF, CSV, JSON-LD and DOT for Graphviz.
- Repository Audit Lab: defensive source review with SARIF export.
- Wallet OSINT: public wallet balances, flows, counterparties, notes and tags.
- Monitoring and webhooks: track changes and trigger external alerts.

Pricing:

- Free: 5 reports/month and 1 monitor.
- Pro: €19/month.
- Agency: €79/month.

Live:
https://osintpro-48j4.onrender.com/

GitHub:
https://github.com/haizen1312/osintpro

I would appreciate technical feedback, especially from people who do client reporting, fraud investigation or pre-engagement passive recon. What is missing before this becomes useful in your workflow?

## 5. Demo GIF Script

```
[0-4 sec] Open OSINTPRO home. Show the dossier-style dashboard and the domain analysis input.
[4-8 sec] Type "example.com" into the domain field and click "Analyze Domain".
[8-13 sec] Show the generated report summary: score, IP/DNS signals, HTTPS certificate, email posture and findings count.
[13-17 sec] Scroll to findings. Highlight plain-English evidence and recommendations instead of raw-only output.
[17-21 sec] Open the entity graph. Show domain, findings and related evidence connected visually.
[21-24 sec] Click graph export and select DOT or JSON-LD. Show the file download starting.
[24-27 sec] Add the domain to monitoring. Show monitor status active.
[27-30 sec] Show pricing strip: Free, Pro €19/month, Agency €79/month. End on "Try Free".
```

Core message of the GIF: domain in, evidence normalized, graph exported, monitor active.

## 6. Launch Day Timeline

### 11:30 PM - 30 minutes before launch

- [ ] Open Product Hunt launch draft.
- [ ] Open OSINTPRO live app: https://osintpro-48j4.onrender.com/
- [ ] Open GitHub repo: https://github.com/haizen1312/osintpro
- [ ] Confirm `/api/health` returns OK.
- [ ] Confirm `/login`, `/register` and `/forgot-password` load.
- [ ] Keep this FAQ document open for fast replies.
- [ ] Prepare screenshot/GIF assets.
- [ ] Prepare Twitter/X, LinkedIn and Reddit drafts.

### 11:50 PM - 10 minutes before launch

- [ ] Final Product Hunt title and tagline check.
- [ ] Confirm pricing in the PH copy matches the live app.
- [ ] Check the first comment from the maker is ready.
- [ ] Check all links use HTTPS.
- [ ] Put the live URL and GitHub URL in a notes file for fast copy-paste.

### 12:01 AM - Post live

- [ ] Click launch on Product Hunt.
- [ ] Copy the Product Hunt URL.
- [ ] Post the Twitter/X launch post with the PH link.
- [ ] Post the LinkedIn launch post.
- [ ] Send the launch link to close contacts who understand security products.
- [ ] Pin or save the PH tab.

### 12:15 AM - First check

- [ ] Confirm the PH page is visible publicly.
- [ ] Test the live app link from the PH page.
- [ ] Upvote/comment from the maker account if Product Hunt asks for maker context.
- [ ] Add a short maker comment: why we built it, passive-only boundary, what feedback we want.

### 1:00 AM - First engagement window

- [ ] Read the first comments.
- [ ] Reply to every question with short, specific answers.
- [ ] Use the objection handling snippets below.
- [ ] Do not argue with comparisons. Acknowledge good tools and explain the target audience.
- [ ] Note every feature request in a small launch notes file.

### 3:00 AM - Stability check

- [ ] Check live app health.
- [ ] Check signups or app activity if admin metrics are available.
- [ ] Check for broken links or reports of failed login.
- [ ] If a bug appears, fix it quietly and comment that it is patched.

### 6:00 AM - Overnight comments

- [ ] Respond to unanswered PH comments.
- [ ] Re-share the Twitter/X post if there is traction.
- [ ] DM 5-10 relevant security friends with a specific ask: "Can you test one domain and tell me what is unclear?"

### 9:00 AM - Reddit and community push

- [ ] Post in r/cybersecurity only if the community rules allow it.
- [ ] Make the post technical and feedback-oriented, not salesy.
- [ ] Share in any relevant founder/security communities where you already participate.
- [ ] Ask for critique on usefulness, not just upvotes.

### 12:00 PM - Midday review

- [ ] Check Product Hunt ranking.
- [ ] Reply to all new comments.
- [ ] Update the launch notes with repeated objections.
- [ ] Identify the top 3 feedback themes.

### 3:00 PM - Proof and momentum

- [ ] Share a short update: what feedback came in and what you are already improving.
- [ ] Highlight one use case: consultant reporting, wallet fraud reconstruction or passive domain review.
- [ ] Avoid fake social proof. Share real numbers only.

### 6:00 PM - Metrics update

- [ ] Record upvotes, comments, signups, Pro clicks and any paid conversions.
- [ ] Share a short, honest update if there is meaningful activity.
- [ ] Thank early testers.

### Day 2 - 24 hours later

- [ ] Respond to all remaining PH comments.
- [ ] Add the most common feature requests to GitHub issues or roadmap.
- [ ] Post a follow-up: "What we learned from launch day."
- [ ] DM serious commenters and ask for a 10-minute feedback call.

### Day 3

- [ ] Thank top supporters.
- [ ] Announce any quick fixes shipped after launch.
- [ ] Share one concrete workflow example.
- [ ] Decide whether the next growth channel is Product Hunt follow-up, LinkedIn agency outreach, Reddit feedback or direct consultant calls.

## 7. Positioning Variants

### Variant A: For Consultants

For security consultants who spend too much time turning OSINT into client reports, OSINTPRO is a passive investigation workspace that turns public evidence into readable findings, graphs and exports. It is not trying to replace enterprise platforms like Maltego; it is built for smaller teams that need clear deliverables fast.

### Variant B: For Investigators

For fraud analysts and investigators who need fast relationship mapping, OSINTPRO connects domains, wallets, usernames and findings into a graph that can be exported and monitored. The focus is passive evidence and case reconstruction, not aggressive scanning or exploitation.

### Variant C: For Learners

For security learners and beginners who want hands-on OSINT without legal risk, OSINTPRO explains passive signals in plain language and keeps the workflow inside safe boundaries. It helps users understand domains, headers, repositories, wallet flows and network concepts without turning into an offensive toolkit.

## 8. Objection Handling

**Objection: "Why should I use this vs Maltego?"**  
Response: Maltego is a strong enterprise graph platform, and we are not trying to pretend otherwise. OSINTPRO is for smaller teams that want passive evidence, simpler client-ready reporting, monitoring and a lower monthly cost.

**Objection: "Is this legal?"**  
Response: OSINTPRO is designed around public evidence and defensive workflows. It does not run exploits, brute force, bypass authentication, scan ports or perform unauthorized packet capture.

**Objection: "Why €19 and not $19?"**  
Response: We are EU-based, so EUR is the default pricing currency. Stripe handles international card payments and currency conversion, so users outside the Eurozone can still subscribe.

**Objection: "Can you do X feature?"**  
Response: Good idea. If it fits the passive-only boundary, we can add it to the roadmap and prioritize it based on how many real investigations it helps. The most useful detail would be the exact workflow you want it to support.

**Objection: "Why no team features yet?"**  
Response: We started with solo consultants and small agencies because the workflow is simpler to validate. Team workspaces and stronger collaboration are on the roadmap, but we want the core investigation and reporting flow to be solid first.

**Objection: "Can I self-host?"**  
Response: The code is public on GitHub, but official self-hosting support is not the main product yet. Right now, the hosted app is the supported path, and production self-hosting docs will come after the SaaS flow is more stable.

**Objection: "Is this just a wrapper around public tools?"**  
Response: OSINTPRO uses public evidence because that is the point: passive-only intelligence. The value is normalization, explanation, graphing, exports, monitoring and client delivery in one workflow.

**Objection: "Can it replace a security analyst?"**  
Response: No. It helps collect and organize passive evidence, but a human still needs to interpret context, validate importance and decide what belongs in the client report.

**Objection: "Why not add active scanning?"**  
Response: Because that changes the legal and operational risk of the product. OSINTPRO is intentionally positioned as passive investigation and defensive evidence packaging, not an offensive scanning suite.

**Objection: "The product is early. Why pay now?"**  
Response: That is fair. The free tier is there so you can test the workflow first, and Pro is meant for people who already see value in unlimited reports, monitoring and webhooks.
