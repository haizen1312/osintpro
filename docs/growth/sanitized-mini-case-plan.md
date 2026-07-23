# Sanitized Mini-Case Plan

This plan turns OSINTPRO findings into short public examples that can be shared
without exposing sensitive targets, private customer data or offensive
procedures.

## Format

Each mini-case should use the same structure:

1. Confirmed evidence: what OSINTPRO actually observed from public sources.
2. Passive enrichment: public context that helps interpret the evidence.
3. Inferred risk: what might be true, labeled clearly as a hypothesis.
4. Owner action: what the site, repo or wallet owner can do next.

Do not include exploitation steps, credential guidance, bypass instructions,
payloads, private customer identifiers or unverified claims.

## Case 1: Domain Posture

Goal: show why email authentication and public web posture matter for a small
business domain.

Safe example structure:

- Evidence: missing or weak SPF/DMARC, missing security headers, observable CT
  names, public robots/sitemap paths.
- Passive enrichment: whether records are absent, present but weak, or present
  with a monitoring-only policy.
- Inferred risk: brand spoofing or browser-side hardening gaps, never stated as
  active compromise.
- Owner action: add SPF/DMARC, review MTA-STS/TLS-RPT, set safe security
  headers, review exposed public paths.

## Case 2: Repository Review

Goal: show how Repository Audit Lab helps developers triage risky patterns
without executing code.

Safe example structure:

- Evidence: file/line leads, dependency advisory matches, suspicious
  deserialization or unsafe URL handling patterns.
- Passive enrichment: confidence and applicability notes, `.gitignore` filtered
  paths, SARIF export availability.
- Inferred risk: where a developer should inspect trust boundaries.
- Owner action: update dependency, validate input, replace unsafe helper,
  add regression test.

## Case 3: Wallet Trace

Goal: show how Wallet OSINT helps track public movement without implying guilt.

Safe example structure:

- Evidence: public balance, recent transfers, counterparties and explorer links.
- Passive enrichment: manual labels such as exchange, service, bridge, mixer or
  unknown when those labels are justified.
- Inferred risk: unusual routing or repeated counterparties, always framed as a
  hypothesis requiring analyst review.
- Owner action: preserve explorer evidence, add case notes, tag counterparties,
  expand one hop only when it clarifies the timeline.

## Distribution Use

- README: link these examples as proof of the owner-ready report style.
- Product Hunt: use one mini-case per update instead of broad feature lists.
- LinkedIn: publish one human explanation every few days, capped at two posts
  per week.
- Reddit: use only when a community discussion asks for an example; avoid
  repeated link-first posts.
