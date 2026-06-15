# OSINTPRO Monetization Checklist

OSINTPRO should be sold as passive intelligence for domains, brands, public usernames and public blockchain wallets.

Do not position it as an offensive scanner. The value is in readable reporting, monitoring, prioritization and investigative workflow.

Live app:

```text
https://osintpro-48j4.onrender.com/
```

## Offer

- Free: 5 starter reports and 1 monitored domain.
- Pro: 19 EUR/month, unlimited reports, 5 monitored domains, PDF/CSV and wallet OSINT.
- Agency: 79 EUR/month, client reporting workflows, 25 monitored domains, Red/Purple Team guidance, wallet OSINT and entity graph.

## Stripe Setup

Create two Stripe Payment Links:

- OSINTPRO Pro, 19 EUR/month.
- OSINTPRO Agency, 79 EUR/month.

Production variables:

```bash
OSINTPRO_STRIPE_PRO_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_AGENCY_URL="https://buy.stripe.com/..."
OSINTPRO_STRIPE_WEBHOOK_SECRET="whsec_..."
```

Webhook endpoint:

```text
https://osintpro-48j4.onrender.com/api/stripe/webhook
```

Required event:

```text
checkout.session.completed
```

This version uses Payment Links so revenue can start before building a full billing portal. The backend appends user context to the Stripe link and the signed webhook activates the correct plan after payment.

## First Customers

Best initial targets:

- small web agencies
- freelance security/GDPR consultants
- SaaS founders
- ecommerce operators
- crypto fraud analysts
- compliance teams that need lightweight public wallet triage
- investigators documenting suspicious wallet movement

Short outbound message:

```text
I can prepare a passive OSINT report for your domain, brand, public username or public wallet address.

It covers DNS/TLS/email posture, public brand exposure, social username presence, or blockchain balance, movements and counterparties.

If you want recurring monitoring, client-ready PDF/CSV exports and an investigation graph, OSINTPRO starts at 19 EUR/month.
```

## What Not To Promise

- No guarantee of absolute security.
- No exploit, brute force or aggressive scanning.
- No certain attribution of usernames without manual verification.
- No certain attribution of wallets without external context, exchange/KYC data, legal process or verified investigation notes.
- No support for obfuscation, mixing, evasion or moving funds.

## Pricing Upsell Logic

Free users should feel value quickly but hit a natural ceiling:

- Free gives enough reports to understand the product.
- Pro removes report friction and adds practical monitoring.
- Agency is for repeat client work, case tracking and higher-volume monitoring.

## Growth Without Paid Ads

Free channels:

- GitHub search traffic through English README keywords and topics.
- Short posts showing sanitized example reports.
- Founder/security communities where passive domain intelligence is useful.
- Web agency outreach: offer a first free report for their own domain.
- Crypto safety communities: frame wallet OSINT as public transaction reconstruction, not deanonymization.
- Build-in-public updates whenever a useful feature ships.

## Features That Increase Willingness To Pay

- true server-side PDF export
- agency client folders
- saved investigation notes
- wallet graph hop expansion
- manual wallet tags such as exchange, scam, victim, mixer, bridge or unknown
- alerting on monitor changes
- stronger admin analytics
- PostgreSQL migration after revenue supports hosting costs
