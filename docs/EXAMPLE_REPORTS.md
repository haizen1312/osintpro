# OSINTPRO Sanitized Example Reports

These examples show the type of client-ready output OSINTPRO produces without exposing private customer data or offensive testing steps.

## Passive Domain Snapshot

Target: `example.com`

Summary:

- Public DNS and HTTPS are reachable.
- Browser security headers should be reviewed.
- `security.txt` is not always present.
- Email posture should be checked for SPF, DMARC, MTA-STS and TLS-RPT.

Client-ready next steps:

1. Add or confirm security headers such as CSP, HSTS, X-Frame-Options and Referrer-Policy.
2. Publish `/.well-known/security.txt` with a responsible disclosure contact.
3. Review DNS records and certificate expiry during every monitoring cycle.

## Web Audit Lab Snapshot

Workflow:

- Scope the exact authorized domain.
- Read public headers with `curl -I`.
- Review TLS certificate metadata with `openssl`.
- Document missing headers, disclosure files and email security posture.

Boundary:

OSINTPRO does not provide exploit payloads, automated fuzzing, brute force, callback exploitation or invasive crawling.

## Network Traffic Lab Snapshot

Website traffic mode:

- DNS query explains how the browser finds the server IP.
- TCP/443 explains how HTTPS transport starts.
- TLS explains certificate issuer, subject and expiry.
- HTTP headers explain the browser-side security posture.

Own-network mode:

- Local IP context is shown only when OSINTPRO runs on the user's own machine.
- Wireshark filters focus on ARP, DNS, TCP/443, mDNS and DHCP/BOOTP.
- The hosted demo does not expose cloud server network details.

Boundary:

Capture only traffic from devices and networks you own or are explicitly authorized to inspect.

## Wallet OSINT Snapshot

Target: public wallet address

Summary:

- Public balance and recent movement are collected from public blockchain sources.
- Counterparties are ranked by observed transaction count and flow direction.
- Manual tags and case notes can mark exchange, scam, victim, bridge, service or unknown.
- Timeline view helps reconstruct suspicious flows without moving funds or claiming identity proof.

Boundary:

OSINTPRO does not move funds, deanonymize private users, bypass mixers or provide evasion guidance.
