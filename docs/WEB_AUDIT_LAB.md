# Web Audit Lab

The OSINTPRO Web Audit Lab is a Burp Suite-inspired workflow for authorized, beginner-friendly web review.

It helps a user understand what a professional tester looks at before running any intrusive testing: scope, requests, responses, headers, cookies, public files, TLS, email posture and evidence quality.

## What It Includes

- Burp-style feature map: Target, Proxy, Repeater, Decoder, Comparer, Logger, Sequencer, Scanner, Intruder and Collaborator.
- Beginner explanations for technical terms.
- Safe commands using `curl`, `openssl` and `dig`.
- Evidence checklist for browser security headers and public metadata files.
- Vulnerability classes explained safely: XSS, SQL injection, IDOR, authentication/session risk, SSRF, file upload risk, command injection and CSRF.
- A clear authorized-use boundary.

## What It Does Not Include

- exploit payloads
- brute force
- credential attacks
- invasive crawling
- automated fuzzing
- callback exploitation
- attempts against third-party accounts or private user data

## Why This Design

Burp Suite is powerful because it helps testers understand traffic and validate findings. OSINTPRO borrows the learning workflow, not the risky automation.

The goal is to make a beginner understand:

- what a request is
- what a response is
- why headers matter
- how CSP and HSTS reduce browser-side risk
- how to collect evidence
- how to write a client-ready recommendation

## Authorized Workflow

1. Define the exact domain and account scope.
2. Run passive domain intelligence.
3. Open Web Audit Lab.
4. Review the evidence checklist.
5. Copy safe commands only for domains you own or are authorized to test.
6. Use the glossary to understand terms before changing requests in Burp Suite.
7. Document findings, screenshots and remediation steps.

## Responsible Use Notice

Use Web Audit Lab only on systems you own or are explicitly authorized to test. Misuse against third-party systems is prohibited and remains the responsibility of the operator.
