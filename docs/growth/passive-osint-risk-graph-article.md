# Building a passive OSINT workspace without overstating risk

I am building OSINTPRO, a passive OSINT workspace for consultants,
investigators and security-minded founders.

The product started from a simple problem: public evidence is easy to collect,
but hard to turn into something a client or business owner can actually use.

A DNS record, certificate entry, repository finding or wallet transaction can
matter. But it is not automatically proof of compromise. That distinction is
important. If a report overstates the risk, it becomes noise. If it hides the
risk behind raw technical output, it does not help the owner fix anything.

The current direction is to separate every signal into four layers:

- confirmed evidence: what was actually observed from public sources
- passive enrichment: context from public sources such as CT logs, DNS,
  dependency manifests or wallet explorers
- inferred risk: what could plausibly go wrong, clearly marked as an
  interpretation
- owner action: the concrete defensive step a domain owner, founder or
  engineering team can take

That model keeps the tool useful without turning it into an offensive guide.
OSINTPRO deliberately does not run exploits, brute force, credential attacks,
unauthorized packet capture or invasive scans. It is meant to help explain
public exposure and organize evidence, not to attack a system.

The modules are inputs into one workspace:

- Domain Intel for DNS, email posture, headers, RDAP and certificate evidence
- Social Intel for public username presence checks
- Wallet Trace for public blockchain balances, movements and counterparties
- Repository Audit Lab for static review leads and SARIF export
- Dependency advisory for npm, pip, Cargo and Composer manifests
- Web Audit Lab, Network Traffic Lab and Game Security Lab for defensive review
- Entity Graph export for JSON-LD, DOT and CSV workflows
- PDF/CSV reports for client delivery

The most useful feedback so far has been about confidence labels. A tool like
this should not say “this is vulnerable” when it only has enough evidence to
say “this deserves review.” The roadmap now treats confirmed, enriched and
inferred data differently, especially in the graph.

That is the part I am trying to get right: owner-ready risk explanations that
are realistic enough to drive action, but restrained enough to stay honest.

Live demo:
https://osintpro-48j4.onrender.com/

GitHub:
https://github.com/haizen1312/osintpro

Feedback I am looking for:

- What would you need to trust a passive OSINT report in a client workflow?
- Where should the line be between useful abuse context and too much offensive
  detail?
- Which passive sources are worth adding first if the product needs to stay
  transparent about cost and evidence quality?
