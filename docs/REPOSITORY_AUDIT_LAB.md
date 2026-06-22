# Repository Audit Lab

Repository Audit Lab is a defensive static-analysis workflow for source code the user owns or is authorized to review.

It is designed for developers, small agencies and learners who want a readable security review before deploying a feature or handing a project to a client.

## How It Works

1. The user selects a repository folder in the browser.
2. The browser excludes dependency folders, build output, binaries and oversized files.
3. Eligible text files are sent to the OSINTPRO backend within strict file and size limits.
4. The backend applies static security rules without executing code.
5. Results show severity, confidence, file, line, redacted evidence, applicability and remediation.

OSINTPRO does not clone private repositories, install packages, run builds, execute uploaded code or retain the source bundle as a report.

## Current Checks

- private keys and live credential patterns
- hard-coded secret-like values
- user-influenced shell execution
- dynamic `eval`/`exec`
- unsafe Python pickle and YAML loading
- disabled TLS verification
- wildcard CORS patterns
- production debug mode
- SQL built with string interpolation
- dynamic `innerHTML` review leads
- committed `.env` files
- missing JavaScript dependency lockfiles

## Context And False Positives

Every result is a review lead, not proof of exploitability.

The report explains when a rule is relevant. For example:

- `innerHTML` is not automatically vulnerable when all values are safely escaped.
- debug mode is not a production issue when it exists only in isolated local configuration.
- a wildcard CORS policy may be acceptable for intentionally public, unauthenticated data.
- a secret-like string may be a fake fixture, but real-looking examples should still be replaced with invalid placeholders.

## Limits

- maximum 180 eligible text files per run
- maximum 180 KB per file
- browser bundle capped below 2 MB
- static pattern and context analysis only
- no dependency installation or runtime behavior analysis
- no exploit generation or automated attack validation

Future versions can add dependency advisory matching, framework-aware rules, saved audit history and pull-request review integrations.
