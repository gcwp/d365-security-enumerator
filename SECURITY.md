# Security policy

## Reporting a vulnerability in this project

Please report vulnerabilities in the tool privately to the repository owner
instead of opening a public issue. Include the affected version, reproduction
steps, expected impact, and a minimal sanitized proof of concept.

Do not include credentials, session cookies, client data, internal URLs, or
unsanitized `d365_enum.json` output in an issue or pull request.

## Assessment findings

This repository is for the scanner itself. Findings discovered in a tested
Dynamics 365 environment must be reported through the assessment's approved
client channel, not through this project's issue tracker.

## Authorized use

Use the tool only on systems you own or are explicitly authorized to assess.
The operator is responsible for defining scope, handling collected data, and
complying with applicable law and contractual requirements.

## Controlled update tester

The local dashboard can send a real PATCH only when it is launched from a live authenticated `d365_enum.py --dashboard` process. The tester is intentionally available for every enumerated entity instead of being gated by the locally reconstructed Write privilege. This is for authorization validation: the target Dynamics server remains authoritative.

The tester still requires an explicit record GUID, an updateable attribute returned by metadata, a successful current-value read, and operator confirmation. If Dynamics returns a record ETag, the tester uses it for optimistic concurrency. If Dynamics omits the ETag, the tester uses `If-Match: *` so the PATCH remains update-only; this prevents upsert of a missing record but does not detect concurrent changes by another writer. Use a dedicated test record and restore the original value after validation.
