# D365 Security Enumerator

A read-only Dynamics 365 Customer Engagement / Dataverse Web API enumeration
tool for authorized security assessments. It authenticates through an
interactive Chromium session, reuses the resulting CRM cookies, writes a JSON
assessment artifact, and can open a local dashboard for review.

> **Authorized testing only.** Use this tool only against systems you own or
> have explicit permission to assess.

## Features

- Browser-assisted authentication; no password is passed to the script.
- Automatic Web API version detection for `v9.2`, `v9.1`, and `v9.0`.
- `WhoAmI`, organization identity, server version, and organization settings.
- Potential insecure-setting checks with direct verification URLs.
- Direct security roles and roles inherited through owner teams.
- Effective user privileges with Global, Deep, Local, and Basic depth.
- Separate access views for default entities and custom entities.
- Passive read probes: data visible, no visible data, access denied, and errors.
- Optional record counts limited to records visible to the authenticated user.
- Metadata-driven secrets and configuration scanning.
- Masked findings with SHA-256 fingerprints and record-specific verification URLs.
- Localhost-only dashboard with tabs, search, filters, and expandable JSON.

The enumerator uses HTTP `GET` requests for collection and verification. It does
not create, modify, assign, share, or delete Dynamics records.

## Requirements

- Python 3.10 or newer
- Chromium installed by Playwright
- A user account that can authenticate to the target Dynamics organization
- Network access to the Dynamics web application and Web API

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows PowerShell

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
playwright install chromium
```

## Basic usage

```bash
python d365_enum.py https://crm.example.test/Organization --dashboard
```

Authentication flow:

1. Chromium opens at the supplied Dynamics organization URL.
2. Sign in normally, including MFA or integrated authentication when required.
3. Wait until the target CRM organization has loaded.
4. Return to the terminal and press **Enter**.
5. The browser closes and enumeration begins with the authenticated cookies.
6. Results are written to `d365_enum.json` by default.
7. With `--dashboard`, the viewer opens on `http://127.0.0.1:8765/`.

The URL must identify the organization itself, for example:

```text
https://crm.example.test/Organization
```

## Common commands

```bash
# Compact CLI summary and JSON output
python d365_enum.py https://crm.example.test/Organization

# Full terminal output
python d365_enum.py https://crm.example.test/Organization --verbose

# Custom output path
python d365_enum.py https://crm.example.test/Organization \
  --output results/customer-test.json

# Force an API version
python d365_enum.py https://crm.example.test/Organization \
  --api-version v9.1

# Verify TLS certificates in Chromium and API requests
python d365_enum.py https://crm.example.test/Organization --verify

# Add visible-record counts; this sends an additional count request per entity
python d365_enum.py https://crm.example.test/Organization --entity-counts

# Use another dashboard port
python d365_enum.py https://crm.example.test/Organization \
  --dashboard --dashboard-port 9000
```

Show all options:

```bash
python d365_enum.py --help
python d365_enum.py --version
```

## Secrets and configuration scan

The module runs by default after entity access enumeration. It first examines
attribute metadata, then retrieves candidate text fields from readable entities.
Configuration-like entities receive broader inspection so key/value records such
as the following can be detected:

```json
{
  "name": "Payments.Api.ClientSecret",
  "value": "..."
}
```

Detection covers normalized singular/plural forms, camelCase, PascalCase,
underscores, dots, common aliases, JSON/XML keys, URLs, endpoints, connection
strings, tokens, API keys, client secrets, passwords, certificates, and private
key material.

Raw detected values are not written to the result JSON. Findings contain a
masked preview, value length, SHA-256 digest, source field, record identifier,
and a direct API verification URL.

```bash
# Inspect at most 500 records per candidate entity
python d365_enum.py https://crm.example.test/Organization \
  --secret-scan-limit 500 --dashboard

# Follow all available OData pages for candidate entities
python d365_enum.py https://crm.example.test/Organization \
  --secret-scan-limit 0 --dashboard

# Disable the module
python d365_enum.py https://crm.example.test/Organization \
  --no-secret-scan --dashboard
```

`--secret-scan-limit 0` can generate many requests and retrieve substantial
amounts of application data. Use it only when the assessment scope and data
handling rules permit it.

## Opening an existing result

```bash
python d365_dashboard.py --input d365_enum.json
```

Additional options:

```bash
python d365_dashboard.py --input results/customer-test.json --port 9000
python d365_dashboard.py --input d365_enum.json --no-browser
```

The dashboard binds to `127.0.0.1` only. Keep `d365_dashboard.py` in the same
directory as `d365_enum.py` when using the enumerator's `--dashboard` option.

## Understanding results

- **Readable with data**: the authenticated user could retrieve at least one row.
- **Readable with no visible data**: the collection request succeeded, but no row
  was returned. The table may be empty or record-level security may filter it.
- **Access denied**: the collection request was rejected for the current user.
- **Visible record count**: records visible to the current user, not necessarily
  the total rows stored in the environment.
- **Checks not evaluated**: the expected setting was not available in the
  readable `organizations` columns or parsed `OrgDbOrgSettings` data. This is an
  unknown result, not confirmation that the setting is secure.
- **Potential insecure setting**: a review signal that requires manual validation
  against the environment's requirements and threat model.

## Output sensitivity

Do **not** publish or commit assessment output. Even though detected secret values
are masked, a result file may contain:

- Internal URLs and hostnames
- User, team, role, and business-unit names
- Record identifiers and verification links
- Custom table and column names
- Security configuration and privilege mappings
- Masked secret previews and hashes

The included `.gitignore` excludes `output.json`, `d365_enum.json`, common result
filenames, and the `results/` and `reports/` directories. Confirm staged files
before every push:

```bash
git status
git diff --cached --name-only
```

## TLS behavior

Certificate verification is disabled by default to support internal assessment
environments using private or self-signed certificates. Use `--verify` when the
target certificate chain is trusted. With `--verify`, both the Chromium context
and API requests enforce certificate validation.

## Scope and limitations

- Intended for Dynamics 365 CE / Dataverse Web API 9.x, with an emphasis on
  on-premises deployments.
- Requires a valid authenticated session and does not bypass authentication.
- Results reflect the privileges and record access of the authenticated user.
- Installed solutions, customizations, and patch levels can change metadata and
  endpoint behavior.
- Secret detection is heuristic and can produce false positives or miss values
  stored in unusual formats.
- A denied or empty collection does not prove that another action, function,
  relationship, plug-in, workflow, or application endpoint cannot expose data.
- Potential insecure-setting checks are assessment aids, not automatic findings.
- Verification links may expose sensitive data when opened and should be handled
  under the engagement's evidence and data-retention rules.

## Repository safety

Before publishing a fork or release, search for client-specific data:

```bash
grep -RniE 'customer|internal-host|example-secret' . \
  --exclude-dir=.git
```

Never add cookies, credentials, HAR files, screenshots containing client data,
or unsanitized enumeration JSON.

## Security reports

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in the tool.
Assessment findings from a target environment must be reported through the
approved client channel, not in this repository's public issues.

## License

Released under the [MIT License](LICENSE).
