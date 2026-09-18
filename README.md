# D365 Security Enumerator

A Dynamics 365 Customer Engagement / Dataverse Web API enumeration and
controlled-validation tool for authorized security assessments. It authenticates through an
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
- Automatic visible-record counts for every addressable entity using the entity-set `/$count` endpoint, with a `$count=true` collection fallback for incompatible entity sets.
- Metadata-driven secrets and configuration scanning.
- Masked findings with SHA-256 fingerprints and record-specific verification URLs.
- Localhost-only dashboard with tabs, search, filters, entity metadata links, Excel export, and expandable JSON.
- Likely custom plug-in assembly inventory with targeted DLL download and strings extraction.
- Controlled `If-Match` PATCH tester available on every enumerated entity, using a server ETag when available and `If-Match: *` as an update-only fallback when Dynamics omits the ETag.

Normal enumeration and export use HTTP `GET` requests only. The dashboard also contains an explicit, controlled PATCH tester for authorized, reversible validation. The tester is available on every enumerated entity with a metadata ID; mapped `Write` privilege is shown as context but is not used as a gate, so the live Dynamics response is the authorization result.

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

Keep `d365_enum.py` and `d365_dashboard.py` in the same directory when using
the integrated dashboard.

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

## Plug-in assembly inventory

When the authenticated user can read the standard `pluginassembly` table, the
enumerator lists likely customized/non-Microsoft assemblies using this heuristic:

```text
customizationlevel gt 0
and publickeytoken ne '31bf3856ad364e35'
and not contains(name, 'Microsoft.')
```

The result JSON stores metadata only, including the assembly ID, name, version,
source type, isolation mode, public key token, modification details, and API
verification links. The Base64 `content` value is never requested during normal
enumeration and is never added to `d365_enum.json`.

Launch the dashboard directly from an authenticated enumeration run to enable
live actions:

```bash
python d365_enum.py https://crm.example.test/Organization --dashboard
```

The **Plug-in assemblies** tab then provides, one assembly at a time:

- **Download DLL**: retrieves `content`, decodes Base64 in memory, and sends the
  selected DLL to the browser without persisting it in the dashboard or JSON.
- **Relevant strings**: extracts ASCII and UTF-16LE strings and returns strings
  matching security-relevant concepts such as URLs, API routes, credentials,
  tokens, connection strings, SharePoint, Elasticsearch, Tika, and SQL.
- **All strings**: returns up to 5,000 unique strings for the selected assembly.

The strings panel opens directly below the selected assembly row. Opening strings
for another assembly automatically closes the previously opened panel.

There is deliberately no bulk-download action. The filter is heuristic:
third-party assemblies may be included, and client assemblies using unusual
names or signing arrangements may be missed.

When an old result is opened with the standalone dashboard command, the
inventory remains available but DLL and strings actions are disabled because
no authenticated Dynamics session is retained:

```bash
python d365_dashboard.py --input d365_enum.json
```

Use a .NET decompiler such as ILSpy or dnSpyEx for full source-level review of a
downloaded DLL. The integrated strings view is triage, not decompilation.

## Dashboard entity export and metadata links

The dashboard header contains one **Export entities** action. It downloads a single
Excel workbook with all default and custom entities in one sheet. The export contains:

```text
Entity, Type, Access status, Create, Read, Write, Delete, Assign, Share, Append, AppendTo, Visible records, URL
```

Each entity row in the dashboard also includes a direct **Metadata** link. The
**Readable organization settings** section has a search field covering the setting
group, name, and value.

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
- **Visible record count**: the integer returned by `/<entity-set>/$count`, or by the collection `@odata.count` fallback, for the authenticated user. A value of `0` can mean the entity is empty or that record-level security filters all rows.
- **Entity metadata link**: opens `EntityDefinitions(LogicalName='<entity>')` for the selected entity.
- **Export entities**: downloads one Excel workbook containing all default and custom entities, access state, detected privilege depths, visible-record count, and API URL.
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
- Record-level sharing, access-team grants, hierarchy reach, ownership, and cascading access remain unknown when listed as not evaluated.
- Verification links may expose sensitive data when opened and should be handled
  under the engagement's evidence and data-retention rules.
- Plug-in DLLs and extracted strings may contain proprietary code, internal URLs,
  credentials, or customer-specific logic and must be handled as assessment data.

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

## Controlled entity update tests

When the dashboard is launched directly from the enumerator, **every enumerated entity with a metadata ID** shows a **Test update** action. The privilege inventory is deliberately advisory here: a mapped `Write` privilege is displayed for context, but the dashboard does not require it before allowing the test. This makes it possible to validate whether the server actually accepts or rejects an update even when privilege metadata is missing, inconsistent, or says `Write` is not held.

The live Dynamics response is authoritative. A successful PATCH demonstrates that the selected record/attribute was updateable in the current authenticated context; a rejected PATCH remains useful authorization evidence. The tester does not automatically iterate records or fields.

This is specifically useful for validating the privilege enumerator: if the inventory reports `Write = not held` but the server accepts the conditional PATCH, that discrepancy is evidence that the local privilege mapping needs review. Conversely, a rejected PATCH helps confirm that a reported non-held Write privilege is not a false positive.

The workflow is intentionally manual and targeted:

1. Select one entity and open **Test update**.
2. Enter a dedicated test record GUID.
3. Load supported writable attributes.
4. Select a harmless, reversible attribute and load its current value.
5. Confirm and submit the conditional PATCH.
6. Restore the original value after validation.

The updater asks Dynamics metadata for attributes where `IsValidForUpdate` is true and supports simple field types only. Lookups, owners, customers, party lists, files, images, virtual fields, and other complex attributes are excluded. The tool still requires a successful current-value read before PATCH. When Dynamics returns a record ETag, that exact ETag is used for optimistic concurrency. When Dynamics omits the ETag, the dashboard stores `*` and sends `If-Match: *`; this keeps the request update-only and prevents creation of a missing record through upsert behavior, but it does not protect against another writer changing the record between the read and PATCH.

Some internal tables, such as `applicationfile`, support `RetrieveMultiple` but reject the keyed `Retrieve` message. When Dynamics returns that specific error, the dashboard automatically retries with a filtered collection query using the primary ID, captures the same record value and any returned ETag, and uses the same fallback for post-PATCH verification.

The feature requires the live authenticated session created by:

```bash
python d365_enum.py https://host/OrgName --dashboard
```

The browser cookies stay in memory in the local dashboard process. They are not saved to `d365_enum.json` or another file. Reopening an existing JSON with `d365_dashboard.py` provides inventory-only mode and disables update actions.
