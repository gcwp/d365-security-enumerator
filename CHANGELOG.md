## 1.0.0

First public release. Promoted from the 0.5.x pre-release line; the development history below is retained for reference.

- Fixed controlled updates for Dynamics records whose Retrieve response contains no `@odata.etag` and no `ETag` response header.
- A successful current-value read now returns `etag="*"` in that case and the dashboard sends `If-Match: *`, allowing the authorization test to proceed while keeping the PATCH update-only.
- Preserved real server ETags when present, so optimistic concurrency remains in use where Dynamics supports it.
- Added dashboard messaging that distinguishes **record-version protected** updates from the **existing-record only** wildcard fallback.
- Added regression tests for missing-ETag fallback, real-ETag preservation, and wildcard PATCH handling.

## 0.5.3

- Confirmed the controlled PATCH validator is available for every enumerated entity with a metadata ID, regardless of the locally mapped `Write` privilege.
- The privilege inventory is advisory only for this validator; the live Dynamics response is authoritative and can therefore be used to detect privilege-mapping false positives or false negatives.
- Added regression coverage proving a PATCH is attempted even when the result JSON says `Write.held = false`.
- Existing safeguards remain: live authenticated dashboard session, explicit record GUID, `IsValidForUpdate` attribute filtering, current-value read, ETag/`If-Match`, operator confirmation, and no bulk iteration.

## 0.5.2

- Removed the entity-access deviation assessment feature and bundled YAML matrix.
- Removed the **Access deviations** dashboard tab, overview count, entity deviation badges/filters, and deviation columns from the entity Excel export.
- Removed `--deviation-matrix` and `--no-deviation-assessment` from the CLI and stopped writing `deviation_assessment` to result JSON.
- Removed the `d365_deviation.py` module, `entityaccessdeviation.yaml`, PyYAML dependency, and deviation-specific tests/CI compilation.
- Kept the v0.5.1 any-entity controlled update behavior unchanged.

## 0.5.1

- Made the controlled **Test update** action available on every enumerated entity with a metadata ID, not only entities where the privilege inventory reports `Write` as held.
- Removed the server-side mapped-Write gate from updateable-attribute discovery; the actual Dynamics GET/PATCH response now determines whether the selected record can be updated.
- Kept the existing safety properties: live authenticated session only, explicit record GUID, `IsValidForUpdate` metadata filtering, successful current-value read, ETag-protected conditional PATCH, manual confirmation, and no bulk update behavior.
- The dashboard now displays mapped Write status/depth as advisory context in the update panel.
- Added regression tests covering attribute discovery when Write is not mapped and the live-session requirement.

## 0.5.0

- Added a safe-loaded YAML deviation engine using the bundled `entityaccessdeviation.yaml` standard-user baseline.
- Evaluates named entity access ceilings from held privileges and collection-probe evidence.
- Evaluates special-entity exposure rules with per-rule severity escalation.
- Detects owner-team-only privileges and reports POA, access-team, and hierarchy record reach as explicit coverage states.
- Skips standard-user findings when the stable System Administrator role-template GUID is assigned.
- Adds an Access deviations dashboard tab, entity-row deviation badges and filters, JSON evidence, unresolved matrix entities, and coverage gaps.
- Adds deviation severity and finding count to the entity Excel export.
- Adds `--deviation-matrix` and `--no-deviation-assessment` CLI options.
- Adds PyYAML and deviation-engine unit tests.
- Corrected the matrix mailbox ceiling to allow Read at User depth while flagging broader or mutating access.

## 0.4.3

- Restored the canonical Dataverse OData headers for `/<entity-set>/$count`; v0.4.2's `text/plain`/header-stripping request caused all counts to fail on some Dynamics 365 on-premises deployments.
- Added an exact-count fallback using `?$select=<primary-id>&$top=1&$count=true` and parses `@odata.count` before degrading to an access-only collection probe.
- Preserves the failed scalar count diagnostics in `count_endpoint_error` when the query-option fallback succeeds.

## 0.4.2

- Sends entity `/$count` requests with browser-like `Accept: text/plain` headers and removes inherited OData JSON headers for better Dynamics 365 on-premises compatibility.
- Keeps count response diagnostics and exposes an `Open count` link when a count is unavailable.
- Adds simple seven-stage CLI progress messages immediately after browser authentication.
- Embeds the supplied Spartan logo in the dashboard header.

## v0.4.1
- Fixed scalar `/$count` parsing for UTF-8 BOM, quoted values, JSON scalar values, and common OData wrapper objects.
- A successful but unrecognized count response now falls back to a one-row collection probe instead of being mislabeled as an access failure.
- Restored secret/configuration scanning when readable entities were previously classified as `NON_JSON_RESPONSE` by the count parser.
- Added a `Type` column (`Default` or `Custom`) to the single-sheet entity export.
- Replaced the Excel label `Unexpected response` with `Unrecognized response` and added an explanatory notice when the secret scan has no results.

## v0.4.0
- Visible-record counts now run automatically for every entity through `/<entity-set>/$count`; the `--entity-counts` flag was removed.
- Retained a one-row collection fallback when a special entity rejects `/$count`, so readable entities are not lost from the access inventory.
- Added one-click Excel export for all default and custom entities in a single sheet.
- Added a direct metadata link for every entity in both dashboard entity tabs.
- Added search to the Readable organization settings table.

## v0.3.1
- Added an automatic RetrieveMultiple fallback for internal entities that reject the keyed Retrieve message.
- The fallback reads the target record with a primary-key filter, preserves the record ETag, and is also used to verify a successful PATCH.
- The controlled update panel now shows whether the value was read through Retrieve or the RetrieveMultiple fallback.

## v0.3.0
- Added a controlled entity update tester to the Default and Custom entity tabs.
- Available for every entity where the authenticated user holds Write at Basic, Local, Deep, or Global depth.
- Retrieves writable attribute metadata only when selected.
- Requires an explicit record GUID and a successful current-value read before PATCH.
- Uses the record ETag for a conditional update and prevents blind/upsert-style writes.
- Supports simple Boolean, numeric, text, memo, date/time, GUID, choice, state, and status attributes.
- Cookies remain only in the live dashboard process and are never written to the enumeration JSON.

## v0.2.2
- Entity enumeration now includes **all default and custom entities** instead of a focused default-entity subset.
- Dashboard labels updated to reflect full default-entity coverage.

# Changelog

## 0.2.1 - 2026-07-17

- Display plug-in strings directly below the selected assembly row.
- Automatically close the previously opened strings panel when another assembly is selected.
- Added an explicit Close button to each inline strings panel.

## 0.2.0 - 2026-07-17

- Added likely custom plug-in assembly enumeration without retrieving binary content.
- Added a dedicated Plug-in assemblies dashboard tab.
- Added targeted, in-memory Base64 decoding and DLL download for one selected assembly.
- Added ASCII and UTF-16LE strings extraction with security-relevant filtering.
- Disabled live plug-in retrieval when reopening a standalone JSON result without authentication.
- Kept assembly content out of enumeration JSON and omitted bulk download by design.

## 0.1.0 - 2026-07-16

- Browser-assisted authentication through Chromium.
- Dynamics Web API version detection.
- Organization settings and potential insecure-setting review.
- Direct and owner-team-inherited role enumeration.
- Effective privilege inventory with depth and source attribution.
- Separate default-entity and custom-entity access views.
- Optional visible-record counts.
- Masked secrets and configuration discovery with verification URLs.
- Localhost-only dashboard with filters, tabs, and JSON inspection.
