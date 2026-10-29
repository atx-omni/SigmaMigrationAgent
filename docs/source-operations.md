# Source operations for a reviewed host

This extension provides fixed, noninteractive **source-only** operations. It does not choose a semantic route, accept a migration proposal, create an Omni client, build a target package, or publish anything. Existing terminal `review` remains required for the Sigma prepush build flow. A chat choice is not terminal acceptance.

## Capability and release binding

`sigma-migrate capabilities` reads no credentials and loads no third-party runtime modules. It emits `sigma-source-capabilities.v1`: runtime name/version, separate extension version, supported operations/evidence schemas, limits, and hashes for the current first-party Python source closure. The installed interpreter, entrypoint, dependencies and capability document must be pinned by the host separately. A capability file is compatibility evidence, not approval or publisher authentication.

The extension is identified as `sigma-source-operations` version `0.1.0`, alongside the existing `0.4.1` runtime. Its distribution status is `source_extension_requires_separate_reviewed_release`. Do not claim the original `f4eda45b0f49dc7335496d028665f7339ed82e8f` commit contains later working-tree files; publish and re-pin the exact reviewed distribution separately.

## Fixed request

Store the request outside tracked source. No credentials, arbitrary URLs, commands, SQL or target writes are accepted in this interface.

```json
{
  "schema_version": "sigma-source-operation-request.v1",
  "request_id": "selected-workbook",
  "operation": "snapshot",
  "api_base_url": "https://api.sigmacomputing.com",
  "approved_api_host": "api.sigmacomputing.com",
  "expected_organization_id": "organization-id",
  "expected_user_id": "source-user-id",
  "principal_ref": "principal-ref://engagement/source-viewer",
  "authorization_ref": "human-authorization-ref://engagement/source-read",
  "evidence_mode": "live_tenant",
  "max_requests": 100,
  "scope": {"workbook_ids": ["workbook-id"], "data_model_ids": []},
  "options": {"include_contents_beta": false}
}
```

| Operation | Meaning and boundary |
|---|---|
| `check` | Read whoami and explicitly selected workbook/model identities; readability is not dependency or effective-audience proof. |
| `inventory` | Bounded accessible workbook/model lists; nonempty selected lists filter the result. Empty lists request discovery, not organization-wide completeness. |
| `snapshot` | Selected workbook evidence, optional explicitly selected data models, and original dependency diagnostics. Empty data-model selection stays empty. |
| `capture` | One exact nested `visual_capture_request`; separately requires source-query authorization. Tagged element PNG/JSON or v2 page PNG. |

Snapshot/capture require explicit workbook IDs, up to ten for snapshot and exactly one for visual capture. `max_requests` is 5–500; the nested visual contract additionally requires 10–500. Capture's nested origin, principal, references, evidence mode, workbook/model selection and per-invocation budget must match the outer request. `include_contents_beta` is snapshot-only. Source references do not prove human authorization. The host fixes the reviewed request and supplies separate grants.

```bash
sigma-migrate capabilities
sigma-migrate source-operation --request /private/path/request.json \
  --directory /private/path/source-run --allow-source-read
```

For `capture`, add `visual_capture_request` containing an exact [visual capture request](source-visual-capture.md), and add `--allow-source-query`. Use identical request/directory plus `--resume` to append a metadata observation or resume the visual journal. The approved process supplies only `SIGMA_CLIENT_ID` and `SIGMA_CLIENT_SECRET`; the request cannot select an environment variable or target credential. No public CSV, Git integration or source changes are enabled.

## Evidence and resume

Every operation returns counts-free status/path metadata only:

```json
{"status":"captured_requires_review","output":"/private/path/source-run/source-operation-000001.json","output_sha256":"...","target_write_authority":false,"native_validation":"not_performed"}
```

The immutable `sigma-source-operation.v1` envelope contains request/request_sha256, operation, result/result_sha256, evidence mode, status, observed time, gaps, journal_revision, previous_content_hash and content_hash. Metadata operations retain observed organization/user. Snapshot `result` preserves the existing native acquisition shape (`connections`, `dataModels`, `workbooks`, diagnostics and acquisition metadata). No selected model means a visible unresolved-dependency gap, not inferred lineage. The normal Sigma semantic build continues to require its reviewed source/model prerequisites; workbook-only capture does not bypass them.

Capture `result.visual_capture` is null in a durable pending marker, then a receipt `{path,bytes,sha256,schema_version,status}` for `visual/capture-NNNNNN.json`. Inspect that separate journal and every attachment before downstream use. Capture status `complete` means the requested files were retained under its configuration bracket; it is not numerical completeness, native acceptance or business approval.

The outer journal uses compact sorted JSON with `ensure_ascii=True`, `allow_nan=False`; content_hash excludes only itself. Existing `sigma-visual-capture.v1` uses its established `ensure_ascii=False` canonical hash. Do not conflate the two. The outer receipt also pins exact visual file bytes. Journals are owner-private, exclusive-write and locally locked; the outer journal permits at most 64 records. The visual child persists POST intent before submission and never retries an ambiguous POST. It resumes only known query IDs. An interrupted outer wrapper cannot discard the child's uncertain submission record. Hosts must also enforce durable total requests/invocation budgets and immutable runtime/request pins.

## Optional workbook contents Beta

Explicit `include_contents_beta:true` adds `_sigma_contents_beta` to the snapshot result using `GET /v2/workbooks/{id}?includeContents=true`. Each `sigma-workbook-contents-evidence.v1` record retains the response, its hash, schemaVersion when present in a JSON object, and omissions. String/YAML contents remain opaque and are never parsed or executed.

This is current workbook contents, **not a tagged or saved-view definition**. It cannot silently replace tagged visual evidence. Preserve separate version evidence; a consumer must reconcile it before parity claims. Known documented omissions include input-table data, webhook HMAC secrets, tagged versions, comments and sharing; referenced assets are not embedded and duplicate-table-name round trips need review. Missing or inaccessible Beta contents fail this explicit acquisition; do not fall back silently and claim equivalent coverage.

Official contracts: [workbooks as code (Beta)](https://help.sigmacomputing.com/docs/manage-workbooks-as-code), [Sigma OpenAPI](https://assets.sigmacomputing.com/openapi/public-rest-api/sigma-computing-public-rest-api.json). REST acquisition is distinct from optional MCP discovery/results; no MCP capability or tagged-state equivalence is inferred here.

## Verification limits

The new `test_sigma_source_operations_stdlib.py` checks pure contracts, injected metadata acquisition and exact lifecycle source functions with inert boundary adapters. It runs under `python3 -I -S -B` without third-party imports. These checks do not qualify the installed HTTP/Pydantic/scanner stack. Additional v2 transport fixtures are retained in `test_sigma_visual_capture.py`; their dependency-backed execution requires scoped authorization. No live tenant, privacy, effective state, source freshness, numerical completeness or Omni delivery acceptance is asserted by this extension.
