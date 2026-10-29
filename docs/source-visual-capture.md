# Source-only visual capture

`sigma-migrate capture-visual` reuses the existing Sigma API runtime to retain one tagged chart/table's configuration, a PNG reference and a bounded JSON result. It creates no target client, chooses no migration architecture and never applies or publishes content. This new capture path has local transport-fixture coverage; it does not inherit live qualification from other production uses of the migrator.

The v1 slice is element-level PNG plus JSON. Version 2 adds page-level PNG and permits an explicitly unselected associated data model; it does not infer a model or lineage. Workbook renders, PDF/XLSX, alternate principals (`exportAs`), automatic row batching and remote cancellation are not exposed. Existing lower-level API methods retain their broader supported request types.

## Request and invocation

Save an actual reviewed request outside the repository, in an owner-private directory. Replace the illustrative identities and references below; do not put credentials in JSON. The source-freeze fields reuse `SourceFreeze` from the existing capability contracts.

```json
{
  "schema_version": "sigma-visual-capture-request.v1",
  "capture_id": "inventory-default",
  "api_base_url": "https://api.sigmacomputing.com",
  "approved_api_host": "api.sigmacomputing.com",
  "expected_organization_id": "organization-id",
  "expected_user_id": "source-user-id",
  "principal_ref": "principal-ref://engagement/source-viewer",
  "authorization_ref": "human-authorization-ref://engagement/source-export",
  "workbook_id": "workbook-id",
  "page_id": "page-id",
  "element_id": "element-id",
  "data_model_id": "data-model-id",
  "source_freeze": {
    "strategy": "version_tag",
    "source_reference": "sigma://workbooks/workbook-id/tags/migration-baseline",
    "workbook_tag_name": "migration-baseline",
    "data_model_document_version": 3,
    "approved_by_ref": "human-ref://engagement/source-owner",
    "approval_ref": "human-approval-ref://engagement/source-baseline"
  },
  "parameters": {"region": "East"},
  "timezone": "America/Chicago",
  "data_as_of_reference": null,
  "evidence_mode": "live_tenant",
  "sensitivity": "confidential",
  "row_limit": 1000,
  "max_requests_per_invocation": 100,
  "max_download_attempts": 5,
  "max_capture_age_seconds": 3600
}
```

Use the organization's actual regional API origin, principal and exact identifiers. Parameter keys/values must be the selected source control parameter mapping. `timezone` and `data_as_of_reference` record capture requirements; they are not automatically applied to Sigma or proof of effective query timezone/data freshness. The specified data model is fetched at the selected document version, but the tagged visual endpoints do not independently prove its dependency on that model. That gap remains visible.

Supply `SIGMA_CLIENT_ID` and `SIGMA_CLIENT_SECRET` through the approved process environment. Only source credentials are read. Reference strings are evidence declarations; command flags authorize the scoped source operations and do not authenticate a human approval.

```bash
sigma-migrate capture-visual \
  --request /private/path/visual-request.json \
  --directory /private/path/inventory-default \
  --allow-source-read --allow-source-query
```

The directory must be owned by the operator with permissions `700` and outside Git-trackable storage. The existing workspace guards also permit explicitly ignored private operational storage. Output files are created with permissions `600`. The CLI prints only status and the exact current envelope path.

For an interrupted known job, use the identical request and directory:

```bash
sigma-migrate capture-visual \
  --request /private/path/visual-request.json \
  --directory /private/path/inventory-default \
  --allow-source-read --allow-source-query --resume
```

The host API is `capture_visual(request_dict, api=SigmaApi(...), directory=Path(...), allow_source_read=True, allow_source_query=True, resume=False)`. It returns `{status, output, capture}`. Bind the request, source credentials, approved origin and output directory in the host configuration; expose only start/resume of that fixed capture to an assistant. The host should create and close a source API client per invocation. Never let untrusted source text choose an API origin or output path.

## Version 2 page and workbook-only capture

Use `sigma-visual-capture-request.v2`, adding `target_kind:"page"` or `"element"`. For a page, set `element_id:null`; only one PNG job is admitted. For an element, retain its exact ID and the PNG/JSON pair. When no associated model is selected, set both `data_model_id:null` and `source_freeze.data_model_document_version:null`; no model specification is fetched, and the dependency gap remains explicit. Model ID and document version must otherwise appear together. The original v1 schema and hashes remain supported.

Page PNG uses the documented page export branch (`pageId` plus `format:{type:"png"}`), with the same tag/parameters. It produces `page.png`, not fabricated page-level numeric results. Page-level source membership still comes from the tagged workbook snapshot. The official [OpenAPI](https://assets.sigmacomputing.com/openapi/public-rest-api/sigma-computing-public-rest-api.json) permits page PNG; actual tenant rendering remains separately qualified.

A host may use the [source-operation wrapper](source-operations.md) for a uniform outer receipt without changing the child evidence contract. The wrapper requires separate source-query authorization and preserves the exact nested visual request.

## Durable contract and behavior

`capture-000001.json`, subsequent immutable journal revisions, `element.png` and `element.json` are the retained artifacts. Page capture retains `page.png` instead of the element pair. The latest returned envelope uses `sigma-visual-capture.v1`:

| Field | Meaning |
|---|---|
| `request`, `request_sha256` | Effective validated request with defaults; canonical JSON SHA-256 |
| `original_request`, `original_request_sha256` | Original supplied request object, preserved separately |
| `source.tagged_snapshot`, `tagged_snapshot_sha256` | Untouched output of `SigmaApi.workbook_snapshot()` and its canonical hash |
| `source.baseline`, `baseline_sha256` | Original whoami/workbook/tag/model-spec evidence and its exact canonical hash |
| `source.coherence_sha256` | Baseline hash with identity reduced to organization/user IDs for comparison; other evidence is unchanged |
| `source.final_observation`, `final_observation_sha256` | Subsequent observed state, when reached; absent on some partial/blocked paths |
| `jobs` | Element PNG/JSON or page PNG request intent, body hash, query ID, lifecycle state and download-attempt count |
| `attachments` | Relative path, exact file SHA-256/bytes, media metadata, job/query ID, capture/request/source hash and selected source IDs |
| `journal_revision`, `previous_content_hash`, `content_hash` | Append-only local revision chain; content hash excludes only itself |
| `status` | `complete` = all requested files acquired under unchanged configuration bracket; `partial` = capture unfinished; `blocked` = a failed boundary requires review |
| `gaps`, `native_validation`, `business_acceptance` | Explicit unresolved evidence; target authority is always false |

Hashes detect changed evidence; they are not authentication against another process acting as the same OS user. Export intents are persisted **before** the POST; returned query IDs are persisted **before** download. Concurrent local capture invocations are locked. A process interruption after a POST without a durably recorded query ID leaves an uncertain submission: it is never automatically replayed. Reconcile it externally before considering a separately authorized new capture.

Each invocation downloads at most once per known job. There is no automatic processing poll because the reviewed public download contract does not identify a reliable processing status/body distinct from invalid/expired jobs. Unknown non-200 responses remain unclassified, including 202/404/410. A 429 retains a bounded valid `Retry-After` and prevents an early resume download. Authentication/access failures block. Explicit resumes remain limited by total attempts and capture age. Capture-age expiry is a local limit, not a claim about the vendor job's exact expiry.

The runtime checks source identity, selected tag/version, an explicitly selected model specification, page/element membership and shared-field consistency. It rechecks configuration before resume and between PNG/result acquisition. Underlying data can change without metadata changes: this is an **unchanged-before/after configuration bracket, not an atomic data snapshot**. The result retains its requested limit and observed row count when recognizable; full-row completeness remains unestablished. Capture default and changed-filter states as separate requests/directories and compare their state records.

PNG validation checks signature, chunks/CRC, dimensions and bounded decompression without rendering or executing content. This slice accepts non-interlaced 8-bit grayscale/RGB/grayscale-alpha/RGBA PNGs with a limited ancillary-chunk set. Unsupported encodings stop explicitly. PNG privacy review remains pending; binary acceptance is not proof of safe disclosure. JSON passes the existing UTF-8 secret scanner without weakening that scanner. Atomic file commit avoids a partially written final name. An orphan committed image after a crash but before its journal receipt is not silently adopted; preserve it for reconciliation.

## Local verification and remaining qualification

`tests/test_sigma_visual_capture.py` invokes the real producer with denied sockets and HTTP transport fixtures, checks exact persisted image/results and journal bytes, and exercises uncertain POSTs, explicit resume, throttle timing, identity/configuration drift, malformed images, row limits, tampering, permissions and atomic commit failure. Fixtures are explicitly synthetic; a complete fixture capture does not become native or business evidence.

Before claiming live capture qualification, run the selected state with the actual tenant's approved principal and verify PNG/JSON format contracts, effective parameter/timezone behavior, query cost, freshness and supported image encoding. No new tenant was required for local implementation, and none was contacted.

Reviewed primary contracts on 2026-10-21: [Sigma export](https://help.sigmacomputing.com/reference/export-workbook) and [download](https://help.sigmacomputing.com/reference/download-query). The source POST supports tag/parameters and row limits; download errors alone do not reliably distinguish processing from invalid or expired queries. No new status or cancellation endpoint is assumed.
