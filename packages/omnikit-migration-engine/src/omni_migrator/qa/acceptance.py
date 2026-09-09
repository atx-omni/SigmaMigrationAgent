"""Immutable, fail-closed Domo-to-Omni QA acceptance-suite contracts.

The contracts in this module deliberately separate three things:

* v2 fixtures and results describe individual comparisons;
* an acceptance suite closes the exact per-migration-unit denominator; and
* a trusted evidence snapshot and registration bind that suite to current artifacts.

None of these records grants tenant acceptance, release, promotion, cutover, or
source-decommission authority.  Store-backed resolver and append implementations
live in the control plane so this module remains independent of persistence.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Annotated, Any, Literal, Mapping, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json
from omni_migrator.control_plane.records import ArtifactEnvelope

_SHA256_PATTERN = r"^sha256:[a-f0-9]{64}$"
_RAW_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_STABLE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{7,127}$"
_NON_SECRET_REF_PATTERN = r"^[A-Za-z][A-Za-z0-9+.-]*:.+$"
_ACTOR_REF_PATTERN = r"^(?:agent-ref|human-ref|person-ref|person):.+$"
_QA_SUBJECT_REF_PATTERN = r"^qa-subject-ref://[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$"
_ZERO_HASH = "sha256:" + "0" * 64

EvidenceClass = Literal["synthetic_local", "development", "staging", "production"]
CoverageDimension = Literal[
    "key",
    "grain",
    "fanout",
    "row_calculation",
    "aggregate_calculation",
    "filter_context",
    "time_semantics",
    "schema",
    "freshness",
    "consumer_contract",
    "query_result",
    "control",
    "filter_propagation",
    "interaction",
    "drill",
    "layout_intent",
    "visual_fixture",
    "operations",
    "security_allow",
    "security_deny",
    "derived_field_leakage",
    "negative_consolidation_control",
]

REQUIRED_COVERAGE_DIMENSIONS: tuple[str, ...] = (
    "key",
    "grain",
    "fanout",
    "row_calculation",
    "aggregate_calculation",
    "filter_context",
    "time_semantics",
    "schema",
    "freshness",
    "consumer_contract",
    "query_result",
    "control",
    "filter_propagation",
    "interaction",
    "drill",
    "layout_intent",
    "visual_fixture",
    "operations",
    "security_allow",
    "security_deny",
    "derived_field_leakage",
    "negative_consolidation_control",
)


def _sha256(value: Any) -> str:
    return f"sha256:{sha256_json(value)}"


def _raw(value: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    return (
        value.model_dump(mode="json")
        if isinstance(value, BaseModel)
        else deepcopy(dict(value))
    )


def _tupleize_json_arrays(value: Any) -> Any:
    """Convert decoded JSON arrays to immutable tuples before strict validation."""

    if isinstance(value, list):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_tupleize_json_arrays(item) for item in value)
    if isinstance(value, Mapping):
        return {key: _tupleize_json_arrays(item) for key, item in value.items()}
    return value


def _canonical_hash(value: Mapping[str, Any] | BaseModel, self_field: str) -> str:
    material = _raw(value)
    material.pop(self_field, None)
    return _sha256(material)


def _safe_reference(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not parsed.scheme
        or parsed.scheme.lower()
        in {
            "secret",
            "secret-ref",
            "vault",
            "vault-ref",
            "credential",
            "credential-ref",
        }
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in value)
        or parsed.scheme.lower() == "http"
        or (parsed.scheme.lower() == "https" and not parsed.hostname)
        or (not parsed.netloc and not parsed.path)
    ):
        raise ValueError("QA references must be safe non-secret URI references")
    return value


def _actor_identity(value: str) -> str:
    parsed = urlsplit(value)
    return "/".join(
        part for part in (parsed.netloc, parsed.path.strip("/")) if part
    ).replace("-", "_")


def _validation_error_messages(exc: ValidationError) -> tuple[str, ...]:
    messages = []
    for item in exc.errors(include_url=False):
        location = ".".join(str(part) for part in item["loc"])
        messages.append(f"{location}: {item['msg']}" if location else item["msg"])
    return tuple(sorted(set(messages)))


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def references_are_safe(self) -> "_StrictFrozenModel":
        for field_name in type(self).model_fields:
            if not (field_name.endswith("_ref") or field_name.endswith("_refs")):
                continue
            value = getattr(self, field_name)
            references = value if isinstance(value, tuple) else (value,)
            for reference in references:
                if isinstance(reference, str):
                    _safe_reference(reference)
        return self


class _PartitionedEvidence(_StrictFrozenModel):
    tenant_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    run_id: str = Field(pattern=_STABLE_ID_PATTERN)
    scope_id: str = Field(pattern=_STABLE_ID_PATTERN)
    wave_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_STABLE_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_STABLE_ID_PATTERN)
    evidence_class: EvidenceClass


class TimestampWatermark(_StrictFrozenModel):
    kind: Literal["timestamp"]
    value: str

    @field_validator("value")
    @classmethod
    def timestamp_is_aware(cls, value: str) -> str:
        parse_time(value)
        return value


class BatchWatermark(_StrictFrozenModel):
    kind: Literal["batch_id"]
    value: str = Field(min_length=1, max_length=4096)


class SnapshotWatermark(_StrictFrozenModel):
    kind: Literal["snapshot_ref"]
    value: str = Field(pattern=_NON_SECRET_REF_PATTERN)


class SequenceWatermark(_StrictFrozenModel):
    kind: Literal["sequence"]
    value: int = Field(ge=0)


Watermark = Annotated[
    TimestampWatermark | BatchWatermark | SnapshotWatermark | SequenceWatermark,
    Field(discriminator="kind"),
]


class ContextValue(_StrictFrozenModel):
    name: str = Field(min_length=1, max_length=512)
    value_type: Literal[
        "null", "boolean", "integer", "decimal", "string", "date", "datetime"
    ]
    canonical_values: tuple[str, ...] = Field(min_length=1)
    value_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def null_representation_is_unambiguous(self) -> "ContextValue":
        if self.value_type == "null" and self.canonical_values != ("null",):
            raise ValueError("null context values must use the exact canonical token 'null'")
        if self.value_type != "null" and any(value == "null" for value in self.canonical_values):
            raise ValueError("non-null context values cannot use the null token")
        return self


class SortBinding(_StrictFrozenModel):
    field_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    direction: Literal["ascending", "descending"]
    nulls: Literal["first", "last", "source_default"]
    ordinal: int = Field(ge=0)


class ComparisonContext(_StrictFrozenModel):
    watermark: Watermark
    logical_snapshot_id: str = Field(pattern=_STABLE_ID_PATTERN)
    parameters: tuple[ContextValue, ...]
    filters: tuple[ContextValue, ...]
    timezone: str = Field(min_length=1, max_length=128)
    persona_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    sort: tuple[SortBinding, ...]
    row_limit: int = Field(ge=1, le=1_000_000)
    execution_context_hash: str = Field(pattern=_SHA256_PATTERN)
    approved_tolerance_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    context_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def context_keys_and_sort_ordinals_are_unique(self) -> "ComparisonContext":
        for label, values in (("parameters", self.parameters), ("filters", self.filters)):
            names = [item.name for item in values]
            if len(names) != len(set(names)):
                raise ValueError(f"comparison context repeats {label}")
        ordinals = [item.ordinal for item in self.sort]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("comparison context repeats sort ordinals")
        if ordinals and sorted(ordinals) != list(range(len(ordinals))):
            raise ValueError("comparison context sort ordinals must be contiguous from zero")
        return self


class ComparisonContextProvenanceBinding(_StrictFrozenModel):
    """One immutable source-context assertion carried by a QA context pair.

    ``provenance_hash`` is derived from the accepted semantic-profile requirement
    or dashboard behavior.  ``binding_hash`` seals that identity into the pair so
    a denominator case cannot silently use a different, internally aligned pair.
    """

    provenance_kind: Literal[
        "semantic_profile_context",
        "dashboard_filter_context",
    ]
    provenance_id: str = Field(pattern=_STABLE_ID_PATTERN)
    provenance_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    provenance_hash: str = Field(pattern=_SHA256_PATTERN)
    binding_hash: str = Field(pattern=_SHA256_PATTERN)


class ComparisonContextPair(_StrictFrozenModel):
    context_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source: ComparisonContext
    target: ComparisonContext
    provenance_bindings: tuple[ComparisonContextProvenanceBinding, ...] = Field(
        default=(),
        exclude_if=lambda value: not value,
    )
    pair_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def source_and_target_are_exactly_aligned(self) -> "ComparisonContextPair":
        if self.source != self.target:
            raise ValueError("source and target comparison contexts must match exactly")
        identities = [
            (item.provenance_kind, item.provenance_id)
            for item in self.provenance_bindings
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("comparison context repeats a provenance identity")
        hashes = [item.binding_hash for item in self.provenance_bindings]
        if len(hashes) != len(set(hashes)):
            raise ValueError("comparison context repeats a provenance binding")
        if any(
            item.binding_hash
            != comparison_context_provenance_binding_hash(item)
            for item in self.provenance_bindings
        ):
            raise ValueError("comparison-context provenance binding hash is stale")
        return self


class QAArtifactObservation(_StrictFrozenModel):
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    revision: int = Field(ge=1)
    content_sha256: str = Field(pattern=_RAW_SHA256_PATTERN)
    environment_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    environment_tier: Literal["source", "development", "staging", "production"]
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def observation_time_is_aware(cls, value: str) -> str:
        parse_time(value)
        return value


class PersonaExpectation(_StrictFrozenModel):
    persona_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    expected_access: Literal["allow", "deny"]
    expected_visible_field_refs: tuple[str, ...]
    expected_hidden_field_refs: tuple[str, ...]
    derived_field_leakage_expected: Literal[False] = False


class QAFixtureV2(_PartitionedEvidence):
    contract_version: Literal["domo-to-omni.qa-fixture.v2"] = (
        "domo-to-omni.qa-fixture.v2"
    )
    fixture_id: str = Field(pattern=_STABLE_ID_PATTERN)
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    dimension: CoverageDimension
    subject_ref: str = Field(pattern=_QA_SUBJECT_REF_PATTERN)
    subject_hash: str = Field(pattern=_SHA256_PATTERN)
    fixture_kind: Literal[
        "semantic",
        "query_result",
        "visual",
        "interaction",
        "operations",
        "security_persona",
        "negative_consolidation",
    ]
    source_observation: QAArtifactObservation
    target_observation: QAArtifactObservation
    source_context: ComparisonContext
    target_context: ComparisonContext
    source_consumer_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    persona_expectation: PersonaExpectation | None = None
    expected_consolidation_outcome: Literal["different", "unknown"] | None = None
    expected_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    expected_hash: str = Field(pattern=_SHA256_PATTERN)
    persona_policy_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    persona_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    tolerance_policy_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    tolerance_policy_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    created_at: str
    fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def fixture_context_and_dimension_are_closed(self) -> "QAFixtureV2":
        parse_time(self.created_at)
        if (
            self.evidence_class == "production"
            and self.target_observation.environment_tier != "production"
        ):
            raise ValueError(
                "production QA fixtures require production target observations"
            )
        if self.source_context != self.target_context:
            raise ValueError("source and target comparison contexts must match exactly")
        if self.tolerance_policy_hash != self.source_context.approved_tolerance_policy_hash:
            raise ValueError("fixture tolerance policy hash differs from comparison context")
        if self.dimension in {"consumer_contract", "query_result"} and self.source_consumer_ref is None:
            raise ValueError("consumer coverage fixtures require a source consumer")
        security_dimensions = {
            "security_allow",
            "security_deny",
            "derived_field_leakage",
        }
        if self.dimension in security_dimensions and self.persona_expectation is None:
            raise ValueError("security fixtures require an explicit persona expectation")
        if self.dimension == "security_allow" and (
            self.persona_expectation is None
            or self.persona_expectation.expected_access != "allow"
        ):
            raise ValueError("security_allow requires an allow persona")
        if self.dimension in {"security_deny", "derived_field_leakage"} and (
            self.persona_expectation is None
            or self.persona_expectation.expected_access != "deny"
        ):
            raise ValueError("security denial and leakage checks require a denied persona")
        if self.dimension == "negative_consolidation_control":
            if self.fixture_kind != "negative_consolidation":
                raise ValueError("negative consolidation coverage requires its typed fixture")
            if self.expected_consolidation_outcome not in {"different", "unknown"}:
                raise ValueError("negative consolidation must remain different or unknown")
        elif self.expected_consolidation_outcome is not None:
            raise ValueError("only negative consolidation fixtures declare an outcome")
        return self


class QAResultCheck(_StrictFrozenModel):
    check_id: str = Field(pattern=_STABLE_ID_PATTERN)
    dimension: CoverageDimension
    expected_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    actual_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    outcome: Literal["passed", "failed", "blocked", "not_run"]
    difference_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    evidence_refs: tuple[str, ...]


class QAResultV2(_PartitionedEvidence):
    contract_version: Literal["domo-to-omni.qa-result.v2"] = "domo-to-omni.qa-result.v2"
    qa_result_id: str = Field(pattern=_STABLE_ID_PATTERN)
    result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    dimension: CoverageDimension
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    producer_refs: tuple[str, ...] = Field(min_length=1)
    source_observation: QAArtifactObservation
    target_observation: QAArtifactObservation
    source_context: ComparisonContext
    target_context: ComparisonContext
    outcome: Literal["passed", "failed", "blocked", "not_run"]
    checks: tuple[QAResultCheck, ...] = Field(min_length=1)
    observed_persona_access: Literal["allow", "deny"] | None = None
    derived_field_leakage_detected: bool
    observed_consolidation_outcome: Literal["exact", "equivalent", "different", "unknown"] | None = None
    evidence_refs: tuple[str, ...]
    blockers: tuple[str, ...]
    executed_at: str
    result_hash: str = Field(pattern=_SHA256_PATTERN)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def result_is_independent_aligned_and_terminal(self) -> "QAResultV2":
        parse_time(self.executed_at)
        if (
            self.evidence_class == "production"
            and self.target_observation.environment_tier != "production"
        ):
            raise ValueError(
                "production QA results require production target observations"
            )
        if self.source_context != self.target_context:
            raise ValueError("source and target comparison contexts must match exactly")
        if self.verifier_ref in self.producer_refs:
            raise ValueError("QA verifier must be independent of every upstream producer")
        if len(self.producer_refs) != len(set(self.producer_refs)):
            raise ValueError("QA producer_refs must be unique")
        if any(check.dimension != self.dimension for check in self.checks):
            raise ValueError("every result check must match the denominator dimension")
        outcomes = {check.outcome for check in self.checks}
        if self.outcome == "passed":
            if outcomes != {"passed"} or not self.evidence_refs or self.blockers:
                raise ValueError("passed results require passed checks, evidence, and no blockers")
            if self.derived_field_leakage_detected:
                raise ValueError("passed results cannot contain derived-field leakage")
        elif self.outcome == "failed" and "failed" not in outcomes:
            raise ValueError("failed results require a failed check")
        elif self.outcome in {"blocked", "not_run"} and not self.blockers:
            raise ValueError("blocked or not-run results require explicit blockers")
        if (
            self.outcome == "passed" and self.dimension == "security_allow"
            and self.observed_persona_access != "allow"
        ):
            raise ValueError("security_allow results must observe allowed access")
        if (
            self.outcome == "passed"
            and self.dimension in {"security_deny", "derived_field_leakage"}
            and self.observed_persona_access != "deny"
        ):
            raise ValueError("security denial and leakage results must observe denied access")
        if (
            self.outcome == "passed" and self.dimension == "negative_consolidation_control"
            and self.observed_consolidation_outcome not in {"different", "unknown"}
        ):
            raise ValueError("negative consolidation results cannot observe an approved merge")
        if self.outcome == "failed":
            if (
                self.dimension in {"security_allow", "security_deny", "derived_field_leakage"}
                and self.observed_persona_access is None
            ):
                raise ValueError("failed security results require the actual access observation")
            if (
                self.dimension == "negative_consolidation_control"
                and self.observed_consolidation_outcome is None
            ):
                raise ValueError("failed consolidation results require the actual observation")
        return self


class QAArtifactBinding(_PartitionedEvidence):
    artifact_id: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_type: str = Field(pattern=_STABLE_ID_PATTERN)
    artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    revision: int = Field(ge=1)
    content_sha256: str = Field(pattern=_RAW_SHA256_PATTERN)
    semantic_hash: str = Field(pattern=_SHA256_PATTERN)
    producer_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    created_at: str
    binding_hash: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def creation_time_is_aware(cls, value: str) -> str:
        parse_time(value)
        return value


class QATargetReceiptBinding(_StrictFrozenModel):
    artifact: QAArtifactBinding
    operation_id: str = Field(pattern=_STABLE_ID_PATTERN)
    request_fingerprint: str = Field(pattern=_RAW_SHA256_PATTERN)
    target_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result: Literal["succeeded"]
    write_receipt_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    readback_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    binding_hash: str = Field(pattern=_SHA256_PATTERN)


class QATargetReadbackBinding(_StrictFrozenModel):
    artifact: QAArtifactBinding
    operation_id: str = Field(pattern=_STABLE_ID_PATTERN)
    request_fingerprint: str = Field(pattern=_RAW_SHA256_PATTERN)
    target_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    state: Literal["matched"]
    write_receipt_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    readback_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    observed_content_fingerprint: str = Field(pattern=_RAW_SHA256_PATTERN)
    binding_hash: str = Field(pattern=_SHA256_PATTERN)


class QAEvidenceBindings(_StrictFrozenModel):
    dashboard_plan: QAArtifactBinding
    semantic_profile_coverage: QAArtifactBinding
    topic_blueprints: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    semantic_profiles: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    consolidation_decisions: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    source_evidence: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    target_artifacts: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    target_receipts: tuple[QATargetReceiptBinding, ...] = Field(min_length=1)
    target_readbacks: tuple[QATargetReadbackBinding, ...] = Field(min_length=1)
    persona_policies: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    tolerance_policies: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    fixture_artifacts: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    result_artifacts: tuple[QAArtifactBinding, ...] = Field(min_length=1)
    bindings_hash: str = Field(pattern=_SHA256_PATTERN)

    def all_artifacts(self) -> tuple[QAArtifactBinding, ...]:
        return (
            self.dashboard_plan,
            self.semantic_profile_coverage,
            *self.topic_blueprints,
            *self.semantic_profiles,
            *self.consolidation_decisions,
            *self.source_evidence,
            *self.target_artifacts,
            *(item.artifact for item in self.target_receipts),
            *(item.artifact for item in self.target_readbacks),
            *self.persona_policies,
            *self.tolerance_policies,
            *self.fixture_artifacts,
            *self.result_artifacts,
        )

    def upstream_artifacts(self) -> tuple[QAArtifactBinding, ...]:
        return tuple(
            artifact
            for artifact in self.all_artifacts()
            if artifact not in self.result_artifacts
        )

    @model_validator(mode="after")
    def binding_roles_and_target_outcomes_are_exact(self) -> "QAEvidenceBindings":
        if self.dashboard_plan.artifact_type != "dashboard_rebuild_plan":
            raise ValueError("dashboard plan binding has the wrong artifact type")
        if self.semantic_profile_coverage.artifact_type != "semantic_profile_coverage":
            raise ValueError(
                "semantic profile coverage binding has the wrong artifact type"
            )
        expected_types = {
            "topic_blueprints": "topic_blueprint",
            "consolidation_decisions": "consolidation_decision",
            "persona_policies": "persona_policy",
            "tolerance_policies": "tolerance_policy",
            "fixture_artifacts": "qa_fixture",
            "result_artifacts": "qa_result",
        }
        for field_name, artifact_type in expected_types.items():
            if any(item.artifact_type != artifact_type for item in getattr(self, field_name)):
                raise ValueError(f"{field_name} contains an unexpected artifact type")
        if any(
            item.artifact_type not in {"semantic_profile", "target_semantic_profile"}
            for item in self.semantic_profiles
        ):
            raise ValueError("semantic_profiles contains an unexpected artifact type")
        if any(item.artifact.artifact_type != "target_write_receipt" for item in self.target_receipts):
            raise ValueError("target receipt bindings require target_write_receipt artifacts")
        accepted_readback_types = {
            "document_readback",
            "dbt_test_evidence",
            "model_validation",
            "semantic_query_evidence",
            "target_visual_fixtures",
            "target_readback",
        }
        if any(
            item.artifact.artifact_type not in accepted_readback_types
            for item in self.target_readbacks
        ):
            raise ValueError("target readback binding has an unsupported artifact type")

        artifact_keys = [
            (item.artifact_id, item.revision, item.content_sha256)
            for item in self.all_artifacts()
        ]
        if len(artifact_keys) != len(set(artifact_keys)):
            raise ValueError("QA evidence bindings repeat an artifact revision")
        refs = [item.artifact_ref for item in self.all_artifacts()]
        if len(refs) != len(set(refs)):
            raise ValueError("QA evidence bindings repeat an artifact reference")

        receipts = {item.operation_id: item for item in self.target_receipts}
        readbacks = {item.operation_id: item for item in self.target_readbacks}
        if len(receipts) != len(self.target_receipts) or len(readbacks) != len(self.target_readbacks):
            raise ValueError("target operation bindings repeat an operation ID")
        if set(receipts) != set(readbacks):
            raise ValueError("every target receipt requires exactly one matched readback")
        for operation_id, receipt in receipts.items():
            readback = readbacks[operation_id]
            if (
                receipt.request_fingerprint != readback.request_fingerprint
                or receipt.target_ref != readback.target_ref
                or receipt.write_receipt_ref != readback.write_receipt_ref
                or receipt.readback_ref != readback.readback_ref
            ):
                raise ValueError("target receipt and readback identities differ")
        return self


class QACoverageCase(_StrictFrozenModel):
    case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    dimension: CoverageDimension
    subject_ref: str = Field(pattern=_QA_SUBJECT_REF_PATTERN)
    subject_hash: str = Field(pattern=_SHA256_PATTERN)
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    fixture_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    comparison_context_id: str = Field(pattern=_STABLE_ID_PATTERN)
    comparison_context_hash: str = Field(pattern=_SHA256_PATTERN)
    source_consumer_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    persona_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    expected_access: Literal["allow", "deny"] | None = None
    negative_candidate_ref: str | None = Field(default=None, pattern=_NON_SECRET_REF_PATTERN)
    expected_consolidation_outcome: Literal["different", "unknown"] | None = None
    case_hash: str = Field(pattern=_SHA256_PATTERN)


class QACoverageDenominator(_StrictFrozenModel):
    derived_from_binding_hashes: tuple[str, ...] = Field(min_length=1)
    source_consumer_refs: tuple[str, ...] = Field(min_length=1)
    allowed_persona_refs: tuple[str, ...] = Field(min_length=1)
    denied_persona_refs: tuple[str, ...] = Field(min_length=1)
    cases: tuple[QACoverageCase, ...] = Field(min_length=1)
    denominator_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def denominator_identifiers_are_unique(self) -> "QACoverageDenominator":
        for label, values in (
            ("derived bindings", self.derived_from_binding_hashes),
            ("source consumers", self.source_consumer_refs),
            ("allowed personas", self.allowed_persona_refs),
            ("denied personas", self.denied_persona_refs),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"QA denominator repeats {label}")
        case_ids = [case.case_id for case in self.cases]
        fixture_refs = [case.fixture_ref for case in self.cases]
        subject_refs = [(case.dimension, case.subject_ref) for case in self.cases]
        subject_hashes = [(case.dimension, case.subject_hash) for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("QA denominator repeats a case ID")
        if len(fixture_refs) != len(set(fixture_refs)):
            raise ValueError("QA denominator repeats a fixture")
        if len(subject_refs) != len(set(subject_refs)):
            raise ValueError("QA denominator repeats a dimension subject reference")
        if len(subject_hashes) != len(set(subject_hashes)):
            raise ValueError("QA denominator repeats a dimension subject hash")
        return self


class QAResultCaseBinding(_StrictFrozenModel):
    case_id: str = Field(pattern=_STABLE_ID_PATTERN)
    dimension: CoverageDimension
    result_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    result_hash: str = Field(pattern=_SHA256_PATTERN)
    result_binding_hash: str = Field(pattern=_SHA256_PATTERN)
    fixture_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    fixture_hash: str = Field(pattern=_SHA256_PATTERN)
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    producer_refs: tuple[str, ...] = Field(min_length=1)
    comparison_context_id: str = Field(pattern=_STABLE_ID_PATTERN)
    source_context_hash: str = Field(pattern=_SHA256_PATTERN)
    target_context_hash: str = Field(pattern=_SHA256_PATTERN)
    outcome: Literal["passed", "failed", "blocked", "not_run"]
    observed_persona_access: Literal["allow", "deny"] | None = None
    derived_field_leakage_detected: bool
    observed_consolidation_outcome: Literal["exact", "equivalent", "different", "unknown"] | None = None
    evidence_refs: tuple[str, ...]
    blockers: tuple[str, ...]
    binding_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def result_binding_context_is_aligned(self) -> "QAResultCaseBinding":
        if self.source_context_hash != self.target_context_hash:
            raise ValueError("result source and target context hashes differ")
        if self.verifier_ref in self.producer_refs:
            raise ValueError("result verifier cannot be an upstream producer")
        return self


class QAEvidenceSnapshot(_PartitionedEvidence):
    """Metadata-only current evidence view supplied by a trusted resolver."""

    snapshot_id: str = Field(pattern=_STABLE_ID_PATTERN)
    revision: int = Field(ge=1)
    snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    supersedes_snapshot_hash: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    migration_unit_status: Literal["validated"] = "validated"
    comparison_contexts: tuple[ComparisonContextPair, ...] = Field(min_length=1)
    bindings: QAEvidenceBindings
    denominator: QACoverageDenominator
    results: tuple[QAResultCaseBinding, ...] = Field(min_length=1)
    registered_at: str
    snapshot_hash: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def snapshot_is_aligned_and_revisioned(self) -> "QAEvidenceSnapshot":
        parse_time(self.registered_at)
        context_ids = [item.context_id for item in self.comparison_contexts]
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("QA snapshot repeats a comparison context")
        provenance_identities = [
            (binding.provenance_kind, binding.provenance_id)
            for context in self.comparison_contexts
            for binding in context.provenance_bindings
        ]
        if len(provenance_identities) != len(set(provenance_identities)):
            raise ValueError(
                "QA snapshot maps one provenance identity to multiple comparison contexts"
            )
        if self.revision == 1 and self.supersedes_snapshot_hash is not None:
            raise ValueError("first QA snapshot cannot supersede another snapshot")
        if self.revision > 1 and self.supersedes_snapshot_hash is None:
            raise ValueError("later QA snapshots require an exact predecessor hash")
        return self


class QAAcceptanceSuite(_PartitionedEvidence):
    contract_version: Literal["domo-to-omni.qa-acceptance-suite.v1"] = (
        "domo-to-omni.qa-acceptance-suite.v1"
    )
    suite_id: str = Field(pattern=_STABLE_ID_PATTERN)
    migration_unit_status: Literal["validated"] = "validated"
    evidence_snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_snapshot_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_snapshot_revision: int = Field(ge=1)
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    producer_refs: tuple[str, ...] = Field(min_length=1)
    comparison_contexts: tuple[ComparisonContextPair, ...] = Field(min_length=1)
    bindings: QAEvidenceBindings
    denominator: QACoverageDenominator
    results: tuple[QAResultCaseBinding, ...] = Field(min_length=1)
    assembled_at: str
    suite_hash: str = Field(pattern=_SHA256_PATTERN)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    immutable: Literal[True] = True

    @model_validator(mode="after")
    def suite_is_aligned_and_independent(self) -> "QAAcceptanceSuite":
        parse_time(self.assembled_at)
        context_ids = [item.context_id for item in self.comparison_contexts]
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("suite repeats a comparison context")
        provenance_identities = [
            (binding.provenance_kind, binding.provenance_id)
            for context in self.comparison_contexts
            for binding in context.provenance_bindings
        ]
        if len(provenance_identities) != len(set(provenance_identities)):
            raise ValueError(
                "suite maps one provenance identity to multiple comparison contexts"
            )
        if self.verifier_ref in self.producer_refs:
            raise ValueError("suite verifier must be independent of every upstream producer")
        if len(self.producer_refs) != len(set(self.producer_refs)):
            raise ValueError("suite producer_refs must be unique")
        return self


class QASuiteValidationRegistration(_PartitionedEvidence):
    suite_id: str = Field(pattern=_STABLE_ID_PATTERN)
    suite_hash: str = Field(pattern=_SHA256_PATTERN)
    suite_artifact_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    suite_artifact_content_sha256: str = Field(pattern=_RAW_SHA256_PATTERN)
    evidence_snapshot_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    evidence_snapshot_hash: str = Field(pattern=_SHA256_PATTERN)
    evidence_snapshot_revision: int = Field(ge=1)
    verifier_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    checked_by_ref: str = Field(pattern=_ACTOR_REF_PATTERN)
    checked_at: str
    status: Literal["valid"] = "valid"
    qa_suite_ready: Literal[True] = True
    validation_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    registration_ref: str = Field(pattern=_NON_SECRET_REF_PATTERN)
    registration_hash: str = Field(pattern=_SHA256_PATTERN)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False

    @model_validator(mode="after")
    def registration_is_exact_and_time_aware(self) -> "QASuiteValidationRegistration":
        parse_time(self.checked_at)
        if self.validation_fingerprint != self.suite_hash:
            raise ValueError("QA validation fingerprint must bind the exact suite")
        if self.checked_by_ref != self.verifier_ref:
            raise ValueError("QA suite registration must be made by its verifier")
        return self


class QAAcceptanceValidation(_StrictFrozenModel):
    valid: bool
    invalidated: bool
    errors: tuple[str, ...]
    invalidation_reasons: tuple[str, ...]
    qa_suite_ready: bool
    covered_dimension_count: int = Field(ge=0)
    denominator_case_count: int = Field(ge=0)
    authorizes_tenant_acceptance: Literal[False] = False
    authorizes_production_readiness: Literal[False] = False
    authorizes_promotion: Literal[False] = False
    authorizes_cutover: Literal[False] = False
    authorizes_decommissioning: Literal[False] = False
    suite_fingerprint: str = Field(pattern=_SHA256_PATTERN)


class TrustedQAEvidenceResolver(Protocol):
    """Resolve only current metadata from the trusted control-plane partition."""

    def resolve_current_qa_evidence_snapshot(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> QAEvidenceSnapshot | None: ...

    def resolve_current_qa_denominator(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
    ) -> QACoverageDenominator | None:
        """Derive the expected cases from current plan, Topics, profiles, and decisions."""

        ...

    def resolve_current_qa_suite_artifact(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        suite_id: str,
    ) -> ArtifactEnvelope | None: ...

    def resolve_current_qa_fixture_v2(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        artifact_ref: str,
    ) -> QAFixtureV2 | None: ...

    def resolve_current_qa_result_v2(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        artifact_ref: str,
    ) -> QAResultV2 | None: ...

    def resolve_current_qa_target_operation_outcome(
        self,
        *,
        tenant_ref: str,
        run_id: str,
        scope_id: str,
        wave_id: str,
        migration_unit_id: str,
        validation_cycle_id: str,
        operation_id: str,
    ) -> Any | None: ...


class QASuiteValidationSink(Protocol):
    """Append one validation attestation to a trusted store implementation."""

    def append_qa_suite_validation(
        self,
        registration: QASuiteValidationRegistration,
        *,
        idempotency_key: str,
    ) -> QASuiteValidationRegistration: ...


def context_value_hash(value: Mapping[str, Any] | ContextValue) -> str:
    return _canonical_hash(value, "value_hash")


def comparison_context_hash(value: Mapping[str, Any] | ComparisonContext) -> str:
    return _canonical_hash(value, "context_hash")


def comparison_context_provenance_binding_hash(
    value: Mapping[str, Any] | ComparisonContextProvenanceBinding,
) -> str:
    return _canonical_hash(value, "binding_hash")


def comparison_context_pair_hash(
    value: Mapping[str, Any] | ComparisonContextPair,
) -> str:
    material = _raw(value)
    material.pop("pair_hash", None)
    if not material.get("provenance_bindings"):
        # Preserve v1 hashes for legacy, non-context-sensitive pairs.  Once a
        # provenance assertion exists it is part of the immutable pair hash.
        material.pop("provenance_bindings", None)
    return _sha256(material)


def qa_fixture_hash(value: Mapping[str, Any] | QAFixtureV2) -> str:
    return _canonical_hash(value, "fixture_hash")


def qa_fixture_content_sha256(value: Mapping[str, Any] | QAFixtureV2) -> str:
    """Return the artifact-envelope content hash for one canonical v2 fixture."""

    return sha256_json(_raw(value))


def qa_result_hash(value: Mapping[str, Any] | QAResultV2) -> str:
    return _canonical_hash(value, "result_hash")


def qa_result_content_sha256(value: Mapping[str, Any] | QAResultV2) -> str:
    """Return the artifact-envelope content hash for one canonical v2 result."""

    return sha256_json(_raw(value))


def qa_artifact_binding_hash(value: Mapping[str, Any] | QAArtifactBinding) -> str:
    return _canonical_hash(value, "binding_hash")


def qa_target_receipt_binding_hash(
    value: Mapping[str, Any] | QATargetReceiptBinding,
) -> str:
    return _canonical_hash(value, "binding_hash")


def qa_target_readback_binding_hash(
    value: Mapping[str, Any] | QATargetReadbackBinding,
) -> str:
    return _canonical_hash(value, "binding_hash")


def qa_evidence_bindings_hash(value: Mapping[str, Any] | QAEvidenceBindings) -> str:
    return _canonical_hash(value, "bindings_hash")


def qa_coverage_case_hash(value: Mapping[str, Any] | QACoverageCase) -> str:
    return _canonical_hash(value, "case_hash")


def qa_coverage_denominator_hash(
    value: Mapping[str, Any] | QACoverageDenominator,
) -> str:
    return _canonical_hash(value, "denominator_hash")


def qa_result_case_binding_hash(
    value: Mapping[str, Any] | QAResultCaseBinding,
) -> str:
    return _canonical_hash(value, "binding_hash")


def qa_evidence_snapshot_hash(
    value: Mapping[str, Any] | QAEvidenceSnapshot,
) -> str:
    return _canonical_hash(value, "snapshot_hash")


def qa_acceptance_suite_hash(
    value: Mapping[str, Any] | QAAcceptanceSuite,
) -> str:
    return _canonical_hash(value, "suite_hash")


def qa_acceptance_suite_content_sha256(
    value: Mapping[str, Any] | QAAcceptanceSuite,
) -> str:
    return sha256_json(_raw(value))


def qa_suite_validation_registration_hash(
    value: Mapping[str, Any] | QASuiteValidationRegistration,
) -> str:
    return _canonical_hash(value, "registration_hash")


def qa_suite_validation_content_sha256(
    value: Mapping[str, Any] | QASuiteValidationRegistration,
) -> str:
    """Return the artifact-envelope content hash for one registration."""

    return sha256_json(_raw(value))


def finalize_context_value(value: Mapping[str, Any] | ContextValue) -> ContextValue:
    raw = _raw(value)
    raw["value_hash"] = _ZERO_HASH
    draft = ContextValue.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["value_hash"] = context_value_hash(raw)
    return ContextValue.model_validate(_tupleize_json_arrays(raw))


def finalize_comparison_context(
    value: Mapping[str, Any] | ComparisonContext,
) -> ComparisonContext:
    raw = _raw(value)
    raw["parameters"] = sorted(
        (
            finalize_context_value(item).model_dump(mode="json")
            for item in raw.get("parameters", ())
        ),
        key=lambda item: item["name"],
    )
    raw["filters"] = sorted(
        (
            finalize_context_value(item).model_dump(mode="json")
            for item in raw.get("filters", ())
        ),
        key=lambda item: item["name"],
    )
    raw["sort"] = sorted(raw.get("sort", ()), key=lambda item: int(item["ordinal"]))
    raw["context_hash"] = _ZERO_HASH
    draft = ComparisonContext.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["context_hash"] = comparison_context_hash(raw)
    return ComparisonContext.model_validate(_tupleize_json_arrays(raw))


def finalize_comparison_context_pair(
    value: Mapping[str, Any] | ComparisonContextPair,
) -> ComparisonContextPair:
    raw = _raw(value)
    raw["source"] = finalize_comparison_context(raw["source"]).model_dump(mode="json")
    raw["target"] = finalize_comparison_context(raw["target"]).model_dump(mode="json")
    raw["provenance_bindings"] = sorted(
        (
            finalize_comparison_context_provenance_binding(item).model_dump(mode="json")
            for item in raw.get("provenance_bindings", ())
        ),
        key=lambda item: (item["provenance_kind"], item["provenance_id"]),
    )
    raw["pair_hash"] = _ZERO_HASH
    draft = ComparisonContextPair.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["pair_hash"] = comparison_context_pair_hash(raw)
    return ComparisonContextPair.model_validate(_tupleize_json_arrays(raw))


def finalize_comparison_context_provenance_binding(
    value: Mapping[str, Any] | ComparisonContextProvenanceBinding,
) -> ComparisonContextProvenanceBinding:
    raw = _raw(value)
    raw["binding_hash"] = _ZERO_HASH
    draft = ComparisonContextProvenanceBinding.model_validate(
        _tupleize_json_arrays(raw)
    )
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = comparison_context_provenance_binding_hash(raw)
    return ComparisonContextProvenanceBinding.model_validate(
        _tupleize_json_arrays(raw)
    )


def finalize_qa_fixture(value: Mapping[str, Any] | QAFixtureV2) -> QAFixtureV2:
    raw = _raw(value)
    raw["source_context"] = finalize_comparison_context(raw["source_context"]).model_dump(
        mode="json"
    )
    raw["target_context"] = finalize_comparison_context(raw["target_context"]).model_dump(
        mode="json"
    )
    raw["producer_ref"] = str(raw["producer_ref"])
    raw["evidence_refs"] = sorted(set(raw.get("evidence_refs", ())))
    raw["fixture_hash"] = _ZERO_HASH
    draft = QAFixtureV2.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["fixture_hash"] = qa_fixture_hash(raw)
    return QAFixtureV2.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_result(value: Mapping[str, Any] | QAResultV2) -> QAResultV2:
    raw = _raw(value)
    raw["source_context"] = finalize_comparison_context(raw["source_context"]).model_dump(
        mode="json"
    )
    raw["target_context"] = finalize_comparison_context(raw["target_context"]).model_dump(
        mode="json"
    )
    raw["producer_refs"] = sorted(set(raw.get("producer_refs", ())))
    raw["checks"] = sorted(raw.get("checks", ()), key=lambda item: item["check_id"])
    raw["evidence_refs"] = sorted(set(raw.get("evidence_refs", ())))
    raw["blockers"] = sorted(set(raw.get("blockers", ())))
    raw["result_hash"] = _ZERO_HASH
    draft = QAResultV2.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["result_hash"] = qa_result_hash(raw)
    return QAResultV2.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_artifact_binding(
    value: Mapping[str, Any] | QAArtifactBinding,
) -> QAArtifactBinding:
    raw = _raw(value)
    raw["binding_hash"] = _ZERO_HASH
    draft = QAArtifactBinding.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_artifact_binding_hash(raw)
    return QAArtifactBinding.model_validate(_tupleize_json_arrays(raw))


def _finalize_target_receipt(
    value: Mapping[str, Any] | QATargetReceiptBinding,
) -> QATargetReceiptBinding:
    raw = _raw(value)
    raw["artifact"] = finalize_qa_artifact_binding(raw["artifact"]).model_dump(mode="json")
    raw["binding_hash"] = _ZERO_HASH
    draft = QATargetReceiptBinding.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_target_receipt_binding_hash(raw)
    return QATargetReceiptBinding.model_validate(_tupleize_json_arrays(raw))


def _finalize_target_readback(
    value: Mapping[str, Any] | QATargetReadbackBinding,
) -> QATargetReadbackBinding:
    raw = _raw(value)
    raw["artifact"] = finalize_qa_artifact_binding(raw["artifact"]).model_dump(mode="json")
    raw["binding_hash"] = _ZERO_HASH
    draft = QATargetReadbackBinding.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_target_readback_binding_hash(raw)
    return QATargetReadbackBinding.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_evidence_bindings(
    value: Mapping[str, Any] | QAEvidenceBindings,
) -> QAEvidenceBindings:
    raw = _raw(value)
    raw["dashboard_plan"] = finalize_qa_artifact_binding(raw["dashboard_plan"]).model_dump(
        mode="json"
    )
    if "semantic_profile_coverage" not in raw:
        raise ValueError(
            "QA evidence bindings require semantic_profile_coverage"
        )
    raw["semantic_profile_coverage"] = finalize_qa_artifact_binding(
        raw["semantic_profile_coverage"]
    ).model_dump(mode="json")
    artifact_fields = (
        "topic_blueprints",
        "semantic_profiles",
        "consolidation_decisions",
        "source_evidence",
        "target_artifacts",
        "persona_policies",
        "tolerance_policies",
        "fixture_artifacts",
        "result_artifacts",
    )
    for field_name in artifact_fields:
        raw[field_name] = sorted(
            (
                finalize_qa_artifact_binding(item).model_dump(mode="json")
                for item in raw.get(field_name, ())
            ),
            key=lambda item: (item["artifact_id"], item["revision"], item["content_sha256"]),
        )
    raw["target_receipts"] = sorted(
        (
            _finalize_target_receipt(item).model_dump(mode="json")
            for item in raw.get("target_receipts", ())
        ),
        key=lambda item: item["operation_id"],
    )
    raw["target_readbacks"] = sorted(
        (
            _finalize_target_readback(item).model_dump(mode="json")
            for item in raw.get("target_readbacks", ())
        ),
        key=lambda item: item["operation_id"],
    )
    raw["bindings_hash"] = _ZERO_HASH
    draft = QAEvidenceBindings.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["bindings_hash"] = qa_evidence_bindings_hash(raw)
    return QAEvidenceBindings.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_coverage_case(
    value: Mapping[str, Any] | QACoverageCase,
) -> QACoverageCase:
    raw = _raw(value)
    raw["case_hash"] = _ZERO_HASH
    draft = QACoverageCase.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["case_hash"] = qa_coverage_case_hash(raw)
    return QACoverageCase.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_coverage_denominator(
    value: Mapping[str, Any] | QACoverageDenominator,
) -> QACoverageDenominator:
    raw = _raw(value)
    for field_name in (
        "derived_from_binding_hashes",
        "source_consumer_refs",
        "allowed_persona_refs",
        "denied_persona_refs",
    ):
        raw[field_name] = sorted(set(raw.get(field_name, ())))
    raw["cases"] = sorted(
        (
            finalize_qa_coverage_case(item).model_dump(mode="json")
            for item in raw.get("cases", ())
        ),
        key=lambda item: item["case_id"],
    )
    raw["denominator_hash"] = _ZERO_HASH
    draft = QACoverageDenominator.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["denominator_hash"] = qa_coverage_denominator_hash(raw)
    return QACoverageDenominator.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_result_case_binding(
    value: Mapping[str, Any] | QAResultCaseBinding,
) -> QAResultCaseBinding:
    raw = _raw(value)
    raw["producer_refs"] = sorted(set(raw.get("producer_refs", ())))
    raw["evidence_refs"] = sorted(set(raw.get("evidence_refs", ())))
    raw["blockers"] = sorted(set(raw.get("blockers", ())))
    raw["binding_hash"] = _ZERO_HASH
    draft = QAResultCaseBinding.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["binding_hash"] = qa_result_case_binding_hash(raw)
    return QAResultCaseBinding.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_evidence_snapshot(
    value: Mapping[str, Any] | QAEvidenceSnapshot,
) -> QAEvidenceSnapshot:
    raw = _raw(value)
    raw["comparison_contexts"] = sorted(
        (
            finalize_comparison_context_pair(item).model_dump(mode="json")
            for item in raw.get("comparison_contexts", ())
        ),
        key=lambda item: item["context_id"],
    )
    raw["bindings"] = finalize_qa_evidence_bindings(raw["bindings"]).model_dump(mode="json")
    raw["denominator"] = finalize_qa_coverage_denominator(raw["denominator"]).model_dump(
        mode="json"
    )
    raw["results"] = sorted(
        (
            finalize_qa_result_case_binding(item).model_dump(mode="json")
            for item in raw.get("results", ())
        ),
        key=lambda item: item["case_id"],
    )
    raw["snapshot_hash"] = _ZERO_HASH
    draft = QAEvidenceSnapshot.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["snapshot_hash"] = qa_evidence_snapshot_hash(raw)
    return QAEvidenceSnapshot.model_validate(_tupleize_json_arrays(raw))


def finalize_qa_acceptance_suite(
    value: Mapping[str, Any] | QAAcceptanceSuite,
) -> QAAcceptanceSuite:
    raw = _raw(value)
    raw["producer_refs"] = sorted(set(raw.get("producer_refs", ())))
    raw["comparison_contexts"] = sorted(
        (
            finalize_comparison_context_pair(item).model_dump(mode="json")
            for item in raw.get("comparison_contexts", ())
        ),
        key=lambda item: item["context_id"],
    )
    raw["bindings"] = finalize_qa_evidence_bindings(raw["bindings"]).model_dump(mode="json")
    raw["denominator"] = finalize_qa_coverage_denominator(raw["denominator"]).model_dump(
        mode="json"
    )
    raw["results"] = sorted(
        (
            finalize_qa_result_case_binding(item).model_dump(mode="json")
            for item in raw.get("results", ())
        ),
        key=lambda item: item["case_id"],
    )
    raw["suite_hash"] = _ZERO_HASH
    draft = QAAcceptanceSuite.model_validate(_tupleize_json_arrays(raw))
    raw = draft.model_dump(mode="json")
    raw["suite_hash"] = qa_acceptance_suite_hash(raw)
    return QAAcceptanceSuite.model_validate(_tupleize_json_arrays(raw))


def _binding_identity(binding: QAArtifactBinding) -> tuple[str, ...]:
    return (
        binding.tenant_ref,
        binding.run_id,
        binding.scope_id,
        binding.wave_id,
        binding.migration_unit_id,
        binding.validation_cycle_id,
        binding.evidence_class,
    )


def _suite_identity(suite: QAAcceptanceSuite) -> tuple[str, ...]:
    return (
        suite.tenant_ref,
        suite.run_id,
        suite.scope_id,
        suite.wave_id,
        suite.migration_unit_id,
        suite.validation_cycle_id,
        suite.evidence_class,
    )


def _observation_identity(
    observation: QAArtifactObservation,
) -> tuple[str, int, str]:
    return (
        observation.artifact_ref,
        observation.revision,
        observation.content_sha256,
    )


def _artifact_observation_identity(
    artifact: QAArtifactBinding,
) -> tuple[str, int, str]:
    return (
        artifact.artifact_ref,
        artifact.revision,
        artifact.content_sha256,
    )


def validate_qa_acceptance_suite(
    value: Mapping[str, Any] | QAAcceptanceSuite,
    *,
    evidence_resolver: TrustedQAEvidenceResolver,
) -> QAAcceptanceValidation:
    """Validate one whole acceptance denominator against current trusted evidence."""

    raw = _raw(value)
    fingerprint = _sha256({k: v for k, v in raw.items() if k != "suite_hash"})
    try:
        suite = (
            value
            if isinstance(value, QAAcceptanceSuite)
            else QAAcceptanceSuite.model_validate(_tupleize_json_arrays(raw))
        )
    except ValidationError as exc:
        errors = _validation_error_messages(exc)
        return QAAcceptanceValidation(
            valid=False,
            invalidated=True,
            errors=errors,
            invalidation_reasons=errors,
            qa_suite_ready=False,
            covered_dimension_count=0,
            denominator_case_count=0,
            suite_fingerprint=fingerprint,
        )

    reasons: list[str] = []
    identity = _suite_identity(suite)
    trusted_denominator = evidence_resolver.resolve_current_qa_denominator(
        tenant_ref=suite.tenant_ref,
        run_id=suite.run_id,
        scope_id=suite.scope_id,
        wave_id=suite.wave_id,
        migration_unit_id=suite.migration_unit_id,
        validation_cycle_id=suite.validation_cycle_id,
    )
    trusted_applicable_dimensions = (
        {case.dimension for case in trusted_denominator.cases}
        if trusted_denominator is not None
        and getattr(
            evidence_resolver,
            "qa_subject_applicability_is_authoritative",
            False,
        )
        is True
        else None
    )

    if suite.suite_hash != qa_acceptance_suite_hash(suite):
        reasons.append("suite_hash does not match canonical suite content")
    contexts = {item.context_id: item for item in suite.comparison_contexts}
    for pair in suite.comparison_contexts:
        if pair.pair_hash != comparison_context_pair_hash(pair):
            reasons.append(f"comparison context pair hash is stale: {pair.context_id}")
        if pair.source.context_hash != comparison_context_hash(pair.source):
            reasons.append(f"source comparison context hash is stale: {pair.context_id}")
        if pair.target.context_hash != comparison_context_hash(pair.target):
            reasons.append(f"target comparison context hash is stale: {pair.context_id}")

    if suite.bindings.bindings_hash != qa_evidence_bindings_hash(suite.bindings):
        reasons.append("evidence bindings hash is stale")
    for artifact in suite.bindings.all_artifacts():
        if _binding_identity(artifact) != identity:
            reasons.append(f"artifact binding crosses suite partition: {artifact.artifact_ref}")
        if artifact.binding_hash != qa_artifact_binding_hash(artifact):
            reasons.append(f"artifact binding hash is stale: {artifact.artifact_ref}")
    for receipt in suite.bindings.target_receipts:
        if receipt.binding_hash != qa_target_receipt_binding_hash(receipt):
            reasons.append(f"target receipt binding hash is stale: {receipt.operation_id}")
    for readback in suite.bindings.target_readbacks:
        if readback.binding_hash != qa_target_readback_binding_hash(readback):
            reasons.append(f"target readback binding hash is stale: {readback.operation_id}")

    trusted_target_observations: dict[
        tuple[str, int, str], tuple[str, str]
    ] = {}
    if suite.evidence_class == "production":
        resolve_target_outcome = getattr(
            evidence_resolver,
            "resolve_current_qa_target_operation_outcome",
            None,
        )
        readback_by_operation = {
            item.operation_id: item for item in suite.bindings.target_readbacks
        }
        trusted_promoted_refs: set[str] = set()
        for receipt in suite.bindings.target_receipts:
            readback = readback_by_operation.get(receipt.operation_id)
            outcome = (
                resolve_target_outcome(
                    tenant_ref=suite.tenant_ref,
                    run_id=suite.run_id,
                    scope_id=suite.scope_id,
                    wave_id=suite.wave_id,
                    migration_unit_id=suite.migration_unit_id,
                    validation_cycle_id=suite.validation_cycle_id,
                    operation_id=receipt.operation_id,
                )
                if callable(resolve_target_outcome)
                else None
            )
            if outcome is None or readback is None:
                reasons.append(
                    "production target operation lacks one exact trusted store outcome: "
                    f"{receipt.operation_id}"
                )
                continue
            if (
                outcome.receipt_binding != receipt
                or outcome.readback_binding != readback
                or outcome.target_environment_tier != "production"
            ):
                reasons.append(
                    "production target operation differs from its trusted store outcome: "
                    f"{receipt.operation_id}"
                )
                continue
            target_binding = next(
                (
                    item
                    for item in suite.bindings.target_artifacts
                    if item == outcome.promoted_target_artifact
                ),
                None,
            )
            if target_binding is None:
                reasons.append(
                    "production target outcome does not bind an exact promoted suite "
                    f"artifact: {receipt.operation_id}"
                )
                continue
            trusted_promoted_refs.add(target_binding.artifact_ref)
            environment = (
                outcome.target_environment_ref,
                outcome.target_environment_tier,
            )
            trusted_target_observations[
                _artifact_observation_identity(target_binding)
            ] = environment
            trusted_target_observations[
                _artifact_observation_identity(readback.artifact)
            ] = environment
        expected_promoted_refs = {
            item.artifact_ref for item in suite.bindings.target_artifacts
        }
        if trusted_promoted_refs != expected_promoted_refs:
            reasons.append(
                "production target outcomes do not exactly cover every promoted target "
                f"artifact: missing={sorted(expected_promoted_refs - trusted_promoted_refs)}, "
                f"extra={sorted(trusted_promoted_refs - expected_promoted_refs)}"
            )

    expected_producers = tuple(
        sorted({artifact.producer_ref for artifact in suite.bindings.upstream_artifacts()})
    )
    if tuple(sorted(suite.producer_refs)) != expected_producers:
        reasons.append("suite producer set does not exactly match every upstream producer")
    if suite.verifier_ref in expected_producers:
        reasons.append("suite verifier is not independent of every upstream producer")

    denominator = suite.denominator
    if denominator.denominator_hash != qa_coverage_denominator_hash(denominator):
        reasons.append("coverage denominator hash is stale")
    for case in denominator.cases:
        if case.case_hash != qa_coverage_case_hash(case):
            reasons.append(f"coverage case hash is stale: {case.case_id}")
        context = contexts.get(case.comparison_context_id)
        if context is None:
            reasons.append(f"coverage case lacks its comparison context: {case.case_id}")
        elif case.comparison_context_hash != context.pair_hash:
            reasons.append(f"coverage case has a stale comparison context: {case.case_id}")
    expected_derived_bindings = tuple(
        sorted(
            {
                suite.bindings.dashboard_plan.binding_hash,
                suite.bindings.semantic_profile_coverage.binding_hash,
                *(item.binding_hash for item in suite.bindings.topic_blueprints),
                *(item.binding_hash for item in suite.bindings.semantic_profiles),
                *(item.binding_hash for item in suite.bindings.consolidation_decisions),
            }
        )
    )
    if tuple(sorted(denominator.derived_from_binding_hashes)) != expected_derived_bindings:
        reasons.append(
            "coverage denominator is not derived from the exact semantic coverage, "
            "plan, Topics, profiles, and decisions"
        )

    dimension_counts = Counter(case.dimension for case in denominator.cases)
    expected_dimensions = (
        trusted_applicable_dimensions
        if trusted_applicable_dimensions is not None
        else set(REQUIRED_COVERAGE_DIMENSIONS)
    )
    missing_dimensions = sorted(expected_dimensions - set(dimension_counts))
    extra_dimensions = sorted(set(dimension_counts) - expected_dimensions)
    if missing_dimensions:
        reasons.append(f"coverage denominator is missing dimensions: {missing_dimensions}")
    if extra_dimensions:
        reasons.append(f"coverage denominator contains unsupported dimensions: {extra_dimensions}")

    fixture_bindings = {item.artifact_ref: item for item in suite.bindings.fixture_artifacts}
    result_bindings = {item.artifact_ref: item for item in suite.bindings.result_artifacts}
    source_observation_bindings = Counter(
        _artifact_observation_identity(item)
        for item in suite.bindings.source_evidence
    )
    target_observation_bindings = Counter(
        _artifact_observation_identity(item)
        for item in (
            *suite.bindings.target_artifacts,
            *(readback.artifact for readback in suite.bindings.target_readbacks),
        )
    )
    partition_kwargs = {
        "tenant_ref": suite.tenant_ref,
        "run_id": suite.run_id,
        "scope_id": suite.scope_id,
        "wave_id": suite.wave_id,
        "migration_unit_id": suite.migration_unit_id,
        "validation_cycle_id": suite.validation_cycle_id,
    }
    denominator_fixture_refs = {case.fixture_ref for case in denominator.cases}
    if denominator_fixture_refs != set(fixture_bindings):
        reasons.append("fixture artifacts do not exactly match the closed denominator")
    resolved_fixtures: dict[str, QAFixtureV2] = {}
    for case in denominator.cases:
        fixture_binding = fixture_bindings.get(case.fixture_ref)
        if fixture_binding is not None and (
            case.fixture_hash != fixture_binding.semantic_hash
            or case.fixture_binding_hash != fixture_binding.binding_hash
        ):
            reasons.append(f"coverage case has a stale fixture binding: {case.case_id}")
        if fixture_binding is None:
            continue
        fixture_payload = evidence_resolver.resolve_current_qa_fixture_v2(
            **partition_kwargs,
            artifact_ref=fixture_binding.artifact_ref,
        )
        if fixture_payload is None:
            reasons.append(
                f"coverage case lacks one current registered canonical v2 fixture: {case.case_id}"
            )
            continue
        resolved_fixtures[case.fixture_ref] = fixture_payload
        context = contexts.get(case.comparison_context_id)
        persona_binding = next(
            (
                item
                for item in suite.bindings.persona_policies
                if item.artifact_ref == fixture_payload.persona_policy_ref
            ),
            None,
        )
        tolerance_binding = next(
            (
                item
                for item in suite.bindings.tolerance_policies
                if item.artifact_ref == fixture_payload.tolerance_policy_ref
            ),
            None,
        )
        if (
            fixture_payload.contract_version != "domo-to-omni.qa-fixture.v2"
            or _suite_identity(fixture_payload) != identity
            or fixture_payload.fixture_hash != qa_fixture_hash(fixture_payload)
            or fixture_payload.fixture_ref != fixture_binding.artifact_ref
            or fixture_binding.semantic_hash != fixture_payload.fixture_hash
            or fixture_binding.content_sha256
            != qa_fixture_content_sha256(fixture_payload)
            or fixture_binding.producer_ref != fixture_payload.producer_ref
        ):
            reasons.append(
                f"coverage case fixture payload does not match its exact artifact: {case.case_id}"
            )
        if (
            fixture_payload.case_id != case.case_id
            or fixture_payload.dimension != case.dimension
            or fixture_payload.subject_ref != case.subject_ref
            or fixture_payload.subject_hash != case.subject_hash
            or fixture_payload.fixture_ref != case.fixture_ref
            or fixture_payload.fixture_hash != case.fixture_hash
            or fixture_payload.source_consumer_ref != case.source_consumer_ref
            or (
                fixture_payload.persona_expectation.persona_ref
                if fixture_payload.persona_expectation is not None
                else None
            )
            != case.persona_ref
            or (
                fixture_payload.persona_expectation.expected_access
                if fixture_payload.persona_expectation is not None
                else None
            )
            != case.expected_access
            or fixture_payload.expected_consolidation_outcome
            != case.expected_consolidation_outcome
        ):
            reasons.append(
                f"coverage case summary differs from its canonical v2 fixture: {case.case_id}"
            )
        if context is None or (
            fixture_payload.source_context != context.source
            or fixture_payload.target_context != context.target
        ):
            reasons.append(
                f"coverage case fixture context differs from its exact comparison: {case.case_id}"
            )
        if persona_binding is None or (
            persona_binding.semantic_hash != fixture_payload.persona_policy_hash
        ):
            reasons.append(
                f"coverage case fixture lacks its exact persona policy: {case.case_id}"
            )
        if tolerance_binding is None or (
            tolerance_binding.semantic_hash != fixture_payload.tolerance_policy_hash
        ):
            reasons.append(
                f"coverage case fixture lacks its exact tolerance policy: {case.case_id}"
            )
        if source_observation_bindings[
            _observation_identity(fixture_payload.source_observation)
        ] != 1:
            reasons.append(
                "coverage case fixture source observation is not one exact source "
                f"binding: {case.case_id}"
            )
        if target_observation_bindings[
            _observation_identity(fixture_payload.target_observation)
        ] != 1:
            reasons.append(
                "coverage case fixture target observation is not one exact target/readback "
                f"binding: {case.case_id}"
            )
        if suite.evidence_class == "production":
            trusted_environment = trusted_target_observations.get(
                _observation_identity(fixture_payload.target_observation)
            )
            if trusted_environment is None or trusted_environment != (
                fixture_payload.target_observation.environment_ref,
                fixture_payload.target_observation.environment_tier,
            ):
                reasons.append(
                    "production coverage case fixture is not bound to its exact trusted "
                    f"promotion outcome and environment: {case.case_id}"
                )

    case_by_id = {case.case_id: case for case in denominator.cases}
    result_counts = Counter(result.case_id for result in suite.results)
    duplicated_results = sorted(case_id for case_id, count in result_counts.items() if count != 1)
    missing_results = sorted(set(case_by_id) - set(result_counts))
    extra_results = sorted(set(result_counts) - set(case_by_id))
    if duplicated_results:
        reasons.append(f"denominator cases do not have exactly one result: {duplicated_results}")
    if missing_results:
        reasons.append(f"denominator cases are missing results: {missing_results}")
    if extra_results:
        reasons.append(f"suite contains results outside the denominator: {extra_results}")
    suite_result_refs = {result.result_ref for result in suite.results}
    if suite_result_refs != set(result_bindings):
        reasons.append("result artifacts do not exactly match the suite result set")

    for result in suite.results:
        if result.binding_hash != qa_result_case_binding_hash(result):
            reasons.append(f"result binding hash is stale: {result.case_id}")
        case = case_by_id.get(result.case_id)
        if case is None:
            continue
        if (
            result.dimension != case.dimension
            or result.fixture_ref != case.fixture_ref
            or result.fixture_hash != case.fixture_hash
        ):
            reasons.append(f"result does not bind its exact denominator case: {result.case_id}")
        bound_result = result_bindings.get(result.result_ref)
        if bound_result is not None and (
            result.result_hash != bound_result.semantic_hash
            or result.result_binding_hash != bound_result.binding_hash
        ):
            reasons.append(f"result artifact binding is stale: {result.case_id}")
        result_payload = (
            evidence_resolver.resolve_current_qa_result_v2(
                **partition_kwargs,
                artifact_ref=bound_result.artifact_ref,
            )
            if bound_result is not None
            else None
        )
        if result_payload is None:
            reasons.append(
                f"denominator case lacks one current registered canonical v2 result: {result.case_id}"
            )
        else:
            fixture_payload = resolved_fixtures.get(result.fixture_ref)
            if (
                result_payload.contract_version != "domo-to-omni.qa-result.v2"
                or _suite_identity(result_payload) != identity
                or result_payload.result_hash != qa_result_hash(result_payload)
                or result_payload.result_ref != bound_result.artifact_ref
                or bound_result.semantic_hash != result_payload.result_hash
                or bound_result.content_sha256
                != qa_result_content_sha256(result_payload)
                or bound_result.producer_ref != result_payload.verifier_ref
            ):
                reasons.append(
                    f"result payload does not match its exact artifact: {result.case_id}"
                )
            if (
                result_payload.case_id != result.case_id
                or result_payload.dimension != result.dimension
                or result_payload.result_ref != result.result_ref
                or result_payload.result_hash != result.result_hash
                or result_payload.fixture_ref != result.fixture_ref
                or result_payload.fixture_hash != result.fixture_hash
                or result_payload.verifier_ref != result.verifier_ref
                or result_payload.producer_refs != result.producer_refs
                or result_payload.source_context.context_hash
                != result.source_context_hash
                or result_payload.target_context.context_hash
                != result.target_context_hash
                or result_payload.outcome != result.outcome
                or result_payload.observed_persona_access
                != result.observed_persona_access
                or result_payload.derived_field_leakage_detected
                != result.derived_field_leakage_detected
                or result_payload.observed_consolidation_outcome
                != result.observed_consolidation_outcome
                or result_payload.evidence_refs != result.evidence_refs
                or result_payload.blockers != result.blockers
            ):
                reasons.append(
                    f"result summary differs from its canonical v2 payload: {result.case_id}"
                )
            if fixture_payload is None or (
                result_payload.fixture_ref != fixture_payload.fixture_ref
                or result_payload.fixture_hash != fixture_payload.fixture_hash
                or result_payload.source_observation != fixture_payload.source_observation
                or result_payload.target_observation != fixture_payload.target_observation
                or result_payload.source_context != fixture_payload.source_context
                or result_payload.target_context != fixture_payload.target_context
            ):
                reasons.append(
                    f"result payload does not consume its exact canonical v2 fixture: {result.case_id}"
                )
            if source_observation_bindings[
                _observation_identity(result_payload.source_observation)
            ] != 1:
                reasons.append(
                    "result source observation is not one exact source binding: "
                    f"{result.case_id}"
                )
            if target_observation_bindings[
                _observation_identity(result_payload.target_observation)
            ] != 1:
                reasons.append(
                    "result target observation is not one exact target/readback binding: "
                    f"{result.case_id}"
                )
            if suite.evidence_class == "production":
                trusted_environment = trusted_target_observations.get(
                    _observation_identity(result_payload.target_observation)
                )
                if trusted_environment is None or trusted_environment != (
                    result_payload.target_observation.environment_ref,
                    result_payload.target_observation.environment_tier,
                ):
                    reasons.append(
                        "production result is not bound to its exact trusted promotion "
                        f"outcome and environment: {result.case_id}"
                    )
        if result.verifier_ref != suite.verifier_ref:
            reasons.append(f"result uses a different verifier: {result.case_id}")
        if tuple(sorted(result.producer_refs)) != expected_producers:
            reasons.append(f"result producer set is incomplete: {result.case_id}")
        result_context = contexts.get(result.comparison_context_id)
        if (
            result_context is None
            or result.comparison_context_id != case.comparison_context_id
            or result.source_context_hash != result_context.source.context_hash
            or result.target_context_hash != result_context.target.context_hash
        ):
            reasons.append(f"result comparison context is stale or misaligned: {result.case_id}")
        if result.outcome != "passed":
            reasons.append(f"denominator result is not passed: {result.case_id}:{result.outcome}")
        if result.blockers:
            reasons.append(f"denominator result hides blockers: {result.case_id}")
        if not result.evidence_refs:
            reasons.append(f"denominator result lacks evidence: {result.case_id}")
        if result.derived_field_leakage_detected:
            reasons.append(f"derived-field leakage detected: {result.case_id}")
        if case.dimension == "security_allow" and result.observed_persona_access != "allow":
            reasons.append(f"allowed persona was not allowed: {result.case_id}")
        if case.dimension in {"security_deny", "derived_field_leakage"} and (
            result.observed_persona_access != "deny"
        ):
            reasons.append(f"denied persona was not denied: {result.case_id}")
        if case.dimension == "negative_consolidation_control" and (
            result.observed_consolidation_outcome not in {"different", "unknown"}
        ):
            reasons.append(f"negative consolidation control leaked into an approved merge: {result.case_id}")

    consumer_dimensions = {"consumer_contract", "query_result"}
    for consumer_ref in denominator.source_consumer_refs:
        covered = {
            case.dimension
            for case in denominator.cases
            if case.source_consumer_ref == consumer_ref
        }
        missing = sorted(consumer_dimensions - covered)
        if missing:
            reasons.append(f"source consumer lacks required coverage {consumer_ref}: {missing}")
    observed_consumers = {
        case.source_consumer_ref
        for case in denominator.cases
        if case.source_consumer_ref is not None
    }
    if observed_consumers - set(denominator.source_consumer_refs):
        reasons.append("coverage cases contain undeclared source consumers")

    for persona_ref in denominator.allowed_persona_refs:
        if not any(
            case.dimension == "security_allow"
            and case.persona_ref == persona_ref
            and case.expected_access == "allow"
            for case in denominator.cases
        ):
            reasons.append(f"allowed persona lacks security_allow coverage: {persona_ref}")
    for persona_ref in denominator.denied_persona_refs:
        if not any(
            case.dimension == "security_deny"
            and case.persona_ref == persona_ref
            and case.expected_access == "deny"
            for case in denominator.cases
        ):
            reasons.append(f"denied persona lacks security_deny coverage: {persona_ref}")
        if not any(
            case.dimension == "derived_field_leakage"
            and case.persona_ref == persona_ref
            and case.expected_access == "deny"
            for case in denominator.cases
        ):
            reasons.append(f"denied persona lacks derived-field leakage coverage: {persona_ref}")
    if set(denominator.allowed_persona_refs) & set(denominator.denied_persona_refs):
        reasons.append("a persona cannot be both allowed and denied")

    tolerance_hashes = {item.semantic_hash for item in suite.bindings.tolerance_policies}
    for pair in suite.comparison_contexts:
        if pair.source.approved_tolerance_policy_hash not in tolerance_hashes:
            reasons.append(
                f"comparison context does not bind a current approved tolerance policy: {pair.context_id}"
            )
    persona_refs = {item.artifact_ref for item in suite.bindings.persona_policies}
    declared_personas = set(denominator.allowed_persona_refs) | set(denominator.denied_persona_refs)
    if declared_personas - persona_refs:
        reasons.append("denominator contains personas without exact policy bindings")

    snapshot = evidence_resolver.resolve_current_qa_evidence_snapshot(
        tenant_ref=suite.tenant_ref,
        run_id=suite.run_id,
        scope_id=suite.scope_id,
        wave_id=suite.wave_id,
        migration_unit_id=suite.migration_unit_id,
        validation_cycle_id=suite.validation_cycle_id,
    )
    if snapshot is None:
        reasons.append("current trusted QA evidence snapshot is unavailable")
    else:
        snapshot_identity = (
            snapshot.tenant_ref,
            snapshot.run_id,
            snapshot.scope_id,
            snapshot.wave_id,
            snapshot.migration_unit_id,
            snapshot.validation_cycle_id,
            snapshot.evidence_class,
        )
        if snapshot_identity != identity:
            reasons.append("trusted QA evidence snapshot crosses the suite partition")
        if snapshot.snapshot_hash != qa_evidence_snapshot_hash(snapshot):
            reasons.append("trusted QA evidence snapshot hash is stale")
        if (
            suite.evidence_snapshot_ref != snapshot.snapshot_ref
            or suite.evidence_snapshot_hash != snapshot.snapshot_hash
            or suite.evidence_snapshot_revision != snapshot.revision
        ):
            reasons.append("suite does not bind the exact current QA evidence snapshot")
        if suite.comparison_contexts != snapshot.comparison_contexts:
            reasons.append("suite comparison context differs from the current snapshot")
        if suite.bindings != snapshot.bindings:
            reasons.append("suite artifact bindings differ from the current snapshot")
        if suite.denominator != snapshot.denominator:
            reasons.append("suite denominator differs from the current snapshot")
        if suite.results != snapshot.results:
            reasons.append("suite results differ from the current snapshot")

    if trusted_denominator is None:
        reasons.append("trusted derived QA denominator is unavailable")
    else:
        if trusted_denominator.denominator_hash != qa_coverage_denominator_hash(
            trusted_denominator
        ):
            reasons.append("trusted derived QA denominator hash is stale")
        if suite.denominator != trusted_denominator:
            reasons.append("suite denominator differs from the trusted derived denominator")
        if snapshot is not None and snapshot.denominator != trusted_denominator:
            reasons.append("QA snapshot denominator differs from the trusted derived denominator")

    invalidation_reasons = tuple(sorted(set(reasons)))
    ready = not invalidation_reasons
    return QAAcceptanceValidation(
        valid=ready,
        invalidated=not ready,
        errors=(),
        invalidation_reasons=invalidation_reasons,
        qa_suite_ready=ready,
        covered_dimension_count=len(dimension_counts),
        denominator_case_count=len(denominator.cases),
        suite_fingerprint=qa_acceptance_suite_hash(suite),
    )


def register_validated_qa_suite(
    *,
    suite: Mapping[str, Any] | QAAcceptanceSuite,
    suite_artifact: Mapping[str, Any] | ArtifactEnvelope,
    evidence_resolver: TrustedQAEvidenceResolver,
    validation_sink: QASuiteValidationSink,
    checked_by_ref: str,
    checked_at: str,
    registration_ref: str,
    idempotency_key: str,
) -> QASuiteValidationRegistration:
    """Validate a current suite and append one proposal-only readiness attestation."""

    accepted_suite = (
        suite
        if isinstance(suite, QAAcceptanceSuite)
        else QAAcceptanceSuite.model_validate(_tupleize_json_arrays(_raw(suite)))
    )
    artifact = (
        suite_artifact
        if isinstance(suite_artifact, ArtifactEnvelope)
        else ArtifactEnvelope.from_mapping(suite_artifact)
    )
    artifact.validate(
        expected_tenant_ref=accepted_suite.tenant_ref,
        expected_run_id=accepted_suite.run_id,
    )
    if (
        artifact.artifact_type != "qa_acceptance_suite"
        or artifact.migration_unit_id != accepted_suite.migration_unit_id
        or artifact.validation_cycle_id != accepted_suite.validation_cycle_id
        or artifact.content_sha256 != qa_acceptance_suite_content_sha256(accepted_suite)
        or artifact.producer_ref != accepted_suite.verifier_ref
    ):
        raise ValueError("QA suite artifact does not bind the exact acceptance suite")

    current_artifact = evidence_resolver.resolve_current_qa_suite_artifact(
        tenant_ref=accepted_suite.tenant_ref,
        run_id=accepted_suite.run_id,
        scope_id=accepted_suite.scope_id,
        wave_id=accepted_suite.wave_id,
        migration_unit_id=accepted_suite.migration_unit_id,
        validation_cycle_id=accepted_suite.validation_cycle_id,
        suite_id=accepted_suite.suite_id,
    )
    if current_artifact is None or current_artifact.to_mapping() != artifact.to_mapping():
        raise ValueError("QA suite artifact is not the exact current trusted artifact")

    checker = urlsplit(checked_by_ref)
    checker_identity = _actor_identity(checked_by_ref)
    if checked_by_ref != accepted_suite.verifier_ref or not (
        checker.scheme in {"human-ref", "person-ref", "person"}
        or (checker.scheme == "agent-ref" and checker_identity == "migration_qa")
    ):
        raise ValueError("QA suite validation requires its independent migration QA verifier")

    checked_time = parse_time(checked_at)
    snapshot = evidence_resolver.resolve_current_qa_evidence_snapshot(
        tenant_ref=accepted_suite.tenant_ref,
        run_id=accepted_suite.run_id,
        scope_id=accepted_suite.scope_id,
        wave_id=accepted_suite.wave_id,
        migration_unit_id=accepted_suite.migration_unit_id,
        validation_cycle_id=accepted_suite.validation_cycle_id,
    )
    if snapshot is None:
        raise ValueError("current trusted QA evidence snapshot is unavailable")
    if checked_time < parse_time(artifact.created_at) or checked_time < parse_time(
        snapshot.registered_at
    ):
        raise ValueError("QA suite validation predates its current evidence")

    validation = validate_qa_acceptance_suite(
        accepted_suite,
        evidence_resolver=evidence_resolver,
    )
    if not validation.valid or not validation.qa_suite_ready:
        raise ValueError(
            "QA acceptance suite failed trusted validation: "
            f"{[*validation.errors, *validation.invalidation_reasons]}"
        )

    registration_raw = {
        "tenant_ref": accepted_suite.tenant_ref,
        "run_id": accepted_suite.run_id,
        "scope_id": accepted_suite.scope_id,
        "wave_id": accepted_suite.wave_id,
        "migration_unit_id": accepted_suite.migration_unit_id,
        "validation_cycle_id": accepted_suite.validation_cycle_id,
        "evidence_class": accepted_suite.evidence_class,
        "suite_id": accepted_suite.suite_id,
        "suite_hash": accepted_suite.suite_hash,
        "suite_artifact_ref": artifact.ref,
        "suite_artifact_content_sha256": artifact.content_sha256,
        "evidence_snapshot_ref": snapshot.snapshot_ref,
        "evidence_snapshot_hash": snapshot.snapshot_hash,
        "evidence_snapshot_revision": snapshot.revision,
        "verifier_ref": accepted_suite.verifier_ref,
        "checked_by_ref": checked_by_ref,
        "checked_at": checked_at,
        "status": "valid",
        "qa_suite_ready": True,
        "validation_fingerprint": validation.suite_fingerprint,
        "registration_ref": registration_ref,
        "registration_hash": _ZERO_HASH,
        "authorizes_tenant_acceptance": False,
        "authorizes_production_readiness": False,
        "authorizes_promotion": False,
        "authorizes_cutover": False,
        "authorizes_decommissioning": False,
    }
    registration = QASuiteValidationRegistration.model_validate(
        _tupleize_json_arrays(registration_raw)
    )
    registration_raw = registration.model_dump(mode="json")
    registration_raw["registration_hash"] = qa_suite_validation_registration_hash(
        registration_raw
    )
    registration = QASuiteValidationRegistration.model_validate(
        _tupleize_json_arrays(registration_raw)
    )
    stored = validation_sink.append_qa_suite_validation(
        registration,
        idempotency_key=idempotency_key,
    )
    if stored != registration:
        raise ValueError("trusted QA validation sink returned a different registration")
    return registration
