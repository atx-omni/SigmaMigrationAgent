"""Governed Omni model and quarantined document target adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable, Literal, Protocol

from pydantic import Field, field_serializer, field_validator, model_validator

from omni_migrator.targets.contracts import (
    AmbiguousTargetInvocation,
    FrozenJsonMap,
    TargetAdapterGuard,
    TargetAuthorizationStore,
    TargetAuthorizationConsumption,
    TargetOperationOutcome,
    TargetOperationStore,
    TargetOperationReadback,
    TargetOperationReceipt,
    TargetOperationRequest,
    _FrozenContract,
    ambiguous_outcome,
    canonical_fingerprint,
    freeze_json,
    indeterminate_outcome,
    mismatched_outcome,
    thaw_json,
    validate_non_secret_ref,
)
from omni_migrator.targets.execution import StoreBackedTargetExecutionResolver


OMNI_MODEL_ACTION = "write_omni_authored_model_yaml"
OMNI_DOCUMENT_CREATE_ACTION = "create_omni_document_in_quarantine"
OMNI_DOCUMENT_DRAFT_ACTION = "create_omni_content_draft"


class OmniYamlChange(_FrozenContract):
    path: str
    path_scope_ref: str
    authored_yaml: str = Field(min_length=1)
    authored_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    previous_checksum: str = Field(min_length=1)
    representation: Literal["authored"] = "authored"

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or ".." in path.parts
            or path.suffix.lower() not in {".yaml", ".yml"}
        ):
            raise ValueError("Omni model change path must be a safe authored YAML path")
        return value

    @field_validator("path_scope_ref")
    @classmethod
    def scope_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @model_validator(mode="after")
    def fingerprint_matches_authored_yaml(self) -> "OmniYamlChange":
        if self.authored_fingerprint != canonical_fingerprint(self.authored_yaml):
            raise ValueError("Omni authored fingerprint does not match its YAML")
        return self


class OmniModelWriteRequest(TargetOperationRequest):
    action: Literal["write_omni_authored_model_yaml"] = OMNI_MODEL_ACTION
    organization_ref: str
    model_ref: str
    branch_ref: str
    branch_name: str = Field(min_length=1)
    base_revision: str = Field(min_length=1)
    changes: tuple[OmniYamlChange, ...] = Field(min_length=1)
    fully_resolved: Literal[False] = False
    include_checksums: Literal[True] = True
    force_override_git_settings: Literal[False] = False
    validate_after_write: Literal[True] = True

    @field_validator("organization_ref", "model_ref", "branch_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @model_validator(mode="after")
    def exact_authored_change_set(self) -> "OmniModelWriteRequest":
        paths = [change.path for change in self.changes]
        if len(paths) != len(set(paths)):
            raise ValueError("Omni model change paths must be unique")
        path_scopes = [change.path_scope_ref for change in self.changes]
        if len(path_scopes) != len(set(path_scopes)):
            raise ValueError("Omni model path scope references must be unique")
        if self.branch_name.casefold() in {"main", "master", "production", "prod"}:
            raise ValueError("Omni model writes require a development branch")
        material = {
            "organization_ref": self.organization_ref,
            "model_ref": self.model_ref,
            "branch_ref": self.branch_ref,
            "branch_name": self.branch_name,
            "base_revision": self.base_revision,
            "changes": [change.model_dump(mode="json") for change in self.changes],
            "fully_resolved": self.fully_resolved,
            "include_checksums": self.include_checksums,
            "force_override_git_settings": self.force_override_git_settings,
            "validate_after_write": self.validate_after_write,
        }
        if self.change_set_fingerprint != canonical_fingerprint(material):
            raise ValueError("Omni model request does not match the exact authored change set")
        return self


class OmniBranchState(_FrozenContract):
    """Trusted current Omni model branch state."""

    organization_ref: str
    model_ref: str
    branch_ref: str
    branch_name: str
    default_branch_name: str
    base_revision: str = Field(min_length=1)
    allowed_path_scope_refs: tuple[str, ...] = Field(min_length=1)
    is_default: bool
    is_protected: bool
    validation_cycle_id: str
    evidence_ref: str

    @field_validator(
        "organization_ref", "model_ref", "branch_ref", "evidence_ref"
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("allowed_path_scope_refs")
    @classmethod
    def path_scopes_are_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("trusted Omni path scope references must be unique")
        return tuple(validate_non_secret_ref(value) for value in values)


class OmniBranchStateResolver(Protocol):
    def __call__(self, request: OmniModelWriteRequest) -> OmniBranchState: ...


class OmniModelDriverResult(_FrozenContract):
    operation_id: str
    idempotency_key: str
    remote_receipt_ref: str
    organization_ref: str
    model_ref: str
    branch_ref: str
    base_revision: str = Field(min_length=1)
    model_revision: str = Field(min_length=1)
    applied_change_set_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    applied_paths: tuple[str, ...] = Field(min_length=1)
    authored_file_fingerprints: FrozenJsonMap
    consumed_previous_checksums: FrozenJsonMap
    current_checksums: FrozenJsonMap
    fully_resolved: bool
    include_checksums: bool
    force_override_git_settings: bool
    publish_invoked: bool
    validation_passed: bool
    validation_job_id: str = Field(min_length=1)
    validation_evidence_ref: str
    readback_evidence_ref: str
    completed_at: str

    @field_validator(
        "remote_receipt_ref",
        "organization_ref",
        "model_ref",
        "branch_ref",
        "validation_evidence_ref",
        "readback_evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator(
        "authored_file_fingerprints",
        "consumed_previous_checksums",
        "current_checksums",
        mode="before",
    )
    @classmethod
    def maps_are_deeply_immutable(cls, value: object) -> FrozenJsonMap:
        frozen = freeze_json(value)
        if not isinstance(frozen, FrozenJsonMap) or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in frozen.items()
        ):
            raise ValueError("Omni model checksum maps must contain only strings")
        return frozen

    @field_serializer(
        "authored_file_fingerprints",
        "consumed_previous_checksums",
        "current_checksums",
    )
    def serialize_maps(self, value: FrozenJsonMap) -> dict[str, object]:
        return thaw_json(value)


class OmniModelReadback(TargetOperationReadback):
    organization_ref: str
    model_ref: str
    branch_ref: str
    base_revision: str
    applied_paths: tuple[str, ...]
    authored_file_fingerprints: FrozenJsonMap
    consumed_previous_checksums: FrozenJsonMap
    current_checksums: FrozenJsonMap
    fully_resolved: bool
    include_checksums: bool
    force_override_git_settings: bool
    publish_invoked: bool
    validation_passed: bool
    validation_job_id: str
    validation_evidence_ref: str
    branch_state_evidence_ref: str

    @field_validator(
        "organization_ref",
        "model_ref",
        "branch_ref",
        "validation_evidence_ref",
        "branch_state_evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator(
        "authored_file_fingerprints",
        "consumed_previous_checksums",
        "current_checksums",
        mode="before",
    )
    @classmethod
    def maps_are_deeply_immutable(cls, value: object) -> FrozenJsonMap:
        frozen = freeze_json(value)
        if not isinstance(frozen, FrozenJsonMap):
            raise ValueError("Omni model readback maps must be JSON objects")
        return frozen

    @field_serializer(
        "authored_file_fingerprints",
        "consumed_previous_checksums",
        "current_checksums",
    )
    def serialize_maps(self, value: FrozenJsonMap) -> dict[str, object]:
        return thaw_json(value)


class OmniModelWriteReceipt(TargetOperationReceipt):
    organization_ref: str
    model_ref: str
    branch_ref: str
    base_revision: str
    model_revision: str
    validation_job_id: str
    validation_evidence_ref: str

    @field_validator(
        "organization_ref", "model_ref", "branch_ref", "validation_evidence_ref"
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class OmniDocumentCreateRequest(TargetOperationRequest):
    action: Literal["create_omni_document_in_quarantine"] = OMNI_DOCUMENT_CREATE_ACTION
    organization_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    restricted_access: Literal[True] = True
    publish_requested: Literal[False] = False
    dashboard_rebuild_plan_ref: str
    dashboard_rebuild_plan_fingerprint: str
    document_name: str = Field(min_length=1)
    document_payload: FrozenJsonMap
    document_content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator(
        "organization_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
        "dashboard_rebuild_plan_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("document_payload", mode="before")
    @classmethod
    def payload_is_deeply_immutable(cls, value: object) -> FrozenJsonMap:
        frozen = freeze_json(value)
        if not isinstance(frozen, FrozenJsonMap):
            raise ValueError("Omni document payload must be a JSON object")
        return frozen

    @field_serializer("document_payload")
    def serialize_payload(self, value: FrozenJsonMap) -> dict[str, object]:
        return thaw_json(value)

    @model_validator(mode="after")
    def exact_quarantine_create(self) -> "OmniDocumentCreateRequest":
        if self.document_content_fingerprint != canonical_fingerprint(self.document_payload):
            raise ValueError("Omni document fingerprint does not match its payload")
        material = {
            "organization_ref": self.organization_ref,
            "parent_folder_ref": self.parent_folder_ref,
            "environment_ref": self.environment_ref,
            "environment_kind": self.environment_kind,
            "parent_access_verification_ref": self.parent_access_verification_ref,
            "destination_verification_ref": self.destination_verification_ref,
            "restricted_access": self.restricted_access,
            "publish_requested": self.publish_requested,
            "dashboard_rebuild_plan_ref": self.dashboard_rebuild_plan_ref,
            "dashboard_rebuild_plan_fingerprint": self.dashboard_rebuild_plan_fingerprint,
            "document_name": self.document_name,
            "document_content_fingerprint": self.document_content_fingerprint,
        }
        if self.change_set_fingerprint != canonical_fingerprint(material):
            raise ValueError("Omni document create does not match its quarantined change set")
        return self


class OmniDocumentDraftUpdateRequest(TargetOperationRequest):
    action: Literal["create_omni_content_draft"] = OMNI_DOCUMENT_DRAFT_ACTION
    organization_ref: str
    document_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    previous_revision: str = Field(min_length=1)
    previous_checksum: str = Field(min_length=1)
    create_if_missing: Literal[False] = False
    publish_requested: Literal[False] = False
    dashboard_rebuild_plan_ref: str
    dashboard_rebuild_plan_fingerprint: str
    document_payload: FrozenJsonMap
    document_content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator(
        "organization_ref",
        "document_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
        "dashboard_rebuild_plan_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("document_payload", mode="before")
    @classmethod
    def payload_is_deeply_immutable(cls, value: object) -> FrozenJsonMap:
        frozen = freeze_json(value)
        if not isinstance(frozen, FrozenJsonMap):
            raise ValueError("Omni document payload must be a JSON object")
        return frozen

    @field_serializer("document_payload")
    def serialize_payload(self, value: FrozenJsonMap) -> dict[str, object]:
        return thaw_json(value)

    @model_validator(mode="after")
    def exact_draft_update(self) -> "OmniDocumentDraftUpdateRequest":
        if self.document_content_fingerprint != canonical_fingerprint(self.document_payload):
            raise ValueError("Omni document fingerprint does not match its payload")
        material = {
            "organization_ref": self.organization_ref,
            "document_ref": self.document_ref,
            "parent_folder_ref": self.parent_folder_ref,
            "environment_ref": self.environment_ref,
            "environment_kind": self.environment_kind,
            "parent_access_verification_ref": self.parent_access_verification_ref,
            "destination_verification_ref": self.destination_verification_ref,
            "previous_revision": self.previous_revision,
            "previous_checksum": self.previous_checksum,
            "create_if_missing": self.create_if_missing,
            "publish_requested": self.publish_requested,
            "dashboard_rebuild_plan_ref": self.dashboard_rebuild_plan_ref,
            "dashboard_rebuild_plan_fingerprint": self.dashboard_rebuild_plan_fingerprint,
            "document_content_fingerprint": self.document_content_fingerprint,
        }
        if self.change_set_fingerprint != canonical_fingerprint(material):
            raise ValueError("Omni document draft does not match its exact update change set")
        return self


class OmniQuarantineVerification(_FrozenContract):
    organization_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    restricted_access: Literal[True]
    public_destination: Literal[False]
    validation_cycle_id: str
    evidence_ref: str

    @field_validator(
        "organization_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
        "evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class OmniDocumentState(_FrozenContract):
    organization_ref: str
    document_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    current_revision: str = Field(min_length=1)
    current_checksum: str = Field(min_length=1)
    restricted_access: Literal[True]
    published: Literal[False]
    validation_cycle_id: str
    evidence_ref: str

    @field_validator(
        "organization_ref",
        "document_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
        "evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class OmniDocumentStateResolver(Protocol):
    def __call__(self, request: OmniDocumentDraftUpdateRequest) -> OmniDocumentState: ...


class OmniDocumentDriverResult(_FrozenContract):
    operation_id: str
    idempotency_key: str
    action: Literal["create_omni_document_in_quarantine", "create_omni_content_draft"]
    remote_receipt_ref: str
    organization_ref: str
    document_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    visibility: str = Field(min_length=1)
    restricted_access: bool
    publish_invoked: bool
    document_revision: str = Field(min_length=1)
    document_checksum: str = Field(min_length=1)
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_new: bool
    consumed_previous_revision: str | None = None
    consumed_previous_checksum: str | None = None
    readback_evidence_ref: str
    completed_at: str

    @field_validator(
        "remote_receipt_ref",
        "organization_ref",
        "document_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
        "readback_evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

class OmniDocumentReadback(TargetOperationReadback):
    organization_ref: str
    document_ref: str
    parent_folder_ref: str
    environment_ref: str
    environment_kind: Literal["development", "sandbox", "non_production"]
    parent_access_verification_ref: str
    destination_verification_ref: str
    visibility: str
    restricted_access: bool
    publish_invoked: bool
    document_checksum: str
    created_new: bool
    consumed_previous_revision: str | None
    consumed_previous_checksum: str | None

    @field_validator(
        "organization_ref",
        "document_ref",
        "parent_folder_ref",
        "environment_ref",
        "parent_access_verification_ref",
        "destination_verification_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class OmniDocumentReceipt(TargetOperationReceipt):
    organization_ref: str
    document_ref: str
    parent_folder_ref: str
    environment_ref: str
    document_revision: str
    document_checksum: str
    visibility: Literal["restricted_quarantine"]
    publish_invoked: Literal[False]

    @field_validator("organization_ref", "document_ref", "parent_folder_ref", "environment_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class OmniTargetDriver(Protocol):
    def write_authored_model(self, request: OmniModelWriteRequest) -> OmniModelDriverResult: ...

    def create_document_in_quarantine(
        self, request: OmniDocumentCreateRequest
    ) -> OmniDocumentDriverResult: ...

    def update_document_draft(
        self, request: OmniDocumentDraftUpdateRequest
    ) -> OmniDocumentDriverResult: ...


class OmniQuarantineVerifier(Protocol):
    def __call__(
        self, request: OmniDocumentCreateRequest
    ) -> OmniQuarantineVerification: ...


class OmniTargetAdapter:
    def __init__(
        self,
        driver: OmniTargetDriver,
        *,
        authorization_store: TargetAuthorizationStore,
        operation_store: TargetOperationStore,
        execution_resolver: StoreBackedTargetExecutionResolver,
        branch_state_resolver: OmniBranchStateResolver,
        quarantine_verifier: OmniQuarantineVerifier,
        document_state_resolver: OmniDocumentStateResolver,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._driver = driver
        self._guard = TargetAdapterGuard(operation_store, execution_resolver)
        self._authorization_store = authorization_store
        self._branch_state_resolver = branch_state_resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._authorization_consumptions: list[TargetAuthorizationConsumption] = []
        self._quarantine_verifier = quarantine_verifier
        self._document_state_resolver = document_state_resolver

    @property
    def authorization_consumptions(self) -> tuple[TargetAuthorizationConsumption, ...]:
        return tuple(self._authorization_consumptions)

    def _prepare(
        self,
        request: TargetOperationRequest,
        *,
        expected_action: str,
        scopes: tuple[str, ...],
    ) -> tuple[TargetOperationOutcome | None, datetime, str]:
        now = self._clock()
        cached = self._guard.prepare(
            request,
            expected_action=expected_action,
            required_scope_refs=scopes,
            now=now,
        )
        completed = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return cached, now, completed

    def _consume(
        self,
        request: TargetOperationRequest,
        *,
        expected_action: str,
        scopes: tuple[str, ...],
        now: datetime,
        completed: str,
    ) -> TargetAuthorizationConsumption:
        self._guard.claim_execution(request, now=now)
        consumption = self._authorization_store.resolve_and_consume(
            request,
            expected_action=expected_action,
            required_scope_refs=scopes,
            now=now,
            consumed_at=completed,
        )
        self._authorization_consumptions.append(consumption)
        return consumption

    def _complete_post_invocation(
        self,
        request: TargetOperationRequest,
        consumption: TargetAuthorizationConsumption,
        target_ref: str,
        completed: str,
        message: str,
        build_outcome: Callable[[], TargetOperationOutcome],
    ) -> TargetOperationOutcome:
        try:
            try:
                outcome = build_outcome()
            except AmbiguousTargetInvocation as exc:
                readback = TargetOperationReadback.model_validate(
                    exc.readback.model_dump(mode="python")
                )
                outcome = ambiguous_outcome(
                    request,
                    target_ref=target_ref,
                    readback=readback,
                    authorization_consumption=consumption,
                    completed_at=completed,
                )
        except Exception:
            outcome = indeterminate_outcome(
                request,
                target_ref=target_ref,
                authorization_consumption=consumption,
                completed_at=completed,
                evidence_ref=(
                    f"evidence-ref://target-adapter/omni/{request.operation_id}/"
                    "post-invocation-validation"
                ),
                sanitized_message=message,
            )
        return self._guard.remember(request, outcome)

    def _resolve_model_branch(self, request: OmniModelWriteRequest) -> OmniBranchState:
        state = self._branch_state_resolver(request)
        if (
            state.organization_ref != request.organization_ref
            or state.model_ref != request.model_ref
            or state.branch_ref != request.branch_ref
            or state.branch_name != request.branch_name
            or state.base_revision != request.base_revision
            or state.allowed_path_scope_refs
            != tuple(change.path_scope_ref for change in request.changes)
            or state.validation_cycle_id != request.validation_cycle_id
        ):
            raise ValueError("trusted Omni branch state differs from the model request")
        if (
            state.is_default
            or state.is_protected
            or state.branch_name.casefold() == state.default_branch_name.casefold()
        ):
            raise ValueError("trusted Omni model branch is default or protected")
        return state

    def execute_model_write(self, request: OmniModelWriteRequest) -> TargetOperationOutcome:
        scopes = (
            request.organization_ref,
            request.model_ref,
            request.branch_ref,
            *(change.path_scope_ref for change in request.changes),
        )
        cached, now, completed = self._prepare(
            request,
            expected_action=OMNI_MODEL_ACTION,
            scopes=scopes,
        )
        if cached is not None:
            return cached
        branch_state = self._resolve_model_branch(request)
        consumption = self._consume(
            request,
            expected_action=OMNI_MODEL_ACTION,
            scopes=scopes,
            now=now,
            completed=completed,
        )
        return self._complete_post_invocation(
            request,
            consumption,
            request.branch_ref,
            completed,
            "Omni model post-invocation result or evidence requires reconciliation",
            lambda: self._model_write_outcome(request, consumption, branch_state),
        )

    def _model_write_outcome(
        self,
        request: OmniModelWriteRequest,
        consumption: TargetAuthorizationConsumption,
        branch_state: OmniBranchState,
    ) -> TargetOperationOutcome:
        result = self._driver.write_authored_model(request)
        expected_files = {change.path: change.authored_fingerprint for change in request.changes}
        expected_previous = {change.path: change.previous_checksum for change in request.changes}
        expected_paths = tuple(change.path for change in request.changes)
        identity_mismatch = (
            result.operation_id != request.operation_id
            or result.idempotency_key != request.idempotency_key
            or result.organization_ref != request.organization_ref
            or result.model_ref != request.model_ref
            or result.branch_ref != request.branch_ref
            or result.base_revision != request.base_revision
            or result.applied_change_set_fingerprint != request.change_set_fingerprint
            or result.applied_paths != expected_paths
            or result.authored_file_fingerprints != expected_files
            or result.consumed_previous_checksums != expected_previous
            or set(result.current_checksums) != set(expected_files)
            or result.fully_resolved
            or not result.include_checksums
            or result.force_override_git_settings
            or result.publish_invoked
            or not result.validation_passed
        )
        readback = OmniModelReadback(
            operation_id=request.operation_id,
            request_fingerprint=request.request_fingerprint(),
            target_ref=result.branch_ref,
            state="different" if identity_mismatch else "matched",
            target_revision=result.model_revision,
            content_fingerprint=request.change_set_fingerprint,
            captured_at=result.completed_at,
            evidence_ref=result.readback_evidence_ref,
            organization_ref=result.organization_ref,
            model_ref=result.model_ref,
            branch_ref=result.branch_ref,
            base_revision=result.base_revision,
            applied_paths=result.applied_paths,
            authored_file_fingerprints=result.authored_file_fingerprints,
            consumed_previous_checksums=result.consumed_previous_checksums,
            current_checksums=result.current_checksums,
            fully_resolved=result.fully_resolved,
            include_checksums=result.include_checksums,
            force_override_git_settings=result.force_override_git_settings,
            publish_invoked=result.publish_invoked,
            validation_passed=result.validation_passed,
            validation_job_id=result.validation_job_id,
            validation_evidence_ref=result.validation_evidence_ref,
            branch_state_evidence_ref=branch_state.evidence_ref,
        )
        if identity_mismatch:
            return mismatched_outcome(
                request,
                readback=readback,
                remote_receipt_ref=result.remote_receipt_ref,
                authorization_consumption=consumption,
                completed_at=result.completed_at,
                sanitized_message=(
                    "Omni model post-invocation branch, checksum, or validation mismatch"
                ),
            )
        receipt = OmniModelWriteReceipt(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            request_fingerprint=request.request_fingerprint(),
            action=request.action,
            target_ref=readback.target_ref,
            attempt=request.attempt,
            result="succeeded",
            remote_receipt_ref=result.remote_receipt_ref,
            readback_ref=readback.evidence_ref,
            completed_at=readback.captured_at,
            organization_ref=result.organization_ref,
            model_ref=result.model_ref,
            branch_ref=result.branch_ref,
            base_revision=result.base_revision,
            model_revision=result.model_revision,
            validation_job_id=result.validation_job_id,
            validation_evidence_ref=result.validation_evidence_ref,
        )
        return TargetOperationOutcome(
            authorization_consumption=consumption,
            receipt=receipt,
            readback=readback,
        )

    def execute_document_create(
        self, request: OmniDocumentCreateRequest
    ) -> TargetOperationOutcome:
        scopes = (request.organization_ref, request.parent_folder_ref, request.environment_ref)
        cached, now, completed = self._prepare(
            request,
            expected_action=OMNI_DOCUMENT_CREATE_ACTION,
            scopes=scopes,
        )
        if cached is not None:
            return cached
        verification = self._quarantine_verifier(request)
        if (
            verification.organization_ref != request.organization_ref
            or verification.parent_folder_ref != request.parent_folder_ref
            or verification.environment_ref != request.environment_ref
            or verification.environment_kind != request.environment_kind
            or verification.parent_access_verification_ref
            != request.parent_access_verification_ref
            or verification.destination_verification_ref
            != request.destination_verification_ref
            or verification.validation_cycle_id != request.validation_cycle_id
            or not verification.restricted_access
            or verification.public_destination
        ):
            raise ValueError("Omni document destination is not independently verified quarantine")
        consumption = self._consume(
            request,
            expected_action=OMNI_DOCUMENT_CREATE_ACTION,
            scopes=scopes,
            now=now,
            completed=completed,
        )
        return self._complete_post_invocation(
            request,
            consumption,
            request.parent_folder_ref,
            completed,
            "Omni document-create result or evidence requires reconciliation",
            lambda: self._document_create_outcome(request, consumption),
        )

    def _document_create_outcome(
        self,
        request: OmniDocumentCreateRequest,
        consumption: TargetAuthorizationConsumption,
    ) -> TargetOperationOutcome:
        result = self._driver.create_document_in_quarantine(request)
        identity_mismatch = self._document_result_differs(
            request=request,
            result=result,
            expected_action=OMNI_DOCUMENT_CREATE_ACTION,
            expected_parent=request.parent_folder_ref,
            expected_environment=request.environment_ref,
            expected_environment_kind=request.environment_kind,
            expected_parent_access_verification=request.parent_access_verification_ref,
            expected_destination_verification=request.destination_verification_ref,
            expected_created_new=True,
        )
        readback = self._document_readback(
            request, result, state="different" if identity_mismatch else "matched"
        )
        if identity_mismatch:
            return mismatched_outcome(
                request,
                readback=readback,
                remote_receipt_ref=result.remote_receipt_ref,
                authorization_consumption=consumption,
                completed_at=result.completed_at,
                sanitized_message=(
                    "Omni document create readback violates target or quarantine identity"
                ),
            )
        receipt = self._document_receipt(request, result, readback)
        return TargetOperationOutcome(
            authorization_consumption=consumption,
            receipt=receipt,
            readback=readback,
        )

    def execute_document_draft_update(
        self, request: OmniDocumentDraftUpdateRequest
    ) -> TargetOperationOutcome:
        scopes = (
            request.organization_ref,
            request.document_ref,
            request.parent_folder_ref,
            request.environment_ref,
        )
        cached, now, completed = self._prepare(
            request,
            expected_action=OMNI_DOCUMENT_DRAFT_ACTION,
            scopes=scopes,
        )
        if cached is not None:
            return cached
        state = self._document_state_resolver(request)
        if (
            state.organization_ref != request.organization_ref
            or state.document_ref != request.document_ref
            or state.parent_folder_ref != request.parent_folder_ref
            or state.environment_ref != request.environment_ref
            or state.environment_kind != request.environment_kind
            or state.parent_access_verification_ref
            != request.parent_access_verification_ref
            or state.destination_verification_ref
            != request.destination_verification_ref
            or state.current_revision != request.previous_revision
            or state.current_checksum != request.previous_checksum
            or state.validation_cycle_id != request.validation_cycle_id
            or not state.restricted_access
            or state.published
        ):
            raise ValueError("trusted Omni document state fails exact draft-update CAS")
        consumption = self._consume(
            request,
            expected_action=OMNI_DOCUMENT_DRAFT_ACTION,
            scopes=scopes,
            now=now,
            completed=completed,
        )
        return self._complete_post_invocation(
            request,
            consumption,
            request.document_ref,
            completed,
            "Omni draft-update result or evidence requires reconciliation",
            lambda: self._document_draft_outcome(request, consumption),
        )

    def _document_draft_outcome(
        self,
        request: OmniDocumentDraftUpdateRequest,
        consumption: TargetAuthorizationConsumption,
    ) -> TargetOperationOutcome:
        result = self._driver.update_document_draft(request)
        identity_mismatch = self._document_result_differs(
            request=request,
            result=result,
            expected_action=OMNI_DOCUMENT_DRAFT_ACTION,
            expected_document=request.document_ref,
            expected_parent=request.parent_folder_ref,
            expected_environment=request.environment_ref,
            expected_environment_kind=request.environment_kind,
            expected_parent_access_verification=request.parent_access_verification_ref,
            expected_destination_verification=request.destination_verification_ref,
            expected_created_new=False,
            expected_previous_revision=request.previous_revision,
            expected_previous_checksum=request.previous_checksum,
        )
        readback = self._document_readback(
            request, result, state="different" if identity_mismatch else "matched"
        )
        if identity_mismatch:
            return mismatched_outcome(
                request,
                readback=readback,
                remote_receipt_ref=result.remote_receipt_ref,
                authorization_consumption=consumption,
                completed_at=result.completed_at,
                sanitized_message=(
                    "Omni document draft readback violates target, CAS, or quarantine"
                ),
            )
        receipt = self._document_receipt(request, result, readback)
        return TargetOperationOutcome(
            authorization_consumption=consumption,
            receipt=receipt,
            readback=readback,
        )

    @staticmethod
    def _document_result_differs(
        *,
        request: OmniDocumentCreateRequest | OmniDocumentDraftUpdateRequest,
        result: OmniDocumentDriverResult,
        expected_action: str,
        expected_parent: str | None = None,
        expected_environment: str | None = None,
        expected_environment_kind: str | None = None,
        expected_document: str | None = None,
        expected_parent_access_verification: str | None = None,
        expected_destination_verification: str | None = None,
        expected_created_new: bool | None = None,
        expected_previous_revision: str | None = None,
        expected_previous_checksum: str | None = None,
    ) -> bool:
        return (
            result.operation_id != request.operation_id
            or result.idempotency_key != request.idempotency_key
            or result.action != expected_action
            or result.organization_ref != request.organization_ref
            or result.content_fingerprint != request.document_content_fingerprint
            or (expected_parent is not None and result.parent_folder_ref != expected_parent)
            or (expected_environment is not None and result.environment_ref != expected_environment)
            or (
                expected_environment_kind is not None
                and result.environment_kind != expected_environment_kind
            )
            or (expected_document is not None and result.document_ref != expected_document)
            or (
                expected_parent_access_verification is not None
                and result.parent_access_verification_ref
                != expected_parent_access_verification
            )
            or (
                expected_destination_verification is not None
                and result.destination_verification_ref
                != expected_destination_verification
            )
            or result.visibility != "restricted_quarantine"
            or not result.restricted_access
            or result.publish_invoked
            or (
                expected_created_new is not None
                and result.created_new != expected_created_new
            )
            or (
                expected_previous_revision is not None
                and result.consumed_previous_revision != expected_previous_revision
            )
            or (
                expected_previous_checksum is not None
                and result.consumed_previous_checksum != expected_previous_checksum
            )
        )

    @staticmethod
    def _document_readback(
        request: OmniDocumentCreateRequest | OmniDocumentDraftUpdateRequest,
        result: OmniDocumentDriverResult,
        *,
        state: Literal["matched", "different"],
    ) -> OmniDocumentReadback:
        return OmniDocumentReadback(
            operation_id=request.operation_id,
            request_fingerprint=request.request_fingerprint(),
            target_ref=result.document_ref,
            state=state,
            target_revision=result.document_revision,
            content_fingerprint=result.content_fingerprint,
            captured_at=result.completed_at,
            evidence_ref=result.readback_evidence_ref,
            organization_ref=result.organization_ref,
            document_ref=result.document_ref,
            parent_folder_ref=result.parent_folder_ref,
            environment_ref=result.environment_ref,
            environment_kind=result.environment_kind,
            parent_access_verification_ref=result.parent_access_verification_ref,
            destination_verification_ref=result.destination_verification_ref,
            visibility=result.visibility,
            restricted_access=result.restricted_access,
            publish_invoked=result.publish_invoked,
            document_checksum=result.document_checksum,
            created_new=result.created_new,
            consumed_previous_revision=result.consumed_previous_revision,
            consumed_previous_checksum=result.consumed_previous_checksum,
        )

    @staticmethod
    def _document_receipt(
        request: OmniDocumentCreateRequest | OmniDocumentDraftUpdateRequest,
        result: OmniDocumentDriverResult,
        readback: OmniDocumentReadback,
    ) -> OmniDocumentReceipt:
        return OmniDocumentReceipt(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            request_fingerprint=request.request_fingerprint(),
            action=request.action,
            target_ref=readback.target_ref,
            attempt=request.attempt,
            result="succeeded",
            remote_receipt_ref=result.remote_receipt_ref,
            readback_ref=readback.evidence_ref,
            completed_at=readback.captured_at,
            organization_ref=result.organization_ref,
            document_ref=result.document_ref,
            parent_folder_ref=result.parent_folder_ref,
            environment_ref=result.environment_ref,
            document_revision=result.document_revision,
            document_checksum=result.document_checksum,
            visibility=result.visibility,
            publish_invoked=result.publish_invoked,
        )

__all__ = [
    "OMNI_DOCUMENT_CREATE_ACTION",
    "OMNI_DOCUMENT_DRAFT_ACTION",
    "OMNI_MODEL_ACTION",
    "OmniBranchState",
    "OmniBranchStateResolver",
    "OmniDocumentCreateRequest",
    "OmniDocumentDraftUpdateRequest",
    "OmniDocumentDriverResult",
    "OmniDocumentReadback",
    "OmniDocumentReceipt",
    "OmniDocumentState",
    "OmniDocumentStateResolver",
    "OmniModelDriverResult",
    "OmniModelReadback",
    "OmniModelWriteRequest",
    "OmniModelWriteReceipt",
    "OmniQuarantineVerification",
    "OmniQuarantineVerifier",
    "OmniTargetAdapter",
    "OmniTargetDriver",
    "OmniYamlChange",
]
