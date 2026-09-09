"""Governed dbt development-branch adapter.

The injected driver is deliberately narrow: it receives one already validated,
immutable request and must return evidence for the exact commit and dbt commands.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Callable, Literal, Protocol

from pydantic import Field, field_validator, model_validator

from omni_migrator.targets.execution import StoreBackedTargetExecutionResolver

from omni_migrator.targets.contracts import (
    AmbiguousTargetInvocation,
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
    indeterminate_outcome,
    mismatched_outcome,
    validate_non_secret_ref,
)


DBT_BRANCH_ACTION = "write_dbt_development_branch"


class DbtFileChange(_FrozenContract):
    path: str
    path_scope_ref: str
    content: str = Field(min_length=1)
    content_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or "\\" in value
            or ".." in path.parts
            or path.suffix.lower() not in {".sql", ".yml", ".yaml"}
        ):
            raise ValueError("dbt change path must be a safe SQL or YAML repository path")
        return value

    @field_validator("path_scope_ref")
    @classmethod
    def scope_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @model_validator(mode="after")
    def fingerprint_matches_content(self) -> "DbtFileChange":
        if self.content_fingerprint != canonical_fingerprint(self.content):
            raise ValueError("dbt file fingerprint does not match its content")
        return self


class DbtExecutionBudget(_FrozenContract):
    timeout_seconds: int = Field(ge=1, le=1800)
    max_workers: int = Field(ge=1, le=16)


class DbtCommandEvidence(_FrozenContract):
    command: Literal["compile", "build", "test"]
    invocation_id: str = Field(min_length=8)
    selectors: tuple[str, ...] = Field(min_length=1)
    development_target_ref: str
    branch_ref: str
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    dependency_lock_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    elapsed_seconds: float = Field(ge=0)
    result: Literal["passed", "failed"]
    evidence_ref: str

    @field_validator("development_target_ref", "branch_ref", "evidence_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class DbtBranchWriteRequest(TargetOperationRequest):
    action: Literal["write_dbt_development_branch"] = DBT_BRANCH_ACTION
    repository_ref: str
    branch_ref: str
    branch_name: str = Field(min_length=1)
    default_branch_name: str = Field(min_length=1)
    protected_branch_names: tuple[str, ...]
    base_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    changes: tuple[DbtFileChange, ...] = Field(min_length=1)
    allowed_path_prefixes: tuple[str, ...] = Field(min_length=1)
    selectors: tuple[str, ...] = Field(min_length=1)
    commands: tuple[Literal["compile", "build", "test"], ...] = (
        "compile",
        "build",
        "test",
    )
    development_target_ref: str
    development_target_name: str = Field(min_length=1)
    development_schema: str = Field(min_length=1)
    dependency_lock_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    invocation_id: str = Field(min_length=8)
    execution_budget: DbtExecutionBudget
    allow_dependency_install: Literal[False] = False
    allow_run_operation: Literal[False] = False

    @field_validator("repository_ref", "branch_ref", "development_target_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("selectors")
    @classmethod
    def selectors_are_explicit(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]+", value) for value in values
        ):
            raise ValueError("dbt selectors must be non-empty and unique")
        return values

    @field_validator("allowed_path_prefixes")
    @classmethod
    def path_prefixes_are_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("dbt allowed path prefixes must be unique")
        for value in values:
            path = PurePosixPath(value)
            if path.is_absolute() or "\\" in value or ".." in path.parts or not value:
                raise ValueError("dbt allowed path prefix is unsafe")
        return values

    @model_validator(mode="after")
    def branch_and_change_set_are_safe(self) -> "DbtBranchWriteRequest":
        protected = {value.casefold() for value in self.protected_branch_names}
        branch = self.branch_name.casefold()
        if branch == self.default_branch_name.casefold() or branch in protected:
            raise ValueError("dbt target branch cannot be default or protected")
        if branch in {"main", "master", "production", "prod"}:
            raise ValueError("dbt target branch must be an isolated development branch")
        if any(token in self.development_target_name.casefold() for token in ("prod", "production")):
            raise ValueError("dbt target must be a development target")
        if any(token in self.development_schema.casefold() for token in ("prod", "production")):
            raise ValueError("dbt schema must be isolated from production")
        if self.commands != ("compile", "build", "test"):
            raise ValueError("dbt adapter requires compile, build, and test in that order")
        paths = [change.path for change in self.changes]
        if len(paths) != len(set(paths)):
            raise ValueError("dbt change paths must be unique")
        path_scopes = [change.path_scope_ref for change in self.changes]
        if len(path_scopes) != len(set(path_scopes)):
            raise ValueError("dbt changed-path scope references must be unique")
        if any(
            not any(
                change.path == prefix.rstrip("/")
                or change.path.startswith(prefix.rstrip("/") + "/")
                for prefix in self.allowed_path_prefixes
            )
            for change in self.changes
        ):
            raise ValueError("dbt change path is outside the authorized path prefixes")
        material = {
            "repository_ref": self.repository_ref,
            "branch_ref": self.branch_ref,
            "branch_name": self.branch_name,
            "base_commit_sha": self.base_commit_sha,
            "changes": [change.model_dump(mode="json") for change in self.changes],
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "selectors": list(self.selectors),
            "commands": list(self.commands),
            "development_target_ref": self.development_target_ref,
            "development_target_name": self.development_target_name,
            "development_schema": self.development_schema,
            "dependency_lock_fingerprint": self.dependency_lock_fingerprint,
            "invocation_id": self.invocation_id,
            "execution_budget": self.execution_budget.model_dump(mode="json"),
        }
        if self.change_set_fingerprint != canonical_fingerprint(material):
            raise ValueError("dbt request fingerprint does not match the exact change set")
        return self


class DbtBranchState(_FrozenContract):
    """Trusted current repository state resolved before authorization consumption."""

    repository_ref: str
    branch_ref: str
    branch_name: str = Field(min_length=1)
    default_branch_name: str = Field(min_length=1)
    protected_branch_names: tuple[str, ...]
    base_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    allowed_path_prefixes: tuple[str, ...] = Field(min_length=1)
    allowed_path_scope_refs: tuple[str, ...] = Field(min_length=1)
    is_default: bool
    is_protected: bool
    validation_cycle_id: str
    evidence_ref: str

    @field_validator("repository_ref", "branch_ref", "evidence_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("allowed_path_scope_refs")
    @classmethod
    def path_scopes_are_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("trusted dbt path scope references must be unique")
        return tuple(validate_non_secret_ref(value) for value in values)


class DbtBranchStateResolver(Protocol):
    def __call__(self, request: DbtBranchWriteRequest) -> DbtBranchState: ...


class DbtDriverResult(_FrozenContract):
    operation_id: str
    idempotency_key: str
    remote_receipt_ref: str
    repository_ref: str
    branch_ref: str
    base_commit_sha: str
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    applied_change_set_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    tree_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    applied_paths: tuple[str, ...] = Field(min_length=1)
    dependency_lock_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    enforced_execution_budget: DbtExecutionBudget
    elapsed_seconds: float = Field(ge=0)
    max_workers_used: int = Field(ge=1)
    command_evidence: tuple[DbtCommandEvidence, ...] = Field(min_length=3, max_length=3)
    readback_evidence_ref: str
    completed_at: str

    @field_validator(
        "remote_receipt_ref",
        "repository_ref",
        "branch_ref",
        "readback_evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class DbtBuildReadback(TargetOperationReadback):
    repository_ref: str
    branch_ref: str
    base_commit_sha: str
    commit_sha: str
    applied_paths: tuple[str, ...]
    dependency_lock_fingerprint: str
    branch_state_evidence_ref: str
    command_evidence: tuple[DbtCommandEvidence, ...]

    @field_validator(
        "repository_ref", "branch_ref", "branch_state_evidence_ref"
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class DbtWriteReceipt(TargetOperationReceipt):
    repository_ref: str
    branch_ref: str
    base_commit_sha: str
    commit_sha: str
    applied_change_set_fingerprint: str
    command_evidence_refs: tuple[str, ...]

    @field_validator("repository_ref", "branch_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("command_evidence_refs")
    @classmethod
    def evidence_refs_are_safe(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(validate_non_secret_ref(value) for value in values)


class DbtTargetDriver(Protocol):
    def write_and_validate(self, request: DbtBranchWriteRequest) -> DbtDriverResult: ...


class DbtTargetAdapter:
    def __init__(
        self,
        driver: DbtTargetDriver,
        *,
        authorization_store: TargetAuthorizationStore,
        operation_store: TargetOperationStore,
        execution_resolver: StoreBackedTargetExecutionResolver,
        branch_state_resolver: DbtBranchStateResolver,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._driver = driver
        self._guard = TargetAdapterGuard(operation_store, execution_resolver)
        self._authorization_store = authorization_store
        self._branch_state_resolver = branch_state_resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._authorization_consumptions: list[TargetAuthorizationConsumption] = []

    @property
    def authorization_consumptions(self) -> tuple[TargetAuthorizationConsumption, ...]:
        return tuple(self._authorization_consumptions)

    def _resolve_branch_state(self, request: DbtBranchWriteRequest) -> DbtBranchState:
        state = self._branch_state_resolver(request)
        requested_protected = {value.casefold() for value in request.protected_branch_names}
        trusted_protected = {value.casefold() for value in state.protected_branch_names}
        if (
            state.repository_ref != request.repository_ref
            or state.branch_ref != request.branch_ref
            or state.branch_name != request.branch_name
            or state.default_branch_name != request.default_branch_name
            or trusted_protected != requested_protected
            or state.base_commit_sha != request.base_commit_sha
            or state.allowed_path_prefixes != request.allowed_path_prefixes
            or state.allowed_path_scope_refs
            != tuple(change.path_scope_ref for change in request.changes)
            or state.validation_cycle_id != request.validation_cycle_id
        ):
            raise ValueError("trusted dbt branch state differs from the target request")
        if (
            state.is_default
            or state.is_protected
            or state.branch_name.casefold() == state.default_branch_name.casefold()
            or state.branch_name.casefold() in trusted_protected
        ):
            raise ValueError("trusted dbt branch state is default or protected")
        return state

    @staticmethod
    def _required_scopes(request: DbtBranchWriteRequest) -> tuple[str, ...]:
        return (
            request.repository_ref,
            request.branch_ref,
            request.development_target_ref,
            *(change.path_scope_ref for change in request.changes),
        )

    def execute(self, request: DbtBranchWriteRequest) -> TargetOperationOutcome:
        now = self._clock()
        required_scopes = self._required_scopes(request)
        cached = self._guard.prepare(
            request,
            expected_action=DBT_BRANCH_ACTION,
            required_scope_refs=required_scopes,
            now=now,
        )
        if cached is not None:
            return cached
        branch_state = self._resolve_branch_state(request)
        consumed_at = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        self._guard.claim_execution(request, now=now)
        consumption = self._authorization_store.resolve_and_consume(
            request,
            expected_action=DBT_BRANCH_ACTION,
            required_scope_refs=required_scopes,
            now=now,
            consumed_at=consumed_at,
        )
        self._authorization_consumptions.append(consumption)
        try:
            outcome = self._post_invocation_outcome(
                request,
                consumption=consumption,
                branch_state=branch_state,
                consumed_at=consumed_at,
            )
        except Exception:
            outcome = indeterminate_outcome(
                request,
                target_ref=request.branch_ref,
                authorization_consumption=consumption,
                completed_at=consumed_at,
                evidence_ref=(
                    f"evidence-ref://target-adapter/dbt/{request.operation_id}/"
                    "post-invocation-validation"
                ),
                sanitized_message=(
                    "dbt post-invocation result or evidence requires reconciliation"
                ),
            )
        return self._guard.remember(request, outcome)

    def _post_invocation_outcome(
        self,
        request: DbtBranchWriteRequest,
        *,
        consumption: TargetAuthorizationConsumption,
        branch_state: DbtBranchState,
        consumed_at: str,
    ) -> TargetOperationOutcome:
        try:
            result = self._driver.write_and_validate(request)
        except AmbiguousTargetInvocation as exc:
            readback = TargetOperationReadback.model_validate(
                exc.readback.model_dump(mode="python")
            )
            return ambiguous_outcome(
                request,
                target_ref=request.branch_ref,
                readback=readback,
                authorization_consumption=consumption,
                completed_at=consumed_at,
            )
        expected_paths = tuple(change.path for change in request.changes)
        identity_mismatch = (
            result.operation_id != request.operation_id
            or result.idempotency_key != request.idempotency_key
            or result.repository_ref != request.repository_ref
            or result.branch_ref != request.branch_ref
            or result.base_commit_sha != request.base_commit_sha
            or result.applied_change_set_fingerprint != request.change_set_fingerprint
            or result.applied_paths != expected_paths
            or result.dependency_lock_fingerprint != request.dependency_lock_fingerprint
            or result.enforced_execution_budget != request.execution_budget
            or result.elapsed_seconds > request.execution_budget.timeout_seconds
            or result.max_workers_used > request.execution_budget.max_workers
            or tuple(item.command for item in result.command_evidence) != request.commands
            or any(
                item.invocation_id != request.invocation_id
                or item.selectors != request.selectors
                or item.development_target_ref != request.development_target_ref
                or item.branch_ref != request.branch_ref
                or item.commit_sha != result.commit_sha
                or item.dependency_lock_fingerprint
                != request.dependency_lock_fingerprint
                or item.elapsed_seconds > request.execution_budget.timeout_seconds
                or item.result != "passed"
                for item in result.command_evidence
            )
        )
        readback = DbtBuildReadback(
            operation_id=request.operation_id,
            request_fingerprint=request.request_fingerprint(),
            target_ref=result.branch_ref,
            state="different" if identity_mismatch else "matched",
            target_revision=result.commit_sha,
            content_fingerprint=result.tree_fingerprint,
            captured_at=result.completed_at,
            evidence_ref=result.readback_evidence_ref,
            repository_ref=result.repository_ref,
            branch_ref=result.branch_ref,
            base_commit_sha=result.base_commit_sha,
            commit_sha=result.commit_sha,
            applied_paths=result.applied_paths,
            dependency_lock_fingerprint=result.dependency_lock_fingerprint,
            branch_state_evidence_ref=branch_state.evidence_ref,
            command_evidence=result.command_evidence,
        )
        if identity_mismatch:
            return mismatched_outcome(
                request,
                readback=readback,
                remote_receipt_ref=result.remote_receipt_ref,
                authorization_consumption=consumption,
                completed_at=result.completed_at,
                sanitized_message=(
                    "dbt post-invocation identity, budget, or validation evidence mismatch"
                ),
            )
        receipt = DbtWriteReceipt(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            request_fingerprint=request.request_fingerprint(),
            action=request.action,
            target_ref=request.branch_ref,
            attempt=request.attempt,
            result="succeeded",
            remote_receipt_ref=result.remote_receipt_ref,
            readback_ref=result.readback_evidence_ref,
            completed_at=result.completed_at,
            repository_ref=result.repository_ref,
            branch_ref=result.branch_ref,
            base_commit_sha=result.base_commit_sha,
            commit_sha=result.commit_sha,
            applied_change_set_fingerprint=result.applied_change_set_fingerprint,
            command_evidence_refs=tuple(
                evidence.evidence_ref for evidence in result.command_evidence
            ),
        )
        return TargetOperationOutcome(
            authorization_consumption=consumption,
            receipt=receipt,
            readback=readback,
        )


__all__ = [
    "DBT_BRANCH_ACTION",
    "DbtBranchState",
    "DbtBranchStateResolver",
    "DbtBranchWriteRequest",
    "DbtBuildReadback",
    "DbtCommandEvidence",
    "DbtDriverResult",
    "DbtExecutionBudget",
    "DbtFileChange",
    "DbtTargetAdapter",
    "DbtTargetDriver",
    "DbtWriteReceipt",
]
