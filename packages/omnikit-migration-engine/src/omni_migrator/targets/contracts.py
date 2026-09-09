"""Shared immutable contracts and pre-invocation guards for target adapters.

These contracts do not grant authority. They bind one already-approved human
authorization to one exact change set, target scope, validation cycle, and operation.
Adapters validate the complete request before invoking an injected target driver.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timezone
from threading import RLock
from typing import TYPE_CHECKING, Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omni_migrator.control_plane.canonical import parse_time, sha256_json

if TYPE_CHECKING:
    from omni_migrator.targets.execution import StoreBackedTargetExecutionResolver

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{7,191}$"
_FORBIDDEN_REF_SCHEMES = {
    "secret",
    "secret-ref",
    "vault",
    "vault-ref",
    "credential",
    "credential-ref",
}


class FrozenJsonSequence(Sequence[Any]):
    """Recursively immutable JSON array used inside signed target requests."""

    __slots__ = ("_values",)

    def __init__(self, values: Sequence[Any]) -> None:
        self._values = tuple(freeze_json(value) for value in values)

    def __getitem__(self, index: int | slice) -> Any:
        return self._values[index]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __repr__(self) -> str:
        return repr(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FrozenJsonSequence):
            return self._values == other._values
        if isinstance(other, Sequence) and not isinstance(other, (str, bytes, bytearray)):
            return tuple(self._values) == tuple(other)
        return False

    def __hash__(self) -> int:
        return hash(self._values)


class FrozenJsonMap(Mapping[str, Any]):
    """Recursively immutable, deterministically ordered JSON object."""

    __slots__ = ("_items",)

    def __init__(self, values: Mapping[str, Any]) -> None:
        if any(not isinstance(key, str) for key in values):
            raise TypeError("JSON object keys must be strings")
        self._items = tuple(
            (key, freeze_json(value)) for key, value in sorted(values.items())
        )

    def __getitem__(self, key: str) -> Any:
        for candidate, value in self._items:
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return repr(dict(self._items))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return thaw_json(self) == thaw_json(other)
        return False

    def __hash__(self) -> int:
        return hash(self._items)


def freeze_json(value: Any) -> Any:
    """Deep-freeze a JSON value and reject non-canonical/non-finite data."""

    if isinstance(value, (FrozenJsonMap, FrozenJsonSequence)):
        return value
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        return FrozenJsonMap(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return FrozenJsonSequence(value)
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def thaw_json(value: Any) -> Any:
    """Return a detached plain-JSON copy suitable for hashing or serialization."""

    if isinstance(value, FrozenJsonMap):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, FrozenJsonSequence):
        return [thaw_json(item) for item in value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [thaw_json(item) for item in value]
    return value


def canonical_fingerprint(value: Any) -> str:
    """Return the repository-standard raw lowercase SHA-256 contract digest."""

    return sha256_json(thaw_json(value))


def validate_non_secret_ref(value: str) -> str:
    parsed = urlsplit(value)
    if (
        not parsed.scheme
        or parsed.scheme.lower() in _FORBIDDEN_REF_SCHEMES
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (not parsed.netloc and not parsed.path)
    ):
        raise ValueError("target references must be non-secret URI references")
    return value


def _validate_timestamp(value: str) -> str:
    try:
        parse_time(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("target contract timestamps must be timezone-aware") from exc
    return value


class _FrozenContract(BaseModel):
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=True,
        strict=True,
    )


class TargetAuthorizationBinding(_FrozenContract):
    """Resolved human authorization for exactly one operation change set."""

    authorization_ref: str
    authorization_id: str = Field(pattern=_ID_PATTERN)
    actor_ref: str
    actor_kind: Literal["human"] = "human"
    action: str = Field(min_length=1)
    scope_refs: tuple[str, ...] = Field(min_length=1)
    approved_at: str
    expires_at: str
    artifact_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    validation_cycle_id: str = Field(pattern=_ID_PATTERN)
    approval_evidence_ref: str

    @field_validator(
        "authorization_ref",
        "actor_ref",
        "approval_evidence_ref",
    )
    @classmethod
    def references_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("scope_refs")
    @classmethod
    def scopes_are_safe_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("authorization scopes must be unique")
        return tuple(validate_non_secret_ref(value) for value in values)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def timestamps_are_valid(cls, value: str) -> str:
        return _validate_timestamp(value)


class TargetReconciliation(_FrozenContract):
    """Independent readback disposition for one ambiguous prior operation."""

    prior_operation_id: str = Field(pattern=_ID_PATTERN)
    prior_request_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    target_ref: str
    readback_ref: str
    outcome: Literal["applied", "not_applied", "indeterminate"]
    reconciled_at: str
    reconciled_by_ref: str

    @field_validator("target_ref", "readback_ref", "reconciled_by_ref")
    @classmethod
    def references_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("reconciled_at")
    @classmethod
    def timestamp_is_valid(cls, value: str) -> str:
        return _validate_timestamp(value)


class TargetOperationRequest(_FrozenContract):
    """Common immutable identity shared by every target adapter request."""

    contract_version: Literal["domo-to-omni.target-operation-request.v1"] = (
        "domo-to-omni.target-operation-request.v1"
    )
    tenant_ref: str
    run_id: str = Field(pattern=_ID_PATTERN)
    migration_unit_id: str = Field(pattern=_ID_PATTERN)
    validation_cycle_id: str = Field(pattern=_ID_PATTERN)
    work_package_id: str = Field(pattern=_ID_PATTERN)
    operation_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    action: str = Field(min_length=1)
    change_set_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    authorization: TargetAuthorizationBinding
    requested_at: str
    attempt: int = Field(default=1, ge=1)
    retry_of_operation_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    reconciliation: TargetReconciliation | None = None

    @field_validator("tenant_ref")
    @classmethod
    def tenant_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("requested_at")
    @classmethod
    def timestamp_is_valid(cls, value: str) -> str:
        return _validate_timestamp(value)

    @model_validator(mode="after")
    def retry_shape_is_explicit(self) -> "TargetOperationRequest":
        if self.attempt == 1 and (
            self.retry_of_operation_id is not None or self.reconciliation is not None
        ):
            raise ValueError("first target attempt cannot carry retry state")
        if self.attempt > 1 and self.retry_of_operation_id is None:
            raise ValueError("target retries require the prior operation ID")
        return self

    def request_fingerprint(self) -> str:
        return canonical_fingerprint(self.model_dump(mode="json"))


class TargetOperationReadback(_FrozenContract):
    contract_version: Literal["domo-to-omni.target-readback.v1"] = (
        "domo-to-omni.target-readback.v1"
    )
    operation_id: str = Field(pattern=_ID_PATTERN)
    request_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    target_ref: str
    state: Literal["matched", "different", "indeterminate"]
    target_revision: str = Field(min_length=1)
    content_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    captured_at: str
    evidence_ref: str

    @field_validator("target_ref", "evidence_ref")
    @classmethod
    def references_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("captured_at")
    @classmethod
    def timestamp_is_valid(cls, value: str) -> str:
        return _validate_timestamp(value)


class TargetAuthorizationConsumption(_FrozenContract):
    """One-time authorization consumption emitted before driver invocation."""

    contract_version: Literal["domo-to-omni.authorization-consumption.v1"] = (
        "domo-to-omni.authorization-consumption.v1"
    )
    authorization_ref: str
    authorization_id: str = Field(pattern=_ID_PATTERN)
    operation_id: str = Field(pattern=_ID_PATTERN)
    action: str = Field(min_length=1)
    request_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    consumed_at: str

    @field_validator("authorization_ref")
    @classmethod
    def reference_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("consumed_at")
    @classmethod
    def timestamp_is_valid(cls, value: str) -> str:
        return _validate_timestamp(value)


class TargetOperationReceipt(_FrozenContract):
    contract_version: Literal["domo-to-omni.target-operation-receipt.v1"] = (
        "domo-to-omni.target-operation-receipt.v1"
    )
    operation_id: str = Field(pattern=_ID_PATTERN)
    idempotency_key: str = Field(pattern=_ID_PATTERN)
    request_fingerprint: str = Field(pattern=_SHA256_PATTERN)
    action: str = Field(min_length=1)
    target_ref: str
    attempt: int = Field(ge=1)
    result: Literal["succeeded", "failed", "ambiguous"]
    remote_receipt_ref: str | None = None
    readback_ref: str | None = None
    completed_at: str
    sanitized_message: str | None = None

    @field_validator("target_ref")
    @classmethod
    def target_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("remote_receipt_ref", "readback_ref")
    @classmethod
    def optional_refs_are_safe(cls, value: str | None) -> str | None:
        return validate_non_secret_ref(value) if value is not None else None

    @field_validator("completed_at")
    @classmethod
    def timestamp_is_valid(cls, value: str) -> str:
        return _validate_timestamp(value)

    @model_validator(mode="after")
    def evidence_matches_result(self) -> "TargetOperationReceipt":
        if self.result == "succeeded" and (
            self.remote_receipt_ref is None or self.readback_ref is None
        ):
            raise ValueError("successful target operations require receipt and readback")
        if self.result == "ambiguous" and self.readback_ref is None:
            raise ValueError("ambiguous target operations require reconciliation readback")
        return self


class TargetOperationOutcome(_FrozenContract):
    authorization_consumption: TargetAuthorizationConsumption
    receipt: TargetOperationReceipt
    readback: TargetOperationReadback | None

    @model_validator(mode="after")
    def readback_matches_receipt(self) -> "TargetOperationOutcome":
        if (
            self.authorization_consumption.operation_id != self.receipt.operation_id
            or self.authorization_consumption.action != self.receipt.action
            or self.authorization_consumption.request_fingerprint
            != self.receipt.request_fingerprint
        ):
            raise ValueError("authorization consumption does not match the target receipt")
        if self.receipt.result in {"succeeded", "ambiguous"} and self.readback is None:
            raise ValueError("successful or ambiguous outcomes require typed readback")
        if self.readback is not None:
            if self.readback.operation_id != self.receipt.operation_id:
                raise ValueError("receipt and readback operation IDs differ")
            if self.readback.request_fingerprint != self.receipt.request_fingerprint:
                raise ValueError("receipt and readback request fingerprints differ")
            if self.readback.target_ref != self.receipt.target_ref:
                raise ValueError("receipt and readback targets differ")
            if self.receipt.result == "succeeded" and self.readback.state != "matched":
                raise ValueError("successful target operation requires exact matched readback")
            if self.receipt.result == "ambiguous" and self.readback.state == "matched":
                raise ValueError("ambiguous target operation cannot carry matched readback")
        return self


class TargetAuthorizationStore(Protocol):
    """Trusted atomic authorization resolver/consumer.

    Production implementations must make resolution and one-time consumption durable.
    The in-memory implementation below is deterministic and can be shared by fake
    adapters to exercise the same cross-instance contract.
    """

    def resolve_and_consume(
        self,
        request: TargetOperationRequest,
        *,
        expected_action: str,
        required_scope_refs: tuple[str, ...],
        now: datetime,
        consumed_at: str,
    ) -> TargetAuthorizationConsumption: ...


class TargetOperationStore(Protocol):
    """Durable operation/idempotency/reconciliation registry boundary."""

    def get_by_idempotency_key(
        self, key: str
    ) -> tuple[str, TargetOperationOutcome] | None: ...

    def get_by_operation_id(
        self, operation_id: str
    ) -> tuple[TargetOperationRequest, TargetOperationOutcome] | None: ...

    def get_reconciliation(self, operation_id: str) -> TargetReconciliation | None: ...

    def remember(
        self,
        request: TargetOperationRequest,
        outcome: TargetOperationOutcome,
    ) -> TargetOperationOutcome: ...


class InMemoryTargetAuthorizationStore:
    """Thread-safe trusted fake authorization store shared across adapters."""

    def __init__(self, bindings: tuple[TargetAuthorizationBinding, ...] = ()) -> None:
        self._lock = RLock()
        self._by_ref: dict[str, TargetAuthorizationBinding] = {}
        self._ref_by_id: dict[str, str] = {}
        self._consumed_by_ref: dict[str, TargetAuthorizationConsumption] = {}
        self._consumed_by_id: dict[str, TargetAuthorizationConsumption] = {}
        for binding in bindings:
            self.register(binding)

    def register(self, binding: TargetAuthorizationBinding) -> None:
        with self._lock:
            prior_by_ref = self._by_ref.get(binding.authorization_ref)
            if prior_by_ref is not None and prior_by_ref != binding:
                raise ValueError("authorization reference is already bound to another record")
            prior_ref = self._ref_by_id.get(binding.authorization_id)
            if prior_ref is not None and prior_ref != binding.authorization_ref:
                raise ValueError("authorization ID cannot be registered under another reference")
            self._by_ref[binding.authorization_ref] = binding
            self._ref_by_id[binding.authorization_id] = binding.authorization_ref

    @property
    def consumptions(self) -> tuple[TargetAuthorizationConsumption, ...]:
        with self._lock:
            return tuple(self._consumed_by_ref.values())

    def resolve_and_consume(
        self,
        request: TargetOperationRequest,
        *,
        expected_action: str,
        required_scope_refs: tuple[str, ...],
        now: datetime,
        consumed_at: str,
    ) -> TargetAuthorizationConsumption:
        with self._lock:
            trusted = self._by_ref.get(request.authorization.authorization_ref)
            if trusted is None:
                raise ValueError("target authorization is absent from the trusted store")
            if trusted != request.authorization:
                raise ValueError("request authorization differs from the trusted record")
            consumed = self._consumed_by_ref.get(trusted.authorization_ref)
            if consumed is None:
                consumed = self._consumed_by_id.get(trusted.authorization_id)
            if consumed is not None:
                raise ValueError(
                    "one-time target authorization is already consumed by operation "
                    f"{consumed.operation_id}"
                )
            validate_authorization(
                request,
                expected_action=expected_action,
                required_scope_refs=required_scope_refs,
                now=now,
            )
            _as_utc(consumed_at, "authorization consumption")
            consumption = TargetAuthorizationConsumption(
                authorization_ref=trusted.authorization_ref,
                authorization_id=trusted.authorization_id,
                operation_id=request.operation_id,
                action=request.action,
                request_fingerprint=request.request_fingerprint(),
                consumed_at=consumed_at,
            )
            self._consumed_by_ref[trusted.authorization_ref] = consumption
            self._consumed_by_id[trusted.authorization_id] = consumption
            return consumption


class InMemoryTargetOperationStore:
    """Thread-safe fake durable registry for cross-adapter idempotency tests."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._by_idempotency_key: dict[str, tuple[str, TargetOperationOutcome]] = {}
        self._by_operation_id: dict[
            str, tuple[TargetOperationRequest, TargetOperationOutcome]
        ] = {}
        self._reconciliations: dict[str, TargetReconciliation] = {}

    def get_by_idempotency_key(
        self, key: str
    ) -> tuple[str, TargetOperationOutcome] | None:
        with self._lock:
            return self._by_idempotency_key.get(key)

    def get_by_operation_id(
        self, operation_id: str
    ) -> tuple[TargetOperationRequest, TargetOperationOutcome] | None:
        with self._lock:
            return self._by_operation_id.get(operation_id)

    def get_reconciliation(self, operation_id: str) -> TargetReconciliation | None:
        with self._lock:
            return self._reconciliations.get(operation_id)

    def register_reconciliation(self, reconciliation: TargetReconciliation) -> None:
        with self._lock:
            prior = self._reconciliations.get(reconciliation.prior_operation_id)
            if prior is not None and prior != reconciliation:
                raise ValueError("target operation already has another reconciliation")
            self._reconciliations[reconciliation.prior_operation_id] = reconciliation

    def remember(
        self,
        request: TargetOperationRequest,
        outcome: TargetOperationOutcome,
    ) -> TargetOperationOutcome:
        with self._lock:
            fingerprint = request.request_fingerprint()
            prior_key = self._by_idempotency_key.get(request.idempotency_key)
            if prior_key is not None:
                prior_fingerprint, prior_outcome = prior_key
                if prior_fingerprint != fingerprint or prior_outcome != outcome:
                    raise ValueError("idempotency key conflicts with a registered outcome")
                return prior_outcome
            prior_operation = self._by_operation_id.get(request.operation_id)
            if prior_operation is not None:
                prior_request, prior_outcome = prior_operation
                if prior_request != request or prior_outcome != outcome:
                    raise ValueError("operation ID conflicts with a registered outcome")
                return prior_outcome
            self._by_idempotency_key[request.idempotency_key] = (fingerprint, outcome)
            self._by_operation_id[request.operation_id] = (request, outcome)
            return outcome


class AmbiguousTargetInvocation(RuntimeError):
    """Driver signal for an operation whose application state is unknown."""

    def __init__(self, readback: TargetOperationReadback):
        super().__init__("target operation result is ambiguous")
        self.readback = readback


def _as_utc(value: str, label: str) -> datetime:
    try:
        return parse_time(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a timezone-aware timestamp") from exc


def validate_authorization(
    request: TargetOperationRequest,
    *,
    expected_action: str,
    required_scope_refs: tuple[str, ...],
    now: datetime,
) -> None:
    """Fail closed on authorization before any target driver is invoked."""

    if now.tzinfo is None:
        raise ValueError("target adapter clock must be timezone-aware")
    authorization = request.authorization
    if request.action != expected_action or authorization.action != expected_action:
        raise ValueError("target action does not match its authorization")
    if authorization.validation_cycle_id != request.validation_cycle_id:
        raise ValueError("target authorization belongs to a stale validation cycle")
    if authorization.artifact_fingerprint != request.change_set_fingerprint:
        raise ValueError("target authorization is not bound to the exact change set")
    expected = set(required_scope_refs)
    if not expected or expected != set(authorization.scope_refs):
        raise ValueError("target authorization does not cover the exact target scope")
    approved_at = _as_utc(authorization.approved_at, "authorization approval")
    expires_at = _as_utc(authorization.expires_at, "authorization expiry")
    requested_at = _as_utc(request.requested_at, "target request time")
    current = now.astimezone(timezone.utc)
    if approved_at > requested_at or requested_at > current:
        raise ValueError("target request predates approval or is in the future")
    if expires_at <= approved_at or expires_at <= current:
        raise ValueError("target authorization is expired or has an invalid lifetime")


class TargetAdapterGuard:
    """Fail-closed idempotency and retry guard over a durable store boundary."""

    def __init__(
        self, operation_store: TargetOperationStore,
        execution_resolver: StoreBackedTargetExecutionResolver,
    ) -> None:
        from omni_migrator.targets.execution import StoreBackedTargetExecutionResolver

        if type(execution_resolver) is not StoreBackedTargetExecutionResolver:
            raise TypeError("target adapters require the canonical store-backed execution resolver")
        self._operation_store = operation_store
        self._execution_resolver = execution_resolver

    def claim_execution(self, request: TargetOperationRequest, *, now: datetime) -> None:
        self._execution_resolver.resolve_and_claim(request, now=now)

    def prepare(
        self,
        request: TargetOperationRequest,
        *,
        expected_action: str,
        required_scope_refs: tuple[str, ...],
        now: datetime,
    ) -> TargetOperationOutcome | None:
        # Re-parse serialized state so model_copy or nested mutation cannot bypass
        # the request's exact-change-set validators.
        reparsed = type(request).model_validate(request.model_dump(mode="python"))
        if reparsed != request:
            raise ValueError("target request is not canonical or was mutated after validation")
        validate_authorization(
            request,
            expected_action=expected_action,
            required_scope_refs=required_scope_refs,
            now=now,
        )
        fingerprint = request.request_fingerprint()
        prior_idempotent = self._operation_store.get_by_idempotency_key(
            request.idempotency_key
        )
        if prior_idempotent is not None:
            prior_fingerprint, outcome = prior_idempotent
            if prior_fingerprint != fingerprint:
                raise ValueError("idempotency key is already bound to another request")
            return outcome
        if self._operation_store.get_by_operation_id(request.operation_id) is not None:
            raise ValueError("target operation ID is already registered")
        if request.attempt > 1:
            prior = self._operation_store.get_by_operation_id(
                str(request.retry_of_operation_id)
            )
            if prior is None:
                raise ValueError("target retry references no prior operation")
            prior_request, prior_outcome = prior
            if request.attempt != prior_request.attempt + 1:
                raise ValueError("target retry attempt is not sequential")
            if request.action != prior_request.action:
                raise ValueError("target retry action differs from the prior operation")
            if request.change_set_fingerprint != prior_request.change_set_fingerprint:
                raise ValueError("target retry change set differs from the prior operation")
            if prior_outcome.receipt.result == "succeeded":
                raise ValueError("successful target operations cannot be retried")
            if prior_outcome.receipt.result == "ambiguous":
                reconciliation = request.reconciliation
                trusted_reconciliation = self._operation_store.get_reconciliation(
                    prior_request.operation_id
                )
                if (
                    reconciliation is None
                    or trusted_reconciliation is None
                    or reconciliation != trusted_reconciliation
                    or reconciliation.prior_operation_id != prior_request.operation_id
                    or reconciliation.prior_request_fingerprint
                    != prior_request.request_fingerprint()
                    or reconciliation.target_ref != prior_outcome.receipt.target_ref
                    or reconciliation.outcome != "not_applied"
                ):
                    raise ValueError(
                        "ambiguous target operation must be reconciled as not applied before retry"
                    )
            elif request.reconciliation is not None:
                raise ValueError("failed target operation retry cannot carry ambiguity reconciliation")
        self._execution_resolver.validate(request, now=now)
        return None

    def remember(
        self,
        request: TargetOperationRequest,
        outcome: TargetOperationOutcome,
    ) -> TargetOperationOutcome:
        if (
            outcome.receipt.operation_id != request.operation_id
            or outcome.receipt.idempotency_key != request.idempotency_key
            or outcome.receipt.action != request.action
            or outcome.receipt.request_fingerprint != request.request_fingerprint()
        ):
            raise ValueError("target outcome is not bound to the exact remote operation request")
        return self._operation_store.remember(request, outcome)


def ambiguous_outcome(
    request: TargetOperationRequest,
    *,
    target_ref: str,
    readback: TargetOperationReadback,
    authorization_consumption: TargetAuthorizationConsumption,
    completed_at: str,
    remote_receipt_ref: str | None = None,
    sanitized_message: str = "target application state requires reconciliation",
) -> TargetOperationOutcome:
    if readback.operation_id != request.operation_id:
        raise ValueError("ambiguous readback belongs to another operation")
    receipt = TargetOperationReceipt(
        operation_id=request.operation_id,
        idempotency_key=request.idempotency_key,
        request_fingerprint=request.request_fingerprint(),
        action=request.action,
        target_ref=target_ref,
        attempt=request.attempt,
        result="ambiguous",
        remote_receipt_ref=remote_receipt_ref,
        readback_ref=readback.evidence_ref,
        completed_at=completed_at,
        sanitized_message=sanitized_message,
    )
    return TargetOperationOutcome(
        authorization_consumption=authorization_consumption,
        receipt=receipt,
        readback=readback,
    )


def mismatched_outcome(
    request: TargetOperationRequest,
    *,
    readback: TargetOperationReadback,
    remote_receipt_ref: str,
    authorization_consumption: TargetAuthorizationConsumption,
    completed_at: str,
    sanitized_message: str,
) -> TargetOperationOutcome:
    """Persist a post-invocation evidence mismatch as ambiguous, never as a raw gap."""

    if readback.state != "different":
        raise ValueError("post-invocation mismatch requires different-state readback")
    return ambiguous_outcome(
        request,
        target_ref=readback.target_ref,
        readback=readback,
        authorization_consumption=authorization_consumption,
        completed_at=completed_at,
        remote_receipt_ref=remote_receipt_ref,
        sanitized_message=sanitized_message,
    )


def indeterminate_outcome(
    request: TargetOperationRequest,
    *,
    target_ref: str,
    authorization_consumption: TargetAuthorizationConsumption,
    completed_at: str,
    evidence_ref: str,
    sanitized_message: str,
) -> TargetOperationOutcome:
    """Build a deterministic safe ambiguity when post-invocation evidence is unusable."""

    readback = TargetOperationReadback(
        operation_id=request.operation_id,
        request_fingerprint=request.request_fingerprint(),
        target_ref=target_ref,
        state="indeterminate",
        target_revision="unknown",
        content_fingerprint="0" * 64,
        captured_at=completed_at,
        evidence_ref=evidence_ref,
    )
    return ambiguous_outcome(
        request,
        target_ref=target_ref,
        readback=readback,
        authorization_consumption=authorization_consumption,
        completed_at=completed_at,
        sanitized_message=sanitized_message,
    )


__all__ = [
    "AmbiguousTargetInvocation",
    "FrozenJsonMap",
    "FrozenJsonSequence",
    "InMemoryTargetAuthorizationStore",
    "InMemoryTargetOperationStore",
    "TargetAdapterGuard",
    "TargetAuthorizationBinding",
    "TargetAuthorizationConsumption",
    "TargetAuthorizationStore",
    "TargetOperationOutcome",
    "TargetOperationReadback",
    "TargetOperationReceipt",
    "TargetOperationRequest",
    "TargetOperationStore",
    "TargetReconciliation",
    "ambiguous_outcome",
    "canonical_fingerprint",
    "freeze_json",
    "indeterminate_outcome",
    "mismatched_outcome",
    "thaw_json",
    "validate_authorization",
    "validate_non_secret_ref",
]
