"""Bounded, read-only Snowflake validation-query adapter."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Literal, Protocol

from pydantic import Field, field_validator, model_validator

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
    validate_non_secret_ref,
)
from omni_migrator.targets.execution import StoreBackedTargetExecutionResolver


SNOWFLAKE_QUERY_ACTION = "execute_snowflake_bounded_query"
_FORBIDDEN_SQL = {
    "ALTER",
    "CALL",
    "COPY",
    "CREATE",
    "DELETE",
    "DROP",
    "EXECUTE",
    "GRANT",
    "INSERT",
    "MERGE",
    "PUT",
    "REMOVE",
    "REVOKE",
    "TRUNCATE",
    "UPDATE",
    "USE",
}


def _sql_without_literals(sql: str) -> str:
    if "--" in sql or "/*" in sql or "*/" in sql:
        raise ValueError("Snowflake validation SQL cannot contain comments")
    output: list[str] = []
    in_string = False
    index = 0
    while index < len(sql):
        char = sql[index]
        if char == "'":
            if in_string and index + 1 < len(sql) and sql[index + 1] == "'":
                output.extend((" ", " "))
                index += 2
                continue
            in_string = not in_string
            output.append(" ")
        else:
            output.append(" " if in_string else char)
        index += 1
    if in_string:
        raise ValueError("Snowflake validation SQL contains an unterminated literal")
    return "".join(output)


def _validate_read_only_statement(sql: str) -> str:
    scrubbed = _sql_without_literals(sql).strip()
    if scrubbed.endswith(";"):
        scrubbed = scrubbed[:-1].rstrip()
    if ";" in scrubbed:
        raise ValueError("Snowflake adapter permits exactly one SQL statement")
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_$]*", scrubbed.upper())
    if not tokens or tokens[0] not in {"SELECT", "WITH"} or "SELECT" not in tokens:
        raise ValueError("Snowflake validation query must be SELECT or WITH ... SELECT")
    forbidden = _FORBIDDEN_SQL.intersection(tokens)
    if forbidden:
        raise ValueError("Snowflake validation query contains a forbidden operation")
    if any(token.startswith("SYSTEM$") for token in tokens):
        raise ValueError("Snowflake validation query cannot invoke SYSTEM$ side effects")
    return sql


class SnowflakeQueryWatermark(_FrozenContract):
    field: str = Field(min_length=1)
    value: str = Field(min_length=1)
    as_of: str = Field(min_length=1)
    timezone: str = Field(min_length=1)


class SnowflakeQueryBudgets(_FrozenContract):
    max_rows: int = Field(ge=1, le=10_000)
    max_bytes: int = Field(ge=1, le=10_000_000)
    timeout_seconds: int = Field(ge=1, le=120)
    max_statements: Literal[1] = 1


class SnowflakeRoleState(_FrozenContract):
    """Trusted current role posture resolved before query authorization is consumed."""

    account_ref: str
    database_ref: str
    schema_ref: str
    role_ref: str
    warehouse_ref: str
    session_ref: str
    read_only: Literal[True] = True
    mutation_privileges: Literal[False] = False
    validation_cycle_id: str
    evidence_ref: str

    @field_validator(
        "account_ref",
        "database_ref",
        "schema_ref",
        "role_ref",
        "warehouse_ref",
        "session_ref",
        "evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeQueryPolicyVerification(_FrozenContract):
    """Trusted parser/policy attestation for the exact SQL fingerprint."""

    query_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    single_statement: Literal[True] = True
    read_only: Literal[True] = True
    side_effect_free: Literal[True] = True
    validation_cycle_id: str
    evidence_ref: str

    @field_validator("evidence_ref")
    @classmethod
    def ref_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeRoleStateResolver(Protocol):
    def __call__(self, request: "SnowflakeBoundedQueryRequest") -> SnowflakeRoleState: ...


class SnowflakeQueryPolicyResolver(Protocol):
    def __call__(
        self, request: "SnowflakeBoundedQueryRequest"
    ) -> SnowflakeQueryPolicyVerification: ...


class SnowflakeBoundedQueryRequest(TargetOperationRequest):
    action: Literal["execute_snowflake_bounded_query"] = SNOWFLAKE_QUERY_ACTION
    account_ref: str
    database_ref: str
    schema_ref: str
    role_ref: str
    warehouse_ref: str
    session_ref: str
    sql: str = Field(min_length=1)
    query_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    query_tag: str = Field(min_length=1)
    watermark: SnowflakeQueryWatermark
    budgets: SnowflakeQueryBudgets

    @field_validator(
        "account_ref",
        "database_ref",
        "schema_ref",
        "role_ref",
        "warehouse_ref",
        "session_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)

    @field_validator("sql")
    @classmethod
    def sql_is_bounded_read_only(cls, value: str) -> str:
        return _validate_read_only_statement(value)

    @model_validator(mode="after")
    def query_identity_is_exact(self) -> "SnowflakeBoundedQueryRequest":
        if not self.query_tag.startswith("domo_to_omni/"):
            raise ValueError("Snowflake query tag must use the domo_to_omni namespace")
        if self.query_fingerprint != canonical_fingerprint(self.sql):
            raise ValueError("Snowflake query fingerprint does not match the exact SQL")
        material = {
            "account_ref": self.account_ref,
            "database_ref": self.database_ref,
            "schema_ref": self.schema_ref,
            "role_ref": self.role_ref,
            "warehouse_ref": self.warehouse_ref,
            "session_ref": self.session_ref,
            "query_fingerprint": self.query_fingerprint,
            "query_tag": self.query_tag,
            "watermark": self.watermark.model_dump(mode="json"),
            "budgets": self.budgets.model_dump(mode="json"),
        }
        if self.change_set_fingerprint != canonical_fingerprint(material):
            raise ValueError("Snowflake request fingerprint does not match its bounded query identity")
        return self


class SnowflakeDriverResult(_FrozenContract):
    operation_id: str
    idempotency_key: str
    remote_receipt_ref: str
    account_ref: str
    database_ref: str
    schema_ref: str
    role_ref: str
    warehouse_ref: str
    session_ref: str
    query_ref: str
    query_id: str = Field(min_length=1)
    query_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    query_tag: str
    watermark: SnowflakeQueryWatermark
    columns: tuple[str, ...]
    row_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    result_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    sanitized_result_ref: str
    redaction_status: Literal["not_required", "redacted"]
    policy_verification_ref: str
    enforced_budgets: SnowflakeQueryBudgets
    statement_count: int = Field(ge=0)
    read_only_enforced: bool
    elapsed_seconds: float = Field(ge=0)
    timed_out: bool
    readback_evidence_ref: str
    completed_at: str

    @field_validator(
        "remote_receipt_ref",
        "account_ref",
        "database_ref",
        "schema_ref",
        "role_ref",
        "warehouse_ref",
        "session_ref",
        "query_ref",
        "sanitized_result_ref",
        "policy_verification_ref",
        "readback_evidence_ref",
    )
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeSanitizedResult(_FrozenContract):
    session_ref: str
    query_ref: str
    query_id: str
    query_fingerprint: str
    query_tag: str
    watermark: SnowflakeQueryWatermark
    columns: tuple[str, ...]
    row_count: int
    byte_count: int
    result_fingerprint: str
    result_ref: str
    redaction_status: Literal["not_required", "redacted"]

    @field_validator("session_ref", "query_ref", "result_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeQueryReadback(TargetOperationReadback):
    session_ref: str
    query_id: str
    query_fingerprint: str
    query_tag: str
    watermark: SnowflakeQueryWatermark
    row_count: int
    byte_count: int
    redaction_status: Literal["not_required", "redacted"]
    columns: tuple[str, ...]
    sanitized_result_ref: str
    policy_verification_ref: str
    enforced_budgets: SnowflakeQueryBudgets
    statement_count: int = Field(ge=0)
    read_only_enforced: bool
    elapsed_seconds: float
    timed_out: bool

    @field_validator("session_ref", "sanitized_result_ref", "policy_verification_ref")
    @classmethod
    def refs_are_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeQueryReceipt(TargetOperationReceipt):
    session_ref: str
    query_ref: str
    query_id: str
    query_fingerprint: str
    query_tag: str
    watermark: SnowflakeQueryWatermark
    budgets: SnowflakeQueryBudgets

    @field_validator("session_ref", "query_ref")
    @classmethod
    def ref_is_safe(cls, value: str) -> str:
        return validate_non_secret_ref(value)


class SnowflakeQueryOutcome(_FrozenContract):
    target_outcome: TargetOperationOutcome
    result: SnowflakeSanitizedResult | None


class SnowflakeQueryDriver(Protocol):
    def execute_bounded_query(
        self, request: SnowflakeBoundedQueryRequest
    ) -> SnowflakeDriverResult: ...


class SnowflakeBoundedQueryAdapter:
    def __init__(
        self,
        driver: SnowflakeQueryDriver,
        *,
        authorization_store: TargetAuthorizationStore,
        operation_store: TargetOperationStore,
        execution_resolver: StoreBackedTargetExecutionResolver,
        role_state_resolver: SnowflakeRoleStateResolver,
        query_policy_resolver: SnowflakeQueryPolicyResolver,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._driver = driver
        self._guard = TargetAdapterGuard(operation_store, execution_resolver)
        self._authorization_store = authorization_store
        self._role_state_resolver = role_state_resolver
        self._query_policy_resolver = query_policy_resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._authorization_consumptions: list[TargetAuthorizationConsumption] = []

    @property
    def authorization_consumptions(self) -> tuple[TargetAuthorizationConsumption, ...]:
        return tuple(self._authorization_consumptions)

    @staticmethod
    def _cached_outcome(target_outcome: TargetOperationOutcome) -> SnowflakeQueryOutcome:
        readback = target_outcome.readback
        if target_outcome.receipt.result != "succeeded":
            return SnowflakeQueryOutcome(target_outcome=target_outcome, result=None)
        if not isinstance(readback, SnowflakeQueryReadback):
            raise ValueError("cached Snowflake success lacks typed query readback")
        if not isinstance(target_outcome.receipt, SnowflakeQueryReceipt):
            raise ValueError("cached Snowflake success lacks typed query receipt")
        return SnowflakeQueryOutcome(
            target_outcome=target_outcome,
            result=SnowflakeSanitizedResult(
                session_ref=readback.session_ref,
                query_ref=target_outcome.receipt.query_ref,
                query_id=readback.query_id,
                query_fingerprint=readback.query_fingerprint,
                query_tag=readback.query_tag,
                watermark=readback.watermark,
                columns=readback.columns,
                row_count=readback.row_count,
                byte_count=readback.byte_count,
                result_fingerprint=readback.content_fingerprint,
                result_ref=readback.sanitized_result_ref,
                redaction_status=readback.redaction_status,
            ),
        )

    def execute(self, request: SnowflakeBoundedQueryRequest) -> SnowflakeQueryOutcome:
        now = self._clock()
        cached = self._guard.prepare(
            request,
            expected_action=SNOWFLAKE_QUERY_ACTION,
            required_scope_refs=(
                request.account_ref,
                request.database_ref,
                request.schema_ref,
                request.role_ref,
                request.warehouse_ref,
                request.session_ref,
            ),
            now=now,
        )
        if cached is not None:
            return self._cached_outcome(cached)
        role_state = self._role_state_resolver(request)
        if (
            role_state.account_ref != request.account_ref
            or role_state.database_ref != request.database_ref
            or role_state.schema_ref != request.schema_ref
            or role_state.role_ref != request.role_ref
            or role_state.warehouse_ref != request.warehouse_ref
            or role_state.session_ref != request.session_ref
            or role_state.validation_cycle_id != request.validation_cycle_id
            or not role_state.read_only
            or role_state.mutation_privileges
        ):
            raise ValueError("trusted Snowflake role state is not exact and read-only")
        policy = self._query_policy_resolver(request)
        if (
            policy.query_fingerprint != request.query_fingerprint
            or policy.validation_cycle_id != request.validation_cycle_id
            or not policy.single_statement
            or not policy.read_only
            or not policy.side_effect_free
        ):
            raise ValueError("trusted Snowflake query policy does not authorize this SQL")
        completed = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        required_scopes = (
            request.account_ref,
            request.database_ref,
            request.schema_ref,
            request.role_ref,
            request.warehouse_ref,
            request.session_ref,
        )
        self._guard.claim_execution(request, now=now)
        consumption = self._authorization_store.resolve_and_consume(
            request,
            expected_action=SNOWFLAKE_QUERY_ACTION,
            required_scope_refs=required_scopes,
            now=now,
            consumed_at=completed,
        )
        self._authorization_consumptions.append(consumption)
        try:
            target_outcome = self._post_invocation_outcome(
                request,
                consumption=consumption,
                policy=policy,
                completed=completed,
            )
        except Exception:
            target_outcome = indeterminate_outcome(
                request,
                target_ref=request.warehouse_ref,
                authorization_consumption=consumption,
                completed_at=completed,
                evidence_ref=(
                    "evidence-ref://target-adapter/snowflake/"
                    f"{request.operation_id}/post-invocation-validation"
                ),
                sanitized_message=(
                    "Snowflake post-invocation result or evidence requires reconciliation"
                ),
            )
        persisted = self._guard.remember(request, target_outcome)
        return self._cached_outcome(persisted)

    def _post_invocation_outcome(
        self,
        request: SnowflakeBoundedQueryRequest,
        *,
        consumption: TargetAuthorizationConsumption,
        policy: SnowflakeQueryPolicyVerification,
        completed: str,
    ) -> TargetOperationOutcome:
        try:
            result = self._driver.execute_bounded_query(request)
        except AmbiguousTargetInvocation as exc:
            readback = TargetOperationReadback.model_validate(
                exc.readback.model_dump(mode="python")
            )
            return ambiguous_outcome(
                request,
                target_ref=request.warehouse_ref,
                readback=readback,
                authorization_consumption=consumption,
                completed_at=completed,
            )
        identity_mismatch = (
            result.operation_id != request.operation_id
            or result.idempotency_key != request.idempotency_key
            or result.account_ref != request.account_ref
            or result.database_ref != request.database_ref
            or result.schema_ref != request.schema_ref
            or result.role_ref != request.role_ref
            or result.warehouse_ref != request.warehouse_ref
            or result.session_ref != request.session_ref
            or result.query_fingerprint != request.query_fingerprint
            or result.query_tag != request.query_tag
            or result.watermark != request.watermark
            or result.policy_verification_ref != policy.evidence_ref
            or result.enforced_budgets != request.budgets
            or result.statement_count != 1
            or not result.read_only_enforced
            or result.timed_out
            or result.elapsed_seconds > request.budgets.timeout_seconds
            or result.row_count > request.budgets.max_rows
            or result.byte_count > request.budgets.max_bytes
        )
        readback = SnowflakeQueryReadback(
            operation_id=request.operation_id,
            request_fingerprint=request.request_fingerprint(),
            target_ref=request.warehouse_ref,
            state="different" if identity_mismatch else "matched",
            target_revision=result.query_id,
            content_fingerprint=result.result_fingerprint,
            captured_at=result.completed_at,
            evidence_ref=result.readback_evidence_ref,
            session_ref=result.session_ref,
            query_id=result.query_id,
            query_fingerprint=result.query_fingerprint,
            query_tag=result.query_tag,
            watermark=result.watermark,
            row_count=result.row_count,
            byte_count=result.byte_count,
            redaction_status=result.redaction_status,
            columns=result.columns,
            sanitized_result_ref=result.sanitized_result_ref,
            policy_verification_ref=result.policy_verification_ref,
            enforced_budgets=result.enforced_budgets,
            statement_count=result.statement_count,
            read_only_enforced=result.read_only_enforced,
            elapsed_seconds=result.elapsed_seconds,
            timed_out=result.timed_out,
        )
        if identity_mismatch:
            receipt = SnowflakeQueryReceipt(
                operation_id=request.operation_id,
                idempotency_key=request.idempotency_key,
                request_fingerprint=request.request_fingerprint(),
                action=request.action,
                target_ref=request.warehouse_ref,
                attempt=request.attempt,
                result="ambiguous",
                remote_receipt_ref=result.remote_receipt_ref,
                readback_ref=result.readback_evidence_ref,
                completed_at=result.completed_at,
                sanitized_message=(
                    "Snowflake post-invocation identity, read-only, or budget mismatch"
                ),
                session_ref=result.session_ref,
                query_ref=result.query_ref,
                query_id=result.query_id,
                query_fingerprint=result.query_fingerprint,
                query_tag=result.query_tag,
                watermark=result.watermark,
                budgets=request.budgets,
            )
            return TargetOperationOutcome(
                authorization_consumption=consumption,
                receipt=receipt,
                readback=readback,
            )
        receipt = SnowflakeQueryReceipt(
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            request_fingerprint=request.request_fingerprint(),
            action=request.action,
            target_ref=request.warehouse_ref,
            attempt=request.attempt,
            result="succeeded",
            remote_receipt_ref=result.remote_receipt_ref,
            readback_ref=result.readback_evidence_ref,
            completed_at=result.completed_at,
            session_ref=result.session_ref,
            query_ref=result.query_ref,
            query_id=result.query_id,
            query_fingerprint=result.query_fingerprint,
            query_tag=result.query_tag,
            watermark=result.watermark,
            budgets=request.budgets,
        )
        return TargetOperationOutcome(
            authorization_consumption=consumption,
            receipt=receipt,
            readback=readback,
        )


__all__ = [
    "SNOWFLAKE_QUERY_ACTION",
    "SnowflakeBoundedQueryAdapter",
    "SnowflakeBoundedQueryRequest",
    "SnowflakeDriverResult",
    "SnowflakeQueryBudgets",
    "SnowflakeQueryDriver",
    "SnowflakeQueryOutcome",
    "SnowflakeQueryPolicyResolver",
    "SnowflakeQueryPolicyVerification",
    "SnowflakeQueryReadback",
    "SnowflakeQueryReceipt",
    "SnowflakeQueryWatermark",
    "SnowflakeRoleState",
    "SnowflakeRoleStateResolver",
    "SnowflakeSanitizedResult",
]
