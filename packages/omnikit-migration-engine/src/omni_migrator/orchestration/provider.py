"""One bounded model call per package. No shell, remote tools, or self-approval.

Contract: https://developers.openai.com/api/docs/guides/structured-outputs
Model identity and price estimates are operator configuration, never guessed here.
"""

from __future__ import annotations

import json
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

EGRESS_DISABLED_REASON = (
    "Production AI dispatch is disabled: an externally authenticated approval gateway "
    "must enforce exact payload, provider/account, expiry, revocation and replay policy. "
    "Local approval references do not authorize data transfer."
)


class DraftArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: str
    title: str
    content: str
    source_refs: list[str]


class SpecialistProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["proposed", "blocked"]
    summary: str
    artifacts: list[DraftArtifact]
    blockers: list[str]
    decision_requests: list[str]


class ProviderResult(BaseModel):
    proposal: SpecialistProposal
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    response_id: str


class ProposalProvider(Protocol):
    def propose(
        self, *, instructions: str, context: str, max_output_tokens: int
    ) -> ProviderResult: ...


class OpenAIProposalProvider:
    """Fail-closed compatibility stub; never retains credentials or creates a client."""

    def __init__(self, *, model: str, api_key: str, transport=None) -> None:
        raise RuntimeError(EGRESS_DISABLED_REASON)

    def propose(self, *, instructions: str, context: str, max_output_tokens: int) -> ProviderResult:
        raise RuntimeError(EGRESS_DISABLED_REASON)


class FixtureProposalProvider:
    """Fixed offline test simulation, not a provider plug-in or production escape hatch.

    No callable, transport, URL, credential, or arbitrary provider is accepted. The
    runner checks this exact concrete type and calls its class method directly.
    These drafts remain explicitly synthetic and can never prove live acceptance.
    """

    def __init_subclass__(cls, **kwargs):
        raise TypeError("the offline fixture provider cannot be extended")

    def __init__(self, *, forged: bool = False, fail: bool = False):
        self.calls: list[dict] = []
        self.forged = bool(forged)
        self.fail = bool(fail)

    def propose(self, *, instructions: str, context: str, max_output_tokens: int) -> ProviderResult:
        raw = json.loads(context)
        self.calls.append({"instructions": instructions, "context": raw})
        if self.fail:
            raise RuntimeError("synthetic offline provider failure")
        package = raw["work_package"]
        return ProviderResult(
            response_id="synthetic-offline-fixture", input_tokens=100, output_tokens=50,
            proposal=SpecialistProposal(
                status="proposed", summary="Synthetic offline fixture; no migration acceptance.",
                artifacts=[DraftArtifact(
                    artifact_type=package["expected_artifacts"][0], title="Synthetic review draft",
                    content="Synthetic fixture: retain lineage and require independent live evidence.",
                    source_refs=["artifact-ref://forged"] if self.forged
                    else sorted(raw["untrusted_evidence"]),
                )], blockers=[], decision_requests=[],
            ),
        )
