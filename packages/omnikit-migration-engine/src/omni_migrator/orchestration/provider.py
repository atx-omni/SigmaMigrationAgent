"""One bounded model call per package. No shell, remote tools, or self-approval.

Contract: https://developers.openai.com/api/docs/guides/structured-outputs
Model identity and price estimates are operator configuration, never guessed here.
"""

from __future__ import annotations

import json
from typing import Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field


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
    """Fixed official origin, no redirects/retries, no response body in exceptions."""

    def __init__(self, *, model: str, api_key: str, transport=None) -> None:
        if not model.strip() or not api_key.strip():
            raise ValueError("model and credential must be explicitly configured")
        self.model = model
        self._api_key = api_key
        self._transport = transport

    def propose(self, *, instructions: str, context: str, max_output_tokens: int) -> ProviderResult:
        try:
            with httpx.Client(
                timeout=40.0,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                response = client.post(
                    "https://api.openai.com/v1/responses",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json={
                        "model": self.model,
                        "store": False,
                        "instructions": instructions,
                        "input": [{"role": "user", "content": context}],
                        "max_output_tokens": max_output_tokens,
                        "text": {
                            "format": {
                                "type": "json_schema",
                                "name": "migration_proposal",
                                "strict": True,
                                "schema": SpecialistProposal.model_json_schema(),
                            }
                        },
                    },
                )
                response.raise_for_status()
                body = response.json()
            if body.get("status") != "completed":
                raise ValueError("incomplete response")
            contents = [
                part
                for item in body.get("output", [])
                if item.get("type") == "message"
                for part in item.get("content", [])
            ]
            if any(part.get("type") == "refusal" for part in contents):
                raise ValueError("provider refusal")
            value = json.loads(
                "".join(part["text"] for part in contents if part.get("type") == "output_text")
            )
            usage = body["usage"]
            return ProviderResult(
                proposal=SpecialistProposal.model_validate(value),
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                response_id=body["id"],
            )
        except Exception:
            raise RuntimeError(
                "Model call failed or returned unusable output; no automatic retry."
            ) from None
