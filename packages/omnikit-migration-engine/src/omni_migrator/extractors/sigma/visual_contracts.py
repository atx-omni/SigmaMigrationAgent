"""Source-only visual capture requests. No route selection or target authority."""
from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from omni_migrator.extractors.sigma.capability_contracts import SourceFreeze


class VisualCaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["sigma-visual-capture-request.v1"]
    capture_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,80}$")
    api_base_url: str
    approved_api_host: str
    expected_organization_id: str = Field(min_length=1, max_length=512)
    expected_user_id: str = Field(min_length=1, max_length=512)
    principal_ref: str = Field(pattern=r"^principal-ref://[^\s?#]+$")
    authorization_ref: str = Field(pattern=r"^human-authorization-ref://[^\s?#]+$")
    workbook_id: str = Field(pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    page_id: str = Field(pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    element_id: str = Field(pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    data_model_id: str = Field(pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    source_freeze: SourceFreeze
    parameters: dict[str, str]
    timezone: str = Field(min_length=1, max_length=100)
    data_as_of_reference: str | None = Field(default=None, max_length=500)
    evidence_mode: Literal["synthetic_fixture", "live_tenant"]
    sensitivity: Literal["internal", "confidential", "restricted"] = "confidential"
    row_limit: int = Field(default=1000, ge=1, le=50000)
    max_requests_per_invocation: int = Field(default=100, ge=10, le=500)
    max_download_attempts: int = Field(default=5, ge=1, le=20)
    max_capture_age_seconds: int = Field(default=3600, ge=60, le=21600)

    @field_validator("parameters")
    @classmethod
    def bounded_parameters(cls, value):
        if len(value) > 100 or any(not k or len(k) > 512 or len(v) > 4096 for k, v in value.items()):
            raise ValueError("Capture parameters exceed the bounded contract")
        return value

    @model_validator(mode="after")
    def exact_source(self):
        url = urlsplit(self.api_base_url)
        if (url.scheme != "https" or url.hostname != self.approved_api_host
                or url.port not in (None, 443) or url.username or url.password
                or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("An exact HTTPS origin and approved API host are required")
        if self.source_freeze.strategy != "version_tag":
            raise ValueError("Visual capture currently requires an explicit workbook version tag")
        from urllib.parse import quote
        expected = f"sigma://workbooks/{self.workbook_id}/tags/{quote(self.source_freeze.workbook_tag_name, safe='-._~')}"
        if self.source_freeze.source_reference != expected:
            raise ValueError("Source freeze must bind this exact workbook and tag")
        return self

    @property
    def tag(self):
        return self.source_freeze.workbook_tag_name

    def export_body(self, kind):
        if kind not in {"png", "json"}:
            raise ValueError("This capture slice supports element PNG and JSON only")
        body = {"tag": self.tag, "elementId": self.element_id,
                "parameters": self.parameters, "format": {"type": kind}}
        if kind == "json":
            body["rowLimit"] = self.row_limit
        return body

    @property
    def job_kinds(self):
        return ("png", "json")

    @property
    def file_stem(self):
        return "element"


class VisualSourceFreeze(SourceFreeze):
    # The existing capability-spike SourceFreeze remains unchanged. A source-only
    # capture may have no selected associated model, with that gap retained.
    data_model_document_version: int | None = Field(default=None, ge=1)


class VisualCaptureRequestV2(VisualCaptureRequest):
    schema_version: Literal["sigma-visual-capture-request.v2"]
    target_kind: Literal["element", "page"]
    element_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    data_model_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-][A-Za-z0-9._~-]{0,511}$")
    source_freeze: VisualSourceFreeze

    @model_validator(mode="after")
    def exact_visual_scope(self):
        if (self.target_kind == "element") != (self.element_id is not None):
            raise ValueError("Element captures require element_id; page captures must omit it")
        if (self.data_model_id is None) != (self.source_freeze.data_model_document_version is None):
            raise ValueError("Associated model ID and document version must be selected together")
        return self

    @property
    def job_kinds(self):
        return ("png",) if self.target_kind == "page" else ("png", "json")

    @property
    def file_stem(self):
        return self.target_kind

    def export_body(self, kind):
        if self.target_kind == "element":
            return super().export_body(kind)
        if kind != "png":
            raise ValueError("The qualified page capture slice supports PNG only")
        return {"tag": self.tag, "pageId": self.page_id,
                "parameters": self.parameters, "format": {"type": "png"}}


def parse_visual_request(value):
    if isinstance(value, VisualCaptureRequest):
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise ValueError("Visual capture request must be an object")
    model = {"sigma-visual-capture-request.v1": VisualCaptureRequest,
             "sigma-visual-capture-request.v2": VisualCaptureRequestV2}.get(value.get("schema_version"))
    if model is None:
        raise ValueError("Unsupported visual capture request schema")
    return model.model_validate(value)
