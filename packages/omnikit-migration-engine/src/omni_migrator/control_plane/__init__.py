"""Deterministic control-plane primitives for governed migration runs.

The control plane is deliberately independent from any model provider.  Agents may
propose work and state changes; only this layer validates and records them.
"""

from omni_migrator.control_plane.policy import (
    PolicyContext,
    validate_manifest_policy,
    validate_manifest_policy_from_store,
)
from omni_migrator.control_plane.contract_integrity import (
    canonical_contract_hash,
    dependency_edge_hash,
    inventory_contract_hash,
    source_object_fingerprint,
    source_object_metadata_hash,
    validate_inventory_contract_set,
    validate_migration_scope,
    validate_migration_lifecycle,
    validate_qa_result,
)
from omni_migrator.control_plane.inventory_projection import (
    InventoryProjection,
    project_domo_evidence_bundle,
)
from omni_migrator.control_plane.domo_inventory import (
    exact_id_set_hash,
    exact_object_set_hash,
    inventory_observation_content_sha256,
    inventory_observation_hash,
    portfolio_inventory_content_sha256,
    portfolio_inventory_hash,
    portfolio_object_hash,
    validate_inventory_observation,
    validate_portfolio_inventory,
)
from omni_migrator.control_plane.store import AppendOnlyControlPlaneStore
from omni_migrator.control_plane.documentation import (
    DocumentationPackage,
    documentation_package_hash,
    finalize_documentation_package,
    validate_documentation_package,
)
from omni_migrator.control_plane.external_handoffs import (
    AcceptedExternalHandoffDecision,
    ExternalHandoffAnalyticOutput,
    ExternalHandoffSourceObject,
    ExternalRedesignHandoff,
    external_redesign_handoff_content_sha256,
    external_redesign_handoff_hash,
    external_redesign_handoff_work_package_id,
    finalize_external_redesign_handoff,
    validate_external_redesign_handoff,
)

__all__ = [
    "AcceptedExternalHandoffDecision",
    "AppendOnlyControlPlaneStore",
    "DocumentationPackage",
    "ExternalHandoffAnalyticOutput",
    "ExternalHandoffSourceObject",
    "ExternalRedesignHandoff",
    "InventoryProjection",
    "PolicyContext",
    "canonical_contract_hash",
    "dependency_edge_hash",
    "documentation_package_hash",
    "exact_id_set_hash",
    "exact_object_set_hash",
    "external_redesign_handoff_content_sha256",
    "external_redesign_handoff_hash",
    "external_redesign_handoff_work_package_id",
    "finalize_external_redesign_handoff",
    "inventory_contract_hash",
    "inventory_observation_content_sha256",
    "inventory_observation_hash",
    "portfolio_inventory_content_sha256",
    "portfolio_inventory_hash",
    "portfolio_object_hash",
    "project_domo_evidence_bundle",
    "finalize_documentation_package",
    "source_object_fingerprint",
    "source_object_metadata_hash",
    "validate_inventory_contract_set",
    "validate_inventory_observation",
    "validate_documentation_package",
    "validate_external_redesign_handoff",
    "validate_manifest_policy",
    "validate_manifest_policy_from_store",
    "validate_migration_scope",
    "validate_portfolio_inventory",
    "validate_migration_lifecycle",
    "validate_qa_result",
]
