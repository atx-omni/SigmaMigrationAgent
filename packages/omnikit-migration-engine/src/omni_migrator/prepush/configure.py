"""Guided local relation mapping; no credentials or internal hashes to edit."""
from omni_migrator.prepush.session import private_write, read_json


def source_rows(source):
    rows = {}
    for dm in source.get("dataModels", []):
        for page in dm.get("spec", {}).get("pages", []):
            for element in page.get("elements", []):
                for field in element.get("columns", []):
                    locator = f"data-model:{dm.get('dataModelId', dm.get('id', ''))}/element:{element.get('elementId', element.get('id', ''))}/column:{field.get('columnId', field.get('id', ''))}"
                    rows[locator] = field
    return rows


def inspect_source(path):
    from omni_migrator.extractors.sigma.extractor import _build_bundle
    from omni_migrator.prepush.build import source_inventory
    source = read_json(path)
    bundle = _build_bundle(source)
    return {"source_inventory": source_inventory(source), "fields": [
        {"view": view.source_locator, "field": field.source_locator, "name": field.name, "kind": field.kind}
        for view in bundle.model.views for field in view.fields], "target_write_authority": False}


def import_context(args):
    from omni_migrator.prepush.build import ReviewedSourceContext, source_context_hash
    from omni_migrator.prepush.session import reject_secrets
    source, context = read_json(args.source), read_json(args.context)
    reject_secrets(source)
    reject_secrets(context)
    context["schema_version"] = "sigma-prepush-context.v1"
    context["source_sha256"] = source_context_hash(source)
    source["prepush_context"] = ReviewedSourceContext.model_validate(context).model_dump(mode="json")
    private_write(args.output, source)
    return {"status": "context_bound_requires_source_import_and_review", "output": str(args.output), "target_write_authority": False}


def configure(args, ask):
    from omni_migrator.security.workspace import assert_private_output
    assert_private_output(args.output)
    from omni_migrator.extractors.sigma.extractor import _build_bundle
    source = read_json(args.source)
    bundle = _build_bundle(source)
    rows = source_rows(source)
    import json

    from omni_migrator.prepush.build import physical_source_field
    from omni_migrator.prepush.session import reject_secrets
    reject_secrets(source)
    profile = None
    if getattr(args, "profile", None):
        from omni_migrator.prepush.settings import load_profile
        profile = load_profile(args.profile)
        if profile["allowed_changes"] == "validation_only":
            return {"status": "assessment_only", **inspect_source(args.source),
                    "next_action": "Review source coverage; choose a new setup profile before preparing target artifacts"}
    print("Confirm target identity. This command makes no connection.")
    if getattr(args, "discovery", None):
        discovery = read_json(args.discovery)
        reject_secrets(discovery)
        if discovery.get("schema_version") != "omni-discovery.v1":
            raise ValueError("Expected a read-only Omni discovery file")
        if profile and profile["target_auth"] != "offline" and discovery.get("origin") != profile["omni_origin"]:
            raise ValueError("Discovery belongs to a different Omni organization")
        models = discovery["models"]
        for index, model in enumerate(models, 1):
            print(json.dumps({"choice": index, "model": model}, ensure_ascii=True))
        choice = ask("Select the model number from this inventory: ")
        if choice not in {str(index) for index in range(1, len(models) + 1)}:
            raise ValueError("Select a listed model")
        model = models[int(choice) - 1]
        model_id, connection_id = model["id"], model["connectionId"]
        if not any(row["id"] == connection_id for row in discovery["connections"]):
            raise ValueError("The selected model's connection was not returned in discovery")
    else:
        model_id, connection_id = ask("Omni model UUID: "), ask("Omni connection UUID: ")
    target = {"model_id": model_id, "connection_id": connection_id,
              "document_name": ask("Name for the proposed Omni workbook: "), "relations": {}}
    if profile:
        target["allowed_changes"] = profile["allowed_changes"]
    if profile and profile["allowed_changes"] == "dashboard_only":
        inventory_path = getattr(args, "topic_inventory", None)
        if not inventory_path:
            raise ValueError("Dashboard-only reuse requires --topic-inventory with reviewed field definitions, grain and filters")
        from omni_migrator.prepush.reuse import TopicInventory, canonical_hash, source_fields, validate_target
        inventory = read_json(inventory_path)
        reject_secrets(inventory)
        inventory = TopicInventory.model_validate(inventory).model_dump()
        if (inventory["model_id"], inventory["connection_id"]) != (model_id, connection_id):
            raise ValueError("Topic inventory does not match the selected model and connection")
        print("Map exact field IDs, not display names. Compatibility notes are assertions for human review, not parity proof.")
        print(json.dumps({"topic": inventory["topic_name"], "available_fields": inventory["fields"]}, ensure_ascii=True))
        mappings = {}
        for locator, (_, raw, _) in source_fields(source).items():
            print(json.dumps({"source_field": locator, "definition": raw}, ensure_ascii=True))
            selected = ask("Exact target field ID (blank leaves this field unresolved and blocked): ")
            if not selected:
                continue
            if selected not in inventory["fields"]:
                raise ValueError("Target field is not in the reviewed inventory")
            compatibility = {"status": "compatible"}
            for dimension in ("grain", "filters", "metric", "joins"):
                compatibility[dimension] = ask(f"Observed evidence for compatible {dimension} (explain why not applicable if so): ")
            mappings[locator] = {"target_field": selected, "source_field_sha256": canonical_hash(raw),
                                 "target_field_sha256": canonical_hash(inventory["fields"][selected]),
                                 "compatibility": compatibility}
        target.pop("relations")
        target["existing_topic"] = {"inventory": inventory, "inventory_sha256": canonical_hash(inventory), "field_mappings": mappings}
        target = validate_target(target, source)
        private_write(args.output, target)
        return {"status": "topic_mapping_created_requires_review", "output": str(args.output), "target_write_authority": False}
    for view in bundle.model.views:
        print(json.dumps({"source_view": view.name, "source_locator": view.source_locator}, ensure_ascii=True))
        relation = {"schema": ask("Existing warehouse schema: "), "table": ask("Existing table name: "), "columns": {}}
        for field in view.fields:
            raw = rows.get(field.source_locator, {})
            physical = physical_source_field(field, raw)
            if physical and field.source_id and not field.untranslatable:
                label = json.dumps({"name": field.name, "id": field.source_id}, ensure_ascii=True)
                relation["columns"][field.source_id] = ask(f"Physical SQL column for {label}: ")
        modeled = ask("Modeled destination table (required for warehouse-first): ") if not profile or profile["route"] == "warehouse_first_refactor" else ""
        if modeled:
            relation["modeled_table"] = modeled
        target["relations"][view.source_locator] = relation
    from omni_migrator.prepush.build import build
    reject_secrets(target)
    build(source, profile["route"] if profile else "omni_semantic_reconstruction", target)
    private_write(args.output, target)
    return {"status": "target_mapping_created_requires_review", "output": str(args.output), "target_write_authority": False}
