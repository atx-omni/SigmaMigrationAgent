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
    from omni_migrator.extractors.sigma.extractor import _build_bundle
    source = read_json(args.source)
    bundle = _build_bundle(source)
    rows = source_rows(source)
    import json

    from omni_migrator.prepush.build import physical_source_field
    print("Copy IDs from the intended Omni model/connection. No connection will be made.")
    target = {"model_id": ask("Omni model UUID: "), "connection_id": ask("Omni connection UUID: "),
              "document_name": ask("Name for the proposed Omni workbook: "), "relations": {}}
    for view in bundle.model.views:
        print(json.dumps({"source_view": view.name, "source_locator": view.source_locator}, ensure_ascii=True))
        relation = {"schema": ask("Existing warehouse schema: "), "table": ask("Existing table name: "), "columns": {}}
        for field in view.fields:
            raw = rows.get(field.source_locator, {})
            physical = physical_source_field(field, raw)
            if physical and field.source_id and not field.untranslatable:
                label = json.dumps({"name": field.name, "id": field.source_id}, ensure_ascii=True)
                relation["columns"][field.source_id] = ask(f"Physical SQL column for {label}: ")
        modeled = ask("Modeled destination table (optional; required for warehouse-first): ")
        if modeled:
            relation["modeled_table"] = modeled
        target["relations"][view.source_locator] = relation
    from omni_migrator.prepush.build import build
    build(source, "omni_semantic_reconstruction", target)  # Validate typed inputs, never write targets.
    private_write(args.output, target)
    return {"status": "target_mapping_created_requires_review", "output": str(args.output), "target_write_authority": False}
