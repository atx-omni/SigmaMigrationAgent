"""No dependency activation: real pure contracts/acquisition + isolated source control flow.

AST slices execute unchanged first-party function bodies with explicit inert I/O
adapters. They do not qualify Pydantic, HTTP transport, scanner, or live tenants.
"""
from __future__ import annotations
import ast
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
from omni_migrator.prepush import source_protocol as P, source_operations as O


def request(operation="snapshot"):
    return {"schema_version": P.REQUEST_SCHEMA, "request_id": "neutral-source",
            "operation": operation, "api_base_url": "https://api.sigmacomputing.com",
            "approved_api_host": "api.sigmacomputing.com", "expected_organization_id": "org-1",
            "expected_user_id": "user-1", "principal_ref": "principal-ref://fixture/operator",
            "authorization_ref": "human-authorization-ref://fixture/read",
            "evidence_mode": "synthetic_fixture", "max_requests": 100,
            "scope": {"workbook_ids": ["w1"], "data_model_ids": []},
            "options": {"include_contents_beta": False}}


def visual_request(kind="page"):
    outer = request("capture")
    value = {key: outer[key] for key in ("api_base_url", "approved_api_host", "expected_organization_id",
                "expected_user_id", "principal_ref", "authorization_ref", "evidence_mode")}
    value.update(schema_version="sigma-visual-capture-request.v2", capture_id="neutral-page",
        target_kind=kind, workbook_id="w1", page_id="p1", element_id=None if kind == "page" else "e1",
        data_model_id=None, parameters={"region": "North"}, timezone="UTC", max_requests_per_invocation=100,
        source_freeze={"strategy": "version_tag", "source_reference": "sigma://workbooks/w1/tags/reviewed",
            "workbook_tag_name": "reviewed", "data_model_document_version": None,
            "approved_by_ref": "human-ref://fixture/operator", "approval_ref": "human-approval-ref://fixture/freeze"})
    return value


class Api:
    base_url = "https://api.sigmacomputing.com"
    request_budget = 100
    def __init__(self):
        self.calls = []
        self.identity = {"organizationId": "org-1", "userId": "user-1"}
        self.rows = [{"workbookId": "w1"}, {"workbookId": "w2"}]
        self.snapshot_value = {"connections": [], "dataModels": [], "workbooks": [{"workbookId": "w1"}],
                               "diagnostics": [{"status": "incomplete", "reason": "source dependency unselected"}]}
    def whoami(self): self.calls.append("identity"); return deepcopy(self.identity)
    def get_workbook(self, id_): self.calls.append(("workbook", id_)); return {"workbookId": id_}
    def get_data_model(self, id_): self.calls.append(("model", id_)); return {"dataModelId": id_}
    def list_workbooks(self): self.calls.append("list_workbooks"); return deepcopy(self.rows)
    def list_data_models(self): self.calls.append("list_models"); return [{"dataModelId": "m1"}]
    def snapshot(self, **kwargs): self.calls.append(kwargs); return deepcopy(self.snapshot_value)
    def workbook_contents(self, id_): return {"workbookId": id_, "contents": {"schemaVersion": 1, "pages": [], "inert": "do not execute"}}


def source_function(relative, name, namespace, *, class_name=None, strip_imports=False):
    tree = ast.parse((SRC / "omni_migrator" / relative).read_text())
    nodes = tree.body
    if class_name:
        nodes = next(n for n in nodes if isinstance(n, ast.ClassDef) and n.name == class_name).body
    node = deepcopy(next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name))
    node.decorator_list = []
    if strip_imports:
        class Imports(ast.NodeTransformer):
            def visit_ImportFrom(self, node): return None
        node = Imports().visit(node)
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    exec(compile(module, str(relative), "exec", flags=__import__('__future__').annotations.compiler_flag), namespace)
    return namespace[name]


class SourceContractTests(unittest.TestCase):
    def test_request_exact_scope_origin_and_budget(self):
        self.assertEqual(P.validate_request(request()), request())
        for key, value in [("api_base_url", "https://api.sigmacomputing.com@wrong.invalid"),
                           ("api_base_url", "https://api.sigmacomputing.com/?token=hidden"),
                           ("max_requests", True), ("max_requests", 501),
                           ("principal_ref", "principal-ref://fixture password=hidden")]:
            bad = request(); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): P.validate_request(bad)
        bad = request(); bad["scope"]["workbook_ids"] = ["../w"]
        with self.assertRaises(ValueError): P.validate_request(bad)
        bad = request(); bad["target_write_authority"] = True
        with self.assertRaises(ValueError): P.validate_request(bad)

    def test_capture_child_cannot_widen_identity_scope_or_grant(self):
        value = request("capture"); value["visual_capture_request"] = visual_request()
        self.assertEqual(P.validate_request(value), value)
        for key, replacement in [("expected_user_id", "other"), ("workbook_id", "w2"),
                                 ("data_model_id", "m1"), ("max_requests_per_invocation", 200)]:
            bad = deepcopy(value); bad["visual_capture_request"][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError): P.validate_request(bad)

    def test_metadata_grant_and_client_origin_checked_before_read(self):
        api = Api()
        with self.assertRaises(ValueError): O.acquire(request(), api=api)
        self.assertEqual(api.calls, [])
        api.base_url = "https://wrong.invalid"
        with self.assertRaises(ValueError): O.acquire(request(), api=api, allow_source_read=True)
        self.assertEqual(api.calls, [])

    def test_optional_model_preserves_no_selection_and_dependency_gap(self):
        api = Api(); result = O.acquire(request(), api=api, allow_source_read=True)
        self.assertIn({"workbook_ids": ["w1"], "data_model_ids": [], "allow_unresolved_dependencies": True}, api.calls)
        self.assertEqual(result["result"]["dataModels"], [])
        self.assertIn("no_associated_data_model_selected_dependencies_still_require_evidence", result["gaps"])
        self.assertEqual(result["request_sha256"], P.digest(request()))
        self.assertFalse(result["target_write_authority"])
        self.assertEqual(result["evidence_mode"], "synthetic_fixture")

    def test_check_without_model_and_identity_drift(self):
        api = Api(); O.acquire(request("check"), api=api, allow_source_read=True)
        self.assertNotIn("list_models", api.calls)
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "model" for c in api.calls))
        api = Api(); original = api.snapshot
        def changed(**kwargs):
            result = original(**kwargs); api.identity["userId"] = "other"; return result
        api.snapshot = changed
        with self.assertRaisesRegex(ValueError, "principal|identity"): O.acquire(request(), api=api, allow_source_read=True)

    def test_inventory_rejects_conflicting_missing_and_duplicate_ids(self):
        for rows in [[{"workbookId": "w1", "id": "w2"}], [{"workbookId": "w2"}],
                     [{"workbookId": "w1"}, {"workbookId": "w1"}]]:
            api = Api(); api.rows = rows
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                O.acquire(request("inventory"), api=api, allow_source_read=True)

    def test_snapshot_refuses_unselected_workbook_or_model(self):
        for key, row in [("workbooks", {"workbookId": "w2"}), ("dataModels", {"dataModelId": "m1"})]:
            api = Api(); api.snapshot_value[key].append(row)
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "expanded"):
                O.acquire(request(), api=api, allow_source_read=True)

    def test_beta_native_contents_retained_not_tagged_or_executed(self):
        value = request(); value["options"]["include_contents_beta"] = True
        out = O.acquire(value, api=Api(), allow_source_read=True)["result"]["_sigma_contents_beta"][0]
        self.assertEqual(out["schemaVersion"], 1)
        self.assertEqual(out["definition_scope"], "current_workbook_not_tagged")
        self.assertEqual(out["response_sha256"], P.digest(out["response"]))
        self.assertFalse(out["source_execution"])
        opaque = "!!python/object/apply:unexpected []"
        record = P.inspect_contents_beta({"workbookId": "w1", "contents": opaque}, "w1")
        self.assertEqual(record["response"]["contents"], opaque)
        self.assertIsNone(record["schemaVersion"])
        with self.assertRaises(ValueError): P.inspect_contents_beta({"workbookId": "w2", "contents": {}}, "w1")

    def test_capabilities_probe_is_stdlib_only_and_pins_live_tree(self):
        # Pytest collection can legitimately import runtime dependencies in this
        # process. Test the probe's imports in its own site-free interpreter.
        probe = """
import sys
sys.path.insert(0, sys.argv[1])
from omni_migrator.prepush.cli import main
status = main(["capabilities"])
forbidden = {"httpx", "pydantic", "yaml", "detect_secrets"}
loaded = forbidden & {name.split(".", 1)[0] for name in sys.modules}
if loaded:
    raise AssertionError("Capability probe imported forbidden packages: " + ", ".join(sorted(loaded)))
raise SystemExit(status)
"""
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", probe, str(SRC)],
            cwd=ROOT, env={"LANG": "C", "LC_ALL": "C"},
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["implementation_sha256"], P.digest(value["implementation_files"]))
        self.assertIn("prepush/source_operations.py", value["implementation_files"])
        self.assertEqual(value["visual_formats"]["page"], ["png"])
        self.assertFalse(value["terminal_review_bypass"])
        self.assertEqual(value["live_qualification"], "not_established")

    def test_visual_page_body_scope_and_optional_model_source_logic(self):
        namespace = {}
        export = source_function("extractors/sigma/visual_contracts.py", "export_body", namespace, class_name="VisualCaptureRequestV2")
        value = types.SimpleNamespace(target_kind="page", tag="reviewed", page_id="p1", parameters={"region": "North"})
        self.assertEqual(export(value, "png"), {"pageId": "p1", "tag": "reviewed", "parameters": {"region": "North"}, "format": {"type": "png"}})
        with self.assertRaises(ValueError): export(value, "json")

    def test_visual_v2_scope_validator(self):
        validate = source_function("extractors/sigma/visual_contracts.py", "exact_visual_scope", {}, class_name="VisualCaptureRequestV2")
        value = types.SimpleNamespace(target_kind="page", element_id=None, data_model_id=None,
                                      source_freeze=types.SimpleNamespace(data_model_document_version=None))
        self.assertIs(validate(value), value)
        value.element_id = "e1"
        with self.assertRaises(ValueError): validate(value)
        value.element_id = None; value.data_model_id = "m1"
        with self.assertRaises(ValueError): validate(value)

    def test_api_explicit_empty_selection_never_broadens(self):
        def row_id(row, *keys): return next((row[k] for k in keys if row.get(k)), None)
        select = source_function("extractors/sigma/api.py", "_select_inventory", {"_row_id": row_id}, class_name="SigmaApi")
        rows = [{"dataModelId": "m1"}]
        self.assertEqual(select(rows, [], id_keys=("dataModelId",), label="models", limit=10), [])
        self.assertEqual(select(rows, None, id_keys=("dataModelId",), label="models", limit=10), rows)


class JournalControlFlowTests(unittest.TestCase):
    """Exact execute function with inert storage/scanner/transport adapters, not runtime QA."""
    def runner(self, capture):
        def read_json(path):
            if path.is_symlink(): raise ValueError("symlink")
            return json.loads(path.read_bytes())
        def write(path, raw):
            with path.open("xb") as output: output.write(raw)
        def prepare(path): path.mkdir(mode=0o700, parents=True, exist_ok=True); return path.resolve()
        namespace = dict(O.__dict__)
        namespace.update(read_json=read_json, reject_secrets=lambda v: None, atomic_private_write=write,
                         prepare_workspace=prepare, capture_visual=capture)
        return source_function("prepush/source_operations.py", "execute", namespace, strip_imports=True)

    def test_capture_outer_envelope_and_resume_do_not_repeat_child_submission(self):
        calls = []
        def child(request, **kwargs):
            folder = kwargs["directory"]; folder.mkdir(mode=0o700, exist_ok=True)
            calls.append(kwargs["resume"])
            path = folder / "capture-000001.json"
            if not kwargs["resume"]: path.write_bytes(b'{"fixture":"ambiguous_submission"}')
            return {"status": "partial", "output": str(path), "capture": {"private_rows": [1]}}
        execute = self.runner(child)
        value = request("capture"); value["visual_capture_request"] = visual_request()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "run"
            out = execute(value, api=Api(), directory=folder, allow_source_read=True, allow_source_query=True)
            self.assertEqual(calls, [False]); self.assertNotIn("capture", out)
            envelope = json.loads(Path(out["output"]).read_bytes())
            self.assertEqual(envelope["journal_revision"], 2)
            self.assertEqual(envelope["request_sha256"], P.digest(value))
            self.assertEqual(envelope["result_sha256"], P.digest(envelope["result"]))
            self.assertEqual(envelope["content_hash"], P.digest({k:v for k,v in envelope.items() if k != "content_hash"}))
            self.assertEqual(envelope["result"]["visual_capture"]["path"], "visual/capture-000001.json")
            self.assertNotIn("private_rows", json.dumps(envelope))
            execute(value, api=Api(), directory=folder, allow_source_read=True, allow_source_query=True, resume=True)
            self.assertEqual(calls, [False, True])
            (folder / "visual/capture-000001.json").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "receipt changed"):
                execute(value, api=Api(), directory=folder, allow_source_read=True, allow_source_query=True, resume=True)
            self.assertEqual(len(calls), 2)

    def test_outer_pending_survives_failure_and_same_request_required(self):
        calls = []
        def child(request, **kwargs):
            folder = kwargs["directory"]; folder.mkdir(mode=0o700, exist_ok=True)
            (folder / "capture-000001.json").write_bytes(b'{"fixture":"submission_uncertain"}')
            calls.append(kwargs["resume"])
            raise ValueError("synthetic interruption")
        execute = self.runner(child); value = request("capture"); value["visual_capture_request"] = visual_request()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "run"
            with self.assertRaises(ValueError): execute(value, api=Api(), directory=folder, allow_source_read=True, allow_source_query=True)
            pending = json.loads((folder / "source-operation-000001.json").read_bytes())
            self.assertEqual(pending["status"], "pending")
            changed = deepcopy(value); changed["request_id"] = "different"
            with self.assertRaisesRegex(ValueError, "binding changed"):
                execute(changed, api=Api(), directory=folder, allow_source_read=True, allow_source_query=True, resume=True)
            self.assertEqual(calls, [False])

    def test_missing_query_grant_precedes_journal_or_transport(self):
        execute = self.runner(lambda *a, **k: self.fail("ungranted source capture"))
        value = request("capture"); value["visual_capture_request"] = visual_request()
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "run"
            with self.assertRaises(ValueError): execute(value, api=Api(), directory=folder, allow_source_read=True)
            self.assertFalse(folder.exists())



class VisualResumeSourceTests(unittest.TestCase):
    """Real lifecycle functions, with model/storage/network boundaries replaced by fixtures."""
    def runtime(self):
        def canonical(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        class Request:
            def __init__(self, value):
                self.value = deepcopy(value)
                for key, item in value.items(): setattr(self, key, item)
                self.source_freeze = types.SimpleNamespace(**value["source_freeze"])
                self.tag = self.source_freeze.workbook_tag_name
                self.job_kinds = ("png",)
                self.file_stem = "page"
                self.row_limit = 10
                self.max_download_attempts = 3
                self.max_capture_age_seconds = 3600
            def model_dump(self, **kwargs): return deepcopy(self.value)
            def export_body(self, kind):
                if kind != "png": raise ValueError("page PNG only")
                return {"tag": self.tag, "pageId": self.page_id, "parameters": self.parameters, "format": {"type": "png"}}
        def prepare(path): path.mkdir(mode=0o700, parents=True, exist_ok=True); return path
        def write(path, data):
            with path.open("xb") as output: output.write(data)
        def read(path): return json.loads(path.read_bytes())
        namespace = {"deepcopy": deepcopy, "datetime": datetime, "UTC": timezone.utc, "fcntl": fcntl,
                     "hashlib": hashlib, "json": json, "os": os, "Path": Path,
                     "sha256_json": canonical, "VisualCaptureRequest": Request, "parse_visual_request": Request,
                     "read_json": read, "atomic_private_write": write, "prepare_workspace": prepare,
                     "SCHEMA": "sigma-visual-capture.v1", "BASE_GAPS": ["result_completeness_not_established"],
                     "selected_sigma_document_version": lambda row,*keys: str(next(row[k] for k in keys if k in row))}
        for name in ("_id", "_observation", "_coherence", "_membership", "_encode", "_save", "_load", "capture_visual"):
            source_function("extractors/sigma/visual_capture.py", name, namespace)
        return namespace

    def test_actual_capture_loop_never_replays_ambiguous_post_on_resume(self):
        namespace = self.runtime(); calls = []
        class Source(Api):
            def workbook_tags(self, id_): return [{"tagName": "reviewed", "sourceVersion": 1}]
            def workbook_snapshot(self, id_, **kwargs):
                return {"workbookId": id_, "tag": "reviewed", "pages": [{"pageId": "p1", "elements": []}],
                    "revisionEvidence": {"workbook": self.get_workbook(id_), "tags": self.workbook_tags(id_)}}
            def export_workbook(self, *args, **kwargs):
                calls.append(kwargs); raise ValueError("synthetic ambiguous POST")
            def download_export(self, *args): raise AssertionError("unknown query must not be downloaded")
            def data_model_spec(self, *args, **kwargs): raise AssertionError("no associated model selected")
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp); source = Source(); req = visual_request()
            out = namespace["capture_visual"](req, api=source, directory=folder, allow_source_read=True, allow_source_query=True)
            self.assertEqual(out["status"], "partial")
            self.assertEqual(out["capture"]["jobs"][0]["status"], "ambiguous_submission")
            again = namespace["capture_visual"](req, api=source, directory=folder, allow_source_read=True, allow_source_query=True, resume=True)
            self.assertEqual(again["status"], "partial")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["page_id"], "p1")
            self.assertIsNone(calls[0]["element_id"])
            self.assertIn("page_image_has_no_paired_numerical_result", again["capture"]["gaps"])

    def test_completed_capture_requires_final_source_observation(self):
        namespace = self.runtime(); req = visual_request(); digest = namespace["sha256_json"]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            state = {"schema_version": "sigma-visual-capture.v1", "request": req, "request_sha256": digest(req),
                     "journal_revision": 1, "previous_content_hash": None, "status": "complete", "source": None}
            state["content_hash"] = digest(state)
            (folder / "capture-000001.json").write_text(json.dumps(state))
            with self.assertRaisesRegex(ValueError, "final source observation"):
                namespace["_load"](folder, digest(req))


if __name__ == "__main__": unittest.main()
