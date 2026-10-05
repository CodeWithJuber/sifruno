"""Read-only integrated-helper verification; all output stays beside this runner."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
TARGETS = ("parse_proc_identity", "worker_matches", "linux_start_identity", "OwnedProcess", "owned_launch", "stop_process")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def node_source(text, node):
    lines = text.splitlines(keepends=True)
    start = min([node.lineno, *[item.lineno for item in getattr(node, "decorator_list", [])]])
    return "".join(lines[start-1:node.end_lineno])


class TranslateError(ast.NodeTransformer):
    def visit_Name(self, node):
        if node.id == "LifecycleError":
            node.id = "FixtureError"
        return node


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--output-dir", type=Path, default=HERE/"artifacts/integrated")
    args = parser.parse_args()
    if args.fixture is None:
        # Primary checkout has a .git directory; linked worktrees have a .git
        # file. This also works when root copies the runner into canonical lab.
        args.fixture = next((parent/"lab/web_runtime_fixture.py" for parent in HERE.parents
                             if (parent/".git").is_dir() and (parent/"lab/web_runtime_fixture.py").is_file()),None)
        if args.fixture is None:
            parser.error("pass --fixture for a standalone review directory")
    args.output_dir.mkdir(parents=True,exist_ok=True)
    proof_files = ("verify_integrated.py","repair_candidate.py","test_repair_candidate.py",
                   "test_lifecycle_review.py","frozen_fixture_excerpt.py")
    proof_pins = {name:sha((HERE/name).read_bytes()) for name in proof_files}
    canonical_bytes = args.fixture.read_bytes()
    canonical = canonical_bytes.decode("utf-8")
    candidate = (HERE / "repair_candidate.py").read_text(encoding="utf-8")
    trees = [ast.parse(text) for text in (canonical, candidate)]
    maps = [{node.name:node for node in tree.body if isinstance(node, (ast.ClassDef,ast.FunctionDef))} for tree in trees]
    imports = {}
    for node in trees[0].body:
        if isinstance(node,ast.Import):
            for item in node.names:
                imports[item.asname or item.name] = [item.name,None]
        elif isinstance(node,ast.ImportFrom):
            for item in node.names:
                imports[item.asname or item.name] = [node.module,item.name]
    required_imports = {"dataclass":["dataclasses","dataclass"],"Path":["pathlib","Path"],
                        **{name:[name,None] for name in ("os","re","signal","subprocess","time")}}
    if any(imports.get(name)!=binding for name,binding in required_imports.items()):
        raise RuntimeError("canonical helper imports are missing or renamed")
    comparisons = []
    for name in TARGETS:
        current = ast.dump(maps[0][name], include_attributes=False)
        expected = ast.dump(TranslateError().visit(copy.deepcopy(maps[1][name])), include_attributes=False)
        comparisons.append({"name":name,"equal":current==expected,"normalized_ast_sha256":sha(current.encode())})
    if not all(item["equal"] for item in comparisons):
        raise RuntimeError("canonical helper AST differs from frozen candidate")

    parents = {child:parent for parent in ast.walk(trees[0]) for child in ast.iter_child_nodes(parent)}
    calls = []
    for node in ast.walk(trees[0]):
        if not isinstance(node,ast.Call):
            continue
        function = ast.unparse(node.func)
        if function not in ("owned_launch","subprocess.Popen"):
            continue
        owner = node
        while owner in parents and not isinstance(owner,ast.FunctionDef):
            owner = parents[owner]
        parent = parents[node]
        target = ast.unparse(parent.targets[0]) if isinstance(parent,ast.Assign) else None
        new_session = next((isinstance(item.value,ast.Constant) and item.value.value is True for item in node.keywords if item.arg=="start_new_session"),False)
        calls.append({"function":function,"owner":getattr(owner,"name",None),"target":target,"line":node.lineno,"new_session":new_session})
    launches = [item for item in calls if item["function"]=="owned_launch"]
    raw = [item for item in calls if item["function"]=="subprocess.Popen"]
    if len(launches)!=8 or not all(item["new_session"] for item in launches):
        raise RuntimeError("expected eight explicit new-session daemon launches")
    if sorted((item["owner"],item["target"]) for item in raw)!=[("owned_launch","process"),("run_cmd","child")]:
        raise RuntimeError("unexpected direct Popen callsite")
    expected_targets = ["backend","backend_procs[0]","backend_procs[0]","broker","fpm","front","front","panel"]
    if sorted(item["target"] for item in launches)!=expected_targets:
        raise RuntimeError("daemon launch targets differ")

    prefix = ("# Generated canonical helper extraction; tests only, not a runtime fixture.\n"
              "# Canonical SHA256: "+sha(canonical_bytes)+"\n"
              "from __future__ import annotations\nfrom dataclasses import dataclass\n"
              "import os\nfrom pathlib import Path\nimport re\nimport signal\nimport subprocess\nimport time\n\n")
    extracted = prefix + "\n\n".join(node_source(canonical,maps[0][name]) for name in ("FixtureError",*TARGETS))
    module_path = args.output_dir / "integrated_helpers.py"
    module_path.write_text(extracted,encoding="utf-8")
    spec = importlib.util.spec_from_file_location("review_integrated_lifecycle_helpers",module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module # dataclass resolves future annotations here
    spec.loader.exec_module(module)
    globals_correct = all(getattr(module,name).__globals__ is module.__dict__ for name in TARGETS if name!="OwnedProcess")
    globals_correct = globals_correct and module.OwnedProcess.__getattr__.__globals__ is module.__dict__
    dataclass_correct = (module.OwnedProcess.__module__==spec.name and
                         module.OwnedProcess.__dataclass_params__.frozen and
                         sys.modules[module.OwnedProcess.__module__] is module)
    if not globals_correct or not dataclass_correct:
        raise RuntimeError("extracted module registration or globals invalid")
    # Only test compatibility aliases the exception spelling; function AST and
    # globals remain those extracted from canonical source, never the candidate.
    module.LifecycleError = module.FixtureError
    import test_repair_candidate
    test_repair_candidate.candidate = module
    output = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_repair_candidate)
    result = unittest.TextTestRunner(stream=output,verbosity=2).run(suite)
    (args.output_dir / "integrated-tests.log").write_text(output.getvalue(),encoding="utf-8")
    source_unchanged = args.fixture.read_bytes()==canonical_bytes
    report = {"schema_version":1,"canonical_path":str(args.fixture.resolve()),"canonical_sha256":sha(canonical_bytes),
              "source_unchanged":source_unchanged,"candidate_sha256":sha((HERE/"repair_candidate.py").read_bytes()),
              "helpers":comparisons,"callsites":calls,"dataclass_registered":dataclass_correct,"canonical_globals":globals_correct,
              "canonical_import_bindings":required_imports,
              "extracted_module_sha256":sha(module_path.read_bytes()),"tests":result.testsRun,"passed":result.wasSuccessful() and source_unchanged,
              "platform":sys.platform,"actual_windows_parent_child":sys.platform=="win32","linux_group_delivery_simulated":True,
              "native_linux_qualified":False,"canonical_written":False,"review_source_pins":proof_pins,
              "review_source_unchanged":all(sha((HERE/name).read_bytes())==value for name,value in proof_pins.items())}
    report["passed"] = report["passed"] and report["review_source_unchanged"]
    (args.output_dir/"integrated-report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))
    print("integrated_report_sha256="+sha((args.output_dir/"integrated-report.json").read_bytes()))
    return 0 if report["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
