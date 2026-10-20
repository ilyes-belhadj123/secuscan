"""Suivi des données d'un fichier à l'autre (interproc.py)."""
from secuscan.analyzers.interproc import cross_file_flows, describe, extract_functions
from secuscan.analyzers.taint import _Tainted
from secuscan.ingest import SourceFile
from secuscan.models import Scan
from secuscan.pipeline import new_id


def py(path: str, code: str) -> SourceFile:
    return SourceFile(path, "python", code)


ROUTES = """from flask import request
from storage import load_attachment

def attachment():
    name = request.args.get("name", "")
    return load_attachment(name)
"""
STORAGE = """def load_attachment(filename):
    with open("/srv/" + filename, "rb") as handle:
        return handle.read()
"""


def test_flow_reported_at_sink_with_caller():
    flows = cross_file_flows([py("routes.py", ROUTES), py("storage.py", STORAGE)])
    assert len(flows) == 1
    f = flows[0]
    assert (f.sink.file, f.sink.line, f.sink.rule_id) == ("storage.py", 2, "PY-PATH-FLOW")
    assert (f.caller_file, f.caller_line) == ("routes.py", 6)
    assert "load_attachment()" in describe(f) and "routes.py (ligne 6)" in describe(f)


def test_sanitized_argument_is_not_a_flow():
    routes = ROUTES.replace("return load_attachment(name)", "return load_attachment(secure_filename(name))")
    assert cross_file_flows([py("routes.py", routes), py("storage.py", STORAGE)]) == []


def test_nested_calls_inside_sanitizers():
    t = _Tainted("python")
    assert t.first_hit('int(request.args.get("id", "0"))', 1) is None
    assert _Tainted("go").first_hit('strconv.Atoi(r.URL.Query().Get("id"))', 1) is None
    assert _Tainted("java").first_hit('Long.parseLong(request.getParameter("id"))', 1) is None
    assert t.first_hit('request.args.get("id")', 1)  # sans nettoyage : toujours suivie


def test_chain_of_three_functions():
    service = """from storage import load_attachment

def serve_document(document_name):
    return load_attachment(document_name)
"""
    routes = ROUTES.replace("from storage import load_attachment", "from service import serve_document")
    routes = routes.replace("load_attachment(name)", "serve_document(name)")
    flows = cross_file_flows([py("routes.py", routes), py("service.py", service), py("storage.py", STORAGE)])
    assert [(f.sink.file, f.sink.line, f.caller_file) for f in flows] == [("storage.py", 2, "routes.py")]


def test_ambiguous_or_generic_names_are_not_linked():
    other = "def load_attachment(path):\n    return path.upper()\n"  # homonyme dans un autre module
    assert cross_file_flows([py("routes.py", ROUTES), py("storage.py", STORAGE), py("other.py", other)]) == []
    generic_routes = "from flask import request\n\ndef a():\n    return read(request.args['f'])\n"
    generic = "def read(f):\n    return open('/srv/' + f).read()\n"
    assert cross_file_flows([py("routes.py", generic_routes), py("io.py", generic)]) == []


def test_methods_skip_self_and_match_across_languages():
    store = "class Store:\n    def fetch_remote(self, url):\n        return requests.get(url, timeout=3)\n"
    caller = "def view():\n    return store.fetch_remote(request.args['u'])\n"
    fn = extract_functions(py("store.py", store))[0]
    assert fn.name == "fetch_remote" and fn.params == ["url"]
    assert [f.sink.rule_id for f in cross_file_flows([py("store.py", store), py("view.py", caller)])] == ["PY-SSRF"]
    # Même nom dans un autre langage : jamais relié (familles séparées)
    js_caller = SourceFile("v.js", "javascript", "app.get('/', (req, res) => {\n  fetch_remote(req.query.u);\n});\n")
    assert cross_file_flows([py("store.py", store), js_caller]) == []


def test_pipeline_reports_cross_file_flow(service, tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "routes.py").write_text(ROUTES, encoding="utf-8")
    (project / "storage.py").write_text(STORAGE, encoding="utf-8")
    scan = Scan(id=new_id(), project_name="Acme", source="upload")
    service.storage.save_scan(scan)
    findings = service.run(scan, project)
    cross = [f for f in findings if "depuis routes.py" in f.message]
    assert len(cross) == 1 and cross[0].file == "storage.py" and cross[0].cwe == "CWE-22"
    assert "open(" in cross[0].snippet  # extrait : la fonction appelée, là où se trouve l'opération dangereuse
