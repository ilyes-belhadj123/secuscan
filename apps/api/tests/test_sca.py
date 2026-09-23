import json

import httpx

from secuscan.analyzers import sca
from secuscan.ingest import ManifestFile


def _deps(n: int) -> list[sca.Dependency]:
    return [sca.Dependency("npm", f"pkg-{i}", "1.0.0", "package-lock.json", 1) for i in range(n)]


def test_querybatch_is_chunked(monkeypatch, service):
    sizes: list[int] = []

    def fake_get_json(self, method, url, **kwargs):
        queries = kwargs["json"]["queries"]
        assert len(queries) <= 1000, "OSV refuse les lots de plus de 1 000 requêtes"
        sizes.append(len(queries))
        return {"results": [{"vulns": []} for _ in queries]}

    monkeypatch.setattr(sca.OSVClient, "_get_json", fake_get_json)
    client = sca.OSVClient(service.storage)
    result = client.vuln_ids(_deps(1108))
    assert len(result) == 1108 and sizes == [500, 500, 108]
    assert client.errors == []


def test_osv_failure_is_reported(monkeypatch, service):
    def failing(self, method, url, **kwargs):
        raise httpx.ConnectError("réseau coupé")

    monkeypatch.setattr(sca.OSVClient, "_get_json", failing)
    client = sca.OSVClient(service.storage)
    assert client.vuln_ids(_deps(3)) == {}
    assert client.errors and "3 dépendance(s)" in client.errors[0]


def test_package_lock_v1_parsed():
    lock = {"lockfileVersion": 1, "dependencies": {
        "express": {"version": "4.13.4", "dependencies": {"qs": {"version": "6.1.0"}}},
        "local-lib": {"version": "file:../lib"},
    }}
    deps = sca.parse_package_lock(ManifestFile("package-lock.json", "package-lock.json", json.dumps(lock)))
    assert {(d.name, d.version) for d in deps} == {("express", "4.13.4"), ("qs", "6.1.0")}
