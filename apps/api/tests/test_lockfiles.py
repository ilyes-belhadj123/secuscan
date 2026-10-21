"""Fichiers de verrouillage des dépendances : versions réellement installées (SCA)."""
from secuscan.analyzers.sca import parse_manifests
from secuscan.ingest import ManifestFile, manifest_kind

YARN_V1 = '''# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.24.5.tgz"

lodash@^4.17.0:
  version "4.17.21"
'''
YARN_BERRY = '''__metadata:
  version: 8

"express@npm:^4.17.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
'''
PNPM = '''lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21

packages:

  '@types/node@20.11.5':
    resolution: {integrity: sha512-x}

  lodash@4.17.21:
    resolution: {integrity: sha512-y}
'''
POETRY = '''[[package]]
name = "django"
version = "4.2.11"
description = "A high-level Python web framework"

[[package]]
name = "requests"
version = "2.31.0"
'''
PIPFILE = '{"default": {"flask": {"version": "==2.3.3"}}, "develop": {"pytest": {"version": "==8.0.0"}}}'


def deps(*manifests: tuple[str, str]) -> set[tuple[str, str, str]]:
    files = [ManifestFile(path, manifest_kind(path.split("/")[-1]), content) for path, content in manifests]
    return {(d.ecosystem, d.name, d.version) for d in parse_manifests(files)}


def test_yarn_pnpm_poetry_pipfile():
    assert deps(("yarn.lock", YARN_V1)) == {("npm", "@babel/core", "7.24.5"), ("npm", "lodash", "4.17.21")}
    assert deps(("yarn.lock", YARN_BERRY)) == {("npm", "express", "4.18.2")}
    assert deps(("pnpm-lock.yaml", PNPM)) == {("npm", "@types/node", "20.11.5"), ("npm", "lodash", "4.17.21")}
    assert deps(("poetry.lock", POETRY)) == {("PyPI", "django", "4.2.11"), ("PyPI", "requests", "2.31.0")}
    assert deps(("Pipfile.lock", PIPFILE)) == {("PyPI", "flask", "2.3.3"), ("PyPI", "pytest", "8.0.0")}


def test_lockfile_replaces_version_ranges_of_the_manifest():
    package = '{"dependencies": {"lodash": "^4.17.0"}}'
    # Sans lockfile : la plage ^4.17.0 est interrogée comme 4.17.0 ; avec yarn.lock : la vraie version
    assert deps(("web/package.json", package)) == {("npm", "lodash", "4.17.0")}
    assert deps(("web/package.json", package), ("web/yarn.lock", YARN_V1)) == {
        ("npm", "@babel/core", "7.24.5"), ("npm", "lodash", "4.17.21")}


def test_requirements_variants_are_manifests():
    assert manifest_kind("requirements-dev.txt") == "requirements.txt"
    assert manifest_kind("requirements.prod.txt") == "requirements.txt"
    assert manifest_kind("requirement.md") is None
    assert deps(("api/requirements-prod.txt", "flask==2.3.3\n")) == {("PyPI", "flask", "2.3.3")}
