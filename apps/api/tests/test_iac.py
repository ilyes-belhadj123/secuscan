"""Infrastructure en code : Dockerfile, Kubernetes, docker-compose, Terraform."""
import pytest

from secuscan.analyzers import sast
from secuscan.config import Settings
from secuscan.ingest import SourceFile, collect_codebase, iac_kind, language_for_filename, yaml_kind


def rules(language: str, code: str, path: str = "f") -> set[str]:
    return {f.rule_id for f in sast.analyze_file(SourceFile(path, language, code))}


def test_file_detection(tmp_path):
    assert iac_kind("Dockerfile") == iac_kind("Dockerfile.prod") == iac_kind("api.dockerfile") == "dockerfile"
    assert iac_kind("main.tf") == "terraform" and iac_kind("docker-compose.yml") == iac_kind("compose.yaml") == "compose"
    assert language_for_filename("infra/Dockerfile") == "dockerfile"
    assert yaml_kind("apiVersion: v1\nkind: Pod\n") == "kubernetes" and yaml_kind("name: CI\non: push\n") is None
    (tmp_path / "k8s.yaml").write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n", encoding="utf-8")
    (tmp_path / "ci.yml").write_text("name: CI\non: push\n", encoding="utf-8")  # pas du Kubernetes : ignoré
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER app\n", encoding="utf-8")
    files = {f.path: f.language for f in collect_codebase(tmp_path, Settings(_env_file=None)).files}
    assert files == {"Dockerfile": "dockerfile", "k8s.yaml": "kubernetes"}


def test_dockerfile_root_and_tags():
    assert "DOCKER-ROOT" in rules("dockerfile", "FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]\n")
    assert "DOCKER-ROOT" in rules("dockerfile", "FROM python:3.12\nUSER app\nUSER root\nCMD [\"x\"]\n")
    assert "DOCKER-LATEST" in rules("dockerfile", "FROM python\nUSER app\n")
    # Étape nommée réutilisée, image par empreinte, variable de build : pas d'alerte de version
    multi = ("FROM node:22 AS build\nRUN npm ci\nFROM build AS test\nFROM nginx@sha256:abc\nARG BASE\n"
             "FROM ${BASE}\nUSER 101\n")
    assert not rules("dockerfile", multi)


@pytest.mark.parametrize("line, expected", [
    ("ENV API_KEY=abc123def456", "DOCKER-SECRET"),
    ("ARG GITHUB_TOKEN=ghp_placeholder", "DOCKER-SECRET"),
    ("RUN wget -qO- https://example.com/i.sh | bash", "DOCKER-PIPE-SHELL"),
    ("ADD https://example.com/a.tgz /opt/", "DOCKER-ADD-URL"),
])
def test_dockerfile_lines(line, expected):
    assert expected in rules("dockerfile", f"FROM alpine:3.20\n{line}\nUSER app\n")


@pytest.mark.parametrize("line", [
    "ARG GITHUB_TOKEN",  # valeur fournie au build, pas écrite dans le fichier
    "ENV API_KEY=$API_KEY",
    "ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/a.tgz /opt/",
])
def test_dockerfile_safe_lines(line):
    assert not rules("dockerfile", f"FROM alpine:3.20\n{line}\nUSER app\n")


SAFE_POD = """apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
  containers:
    - name: a
      image: acme/a:1.0.0
      resources:
        limits:
          memory: 128Mi
"""


def test_kubernetes():
    assert not rules("kubernetes", SAFE_POD)
    bad = SAFE_POD.replace("    runAsNonRoot: true\n", "    runAsUser: 0\n")
    bad = bad.replace("        limits:\n          memory: 128Mi\n", "")
    found = rules("kubernetes", bad)
    assert {"K8S-RUN-AS-ROOT", "K8S-NO-NONROOT", "K8S-NO-LIMITS"} <= found
    # Une ConfigMap n'est pas une charge de travail : pas de contrôle runAsNonRoot / limits
    assert not rules("kubernetes", "apiVersion: v1\nkind: ConfigMap\ndata:\n  a: b\n")
    # « - ALL » dans drop (normal) n'est pas une capacité ajoutée
    assert "IAC-CAPABILITIES" not in rules("kubernetes", SAFE_POD + "      securityContext:\n        capabilities:\n"
                                                          "          drop:\n            - ALL\n")


def test_terraform_ingress_only():
    ingress = 'resource "aws_security_group" "a" {\n  ingress {\n    from_port = 3389\n    to_port = 3389\n' \
              '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    egress = ingress.replace("ingress", "egress")
    assert "TF-OPEN-INGRESS" in rules("terraform", ingress)
    assert not rules("terraform", egress)  # sortir vers Internet est l'usage normal
    rule = 'resource "aws_security_group_rule" "r" {\n  type = "egress"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
    assert not rules("terraform", rule)


@pytest.mark.parametrize("line, expected", [
    ('acl = "public-read-write"', "TF-PUBLIC-ACL"),
    ("publicly_accessible = true", "TF-PUBLIC-DB"),
    ("encrypted = false", "TF-UNENCRYPTED"),
    ('actions = ["*"]', "TF-IAM-WILDCARD"),
    ('password = "Placeholder-Pass-1"', "TF-SECRET"),
])
def test_terraform_lines(line, expected):
    assert expected in rules("terraform", f'resource "x" "y" {{\n  {line}\n}}\n')


def test_terraform_variable_secret_is_fine():
    assert not rules("terraform", 'resource "x" "y" {\n  password = var.db_password\n  token = "${var.t}"\n}\n')
