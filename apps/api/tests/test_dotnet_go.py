"""C# et Go : langages, dépendances NuGet / Go, syntaxe des correctifs, suivi des données."""
import pytest

from secuscan.analyzers import sast
from secuscan.analyzers.sca import parse_manifests
from secuscan.analyzers.syntax import count_errors
from secuscan.config import Settings
from secuscan.ingest import ManifestFile, SourceFile, collect_codebase, language_for_filename, manifest_kind

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog">
      <Version>2.10.0</Version>
    </PackageReference>
    <PackageReference Include="Flottant" Version="6.*" />
  </ItemGroup>
</Project>
"""
GO_MOD = """module example.com/boutique

go 1.22

require github.com/gin-gonic/gin v1.6.0

require (
\tgithub.com/golang-jwt/jwt/v4 v4.4.1 // indirect
\tgolang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
)
"""


def test_languages_and_manifests(tmp_path):
    assert language_for_filename("Program.cs") == "csharp" and language_for_filename("main.go") == "go"
    assert manifest_kind("Boutique.Api.csproj") == "*.csproj" and manifest_kind("go.mod") == "go.mod"
    (tmp_path / "Api.csproj").write_text(CSPROJ, encoding="utf-8")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "Generated.cs").write_text("class G {}", encoding="utf-8")  # sortie de compilation
    (tmp_path / "Program.cs").write_text("class P {}", encoding="utf-8")
    codebase = collect_codebase(tmp_path, Settings(_env_file=None))
    assert [f.path for f in codebase.files] == ["Program.cs"]
    assert [(m.path, m.name) for m in codebase.manifests] == [("Api.csproj", "*.csproj")]


def test_nuget_and_go_dependencies():
    deps = parse_manifests([ManifestFile("Api.csproj", "*.csproj", CSPROJ), ManifestFile("go.mod", "go.mod", GO_MOD)])
    found = {(d.ecosystem, d.name, d.version, d.line) for d in deps}
    assert ("NuGet", "Newtonsoft.Json", "12.0.1", 3) in found and ("NuGet", "Serilog", "2.10.0", 4) in found
    assert not any(d.name == "Flottant" for d in deps)  # version flottante : inconnue, ignorée
    assert ("Go", "github.com/gin-gonic/gin", "1.6.0", 5) in found
    assert ("Go", "github.com/golang-jwt/jwt/v4", "4.4.1", 8) in found
    assert any(d.name == "golang.org/x/crypto" for d in deps)


def test_csproj_with_dtd_is_refused():
    evil = '<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><Project>&x;</Project>'
    assert parse_manifests([ManifestFile("Evil.csproj", "*.csproj", evil)]) == []


@pytest.mark.parametrize("language, ok, broken", [
    ("csharp", "class A { void F() { var x = 1; } }", "class A { void F() { var x = ; } }"),
    ("go", "package main\nfunc main() { x := 1; _ = x }\n", "package main\nfunc main() { x := }\n"),
])
def test_syntax_check(language, ok, broken):
    assert count_errors(language, ok) == 0 and count_errors(language, broken) > 0


def rules(language: str, code: str) -> set[str]:
    ext = {"csharp": "cs", "go": "go"}[language]
    return {f.rule_id for f in sast.analyze_file(SourceFile(f"x.{ext}", language, code))}


CONTROLLER = "[ApiController]\npublic class C : ControllerBase\n{{\n{body}\n}}\n"


def test_aspnet_action_parameters_are_user_input():
    vulnerable = CONTROLLER.format(body='    public IActionResult Get(string path)\n    {\n'
                                        '        return PhysicalFile("/srv/" + path, "text/plain");\n    }')
    assert "CS-PATH-FLOW" in rules("csharp", vulnerable)
    numeric = CONTROLLER.format(body='    public IActionResult Get(int id)\n    {\n'
                                     '        return PhysicalFile("/srv/" + id, "text/plain");\n    }')
    assert not rules("csharp", numeric)  # un entier ne peut pas contenir « ../ »
    not_controller = vulnerable.replace("[ApiController]\n", "").replace(" : ControllerBase", "")
    assert not rules("csharp", not_controller)


@pytest.mark.parametrize("code, expected", [
    ('var cmd = new SqlCommand($"SELECT * FROM U WHERE N = \'{name}\'", cn);', "CS-SQLI"),
    ("var f = new BinaryFormatter();", "CS-DESER"),
    ("settings.TypeNameHandling = TypeNameHandling.All;", "CS-DESER"),
    ("handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;", "CS-TLS"),
    ("var aes = Aes.Create(); aes.Mode = CipherMode.ECB;", "CS-WEAKCIPHER"),
])
def test_csharp_rules(code, expected):
    assert expected in rules("csharp", code)


@pytest.mark.parametrize("code, expected", [
    ('rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE n = \'%s\'", n))', "GO-SQLI"),
    ('id := c.Query("id")\nrows, _ := db.QueryContext(ctx, "SELECT * FROM t WHERE id = " + id)', "GO-SQLI"),
    ('prog := r.URL.Query().Get("p")\nexec.Command(prog).Run()', "GO-CMDI-FLOW"),
    ("cfg := &tls.Config{InsecureSkipVerify: true}", "GO-TLS"),
])
def test_go_rules(code, expected):
    assert any(r.startswith(expected) for r in rules("go", code))


@pytest.mark.parametrize("code", [
    'name := r.URL.Query().Get("n")\nrows, _ := db.Query("SELECT * FROM u WHERE n = $1", name)',
    'id := c.Query("id")\nrows, _ := db.QueryContext(ctx, "SELECT * FROM t WHERE id = ?", id)',
    'host := r.FormValue("h")\nout, _ := exec.Command("ping", "-c", "1", host).Output()\nw.Write(out)',
    'f := r.URL.Query().Get("f")\ndata, _ := os.ReadFile(filepath.Join("/srv", filepath.Base(f)))',
])
def test_go_safe_code(code):
    assert not rules("go", code)
