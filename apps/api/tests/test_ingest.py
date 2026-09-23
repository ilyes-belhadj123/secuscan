import zipfile

import pytest

from secuscan.ingest import UploadError, collect_codebase, safe_extract_zip


def _zip(path, entries: dict[str, bytes]):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def test_extract_ok(tmp_path, settings):
    archive = _zip(tmp_path / "ok.zip", {"src/app.py": b"print('ok')\n", "package.json": b"{}"})
    dest = tmp_path / "out"
    dest.mkdir()
    safe_extract_zip(archive, dest, settings)
    code = collect_codebase(dest, settings)
    assert [f.path for f in code.files] == ["src/app.py"]
    assert [m.name for m in code.manifests] == ["package.json"]


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/abs/evil.py", "C:/evil.py"])
def test_zip_slip_rejected(tmp_path, settings, name):
    archive = _zip(tmp_path / "evil.zip", {name: b"x"})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(UploadError):
        safe_extract_zip(archive, dest, settings)
    assert not (tmp_path / "evil.py").exists()


def test_zip_bomb_rejected(tmp_path, settings):
    archive = _zip(tmp_path / "bomb.zip", {"big.txt": b"0" * 5_000_000})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(UploadError, match="compression"):
        safe_extract_zip(archive, dest, settings)


def test_not_a_zip(tmp_path, settings):
    fake = tmp_path / "fake.zip"
    fake.write_bytes(b"not a zip")
    with pytest.raises(UploadError):
        safe_extract_zip(fake, tmp_path, settings)


def test_ignored_dirs(tmp_path, settings):
    (tmp_path / "node_modules" / "lib").mkdir(parents=True)
    (tmp_path / "node_modules" / "lib" / "index.js").write_text("eval(x)")
    (tmp_path / "main.js").write_text("console.log(1)")
    code = collect_codebase(tmp_path, settings)
    assert [f.path for f in code.files] == ["main.js"]
