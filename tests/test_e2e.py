import os, sys, subprocess, pathlib
PY = sys.executable

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEX_DIR = ROOT / "lexicons"


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if p.returncode != 0:
        print(p.stdout); print(p.stderr)
    assert p.returncode == 0
    return p.stdout

def test_roundtrip(tmp_path: pathlib.Path):
    ids = tmp_path / "ids"; ids.mkdir()
    run([PY,"forgotten_e2ee.py","keygen","--name","A","--out",str(ids),"--no-pass"])
    run([PY,"forgotten_e2ee.py","keygen","--name","B","--out",str(ids),"--no-pass"])
    m = tmp_path / "m.txt"; m.write_text("hello forgotten")
    out = tmp_path / "m.fg.asc"
    lexicon_path = tmp_path / "lex.txt"
    lexicon_path.write_text((LEX_DIR / "cyberpunk.txt").read_text())
    run([PY,"forgotten_e2ee.py","encrypt","--to",str(ids/"b.id.pub"),"--in",str(m),"--out",str(out),"--armor","--lexicon",str(lexicon_path)])
    plain = tmp_path / "plain.txt"
    run([PY,"forgotten_e2ee.py","decrypt","--priv",str(ids/"b.id.sec"),"--in",str(out),"--out",str(plain),"--no-pass","--lexicon",str(lexicon_path)])
    assert plain.read_text() == "hello forgotten"
