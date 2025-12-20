import subprocess
import sys
import pathlib

PY = sys.executable
ROOT = pathlib.Path(__file__).resolve().parents[1]
LEX_DIR = ROOT / "lexicons"


PARAGRAPHS = [
    "Autumn sunlight spilled across the quiet courtyard. I met the archivist who guarded the bronze doors. "
    "She whispered about hidden indexes beneath the marble floor. We traced the pattern of constellations carved "
    "into the railings. Finally we promised to return with stories worth preserving.",
    "At dawn the research vessel drifted beyond the harbor. Sensors hummed while gulls paced the railing. "
    "The captain logged every color the clouds reflected. My notebook filled with sketches of salt-stained machinery. "
    "We agreed the sea could keep our hurried confessions.",
    "Inside the orbital laboratory, alarms echoed softly. Engineers calibrated the shimmering solar sails. "
    "A botanist described seedlings that thrived in recycled mist. We shared dried fruit packets while mapping tomorrow's "
    "experiments. The viewport framed Earth like a patient blue lantern.",
    "Rain glazed the neon alleys of the lower district. Hackers bartered over quantum access keys. "
    "A street poet sampled chorus loops through a cracked amplifier. I downloaded the last firmware patch before curfew "
    "sirens rose. Hope lingered in the glow of rain-slick billboards.",
]

CONFIGS = [
    {"armor": True, "lex": LEX_DIR / "en.txt", "sign": True},
    {"armor": False, "lex": LEX_DIR / "cyberpunk.txt", "sign": False},
    {"armor": True, "lex": LEX_DIR / "fr.txt", "sign": True},
    {"armor": True, "lex": None, "sign": False},
]


def run(cmd, input_text=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, input=input_text)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
    assert proc.returncode == 0
    return proc.stdout


def test_cli_multiple_roundtrips(tmp_path):
    ids = tmp_path / "ids"
    ids.mkdir()

    run([PY, "forgotten_e2ee.py", "keygen", "--name", "Alice", "--out", str(ids), "--no-pass"])
    run([PY, "forgotten_e2ee.py", "keygen", "--name", "Bob", "--out", str(ids), "--no-pass"])

    # Validate show-fp output for Bob to cover the CLI surface.
    show_fp_output = run([PY, "forgotten_e2ee.py", "show-fp", "--pub", str(ids / "bob.id.pub")]).strip()
    assert len(show_fp_output) == 24

    for idx, (paragraph, cfg) in enumerate(zip(PARAGRAPHS, CONFIGS)):
        msg_path = tmp_path / f"msg_{idx}.txt"
        msg_path.write_text(paragraph)
        out_suffix = ".fg.asc" if cfg["armor"] else ".fg.bin"
        out_path = tmp_path / f"cipher_{idx}{out_suffix}"
        dec_path = tmp_path / f"plain_{idx}.txt"

        encrypt_cmd = [
            PY,
            "forgotten_e2ee.py",
            "encrypt",
            "--to",
            str(ids / "bob.id.pub"),
            "--in",
            str(msg_path),
            "--out",
            str(out_path),
        ]
        if cfg["armor"]:
            encrypt_cmd.append("--armor")
            if cfg["lex"]:
                encrypt_cmd.extend(["--lexicon", str(cfg["lex"])])
        elif cfg["lex"]:
            encrypt_cmd.extend(["--lexicon", str(cfg["lex"])])
        sign_input = None
        if cfg["sign"]:
            encrypt_cmd.extend(["--sign-priv", str(ids / "alice.id.sec")])
            sign_input = "\n"
        run(encrypt_cmd, input_text=sign_input)

        decrypt_cmd = [
            PY,
            "forgotten_e2ee.py",
            "decrypt",
            "--priv",
            str(ids / "bob.id.sec"),
            "--in",
            str(out_path),
            "--out",
            str(dec_path),
            "--no-pass",
        ]
        if cfg["lex"]:
            decrypt_cmd.extend(["--lexicon", str(cfg["lex"])])
        run(decrypt_cmd)

        assert dec_path.read_text() == paragraph

