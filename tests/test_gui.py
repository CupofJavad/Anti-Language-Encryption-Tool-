import pathlib
import subprocess
import sys

PY = sys.executable
ROOT = pathlib.Path(__file__).resolve().parents[1]
LEX_DIR = ROOT / "lexicons"


def test_gui_smoke(monkeypatch, tmp_path):
    from forgotten_e2ee import gui

    ids_dir = tmp_path / "ids"
    ids_dir.mkdir()
    encrypted_path = tmp_path / "message.fg.asc"
    recovered_path = tmp_path / "recovered.txt"

    # Pre-create Bob so Alice can target him.
    subprocess.check_call(
        [PY, "forgotten_e2ee.py", "keygen", "--name", "Bob", "--out", str(ids_dir), "--no-pass"],
        cwd=ROOT,
    )

    status_updates = []

    class DummyElement:
        def update(self, value):
            status_updates.append(value)

    events = [
        (
            "KeyGen",
            {
                "-NAME-": "Alice",
                "-OUT-": str(ids_dir),
            },
        ),
        (
            "Encrypt",
            {
                "-PLAINTEXT-": "Five sentences reside within this sample paragraph. "
                               "Each sentence demonstrates sober descriptive prose. "
                               "We rely on this text to exercise the GUI encrypt path. "
                               "The token-map armor should land in message.fg.asc. "
                               "Finally this paragraph confirms deterministic behavior.",
                "-TO-": str(ids_dir / "bob.id.pub"),
                "-ARMOR-": True,
                "-LEX-": str(LEX_DIR / "en.txt"),
                "-SIGN-": "",
                "-ENC_OUT-": str(encrypted_path),
            },
        ),
        (
            "Decrypt",
            {
                "-PRIV-": str(ids_dir / "bob.id.sec"),
                "-INFILE-": str(encrypted_path),
                "-OUTFILE-": str(recovered_path),
                "-LEX_DEC-": str(LEX_DIR / "en.txt"),
            },
        ),
        (None, None),
    ]

    closed_sentinel = object()

    class DummyWindow:
        def __init__(self):
            self._events = iter(events)
            self._elements = {"-STATUS-": DummyElement()}

        def read(self):
            try:
                return next(self._events)
            except StopIteration:
                return (closed_sentinel, {})

        def __getitem__(self, key):
            return self._elements.setdefault(key, DummyElement())

        def close(self):
            pass

    class DummySG:
        WIN_CLOSED = closed_sentinel

        def __getattr__(self, _name):
            return lambda *args, **kwargs: None

        def Window(self, _title, _layout, **_kwargs):
            return DummyWindow()

    monkeypatch.setattr(gui, "sg", DummySG())

    gui.main()

    assert recovered_path.exists(), f"GUI status updates: {status_updates}"
    assert recovered_path.read_text().startswith("Five sentences reside within this sample paragraph.")
    assert any(status_updates), "GUI produced no status updates"

    if encrypted_path.exists():
        encrypted_path.unlink()
