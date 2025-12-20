try:
    import PySimpleGUI as sg
except Exception:
    sg = None

import os, sys, subprocess, tempfile

def run_cli(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def main():
    if sg is None:
        print("PySimpleGUI not installed; use CLI.")
        return
    sg.theme("DarkBlue14")

    welcome = sg.Frame(
        "👋 Welcome to Forgotten‑E2EE",
        [[sg.Text(
            "This helper guides you through private messaging:\n"
            "• Step 1 – Create an identity (public + secret key pair).\n"
            "• Step 2 – Paste a message, choose the recipient’s public key, and encrypt.\n"
            "• Step 3 – Load your secret key with the received file to decrypt.\n"
            "Every field below includes a hint designed for first-time users.",
            size=(70, 4),
            justification="left",
        )]],
        pad=(0, 10),
    )

    identity_frame = sg.Frame(
        "🔐 Create Your Identity",
        [
            [
                sg.Text("Key name (will be stored in lowercase):"),
                sg.Input(key="-NAME-", size=(25, 1), tooltip="Example: Javad"),
                sg.Text("Save keys into:"),
                sg.Input(key="-OUT-", size=(28, 1), tooltip="Choose or create a folder for your identity files"),
                sg.FolderBrowse("Select Folder"),
                sg.Button("Create Identity", key="KeyGen")
            ],
            [sg.Text("Outputs: <name>.id.pub to share, <name>.id.sec to keep safe.", text_color="#B0C7FF")]
        ],
        pad=(0, 10),
    )

    encrypt_frame = sg.Frame(
        "✉️ Compose & Encrypt",
        [
            [
                sg.Text("Recipient public key (.id.pub):"),
                sg.Input(key="-TO-", size=(45, 1), tooltip="Browse to the .id.pub file your contact gave you"),
                sg.FileBrowse("Browse")
            ],
            [sg.Text("Message to protect (paste or type below):")],
            [
                sg.Multiline(
                    key="-PLAINTEXT-",
                    size=(72, 8),
                    tooltip="Type your private message here – all text will be encrypted"
                )
            ],
            [
                sg.Checkbox("Create prose-style armor", key="-ARMOR-", default=True),
                sg.Text("Lexicon:"),
                sg.Input(
                    key="-LEX-",
                    size=(28, 1),
                    default_text="lexicons/en.txt",
                    tooltip="Pick vocabulary from the lexicons/ folder (must match during decrypt)"
                ),
                sg.FileBrowse("Choose Lexicon")
            ],
            [
                sg.Text("Signer secret key (optional, adds authenticity):"),
                sg.Input(
                    key="-SIGN-",
                    size=(40, 1),
                    tooltip="Load your own .id.sec if you want to sign the message"
                ),
                sg.FileBrowse("Select .id.sec")
            ],
            [
                sg.Text("Save encrypted file as:"),
                sg.Input(
                    key="-ENC_OUT-",
                    size=(30, 1),
                    default_text="message.fg.asc",
                    tooltip="Name for the encrypted output (use .fg.asc for armor or .fg.bin for binary)"
                ),
                sg.Button("Encrypt ✨", key="Encrypt")
            ],
            [sg.Text("Share the generated file with your contact using your usual channel.", text_color="#B0C7FF")]
        ],
        pad=(0, 10),
    )

    decrypt_frame = sg.Frame(
        "📬 Decrypt & Read",
        [
            [
                sg.Text("Your secret key (.id.sec):"),
                sg.Input(key="-PRIV-", size=(45, 1), tooltip="Browse to the .id.sec that belongs to you"),
                sg.FileBrowse("Browse")
            ],
            [
                sg.Text("Encrypted message file:"),
                sg.Input(key="-INFILE-", size=(45, 1), tooltip="Select the .fg.asc or .fg.bin you received"),
                sg.FileBrowse("Message")
            ],
            [
                sg.Text("Save decrypted text as:"),
                sg.Input(
                    key="-OUTFILE-",
                    size=(30, 1),
                    default_text="plain.txt",
                    tooltip="Where to store the recovered plaintext"
                )
            ],
            [
                sg.Text("Lexicon used during encryption:"),
                sg.Input(
                    key="-LEX_DEC-",
                    size=(28, 1),
                    default_text="lexicons/en.txt",
                    tooltip="Must match the lexicon the sender selected for armor output"
                ),
                sg.FileBrowse("Choose Lexicon")
            ],
            [sg.Button("Decrypt ✅", key="Decrypt")],
            [sg.Text("Tip: Armor messages will fail if you select the wrong lexicon.", text_color="#B0C7FF")]
        ],
        pad=(0, 10),
    )

    layout = [
        [sg.Text("Forgotten‑E2EE Assistant", font=("Helvetica", 16), text_color="#ffffff")],
        [welcome],
        [identity_frame],
        [encrypt_frame],
        [decrypt_frame],
        [sg.StatusBar("Ready to begin. 😊", key="-STATUS-", size=(75, 1))]
    ]
    win = sg.Window("Forgotten-E2EE", layout, finalize=True, resizable=True)
    while True:
        ev, val = win.read()
        if ev in (sg.WIN_CLOSED, None):
            break
        if ev == "KeyGen":
            code, out, err = run_cli([sys.executable, "forgotten_e2ee.py", "keygen",
                                      "--name", val["-NAME-"],
                                      "--out", val["-OUT-"],
                                      "--no-pass"])
            if code == 0:
                win["-STATUS-"].update("✅ Identity created – keep the .id.sec secret and share the .id.pub.")
            else:
                win["-STATUS-"].update(f"⚠️ Key generation error: {err.strip() or out}")
        if ev == "Encrypt":
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(val["-PLAINTEXT-"].encode())
            tmp.close()
            out_path = val.get("-ENC_OUT-", "message.fg.asc") or "message.fg.asc"
            cmd = [sys.executable, "forgotten_e2ee.py", "encrypt",
                   "--to", val["-TO-"],
                   "--in", tmp.name,
                   "--out", out_path]
            if val["-ARMOR-"]:
                lex_path = val.get("-LEX-", "")
                if lex_path:
                    cmd += ["--armor", "--lexicon", lex_path]
                else:
                    cmd.append("--armor")
            if val["-SIGN-"]:
                cmd += ["--sign-priv", val["-SIGN-"]]
            code, out, err = run_cli(cmd)
            tempfile_path = tmp.name
            try:
                os.unlink(tempfile_path)
            except Exception:
                pass
            if code == 0:
                win["-STATUS-"].update(f"✨ Encrypted message saved to {out_path}.")
            else:
                win["-STATUS-"].update(f"⚠️ Encryption error: {err.strip() or out}")
        if ev == "Decrypt":
            lex_path = val.get("-LEX_DEC-", val.get("-LEX-", ""))
            cmd = [sys.executable, "forgotten_e2ee.py", "decrypt",
                   "--priv", val["-PRIV-"],
                   "--in", val["-INFILE-"],
                   "--out", val["-OUTFILE-"],
                   "--no-pass"]
            if lex_path:
                cmd += ["--lexicon", lex_path]
            code, out, err = run_cli(cmd)
            if code == 0:
                win["-STATUS-"].update(f"✅ Decrypted message saved to {val['-OUTFILE-']}.")
            else:
                win["-STATUS-"].update(f"⚠️ Decryption error: {err.strip() or out}")
    win.close()

if __name__ == "__main__":
    main()
