"""
Step 1 -- CONNECTION TEST (the smallest first step).

This script connects to the Gmail inbox and prints the subject, sender and
attachment name of the last 5 emails.

It is only a PROOF that the app password works.
It does NOT download / delete / move anything. Completely safe.
"""
import email
import imaplib
from email.header import decode_header
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # the VulnManager/ folder


def load_env(path=ROOT / ".env"):
    """Tiny .env reader -- parses KEY=VALUE lines (stripping quotes)."""
    env = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def decode(value):
    """Turn a raw email header into readable text."""
    if not value:
        return ""
    out = ""
    for text, enc in decode_header(value):
        if isinstance(text, bytes):
            out += text.decode(enc or "utf-8", errors="replace")
        else:
            out += text
    return out


def main():
    env = load_env()
    host = env.get("IMAP_HOST", "imap.gmail.com")
    port = int(env.get("IMAP_PORT", "993"))
    user = env["IMAP_USER"]
    pwd = env["APP_PASSWORD"].replace(" ", "")  # remove the spaces

    print(f"Connecting to {host}:{port} as {user} ...")
    mail = imaplib.IMAP4_SSL(host, port)
    mail.login(user, pwd)
    print("LOGIN SUCCESS -- the app password works!\n")

    mail.select("INBOX")
    _, data = mail.search(None, "ALL")
    ids = data[0].split()
    print(f"Total emails in inbox: {len(ids)}.")

    last = ids[-5:] if len(ids) >= 5 else ids
    print(f"Last {len(last)} emails (newest first):\n")
    for num in reversed(last):
        _, msg_data = mail.fetch(num, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])
        subject = decode(msg.get("Subject"))
        sender = decode(msg.get("From"))
        attachments = [p.get_filename() for p in msg.walk() if p.get_filename()]
        print(f"  - From   : {sender}")
        print(f"    Subject: {subject}")
        print(f"    Files  : {attachments if attachments else 'none'}")
        print()

    mail.logout()
    print("Done. Logout OK")


if __name__ == "__main__":
    main()
