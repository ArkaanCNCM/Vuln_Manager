"""
Step 1 helper -- puts a TEST scan email into the inbox.

The real Tenable scanner is not available yet, so we send ourselves
(easetaskswithai@gmail.com) an email that carries the real xlsx attachment
and has exactly the subject it would have in production.

This is only a TEST fixture -- self to self. Safe.
"""
import smtplib
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCAN_FILE = Path(
    "/Users/arkaanfaizadkhan/Desktop/AI Consultation Proj DOCS/"
    "DMS PROD Tenable Scan_Data.xlsx"
)
SUBJECT = "DMS Middleware Prod Tenable vulnerability scan data"
XLSX_SUBTYPE = "vnd.openxmlformats-officedocument.spreadsheetml.sheet"


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


def main():
    env = load_env()
    user = env["IMAP_USER"]
    pwd = env["APP_PASSWORD"].replace(" ", "")

    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = user
    msg["Subject"] = SUBJECT
    msg.set_content(
        "Automated test: weekly Tenable vulnerability scan data attached.\n"
        "(Dev/test email for VulnManager ingestion.)"
    )

    data = SCAN_FILE.read_bytes()
    msg.add_attachment(
        data,
        maintype="application",
        subtype=XLSX_SUBTYPE,
        filename=SCAN_FILE.name,
    )

    print(f"Sending test scan email to {user} ...")
    print(f"  Subject : {SUBJECT}")
    print(f"  Attach  : {SCAN_FILE.name} ({len(data):,} bytes)")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(user, pwd)
        server.send_message(msg)
    print("Sent OK. It should land in the inbox shortly.")


if __name__ == "__main__":
    main()
