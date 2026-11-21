"""
Step 1 -- INGESTION PIPELINE (complete).

Stages: FIND -> FETCH -> VALIDATE -> STORE.

FIND     = locate the weekly Tenable scan email in the inbox, matched by subject
           (a case-insensitive substring) and, optionally, by sender.
FETCH    = download the .xlsx attachment from that email into data/raw/.
VALIDATE = open the .xlsx and confirm it has the expected sheet and 20 columns.
STORE    = a valid file goes to data/staging/, a bad one to data/quarantine/;
           the email's Message-ID is recorded so it is never processed twice.
"""
import email
import imaplib
import shutil
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path

from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parent.parent  # the VulnManager/ folder
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"  # every downloaded original is archived here
STAGING_DIR = DATA_DIR / "staging"  # validated files ready for the next stage
QUARANTINE_DIR = DATA_DIR / "quarantine"  # files that failed validation
# One Message-ID per line; lets us skip an email we already handled.
PROCESSED_FILE = DATA_DIR / "processed_ids.txt"

# The scan workbook must contain this sheet...
EXPECTED_SHEET = "Nessus Scan Data"
# ...with exactly these 20 column headers, in this order.
EXPECTED_COLUMNS = [
    "Plugin",
    "Plugin Name",
    "Family",
    "Severity",
    "IP Address",
    "Protocol",
    "Port",
    "DNS Name",
    "Plugin Output",
    "Synopsis",
    "Description",
    "Steps to Remediate",
    "Risk Factor",
    "CVSS V2 Base Score",
    "First Discovered",
    "Last Observed",
    "Vuln Publication Date",
    "Patch Publication Date",
    "Plugin Publication Date",
    "Plugin Modification Date",
]


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


def connect(env):
    """Open an authenticated IMAP connection and select the inbox."""
    host = env.get("IMAP_HOST", "imap.gmail.com")
    port = int(env.get("IMAP_PORT", "993"))
    user = env["IMAP_USER"]
    pwd = env["APP_PASSWORD"].replace(" ", "")  # app passwords are shown with spaces

    mail = imaplib.IMAP4_SSL(host, port)
    mail.login(user, pwd)
    mail.select("INBOX")
    return mail


def find_scan_email(mail, subject, sender=""):
    """
    Find the NEWEST inbox email whose subject contains `subject`
    (and, if `sender` is given, whose From matches it).

    Returns (msg_id, msg) for the newest match, or (None, None) if nothing matches.
    The subject/sender filtering is done server-side by the IMAP SEARCH command,
    which matches substrings case-insensitively.
    """
    # Build the SEARCH criteria. Multiple criteria are ANDed together.
    criteria = ["SUBJECT", f'"{subject}"']
    if sender:
        criteria += ["FROM", f'"{sender}"']

    _, data = mail.search(None, *criteria)
    ids = data[0].split()
    if not ids:
        return None, None

    # IDs come back oldest -> newest, so the last one is the most recent match.
    newest = ids[-1]
    _, msg_data = mail.fetch(newest, "(RFC822)")
    msg = email.message_from_bytes(msg_data[0][1])
    return newest, msg


def fetch_attachment(msg, dest_dir=RAW_DIR):
    """
    Download the .xlsx attachment from `msg` and save it under `dest_dir`.

    The saved name is prefixed with a UTC timestamp so repeated weekly scans
    never overwrite each other, e.g. 20261121T183235Z__DMS PROD Tenable Scan_Data.xlsx.

    Returns the Path of the saved file, or None if the email has no .xlsx attachment.
    """
    for part in msg.walk():
        filename = part.get_filename()
        if not filename or not filename.lower().endswith(".xlsx"):
            continue

        data = part.get_payload(decode=True)  # raw attachment bytes
        dest_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = dest_dir / f"{stamp}__{filename}"
        out_path.write_bytes(data)
        return out_path

    return None


def validate_xlsx(path):
    """
    Check that the workbook at `path` looks like a real Tenable scan file.

    It must contain the sheet EXPECTED_SHEET whose first row is exactly
    EXPECTED_COLUMNS (same names, same order).

    Returns (ok, problems) where `ok` is True/False and `problems` is a list
    of human-readable strings describing what was wrong (empty when ok).
    """
    problems = []

    # read_only is fast and memory-light; we only need the header row.
    wb = load_workbook(path, read_only=True)
    try:
        if EXPECTED_SHEET not in wb.sheetnames:
            problems.append(
                f"missing sheet {EXPECTED_SHEET!r} (found: {wb.sheetnames})"
            )
            return False, problems

        ws = wb[EXPECTED_SHEET]
        # Read the first row (the header). next() gives the first row's cells.
        header_row = next(ws.iter_rows(min_row=1, max_row=1, values_only=True), ())
        headers = [str(c).strip() if c is not None else "" for c in header_row]

        if headers != EXPECTED_COLUMNS:
            if len(headers) != len(EXPECTED_COLUMNS):
                problems.append(
                    f"expected {len(EXPECTED_COLUMNS)} columns, found {len(headers)}"
                )
            # Report the first few specific mismatches to make fixing easy.
            for i, expected in enumerate(EXPECTED_COLUMNS):
                actual = headers[i] if i < len(headers) else "<missing>"
                if actual != expected:
                    problems.append(
                        f"column {i + 1}: expected {expected!r}, found {actual!r}"
                    )
    finally:
        wb.close()

    return (not problems), problems


def load_processed_ids(path=PROCESSED_FILE):
    """Return the set of Message-IDs we have already ingested."""
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def mark_processed(message_id, path=PROCESSED_FILE):
    """Record a Message-ID so this email is not ingested again."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(message_id + "\n")


def store_file(src, ok):
    """
    Copy the raw file into staging/ (if valid) or quarantine/ (if not).

    The original stays in raw/ as the archive; we copy rather than move so the
    archive is never emptied. Returns the destination Path.
    """
    dest_dir = STAGING_DIR if ok else QUARANTINE_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    shutil.copy2(src, dest)  # copy2 keeps the file's timestamps
    return dest


def main():
    env = load_env()
    subject = env.get("TARGET_SUBJECT", "")
    sender = env.get("TARGET_SENDER", "")

    print(f"Looking for scan email -- subject contains: {subject!r}")
    if sender:
        print(f"                         from sender      : {sender!r}")
    print()

    mail = connect(env)
    msg_id, msg = find_scan_email(mail, subject, sender)

    if msg is None:
        print("No matching scan email found in the inbox.")
        mail.logout()
        return

    # --- FIND result ---
    message_id = decode(msg.get("Message-ID"))
    attachments = [p.get_filename() for p in msg.walk() if p.get_filename()]
    print("FOUND scan email:")
    print(f"  - Message-ID : {message_id}")
    print(f"    From       : {decode(msg.get('From'))}")
    print(f"    Subject    : {decode(msg.get('Subject'))}")
    print(f"    Date       : {decode(msg.get('Date'))}")
    print(f"    Attachments: {attachments if attachments else 'none'}")

    # --- IDEMPOTENCY: skip if we have already ingested this exact email ---
    if message_id and message_id in load_processed_ids():
        print()
        print("Already processed this email before -- skipping (nothing to do).")
        mail.logout()
        return

    # --- FETCH the .xlsx attachment ---
    print()
    saved = fetch_attachment(msg)
    if saved is None:
        print("No .xlsx attachment found on this email -- nothing to fetch.")
        mail.logout()
        return

    size = saved.stat().st_size
    print("FETCHED attachment:")
    print(f"  - Saved to : {saved}")
    print(f"    Size     : {size:,} bytes")

    # --- VALIDATE the downloaded file ---
    print()
    ok, problems = validate_xlsx(saved)
    if ok:
        print("VALIDATION PASSED:")
        print(f"  - Sheet {EXPECTED_SHEET!r} present")
        print(f"    All {len(EXPECTED_COLUMNS)} columns present and in order")
    else:
        print("VALIDATION FAILED:")
        for p in problems:
            print(f"  - {p}")

    # --- STORE: valid -> staging, invalid -> quarantine ---
    print()
    dest = store_file(saved, ok)
    print("STORED:")
    print(f"  - {'staging' if ok else 'quarantine'}: {dest}")

    # Remember this email so a later run does not re-ingest it.
    if message_id:
        mark_processed(message_id)
        print(f"    recorded Message-ID as processed")

    mail.logout()


if __name__ == "__main__":
    main()
