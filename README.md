# VulnManager — Email Ingestion (Step 1)

Part of the agentic **VulnManager** platform. This repo covers **Step 1:
inbound email ingestion** — the step that picks up the weekly Tenable
vulnerability scan (which arrives as an `.xlsx` email attachment), validates
it, and stores it for the next stage of the pipeline.

## What it does
1. **Find** — locate the scan email in the inbox by subject (and optionally sender).
2. **Fetch** — download the `.xlsx` attachment.
3. **Validate** — check the workbook has the expected sheet (`Nessus Scan Data`) and the 20 expected columns.
4. **Store** — valid files go to `data/staging/`, bad files go to `data/quarantine/`; every original is archived in `data/raw/`.

## Mailbox backend
Dev uses **Gmail over IMAP** with an app password (no OAuth needed). The code
is written so the mailbox backend can later be swapped for **Microsoft Graph**
(the production GovCloud/Exchange inbox) without changing the pipeline.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then fill in your inbox + app password
```

`.env` holds inbox credentials and is **gitignored** — never commit it.

## Scripts
- `scripts/check_inbox.py` — connection test: prints the last few inbox emails.
- `scripts/send_test_scan.py` — dev-only helper: emails a sample scan to yourself so there is something to ingest.

## Roadmap
- `scripts/ingest.py` — the full Step 1 pipeline (find → fetch → validate → store). *In progress.*

## Config (`.env`)
| Key | Meaning |
|-----|---------|
| `IMAP_HOST` / `IMAP_PORT` | Gmail IMAP server (`imap.gmail.com` / `993`) |
| `IMAP_USER` | the inbox address |
| `APP_PASSWORD` | 16-char Gmail app password |
| `TARGET_SUBJECT` | subject substring that identifies a scan email |
| `TARGET_SENDER` | optional sender filter (blank = any) |
