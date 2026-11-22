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
- `scripts/ingest.py` — **the full Step 1 pipeline**: find → fetch → validate → store, with idempotency. Run it with `python scripts/ingest.py`.
- `scripts/categorize.py` — **Step 2 (column work)**: reshapes the validated scan for the tracker. Run it with `python scripts/categorize.py` (after `ingest.py`).
- `scripts/check_inbox.py` — connection test: prints the last few inbox emails.
- `scripts/send_test_scan.py` — dev-only helper: emails a sample scan to yourself so there is something to ingest.

## How `ingest.py` works
1. **Find** — searches the inbox (IMAP) for the newest email whose subject contains `TARGET_SUBJECT`.
2. **Fetch** — downloads the `.xlsx` attachment into `data/raw/`, prefixed with a UTC timestamp so weekly scans never overwrite each other.
3. **Validate** — opens the workbook and checks the sheet `Nessus Scan Data` exists with the 20 expected columns, in order.
4. **Store** — a valid file is copied to `data/staging/`; a bad one to `data/quarantine/`.
5. **Idempotency** — the email's `Message-ID` is recorded in `data/processed_ids.txt`, so re-running never ingests the same email twice.

## How `categorize.py` works (Step 2)
Runs after `ingest.py`. It picks up the newest validated file from `data/staging/`,
reshapes it for the tracker, and writes the result to `data/processed/`.
1. **Drop columns** — removes six columns the tracker does not need: `Risk Factor`,
   `CVSS V2 Base Score`, `Vuln Publication Date`, `Patch Publication Date`,
   `Plugin Publication Date`, `Plugin Modification Date`.
2. **Add `Age`** — computed in code as `Last Observed − First Discovered`, in whole days.
3. **Add `System Environment`** — derived from the scan file's name (a `PROD` file → `DMS-Prod`, a `TEST` file → `DMS-Test`).
4. **Add `Group`** — added as an empty column for now; its per-row value is assigned by a later (AI) categorization step.

### Data layout (gitignored — may contain sensitive scan data)
```
data/
├── raw/               # archive of every downloaded original
├── staging/           # validated files, ready for the next stage
├── processed/         # reshaped files (Step 2 output), ready for the tracker
├── quarantine/        # files that failed validation
└── processed_ids.txt  # Message-IDs already ingested
```

## Roadmap
- Fill the `Group` column with an AI categorization step.
- Wire `ingest.py` → `categorize.py` to run together (one after the other).
- Swap the Gmail/IMAP backend for **Microsoft Graph** (production GovCloud/Exchange inbox).
- Schedule the pipeline to run automatically (e.g. weekly) instead of by hand.

## Config (`.env`)
| Key | Meaning |
|-----|---------|
| `IMAP_HOST` / `IMAP_PORT` | Gmail IMAP server (`imap.gmail.com` / `993`) |
| `IMAP_USER` | the inbox address |
| `APP_PASSWORD` | 16-char Gmail app password |
| `TARGET_SUBJECT` | subject substring that identifies a scan email |
| `TARGET_SENDER` | optional sender filter (blank = any) |
