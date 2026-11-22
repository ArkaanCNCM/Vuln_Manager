"""
Step 2 -- CATEGORIZATION (part 1: column surgery).

Takes the validated scan file produced by Step 1 (ingest.py) and reshapes it:

DROP     = remove columns the tracker does not need
           (Risk Factor, CVSS V2 Base Score, and the four *Publication/Modification
            Date* columns).
ADD      = add an "Age" column, computed in code as
           (Last Observed - First Discovered) in whole days;
           add "System Environment", derived from the scan file's name
           (a PROD file -> "DMS-Prod", a TEST file -> "DMS-Test");
           add "Group" as an empty placeholder -- its value is decided per-row
           by a later (AI) categorization step.

Input : the newest file in data/staging/ (written by ingest.py).
Output: a reshaped .xlsx in data/processed/ with the same file name.
"""
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook, load_workbook

ROOT = Path(__file__).resolve().parent.parent  # the VulnManager/ folder
DATA_DIR = ROOT / "data"
STAGING_DIR = DATA_DIR / "staging"  # validated files from Step 1
PROCESSED_DIR = DATA_DIR / "processed"  # reshaped files land here

SHEET = "Nessus Scan Data"

# Columns to drop from the scan file.
DROP_COLUMNS = [
    "Risk Factor",
    "CVSS V2 Base Score",
    "Vuln Publication Date",
    "Patch Publication Date",
    "Plugin Publication Date",
    "Plugin Modification Date",
]

# New columns we add. "Age" is computed below; the other two start empty and
# are filled by a later categorization step.
NEW_COLUMNS = ["Age", "System Environment", "Group"]

# The dates in the scan look like: "Feb 24, 2025 19:35:59 UTC".
DATE_FORMAT = "%b %d, %Y %H:%M:%S UTC"

# System Environment is decided by the scan file's name: a weekly export is for a
# single environment, so the whole column gets one value.
ENVIRONMENT_FROM_FILENAME = [
    ("PROD", "DMS-Prod"),
    ("TEST", "DMS-Test"),
]


def latest_staged_file(folder=STAGING_DIR):
    """Return the most recently modified .xlsx in the staging folder, or None."""
    files = sorted(folder.glob("*.xlsx"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def parse_date(value):
    """Turn a scan date string into a datetime, or None if it cannot be parsed."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), DATE_FORMAT)
    except ValueError:
        return None


def detect_environment(filename):
    """
    Work out the System Environment from the scan file's name.

    e.g. "...DMS PROD Tenable Scan_Data.xlsx" -> "DMS-Prod".
    Returns "" if the name does not say PROD or TEST (so the cell is left blank
    rather than guessed).
    """
    upper = filename.upper()
    for marker, value in ENVIRONMENT_FROM_FILENAME:
        if marker in upper:
            return value
    return ""


def compute_age_days(first_discovered, last_observed):
    """
    Age = Last Observed - First Discovered, in whole days.

    Returns an int, or "" when either date is missing/unreadable so the cell
    is simply left blank instead of guessing.
    """
    fd = parse_date(first_discovered)
    lo = parse_date(last_observed)
    if fd is None or lo is None:
        return ""
    return (lo - fd).days


def transform(src_path):
    """
    Read the staged scan file, drop unwanted columns, add the new columns, and
    write the result to data/processed/ under the same file name.

    Returns the output Path.
    """
    wb_in = load_workbook(src_path, read_only=True)
    ws_in = wb_in[SHEET]

    rows = ws_in.iter_rows(values_only=True)
    headers = list(next(rows))  # first row is the header

    # Which original columns do we keep, and in what positions?
    keep_index = [i for i, h in enumerate(headers) if h not in DROP_COLUMNS]
    kept_headers = [headers[i] for i in keep_index]

    # We need First Discovered / Last Observed to compute Age.
    fd_i = headers.index("First Discovered")
    lo_i = headers.index("Last Observed")

    # Same environment for every row in this file (decided by the file name).
    environment = detect_environment(src_path.name)

    wb_out = Workbook()
    ws_out = wb_out.active
    ws_out.title = SHEET
    ws_out.append(kept_headers + NEW_COLUMNS)  # header row

    for row in rows:
        kept = [row[i] for i in keep_index]
        age = compute_age_days(row[fd_i], row[lo_i])
        # Group is blank for now -- filled per-row by a later (AI) step.
        ws_out.append(kept + [age, environment, ""])

    wb_in.close()

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_DIR / src_path.name
    wb_out.save(out_path)
    return out_path


def main():
    src = latest_staged_file()
    if src is None:
        print("No staged file found in data/staging/ -- run ingest.py first.")
        return

    print(f"Reshaping staged file: {src.name}")
    out = transform(src)

    # Show a quick before/after so the change is easy to see.
    wb = load_workbook(out, read_only=True)
    ws = wb[SHEET]
    headers = list(next(ws.iter_rows(min_row=1, max_row=1, values_only=True)))
    sample = next(ws.iter_rows(min_row=2, max_row=2, values_only=True), None)
    wb.close()

    print()
    print(f"DROPPED {len(DROP_COLUMNS)} columns: {', '.join(DROP_COLUMNS)}")
    print(f"ADDED   {len(NEW_COLUMNS)} columns: {', '.join(NEW_COLUMNS)}")
    print()
    print(f"New column list ({len(headers)}): {headers}")
    if sample is not None:
        age = sample[headers.index("Age")]
        env = sample[headers.index("System Environment")]
        print(f"Example row 1 -> Age: {age} days | System Environment: {env!r}")
    print()
    print(f"Saved -> {out}")


if __name__ == "__main__":
    main()
