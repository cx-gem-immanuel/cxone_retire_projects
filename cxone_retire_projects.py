"""
cxone_retire_projects.py
========================
For each project supplied via --projects or --csv, this script:

  1. Resolves the project name -> project ID
  2. Fetches the latest completed scan for that project
  3. Submits a PDF report (all severities, all states, all scanners)
  4. Polls until the report is completed
  5. Downloads the PDF, saving it as <project_name>.pdf
  6. Validates the PDF (non-empty, starts with the %PDF magic bytes)
  7. Deletes the CxOne project ONLY when the PDF has been validated

Projects are processed in parallel batches (--batch-size, default 5).

Resumable execution via a control folder (--control, default .control):
  - "reported.txt" — project names appended after PDF is validated.
    On subsequent runs, report generation is skipped for those projects.
  - "deleted.txt"  — project names appended after successful deletion.
    On subsequent runs, those projects are skipped entirely.

Usage examples
--------------
  python cxone_retire_projects.py --projects "proj-alpha,proj-beta"
  python cxone_retire_projects.py --csv projects.csv
  python cxone_retire_projects.py --csv projects.csv \\
      --output-dir ./reports \\
      --control   ./.control \\
      --batch-size 10 \\
      --poll-interval 10 \\
      --poll-timeout 600 \\
      --insecure \\
      --delete
"""

import argparse
import configparser
import csv
import io
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from cxsupport import CxOneClient
from logsupport import TRACE, setup_logger, add_file_handler

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PDF_MIN_BYTES         = 1024   # minimum valid PDF size in bytes
DEFAULT_POLL_INTERVAL = 15     # seconds between report-status polls
DEFAULT_POLL_TIMEOUT  = 300    # maximum seconds to wait for a report
DEFAULT_BATCH_SIZE    = 5      # projects processed in parallel
DEFAULT_CONTROL_DIR   = ".control"

# Control files written into --control dir
_FILE_REPORTED = "reported.txt"
_FILE_DELETED  = "deleted.txt"
_FILE_TIMEOUT  = "report_timeout.csv"   # project_name,report_id

logger = setup_logger(file_logging=False)


# ---------------------------------------------------------------------------
# Status codes
#
# Returned by process_project as the second element of its (bool, str) tuple.
#
# Success codes (ok=True):
#   OK             – PDF downloaded and validated this run
#   SKIP_GENERATED – PDF already generated in a prior run; not deleted
#   DELETED        – project deleted this run (after PDF validated or no scan)
#   SKIP_DELETED   – project was already deleted in a prior run
#   NO_SCAN_FOUND        – project exists but has no completed scan; nothing to report
#
# Failure codes (ok=False):
#   PROJECT_NOT_FOUND – project name not found in CxOne
#   REPORT_REQUEST_ERROR         – report submission returned no reportId
#   REPORT_TIMEOUT       – report did not complete within --poll-timeout seconds
#   REPORT_GENERATION_FAILED        – report reached a terminal 'failed' status during polling
#   REPORT_DOWNLOAD_FAILED           – PDF download HTTP call failed
#   REPORT_PDF_INVALID       – downloaded file failed PDF validation (too small / bad magic)
#   PROJECT_DELETE_FAILED          – project deletion API call failed
#   UNEXPECTED_ERROR        – unhandled exception (full stack trace in log file)
# ---------------------------------------------------------------------------

OK             = "OK"
SKIP_GENERATED = "SKIP_GENERATED"
DELETED        = "DELETED"
SKIP_DELETED   = "SKIP_DELETED"
NOT_FOUND      = "PROJECT_NOT_FOUND"
NO_SCAN_FOUND        = "NO_SCAN_FOUND"
REPORT_REQUEST_ERROR      = "REPORT_REQUEST_ERROR"
REPORT_TIMEOUT    = "REPORT_TIMEOUT"
REPORT_GENERATION_FAILED     = "REPORT_GENERATION_FAILED"
REPORT_DOWNLOAD_FAILED        = "REPORT_DOWNLOAD_FAILED"
REPORT_PDF_INVALID    = "REPORT_PDF_INVALID"
PROJECT_DELETE_FAILED       = "PROJECT_DELETE_FAILED"
UNEXPECTED_ERROR     = "UNEXPECTED_ERROR"


# ---------------------------------------------------------------------------
# Windows console UTF-8 fix
# ---------------------------------------------------------------------------

def _fix_console_encoding() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name)
        if getattr(stream, "encoding", "utf-8").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except AttributeError:
                setattr(
                    sys, stream_name,
                    io.TextIOWrapper(
                        stream.buffer,
                        encoding="utf-8",
                        errors="replace",
                        line_buffering=stream.line_buffering,
                    ),
                )


_fix_console_encoding()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_WIDTH = 62


def _banner_line(label: str, value: str) -> str:
    return f"  {label:<20} {value}"


def _print_banner(args: argparse.Namespace, iam: str, ast_host: str,
                  ten: str, projects: list[str], log_file: Path) -> None:
    sep = "=" * _BANNER_WIDTH
    logger.info(sep)
    logger.info("  CxOne Project Retirement Tool")
    logger.info("  Generate PDF reports and optionally retire projects")
    logger.info(sep)
    logger.info(_banner_line("Tenant:",        ten))
    logger.info(_banner_line("AST host:",      ast_host))
    logger.info(_banner_line("IAM host:",      iam))
    logger.info(_banner_line("Config:",        str(Path(args.config).resolve())))
    logger.info(_banner_line("Output dir:",    str(Path(args.output_dir).resolve())))
    logger.info(_banner_line("Control dir:",   str(Path(args.control).resolve())))
    logger.info(_banner_line("Log file:",      str(log_file.resolve())))
    logger.info(_banner_line("Batch size:",    str(args.batch_size)))
    logger.info(_banner_line("Poll interval:", f"{args.poll_interval}s"))
    logger.info(_banner_line("Poll timeout:",  f"{args.poll_timeout}s"))
    logger.info(_banner_line("TLS verify:",    "NO (--insecure)" if args.insecure else "yes"))
    logger.info(_banner_line("Delete mode:",   "YES (--delete)" if args.delete else "no"))
    src = f"--csv {args.csv}" if args.csv else f"--projects ({len(projects)} project(s))"
    logger.info(_banner_line("Source:",        src))
    logger.info(sep)


# ---------------------------------------------------------------------------
# Control file helpers
#
# _control_lock guards both the in-memory set mutation and the file append
# together, making the check-then-write sequence atomic across threads.
# ---------------------------------------------------------------------------

_control_lock = threading.Lock()


def load_control_set(control_dir: Path, filename: str) -> set[str]:
    """Read a control file and return the set of project names it contains."""
    path = control_dir / filename
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as fh:
        return {line.strip() for line in fh if line.strip()}


def _append_control(control_dir: Path, filename: str,
                    project_name: str, live_set: set[str]) -> None:
    """
    Append *project_name* to a control file and add it to *live_set*.
    Both operations are performed under *_control_lock* so that concurrent
    threads cannot race through the guard → write sequence.
    The control directory is guaranteed to exist before this is called.
    """
    with _control_lock:
        live_set.add(project_name)
        with open(control_dir / filename, "a", encoding="utf-8") as fh:
            fh.write(project_name + "\n")


def load_timeout_map(control_dir: Path) -> dict[str, str]:
    """
    Read report_timeout.csv and return a dict of {project_name: report_id}.
    Each line is: project_name,report_id
    """
    path = control_dir / _FILE_TIMEOUT
    result: dict[str, str] = {}
    if not path.exists():
        return result
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) >= 2:
                name, report_id = row[0].strip(), row[1].strip()
                if name and report_id:
                    result[name] = report_id
    return result


def _append_timeout(control_dir: Path, project_name: str,
                    report_id: str, live_map: dict[str, str]) -> None:
    """
    Append a project_name,report_id entry to report_timeout.csv (thread-safe).
    Updates *live_map* in-memory at the same time.
    """
    with _control_lock:
        live_map[project_name] = report_id
        with open(control_dir / _FILE_TIMEOUT, "a", newline="",
                  encoding="utf-8") as fh:
            csv.writer(fh).writerow([project_name, report_id])


def _remove_timeout(control_dir: Path, project_name: str,
                    live_map: dict[str, str]) -> None:
    """
    Remove *project_name* from the timeout control file and *live_map*.
    Rewrites the file in-place under the lock.
    """
    with _control_lock:
        live_map.pop(project_name, None)
        path = control_dir / _FILE_TIMEOUT
        if not path.exists():
            return
        with open(path, newline="", encoding="utf-8") as fh:
            rows = [r for r in csv.reader(fh)
                    if len(r) >= 2 and r[0].strip() != project_name]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(rows)


# ---------------------------------------------------------------------------
# PDF validation
# ---------------------------------------------------------------------------

def validate_pdf(path: Path) -> bool:
    if not path.exists():
        logger.error("Validation failed: '%s' does not exist.", path)
        return False

    size = path.stat().st_size
    logger.debug("Validating PDF '%s' (%d bytes).", path, size)

    if size < PDF_MIN_BYTES:
        logger.error(
            "Validation failed: '%s' is only %d bytes (minimum expected: %d).",
            path, size, PDF_MIN_BYTES,
        )
        return False

    with open(path, "rb") as fh:
        header = fh.read(8)

    logger.trace("PDF header bytes: %s", header)   # type: ignore[attr-defined]

    if not header.startswith(b"%PDF"):
        logger.error(
            "Validation failed: '%s' does not begin with %%PDF magic bytes "
            "(got %r).", path, header,
        )
        return False

    logger.debug("PDF '%s' validated OK (%d bytes).", path, size)
    return True


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def _fmt(seconds: float) -> str:
    """Format a duration as Xm Ys or Xs."""
    if seconds >= 60:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s:02d}s"
    return f"{seconds:.1f}s"


# ---------------------------------------------------------------------------
# Per-project pipeline
# ---------------------------------------------------------------------------

def process_project(
    client:        CxOneClient,
    project_name:  str,
    project_id:    str | None,
    output_dir:    Path,
    control_dir:   Path,
    reported_set:  set[str],
    deleted_set:   set[str],
    timeout_map:   dict[str, str],
    poll_interval: int,
    poll_timeout:  int,
    delete:        bool,
) -> tuple[bool, str]:
    """
    Full pipeline for one project: report → download → (delete).
    Returns (success: bool, status_code: str).

    Thread safety: guard checks and control-file writes are performed under
    _control_lock so that concurrent threads cannot double-process a project.
    """
    logger.debug("Project: '%s'", project_name)

    # ── Guard: already deleted ───────────────────────────────────────
    with _control_lock:
        if project_name in deleted_set:
            logger.debug("  [SKIP] Already deleted (found in deleted.txt).")
            return True, SKIP_DELETED

    # ── Guard: already reported — skip straight to delete if needed ──
    with _control_lock:
        already_reported = project_name in reported_set

    if already_reported:
        logger.debug("  [SKIP] Report already generated (found in reported.txt).")
        if not delete:
            return True, SKIP_GENERATED
        # Fall through to deletion — project_id still needed below
    else:
        # ── 1. Confirm project was resolved ──────────────────────────
        if not project_id:
            logger.debug("  Project not found in CxOne.")
            return False, NOT_FOUND

        logger.debug("  Project ID : %s", project_id)

        # ── 2. Get latest scan ID ────────────────────────────────────
        scan_id = client.get_latest_scan_id(project_id)
        if not scan_id:
            logger.debug("  No completed scan found; skipping report generation.")
            if not delete:
                return True, NO_SCAN_FOUND
            # No report to generate — delete directly
            if not client.delete_project(project_id):
                logger.debug("  Project deletion failed (no-scan path).")
                return False, PROJECT_DELETE_FAILED
            _append_control(control_dir, _FILE_DELETED, project_name, deleted_set)
            logger.debug("  Deleted (no scan).")
            return True, DELETED

        logger.debug("  Scan ID    : %s", scan_id)

        # ── 3. Resume from prior timeout if applicable ────────────────
        # If a previous run timed out on this project, a report may already
        # be ready on the server. Try to check status and download it first
        # before submitting a brand-new request.
        with _control_lock:
            prior_report_id = timeout_map.get(project_name)

        report_id: str | None = None

        if prior_report_id:
            logger.debug(
                "  Prior timeout found (report_id: %s); checking status …",
                prior_report_id,
            )
            ready = client.poll_report_status(
                prior_report_id, interval=poll_interval, timeout=poll_interval
            )
            if ready:
                logger.debug("  Prior report is ready; attempting download.")
                safe_name = _safe_filename(project_name)
                pdf_path  = output_dir / f"{safe_name}.pdf"
                if client.download_report(prior_report_id, str(pdf_path)) \
                        and validate_pdf(pdf_path):
                    logger.debug("  Resumed from prior report successfully.")
                    _remove_timeout(control_dir, project_name, timeout_map)
                    _append_control(control_dir, _FILE_REPORTED,
                                    project_name, reported_set)
                    # Jump straight to deletion step
                    if not delete:
                        return True, OK
                    if not client.delete_project(project_id):
                        return False, PROJECT_DELETE_FAILED
                    _append_control(control_dir, _FILE_DELETED,
                                    project_name, deleted_set)
                    return True, DELETED
                else:
                    logger.debug(
                        "  Prior report download/validation failed; "
                        "submitting a new request."
                    )
            else:
                logger.debug(
                    "  Prior report not yet ready or failed; "
                    "submitting a new request."
                )
            # Remove the stale timeout entry before re-requesting
            _remove_timeout(control_dir, project_name, timeout_map)

        # ── 4. Create report ─────────────────────────────────────────
        report_id = client.create_report(scan_id, project_id)
        if not report_id:
            logger.debug("  Report submission returned no reportId.")
            return False, REPORT_REQUEST_ERROR

        logger.debug("  Report requested (id: %s)", report_id)

        # ── 5. Poll until completed ──────────────────────────────────
        ready = client.poll_report_status(
            report_id, interval=poll_interval, timeout=poll_timeout
        )
        if not ready:
            logger.debug("  Report did not complete within %ds.", poll_timeout)
            _append_timeout(control_dir, project_name, report_id, timeout_map)
            logger.debug("  Written to report_timeout.csv (id: %s).", report_id)
            return False, REPORT_TIMEOUT

        logger.debug("  Report : completed")

        # ── 6. Download PDF ──────────────────────────────────────────
        safe_name = _safe_filename(project_name)
        pdf_path  = output_dir / f"{safe_name}.pdf"

        if not client.download_report(report_id, str(pdf_path)):
            logger.debug("  PDF download failed.")
            return False, REPORT_DOWNLOAD_FAILED

        logger.debug("  PDF : %s", pdf_path)

        # ── 7. Validate PDF ──────────────────────────────────────────
        if not validate_pdf(pdf_path):
            logger.debug("  PDF validation failed; project will NOT be deleted.")
            return False, REPORT_PDF_INVALID

        logger.debug("  Report received (%d bytes, %s)",
                     pdf_path.stat().st_size, pdf_path.name)

        # ── Record in reported.txt (atomic: lock covers set + file) ──
        _append_control(control_dir, _FILE_REPORTED, project_name, reported_set)
        logger.debug("  Control : appended to reported.txt")

    # ── 7. Delete project (only when --delete flag is set) ───────────
    if not delete:
        return True, OK

    if not project_id:
        # Can only happen in the already_reported + delete resume path
        # if the project was deleted externally between runs.
        logger.debug("  Cannot delete: project ID not available.")
        return False, PROJECT_DELETE_FAILED

    if not client.delete_project(project_id):
        logger.debug("  Project deletion failed.")
        return False, PROJECT_DELETE_FAILED

    _append_control(control_dir, _FILE_DELETED, project_name, deleted_set)
    logger.debug("  Project deleted.")
    return True, DELETED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_filename(name: str) -> str:
    """Replace characters illegal in most filesystems with underscores."""
    keep = frozenset("abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "0123456789-_.()")
    return "".join(c if c in keep else "_" for c in name)


def load_projects_from_csv(csv_path: str) -> list[str]:
    """
    Read project names from *csv_path*.
    Accepts one project name per line, or a CSV where the first column holds
    project names. Header row skipped when first cell is 'project',
    'project_name', 'projectname', or 'name' (case-insensitive).
    Raises SystemExit on file-not-found or read errors.
    """
    try:
        projects = []
        with open(csv_path, newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            for i, row in enumerate(reader):
                if not row:
                    continue
                name = row[0].strip()
                if i == 0 and name.lower() in ("project", "project_name",
                                               "projectname", "name"):
                    logger.debug("CSV header row detected and skipped: %s", row)
                    continue
                if name:
                    projects.append(name)
    except FileNotFoundError:
        logger.error("CSV file not found: '%s'", csv_path)
        sys.exit(1)
    except OSError as exc:
        logger.error("Failed to read CSV file '%s': %s", csv_path, exc)
        sys.exit(1)

    logger.debug("Loaded %d project name(s) from '%s'.", len(projects), csv_path)
    return projects


def _dedup_ordered(items: list[str]) -> list[str]:
    """Return *items* with duplicates removed, preserving first-occurrence order."""
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _chunked(lst: list, size: int):
    """Yield successive chunks of *size* from *lst*."""
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download CxOne PDF reports and (optionally) retire projects.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--projects", metavar="NAME[,NAME...]",
                     help="Comma-separated list of CxOne project names.")
    src.add_argument("--csv", metavar="FILE",
                     help="Path to a CSV file containing project names (first column).")

    parser.add_argument("--config",        default="config.ini",
                        help="Path to config.ini with [CXONE] section.")
    parser.add_argument("--output-dir",    default="./reports",         metavar="DIR",
                        help="Directory to save downloaded PDF reports.")
    parser.add_argument("--control",       default=DEFAULT_CONTROL_DIR, metavar="DIR",
                        help="Directory for control files (reported.txt / deleted.txt).")
    parser.add_argument("--log-dir",       default="./logs",            metavar="DIR",
                        help="Directory to write the execution log file.")
    parser.add_argument("--batch-size",    type=int, default=DEFAULT_BATCH_SIZE,    metavar="N",
                        help="Number of projects to process in parallel.")
    parser.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL, metavar="SECS",
                        help="Seconds between report-status polls.")
    parser.add_argument("--poll-timeout",  type=int, default=DEFAULT_POLL_TIMEOUT,  metavar="SECS",
                        help="Maximum seconds to wait for a report to complete.")
    parser.add_argument("--insecure",      action="store_true",
                        help="Disable TLS certificate verification.")
    parser.add_argument("--delete",        action="store_true",
                        help="Delete each project after its PDF is validated.")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # ── File logging ─────────────────────────────────────────────────
    log_dir  = Path(args.log_dir)
    run_ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"cx_retire_{run_ts}.log"
    add_file_handler(str(log_file))

    # ── Config ───────────────────────────────────────────────────────
    config = configparser.ConfigParser()
    if not config.read(args.config):
        logger.error("Cannot read config file: '%s'", args.config)
        sys.exit(1)

    try:
        cx  = config["CXONE"]
        iam = cx["iam_host"]
        ast = cx["ast_host"]
        ten = cx["tenant"]
        key = cx["api_key"]
    except KeyError as exc:
        logger.error("Missing [CXONE] config key: %s", exc)
        sys.exit(1)

    # ── Project list ─────────────────────────────────────────────────
    if args.projects:
        raw = [p.strip() for p in args.projects.split(",") if p.strip()]
    else:
        raw = load_projects_from_csv(args.csv)

    projects = _dedup_ordered(raw)
    dupes    = len(raw) - len(projects)
    if dupes:
        logger.warning("%d duplicate project name(s) removed from input.", dupes)

    if not projects:
        logger.error("No project names found. Exiting.")
        sys.exit(1)

    # ── Directories ──────────────────────────────────────────────────
    output_dir  = Path(args.output_dir)
    control_dir = Path(args.control)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        control_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Failed to create required directory: %s", exc)
        sys.exit(1)

    _print_banner(args, iam, ast, ten, projects, log_file)

    # ── Load control sets once at startup ────────────────────────────
    reported_set = load_control_set(control_dir, _FILE_REPORTED)
    deleted_set  = load_control_set(control_dir, _FILE_DELETED)
    timeout_map  = load_timeout_map(control_dir)
    if timeout_map:
        logger.info("  Resuming: %d project(s) with prior timeout — "
                    "will attempt status check before re-requesting.",
                    len(timeout_map))

    # ── Client ───────────────────────────────────────────────────────
    client = CxOneClient(iam, ast, ten, key, False, not args.insecure)

    # ── Pre-filter: classify every project before batching ────────────
    # Projects already fully handled are recorded directly into results
    # so they appear in the summary without consuming any worker slots,
    # API calls, or batch output lines.
    results:  dict[str, tuple[bool, str]] = {}
    pending:  list[str] = []

    for name in projects:
        if name in deleted_set:
            results[name] = (True, SKIP_DELETED)
        elif name in reported_set and not args.delete:
            results[name] = (True, SKIP_GENERATED)
        else:
            pending.append(name)

    n_skip_deleted   = sum(1 for _, c in results.values() if c == SKIP_DELETED)
    n_skip_generated = sum(1 for _, c in results.values() if c == SKIP_GENERATED)
    if n_skip_deleted:
        logger.info("  Skipping %d project(s) already deleted.", n_skip_deleted)
    if n_skip_generated:
        logger.info("  Skipping %d project(s) already reported (report-only mode).",
                    n_skip_generated)
    if not pending:
        logger.info("  Nothing left to process.")
    else:
        logger.info("  %d project(s) queued for processing.", len(pending))

    # ── Parallel batch processing ─────────────────────────────────────
    batch_times: list[float] = []

    total       = len(pending)
    batch_size  = max(1, args.batch_size)
    num_batches = -(-total // batch_size) if total else 0  # ceiling division

    overall_start = time.monotonic()

    for batch_num, batch in enumerate(_chunked(pending, batch_size), start=1):
        batch_end   = min(batch_num * batch_size, total)
        batch_start = batch_end - len(batch) + 1
        batch_t0    = time.monotonic()

        # Resolve all project IDs for this batch in one API call.
        # reported_set projects included here only when --delete is set
        # (they skipped report generation but still need an ID to delete).
        needs_resolve = [
            n for n in batch
            if n not in reported_set or args.delete
        ]
        if needs_resolve:
            batch_id_map = client.get_project_ids_for_batch(needs_resolve)
            logger.debug(
                "Batch %d: resolved %d / %d project ID(s) via name-regex.",
                batch_num, len(batch_id_map), len(needs_resolve),
            )
        else:
            batch_id_map = {}

        with ThreadPoolExecutor(max_workers=batch_size) as pool:
            future_to_name = {
                pool.submit(
                    process_project,
                    client, name, batch_id_map.get(name),
                    output_dir, control_dir,
                    reported_set, deleted_set, timeout_map,
                    args.poll_interval, args.poll_timeout, args.delete,
                ): name
                for name in batch
            }
            batch_results: dict[str, tuple[bool, str]] = {}
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    batch_results[name] = future.result()
                except Exception as exc:        # pylint: disable=broad-except
                    logger.exception("Unexpected error processing '%s': %s", name, exc)
                    batch_results[name] = (False, UNEXPECTED_ERROR)

        batch_elapsed = time.monotonic() - batch_t0
        batch_times.append(batch_elapsed)

        # Print one line per project serially, in original input order
        logger.info("=" * _BANNER_WIDTH)
        logger.info("  Batch %d / %d  —  projects %d-%d of %d  (%s)",
                    batch_num, num_batches,
                    batch_start, batch_end, total,
                    _fmt(batch_elapsed))
        for name in batch:
            ok, code = batch_results[name]
            if ok:
                detail = "REPORT_GENERATED, PROJECT_DELETED" if code == DELETED else code
                if code == OK:
                    detail = "REPORT_GENERATED"
                logger.info("  [OK]    %-45s  %s", name, detail)
            else:
                logger.info("  [FAIL]  %-45s  %s", name, code)
        results.update(batch_results)

    # ── Timing stats ─────────────────────────────────────────────────
    overall_elapsed = time.monotonic() - overall_start
    avg_batch       = sum(batch_times) / len(batch_times) if batch_times else 0.0
    avg_project     = overall_elapsed / total if total else 0.0

    # ── Summary ───────────────────────────────────────────────────────
    grand_total = len(projects)
    success     = sum(1 for ok, _ in results.values() if ok)
    failed      = grand_total - success

    # Map internal codes to display strings for the status breakdown
    status_counts: Counter = Counter()
    for ok, code in results.values():
        if ok and code == DELETED:
            status_counts["REPORT_GENERATED, PROJECT_DELETED"] += 1
        elif ok and code == OK:
            status_counts["REPORT_GENERATED"] += 1
        else:
            status_counts[code] += 1

    sep = "=" * _BANNER_WIDTH
    logger.info(sep)
    logger.info("  SUMMARY: %d / %d project(s) completed successfully.", success, grand_total)
    logger.info(sep)

    if failed:
        logger.info("  Failed (%d):", failed)
        for name, (ok, code) in results.items():
            if not ok:
                logger.info("    [FAIL]  %-45s  %s", name, code)

    if success:
        logger.info("  Succeeded (%d):", success)
        for name, (ok, _) in results.items():
            if ok:
                logger.info("    [OK]    %s", name)

    logger.info(sep)
    logger.info("  Status Breakdown")
    for code in (
        "REPORT_GENERATED", "REPORT_GENERATED, PROJECT_DELETED",
        SKIP_GENERATED, SKIP_DELETED, NO_SCAN_FOUND,
        NOT_FOUND, REPORT_REQUEST_ERROR,
        REPORT_TIMEOUT, REPORT_GENERATION_FAILED,
        REPORT_DOWNLOAD_FAILED, REPORT_PDF_INVALID, PROJECT_DELETE_FAILED, UNEXPECTED_ERROR,
    ):
        count = status_counts.get(code, 0)
        if count:
            logger.info("    %-40s  %d", code, count)

    logger.info(sep)
    logger.info("  Execution Duration Summary")
    logger.info(_banner_line("  Overall:",         _fmt(overall_elapsed)))
    logger.info(_banner_line("  Avg per batch:",   _fmt(avg_batch)))
    logger.info(_banner_line("  Avg per project:", _fmt(avg_project)))
    logger.info(sep)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
