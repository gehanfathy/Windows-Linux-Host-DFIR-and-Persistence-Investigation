"""
One-command demo / pipeline runner for the Windows evidence chain.

    sample_data/windows  (or any collector output dir)
        -> parsers/windows/parser.py     -> NormalizedEvents  (JSONL)
        -> detection/windows/rules.py    -> Findings + IOCs   (JSON)
        -> [optional --push] POST everything into the FastAPI/SQLite app

Usage:
    python run_windows_demo.py                      # offline demo
    python run_windows_demo.py --input output/windows
    python run_windows_demo.py --push               # also load into the API
    python run_windows_demo.py --push --api-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from parsers.windows.parser import parse_directory  # noqa: E402
from detection.windows import rules  # noqa: E402


def post_json(api_url: str, path: str, payload: dict) -> tuple[bool, str]:
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}{path}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
            return True, str(response.status)
    except urllib.error.HTTPError as error:
        return False, f"HTTP {error.code}: {error.read().decode('utf-8', 'replace')[:120]}"
    except Exception as error:  # noqa: BLE001
        return False, str(error)


def main(argv: list[str] | None = None) -> int:
    arg_parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    arg_parser.add_argument("--input", default="sample_data/windows",
                            help="directory with raw Windows evidence "
                                 "(default: sample_data/windows)")
    arg_parser.add_argument("--out-dir", default="output/windows",
                            help="directory for pipeline output "
                                 "(default: output/windows)")
    arg_parser.add_argument("--case-id", default="case-000001",
                            help="case id used for all events/findings/iocs")
    arg_parser.add_argument("--push", action="store_true",
                            help="POST all events/findings/iocs into the "
                                 "FastAPI app (must be running)")
    arg_parser.add_argument("--api-url", default="http://127.0.0.1:8000",
                            help="API base URL for --push (default: "
                                 "http://127.0.0.1:8000)")
    args = arg_parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- Step 1: parse raw evidence -> NormalizedEvents -------------------
    events, warnings = parse_directory(args.input, case_id=args.case_id)
    events_path = out_dir / "events.jsonl"
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"[1/3] Parser    : {len(events)} NormalizedEvents "
          f"({len(warnings)} skipped) -> {events_path}")
    for warning in warnings[:10]:
        print(f"      WARNING   : {warning}")

    # ---- Step 2: detection rules -> findings + IOCs ------------------------
    findings, iocs = rules.run_detection(events, case_id=args.case_id)
    findings_path = out_dir / "findings.json"
    iocs_path = out_dir / "iocs.json"
    findings_path.write_text(
        json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")
    iocs_path.write_text(
        json.dumps(iocs, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[2/3] Detection : {len(findings)} findings, {len(iocs)} IOCs")
    for finding in findings:
        print(f"      {finding['rule_id']:<14} [{finding['severity']:^8}] "
              f"{finding['title']}  ({finding['evidence_reference']})")
    print(f"      findings -> {findings_path}")
    print(f"      iocs     -> {iocs_path}")

    # ---- Step 3: optional push into the API/DB -----------------------------
    if args.push:
        print(f"[3/3] Push      : sending to {args.api_url} ...")
        ok = fail = 0
        for event in events:
            success, detail = post_json(args.api_url, "/events", event)
            ok, fail = ok + success, fail + (not success)
        for finding in findings:
            success, detail = post_json(args.api_url, "/findings", finding)
            ok, fail = ok + success, fail + (not success)
        for ioc in iocs:
            success, detail = post_json(args.api_url, "/iocs", ioc)
            ok, fail = ok + success, fail + (not success)
        print(f"      pushed {ok} records OK, {fail} failed")
        if fail:
            print("      (hint: is the API running?  uvicorn app.api.main:app --reload)")
            return 1
    else:
        print("[3/3] Push      : skipped (use --push to load the API/DB)")

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
