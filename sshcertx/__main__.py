from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .engine import admit_object, inspect_object
from .load import load_json, load_store, save_store


def _parse_now(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        from datetime import datetime
        return int(
            datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sshcertx")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ins = sub.add_parser("inspect")
    p_ins.add_argument("--input", required=True)

    p_ad = sub.add_parser("admit")
    p_ad.add_argument("--input", required=True)
    p_ad.add_argument("--keys", required=True)
    p_ad.add_argument("--policy", required=True)
    p_ad.add_argument("--store", required=True)
    p_ad.add_argument("--now", default=None)
    p_ad.add_argument("--report", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "inspect":
        obj = load_json(args.input)
        print(json.dumps(inspect_object(obj), ensure_ascii=False, indent=2))
        return 0

    # Any load failure exits 2 and must not touch the store or report.
    try:
        obj = load_json(args.input)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_store(args.store)
        now = _parse_now(args.now)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"load failure: {exc}", file=sys.stderr)
        return 2
    try:
        report = admit_object(obj, keys, policy, store, now)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if report.get("decision") == "allow":
        save_store(args.store, store)
        return 0
    if report.get("decision") == "deny":
        return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
