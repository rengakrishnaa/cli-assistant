"""Command-line interface: parse arguments, call the pipeline, format output. No business logic."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .config import Paths, SettingsError, data_dir, ensure_private_dir, load_settings, write_default_settings
from .crypto import Cipher, KeyManager, KeyUnavailable
from .ingest import EventFileError
from .models import Memory, Sensitivity, iso
from .pipeline import Pipeline
from .redactor import redact_text
from .safe_log import get_logger

log = get_logger()
HIDDEN_BY_DEFAULT = {Sensitivity.SECRET, Sensitivity.PERSONAL}
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


# ---------- helpers ----------
def _paths(args) -> Paths:
    return Paths(Path(args.home).expanduser()) if args.home else Paths(data_dir())


def _open(args) -> Pipeline:
    paths = _paths(args)
    if not paths.root.exists():
        raise SettingsError("no data directory yet; run `local-ai init` first")
    settings = load_settings(Path(args.settings) if args.settings else paths.settings)
    return Pipeline(paths, settings, Cipher(KeyManager().load()))


def _view(memory: Memory, reveal: bool) -> dict:
    data = memory.to_dict()
    if memory.sensitivity in HIDDEN_BY_DEFAULT and not reveal:
        data["summary"] = f"[hidden: {memory.sensitivity.label} memory; add --reveal to show]"
    return data


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _duration(text: str) -> timedelta:
    match = _DURATION.match(text.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError("use a duration like 30m, 2h or 7d")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _instant(text: str) -> int:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError("use ISO-8601, e.g. 2026-05-19T10:00:00Z") from None
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("include a timezone, e.g. Z or +05:30")
    return int(moment.timestamp())


# ---------- commands ----------
def cmd_init(args) -> int:
    paths = _paths(args)
    ensure_private_dir(paths.root)
    key_location = KeyManager().create()
    created = write_default_settings(paths.settings)
    Pipeline(paths, load_settings(paths.settings), Cipher(KeyManager().load())).close()
    print(f"data directory : {paths.root}")
    print(f"master key     : {key_location}")
    state = "created with cloud AI disabled" if created else "existing file kept"
    print(f"settings       : {paths.settings} ({state})")
    return 0


def cmd_ingest(args) -> int:
    with _open(args) as pipe:
        report = pipe.ingest_file(Path(args.file))
    if args.json:
        _print_json(report.to_dict())
        return 0
    print(f"received {report.received} | stored {report.stored} | duplicates {report.duplicates} "
          f"| dropped by capture policy {report.dropped} | invalid {report.invalid}")
    for row in report.events:
        flags = f"  flags={','.join(row['flags'])}" if row["flags"] else ""
        print(f"  {row['event_id'][:8]}  {row['type']:<17}{row['sensitivity']:<13}"
              f"extract -> {row['route']}{flags}")
    return 0


def cmd_search(args) -> int:
    with _open(args) as pipe:
        hits, decision = pipe.search(args.query, limit=args.limit, prefer=args.prefer)
    if args.json:
        _print_json({"results": [dict(_view(m, args.reveal), score=round(s, 3)) for m, s in hits],
                     "routing": decision.to_dict()})
        return 0
    if not hits:
        print("no matching memories")
    for rank, (memory, score) in enumerate(hits, start=1):
        view = _view(memory, args.reveal)
        print(f"{rank}. [{view['sensitivity']}] {view['timestamp']}  id={memory.id[:8]}  score={score:.2f}")
        print(f"   {view['summary']}")
        for label in ("people", "projects", "topics"):
            if view[label]:
                print(f"   {label}: {', '.join(view[label])}")
    print("\nrouting verdict for answering from these memories:")
    _print_json(decision.to_dict())
    return 0


def cmd_inspect(args) -> int:
    with _open(args) as pipe:
        memory = pipe.memories.get(args.memory_id)
    if memory is None:
        print("no memory with that id", file=sys.stderr)
        return 1
    _print_json(_view(memory, args.reveal))
    return 0


def cmd_route(args) -> int:
    with _open(args) as pipe:
        if args.memory:
            decision = pipe.route_memory(args.memory, prefer=args.prefer)
        else:
            decision = pipe.route_text(sys.stdin.read(), prefer=args.prefer)
    _print_json(decision.to_dict())
    return 0


def cmd_forget(args) -> int:
    now = int(datetime.now(timezone.utc).timestamp())
    if args.last is not None:
        start, end = now - int(args.last.total_seconds()), now
    else:
        start, end = args.since, args.until if args.until is not None else now
    with _open(args) as pipe:
        memories, raw = pipe.forget_range(start, end, by=args.by)
    print(f"forgot {memories} memories and {raw} raw events ({args.by} time {iso(start)} .. {iso(end)})")
    return 0


def cmd_wipe(args) -> int:
    paths = _paths(args)
    if not args.yes:
        if input("Type 'wipe' to delete all local-ai data and destroy its key: ").strip() != "wipe":
            print("aborted")
            return 1
    key_status = KeyManager().destroy()  # crypto-shred first, then delete files
    if paths.root.exists():
        shutil.rmtree(paths.root)
    print(f"{key_status}; removed {paths.root}")
    return 0


def cmd_stats(args) -> int:
    with _open(args) as pipe:
        _print_json(pipe.stats())
    return 0


# ---------- parser ----------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", help="data directory (default: per-OS user data dir or $LOCAL_AI_HOME)")
    common.add_argument("--settings", help="settings.json to use (default: <home>/settings.json)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    parser = argparse.ArgumentParser(prog="local-ai", description="Privacy-first local memory assistant")
    parser.add_argument("--version", action="version", version=f"local-ai {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", parents=[common], help="create data dir, master key and default settings")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("ingest", parents=[common], help="ingest a JSON array of events")
    p.add_argument("file")
    p.set_defaults(func=cmd_ingest)
    p = sub.add_parser("search", parents=[common], help="search memories")
    p.add_argument("query")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--prefer", choices=("auto", "local", "cloud"), default="auto")
    p.add_argument("--reveal", action="store_true", help="show personal/secret summaries (still redacted)")
    p.set_defaults(func=cmd_search)
    p = sub.add_parser("inspect", parents=[common], help="show one memory and its classification")
    p.add_argument("memory_id")
    p.add_argument("--reveal", action="store_true")
    p.set_defaults(func=cmd_inspect)
    p = sub.add_parser("route", parents=[common], help="routing verdict for a memory or for text on stdin")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--memory", metavar="ID")
    target.add_argument("--stdin", action="store_true", help="read text from stdin (stays out of shell history)")
    p.add_argument("--prefer", choices=("auto", "local", "cloud"), default="auto")
    p.set_defaults(func=cmd_route)
    p = sub.add_parser("forget", parents=[common], help="delete raw events and memories in a time range")
    window = p.add_mutually_exclusive_group(required=True)
    window.add_argument("--last", type=_duration, help="e.g. 30m, 2h, 7d")
    window.add_argument("--since", type=_instant)
    p.add_argument("--until", type=_instant)
    p.add_argument("--by", choices=("event", "ingested"), default="event",
                   help="which clock the range uses")
    p.set_defaults(func=cmd_forget)
    p = sub.add_parser("wipe", parents=[common], help="destroy the key and delete all data")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_wipe)
    p = sub.add_parser("stats", parents=[common], help="counts only, no content")
    p.set_defaults(func=cmd_stats)
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.name == "posix":
        os.umask(0o077)  # every file we create, incl. SQLite -wal/-shm, is owner-only
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (SettingsError, KeyUnavailable, EventFileError, LookupError, ValueError) as exc:
        print(f"error: {redact_text(str(exc))}", file=sys.stderr)
        return 2
    except Exception as exc:  # never dump raw state to the terminal
        log.debug("unhandled error", exc_info=True)
        print(f"error: unexpected {type(exc).__name__}; rerun with LOCAL_AI_DEBUG=1 for a redacted traceback",
              file=sys.stderr)
        return 1
