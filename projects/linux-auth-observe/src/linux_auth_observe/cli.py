from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
import sys

from .filters import iter_filtered_events, load_events
from .parsers import journal_json, syslog_auth
from .report import build_summary


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="linux_auth_observe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize_parser = subparsers.add_parser("normalize", help="normalize source logs into JSONL")
    normalize_parser.add_argument("--input", required=True, help="path to the input log file")
    normalize_parser.add_argument(
        "--source",
        default="auto",
        choices=["auto", "auth.log", "secure", "journal_json"],
        help="input family",
    )
    normalize_parser.add_argument("--output", required=True, help="path to the output JSONL file")
    normalize_parser.add_argument(
        "--year",
        type=int,
        default=datetime.now(timezone.utc).year,
        help="reference year for yearless syslog timestamps",
    )
    normalize_parser.add_argument(
        "--timezone",
        default="local",
        help="IANA timezone name for syslog timestamps, or 'local'",
    )
    normalize_parser.set_defaults(handler=_handle_normalize)

    filter_parser = subparsers.add_parser("filter", help="filter normalized JSONL rows")
    filter_parser.add_argument("--input", required=True, help="path to normalized JSONL")
    filter_parser.add_argument("--user", help="exact user match")
    filter_parser.add_argument("--ip", help="exact source IP match")
    filter_parser.add_argument("--service", help="exact service match")
    filter_parser.add_argument("--since", help="inclusive start timestamp in ISO-8601")
    filter_parser.add_argument("--until", help="inclusive end timestamp in ISO-8601")
    filter_parser.set_defaults(handler=_handle_filter)

    summary_parser = subparsers.add_parser("summary", help="build a Markdown summary report")
    summary_parser.add_argument("--input", required=True, help="path to normalized JSONL")
    summary_parser.add_argument("--output", required=True, help="path to the Markdown report")
    summary_parser.set_defaults(handler=_handle_summary)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[Namespace], int] = args.handler
    return handler(args)


def _handle_normalize(args: Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    source = _detect_source(input_path, args.source)

    parser_fn, parser_kwargs = _resolve_parser(source, args.year, args.timezone)

    processed = 0
    written = 0
    skipped = 0
    errors = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8") as source_handle, output_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as output_handle:
        for line_number, raw_line in enumerate(source_handle, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            processed += 1
            try:
                event = parser_fn(line, **parser_kwargs)
            except ValueError as exc:
                errors += 1
                print(f"line {line_number}: {exc}", file=sys.stderr)
                continue

            if event is None:
                skipped += 1
                continue

            output_handle.write(event.to_json())
            output_handle.write("\n")
            written += 1

    print(
        f"normalized {written} events from {processed} records ({skipped} skipped, {errors} errors)",
        file=sys.stderr,
    )
    return 0


def _handle_filter(args: Namespace) -> int:
    events = load_events(args.input)
    filtered = iter_filtered_events(
        events,
        user=args.user,
        ip=args.ip,
        service=args.service,
        since=args.since,
        until=args.until,
    )
    for event in filtered:
        print(event.to_json())
    return 0


def _handle_summary(args: Namespace) -> int:
    rows = list(load_events(args.input))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_summary(rows), encoding="utf-8", newline="\n")
    return 0


def _detect_source(input_path: Path, declared_source: str) -> str:
    if declared_source != "auto":
        return declared_source

    with input_path.open("r", encoding="utf-8") as handle:
        first_nonempty = ""
        for raw_line in handle:
            if raw_line.strip():
                first_nonempty = raw_line.lstrip()
                break

    if first_nonempty.startswith("{"):
        return "journal_json"

    lower_name = input_path.name.casefold()
    if "secure" in lower_name:
        return "secure"
    return "auth.log"


def _resolve_parser(source: str, year: int, timezone_name: str) -> tuple[Callable[..., object], dict[str, object]]:
    if source == "journal_json":
        return journal_json.parse_line, {}
    return syslog_auth.parse_line, {"collector": source, "year": year, "timezone_name": timezone_name}
