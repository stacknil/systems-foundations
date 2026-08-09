from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from pathlib import Path
import sys

from .adapters import build_telemetry_events, write_telemetry_events
from .diff import build_diff_envelope
from .report import build_markdown_report
from .snapshot import EvidenceInputError, build_snapshot_artifacts, load_envelope, write_envelope


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="linux_process_observe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="build normalized process and socket-link artifacts")
    snapshot_parser.add_argument("--proc-root", required=True, help="path to a saved procfs process export")
    snapshot_parser.add_argument("--ss", required=True, help="path to saved TCP/UDP ss -H -a -n -t -u -p output")
    snapshot_parser.add_argument("--host-id", required=True, help="stable sanitized host identifier")
    snapshot_parser.add_argument("--observed-at", required=True, help="timezone-aware ISO 8601 observation time")
    snapshot_parser.add_argument("--output-dir", required=True, help="directory for normalized JSON artifacts")
    snapshot_parser.set_defaults(handler=_handle_snapshot)

    diff_parser = subparsers.add_parser("diff", help="compare two process evidence snapshots")
    diff_parser.add_argument("--before-processes", required=True, help="earlier process_snapshot.json")
    diff_parser.add_argument("--after-processes", required=True, help="later process_snapshot.json")
    diff_parser.add_argument("--before-links", required=True, help="earlier process_socket_links.json")
    diff_parser.add_argument("--after-links", required=True, help="later process_socket_links.json")
    diff_parser.add_argument("--output-dir", required=True, help="directory for process_diff.json and report.md")
    diff_parser.set_defaults(handler=_handle_diff)

    adapt_parser = subparsers.add_parser(
        "adapt",
        help="map process_diff.json to telemetry-lab-compatible JSONL events",
    )
    adapt_parser.add_argument("--input", required=True, help="process_diff.json")
    adapt_parser.add_argument("--output", required=True, help="output telemetry JSONL path")
    adapt_parser.set_defaults(handler=_handle_adapt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[Namespace], int] = args.handler
    return handler(args)


def _handle_snapshot(args: Namespace) -> int:
    try:
        process_snapshot, socket_links = build_snapshot_artifacts(
            proc_root=args.proc_root,
            ss_path=args.ss,
            host_id=args.host_id,
            observed_at=args.observed_at,
        )
    except EvidenceInputError as exc:
        _print_error("snapshot", exc)
        return 1

    output_dir = Path(args.output_dir)
    write_envelope(process_snapshot, output_dir / "process_snapshot.json")
    write_envelope(socket_links, output_dir / "process_socket_links.json")
    print(
        f"snapshot wrote {len(process_snapshot.records)} processes and {len(socket_links.records)} process/socket links",
        file=sys.stderr,
    )
    return 0


def _handle_diff(args: Namespace) -> int:
    try:
        before_processes = load_envelope(args.before_processes, input_name="before-processes")
        after_processes = load_envelope(args.after_processes, input_name="after-processes")
        before_links = load_envelope(args.before_links, input_name="before-links")
        after_links = load_envelope(args.after_links, input_name="after-links")
        diff = build_diff_envelope(
            before_processes=before_processes,
            after_processes=after_processes,
            before_links=before_links,
            after_links=after_links,
        )
    except EvidenceInputError as exc:
        _print_error("diff", exc)
        return 1
    except ValueError as exc:
        _print_error("diff", EvidenceInputError("artifacts", "-", exc.__class__.__name__, str(exc)))
        return 1

    output_dir = Path(args.output_dir)
    write_envelope(diff, output_dir / "process_diff.json")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.md").write_text(build_markdown_report(diff), encoding="utf-8", newline="\n")
    return 0


def _handle_adapt(args: Namespace) -> int:
    try:
        diff = load_envelope(args.input, input_name="process-diff")
        events = build_telemetry_events(diff)
        write_telemetry_events(events, args.output)
    except EvidenceInputError as exc:
        _print_error("adapt", exc)
        return 1
    except OSError as exc:
        _print_error(
            "adapt",
            EvidenceInputError("output", str(args.output), exc.__class__.__name__, str(exc)),
        )
        return 1
    except ValueError as exc:
        _print_error(
            "adapt",
            EvidenceInputError(
                "process-diff",
                str(args.input),
                exc.__class__.__name__,
                str(exc),
            ),
        )
        return 1

    print(f"adapt wrote {len(events)} telemetry events", file=sys.stderr)
    return 0


def _print_error(command: str, error: EvidenceInputError) -> None:
    print(
        f"error command={command} input={error.input_name} path={error.path} "
        f"type={error.error_type} message={error}",
        file=sys.stderr,
    )
