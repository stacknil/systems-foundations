from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from pathlib import Path
import sys

from .diff import compare_snapshots
from .report import build_diff_report
from .snapshot import SnapshotInputError, build_snapshot, load_snapshot


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="linux_permission_observe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="build one normalized permission snapshot")
    snapshot_parser.add_argument("--files", required=True, help="path to file inventory TSV")
    snapshot_parser.add_argument("--groups", required=True, help="path to getent group style input")
    snapshot_parser.add_argument("--sudoers", required=True, help="path to sanitized sudoers rule input")
    snapshot_parser.add_argument("--output", required=True, help="path to output snapshot JSON")
    snapshot_parser.set_defaults(handler=_handle_snapshot)

    diff_parser = subparsers.add_parser("diff", help="compare two normalized permission snapshots")
    diff_parser.add_argument("--before", required=True, help="path to earlier snapshot JSON")
    diff_parser.add_argument("--after", required=True, help="path to later snapshot JSON")
    diff_parser.add_argument("--output", required=True, help="path to Markdown drift report")
    diff_parser.set_defaults(handler=_handle_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[Namespace], int] = args.handler
    return handler(args)


def _handle_snapshot(args: Namespace) -> int:
    try:
        snapshot = build_snapshot(files_path=args.files, groups_path=args.groups, sudoers_path=args.sudoers)
    except SnapshotInputError as exc:
        print(
            f"error command=snapshot input={exc.input_name} path={exc.path} type={exc.error_type} message={exc}",
            file=sys.stderr,
        )
        return 1
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(snapshot.to_json() + "\n", encoding="utf-8", newline="\n")
    print(
        f"snapshot wrote {len(snapshot.files)} files, {len(snapshot.groups)} groups, "
        f"{len(snapshot.sudoers)} sudoers rules",
        file=sys.stderr,
    )
    return 0


def _handle_diff(args: Namespace) -> int:
    try:
        before = load_snapshot(args.before, input_name="before")
        after = load_snapshot(args.after, input_name="after")
    except SnapshotInputError as exc:
        print(
            f"error command=diff input={exc.input_name} path={exc.path} type={exc.error_type} message={exc}",
            file=sys.stderr,
        )
        return 1
    report = build_diff_report(compare_snapshots(before, after))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8", newline="\n")
    return 0

