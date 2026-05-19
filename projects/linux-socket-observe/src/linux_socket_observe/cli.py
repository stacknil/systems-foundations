from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from pathlib import Path
import sys

from .diff import compare_snapshots
from .report import build_diff_report
from .snapshot import SnapshotInputError, build_snapshot, load_snapshot


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="linux_socket_observe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot", help="build one normalized network snapshot")
    snapshot_parser.add_argument("--ss", required=True, help="path to ss text output")
    snapshot_parser.add_argument("--ip-addr", required=True, help="path to ip -j addr show output")
    snapshot_parser.add_argument("--ip-link", required=True, help="path to ip -j link show output")
    snapshot_parser.add_argument("--ip-neigh", required=True, help="path to ip -j neigh show output")
    snapshot_parser.add_argument("--ip-link-stats", help="optional path to ip -s -s link show output")
    snapshot_parser.add_argument("--output", required=True, help="path to the output snapshot JSON")
    snapshot_parser.set_defaults(handler=_handle_snapshot)

    diff_parser = subparsers.add_parser("diff", help="compare two normalized snapshots")
    diff_parser.add_argument("--before", required=True, help="path to the earlier snapshot JSON")
    diff_parser.add_argument("--after", required=True, help="path to the later snapshot JSON")
    diff_parser.add_argument("--output", required=True, help="path to the Markdown diff report")
    diff_parser.set_defaults(handler=_handle_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[Namespace], int] = args.handler
    return handler(args)


def _handle_snapshot(args: Namespace) -> int:
    try:
        snapshot = build_snapshot(
            ss_path=args.ss,
            ip_addr_path=args.ip_addr,
            ip_link_path=args.ip_link,
            ip_neigh_path=args.ip_neigh,
            ip_link_stats_path=args.ip_link_stats,
        )
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
        f"snapshot wrote {len(snapshot.sockets)} sockets, {len(snapshot.interfaces)} interfaces, "
        f"{len(snapshot.addresses)} addresses, {len(snapshot.neighbors)} neighbors",
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
