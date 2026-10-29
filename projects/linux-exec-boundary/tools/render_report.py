"""Render observed manifest fields without inferring stronger containment."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("manifest", type=Path)
parser.add_argument("report", type=Path)
args = parser.parse_args()
data = json.loads(args.manifest.read_text())
lines = [
    "# Execution observation",
    "",
    f"- Request: {data['request']['request_id']}",
    f"- Run: {data['request']['run_id']}",
    f"- Result: {data['outcome']['state']}",
    f"- Child exit: {data['outcome']['exit_code']}; signal: {data['outcome']['signal']}",
    f"- Timeout decision: {data['outcome']['timed_out']}",
    f"- Cancellation decision: {data['outcome']['cancelled']}",
    f"- Post-exec fixture observed: {data['setup']['exec_observed']}",
    f"- Direct child reaped: {data['cleanup']['direct_child_reaped']}",
    f"- Adopted descendants reaped: {data['cleanup']['adopted_reaped']}",
    f"- Owned descriptor delta: {data['cleanup']['owned_fd_delta']}",
    f"- Owned artifacts removed: {data['cleanup']['artifacts_removed']}",
    f"- Process-group cleanup attempted: {data['cleanup']['group_cleanup_attempted']}",
    f"- Whole-tree containment confirmed: {data['cleanup']['whole_tree_confirmed']}",
    f"- Unsupported: {', '.join(data['unsupported'])}",
    "",
    "## Request-local controls confirmed by successful setup",
    "",
]
for name in ("pidfd", "waitid_pidfd", "no_new_privs", "limits_setup", "landlock", "seccomp", "cgroup"):
    lines.append(f"- {name}: {data['features'][name]}")
lines.extend([
    "",
    f"Inherited seccomp mode: {data['observed']['inherited_seccomp']}; "
    f"post-exec mode: {data['observed']['seccomp']}.",
    "Inherited mode alone does not establish installation of this request's filter.",
    "",
    "## Bounded capture",
    "",
])
for name, capture in data["output"].items():
    lines.append(f"- {name}: {capture['captured_bytes']} retained / "
                 f"{capture['total_bytes']} observed bytes; truncated={capture['truncated']}")
args.report.write_text("\n".join(lines) + "\n")
