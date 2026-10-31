"""Small dependency-free formatting gate; not a substitute for clang-format."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
errors = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or any(part.startswith("build") or part in
                                 ("__pycache__", "evidence") for part in path.relative_to(root).parts):
        continue
    if path.suffix not in (".cpp", ".hpp", ".py", ".md", ".json", ".txt"):
        continue
    data = path.read_bytes()
    name = path.relative_to(root).as_posix()
    if b"\r" in data or b"\t" in data or b"\0" in data:
        errors.append(name + ": CR, tab or NUL")
    if data and not data.endswith(b"\n"):
        errors.append(name + ": missing final LF")
    for index, line in enumerate(data.splitlines(), 1):
        if line.rstrip(b" ") != line:
            errors.append(f"{name}:{index}: trailing spaces")
print("\n".join(errors) if errors else "LF, no tabs/NUL, final newline, trailing-whitespace checks passed")
raise SystemExit(bool(errors))
