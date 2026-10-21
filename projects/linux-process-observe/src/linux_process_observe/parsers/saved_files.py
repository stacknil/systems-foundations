"""Read saved regular files, retaining native error types and field context."""
import errno
import os
from pathlib import Path
import stat


def _require_regular(mode: int, context: str) -> None:
    if stat.S_ISDIR(mode):
        raise IsADirectoryError(errno.EISDIR, "Is a directory")
    if not stat.S_ISREG(mode):
        raise ValueError(f"{context}: expected a regular file")


def read_saved_bytes(path: Path, *, context: str) -> bytes:
    descriptor = None
    try:
        _require_regular(path.stat().st_mode, context)
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None  # the stream owns the descriptor from here
            _require_regular(os.fstat(stream.fileno()).st_mode, context)
            return stream.read()
    except OSError as error:
        error.add_note(context)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_saved_text(path: Path, *, context: str) -> str:
    try:
        text = read_saved_bytes(path, context=context).decode("utf-8")
    except UnicodeDecodeError as error:
        error.add_note(context)
        raise
    return text.replace("\r\n", "\n").replace("\r", "\n")
