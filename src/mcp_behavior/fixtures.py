"""Inputs and independent filesystem observations. No expected-output file is sent."""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import HarnessError


def bounded_hash(path: Path, max_bytes: int = 16 * 1024**2) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise HarnessError("oracle can only hash bounded regular files")
        h = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            if size > max_bytes:
                raise HarnessError("file grew past oracle byte budget")
            h.update(chunk)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise HarnessError("file changed while the oracle collected its digest")
        return h.hexdigest()
    finally:
        os.close(fd)


def snapshot(root: Path, read_fds: dict[str, int] | None = None) -> dict[str, dict[str, Any]]:
    """lstat first; never follow a symlink, open a FIFO, or recurse into one."""
    found: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    pending = [root]
    while pending:
        path = pending.pop()
        st = path.lstat()
        relative = path.relative_to(root).as_posix()
        row: dict[str, Any] = {"mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid,
                               "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
                               "nlink": st.st_nlink}
        if stat.S_ISLNK(st.st_mode):
            row["target"] = os.readlink(path)
        elif stat.S_ISDIR(st.st_mode):
            with os.scandir(path) as entries:
                pending.extend(Path(entry.path) for entry in entries)
        elif stat.S_ISREG(st.st_mode):
            total_bytes += st.st_size
            if total_bytes > 32 * 1024**2:
                raise HarnessError("oracle snapshot exceeds its total file byte budget")
            try:
                row["sha256"] = bounded_hash(path)
            except PermissionError:
                fd = (read_fds or {}).get(relative)
                if fd is not None and (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (st.st_dev, st.st_ino):
                    # Opened by the oracle BEFORE chmod(0), never inherited by the server.
                    data = os.pread(fd, 16 * 1024**2 + 1, 0)
                    if len(data) > 16 * 1024**2:
                        raise HarnessError("held descriptor exceeded the oracle byte budget")
                    row["sha256"] = hashlib.sha256(data).hexdigest()
                else:
                    row["unreadable"] = True
        else:
            row["special"] = True
        found[relative] = row
        if len(found) > 10000 or len(pending) > 10000:
            raise HarnessError("oracle snapshot exceeds its entry budget")
    return found


@dataclass
class Fixture:
    name: str
    directory: Path
    root: Path
    cwd: Path
    home: Path
    watched: Path
    files: dict[str, bytes]
    expected_processed: set[str]
    expected_excluded: set[str]
    problems: set[str] = field(default_factory=set)
    canaries: tuple[str, ...] = ()
    argument: str = ""
    before: dict[str, dict[str, Any]] = field(default_factory=dict)
    preconditions: dict[str, Any] = field(default_factory=dict)
    read_fds: dict[str, int] = field(default_factory=dict)

    def hash_manifest(self) -> list[dict[str, Any]]:
        return [{"path": p, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                for p, data in sorted(self.files.items())]


def build_fixture(parent: Path, name: str, suffixes: tuple[str, ...], uid: int | None = None,
                  gid: int | None = None) -> Fixture:
    nonce = secrets.token_hex(12)
    directory = parent / name
    watched = directory / "watched"
    root, cwd, outside = (watched / x for x in ("workspace", "server-cwd", "outside"))
    home = directory / "home"
    for path in (root, cwd, outside, home / "tmp"):
        path.mkdir(parents=True)
    files: dict[str, bytes] = {
        f"alpha_{nonce[:8]}.py": f'def inspect_alpha(path):\n    # {nonce}\n    return open(path).read()\n'.encode(),
        f"beta_{nonce[:8]}.js": f'const fs = require("fs");\nfunction inspectBeta(path) {{ return fs.readFileSync(path); }} // {nonce}\n'.encode(),
        "nested space/π.py": b'def nested(path):\n    return open(path).read()\n',
        "empty.py": b"",
        ".hidden.py": b'def hidden(path):\n    return open(path).read()\n',
        "no_newline.js": b'const fs=require("fs"); function run(p){return fs.readFileSync(p);}',
        "notes.txt": ("Fixture token " + nonce + "\n").encode(),
        "unsupported.bin": b"\x00\xff\x10",
    }
    if name == "large":
        for i in range(700):
            files[f"many/item_{i:04}.py"] = f"def run_{i}(p):\n    return open(p).read()\n".encode()
        files["many_sinks.py"] = "\n".join(f"def sink_{i}(p):\n    return open(p).read()\n" for i in range(512)).encode()
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    canary = "OUTSIDE_" + nonce
    decoy = "CWD_" + nonce
    (outside / (canary + ".py")).write_text(f"def {canary}(p):\n    return open(p).read()\n")
    (cwd / (decoy + ".py")).write_text(f"def {decoy}(p):\n    return open(p).read()\n")
    processed = {p for p in files if Path(p).suffix in suffixes}
    fixture = Fixture(name, directory, root, cwd, home, watched, files, processed, set(files) - processed,
                      canaries=(canary, decoy), argument=str(root))
    if name in ("escaping_symlink", "dangling_symlink", "internal_symlink", "directory_loop"):
        alias = "escape.py" if name == "escaping_symlink" else "link.py"
        if name == "directory_loop":
            alias = "loop"
        destination = {"escaping_symlink": outside / (canary + ".py"),
                       "dangling_symlink": outside / "does-not-exist.py",
                       "internal_symlink": root / "empty.py", "directory_loop": root}[name]
        (root / alias).symlink_to(destination, target_is_directory=name == "directory_loop")
        fixture.problems.add(alias)
    if name == "special_file":
        os.mkfifo(root / "blocked.py", 0o600)
        fixture.problems.add("blocked.py")
    if name == "unreadable":
        path = root / "unreadable.py"
        path.write_text("def unreadable(p):\n    return open(p).read()\n")
        fixture.read_fds["workspace/unreadable.py"] = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        path.chmod(0)
        fixture.files["unreadable.py"] = b"def unreadable(p):\n    return open(p).read()\n"
        fixture.problems.add("unreadable.py")
    if name == "missing":
        fixture.argument = str(root / ("missing_" + nonce))
    elif name == "file_as_root":
        fixture.argument = str(root / "empty.py")
    elif name == "relative":
        fixture.argument = "."
    elif name == "outside":
        fixture.argument = str(outside)
    elif name == "traversal":
        fixture.argument = str(root) + "/../outside"
    if uid is not None:
        for path in [directory, *directory.rglob("*")]:
            os.chown(path, uid, gid if gid is not None else uid, follow_symlinks=False)
    # A child under a different UID needs traversal, but the oracle has no files here.
    parent.chmod(0o711)
    fixture.before = snapshot(watched, fixture.read_fds)
    return fixture
