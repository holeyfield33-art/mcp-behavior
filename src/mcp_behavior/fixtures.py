"""Inputs and independent filesystem observations. No expected-output file is sent."""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Fixture:
    root: Path
    workspace: Path
    decoy_cwd: Path
    outside: Path
    canary_outside: Path
    canary_cwd: Path
    token: str
    expected: dict[str, Any] = field(default_factory=dict)
    read_fds: list = field(default_factory=list)

    def close(self) -> None:
        for fd in self.read_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.read_fds.clear()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return _sha256(data)


def build_fixture(base: Path) -> Fixture:
    """Create a fresh randomized fixture tree. Expected digests stay outside the server workspace."""
    token = secrets.token_hex(8)
    root = base / f"fx_{token}"
    workspace = root / "workspace"
    decoy_cwd = root / "decoy_cwd"
    outside = root / "outside"
    workspace.mkdir(parents=True)
    decoy_cwd.mkdir(parents=True)
    outside.mkdir(parents=True)

    canary_outside = outside / f"canary_outside_{token}.txt"
    canary_cwd = decoy_cwd / f"canary_cwd_{token}.txt"
    canary_outside.write_text(f"outside-canary-{token}\n", encoding="utf-8")
    canary_cwd.write_text(f"cwd-canary-{token}\n", encoding="utf-8")

    expected: dict[str, Any] = {
        "token": token,
        "processed": {},
        "excluded": {},
        "failed": {},
        "unsupported": [],
        "unsafe": [],
    }

    # Supported language mix
    files = {
        f"main_{token}.py": f"# py {token}\nprint({token!r})\n".encode(),
        f"lib_{token}.js": f"// js {token}\nconsole.log({token!r});\n".encode(),
        f"notes_{token}.txt": f"text {token}\n".encode(),
        f".hidden_{token}.py": f"# hidden {token}\n".encode(),
        f"nested/dir/a_{token}.py": f"# nested {token}\n".encode(),
        f"empty_{token}.txt": b"",
        f"unicode_{token}_café.txt": f"café {token}\n".encode("utf-8"),
    }
    for rel, data in files.items():
        p = workspace / rel
        digest = _write(p, data)
        expected["processed"][rel.replace("\\", "/")] = digest

    # Unsupported extension (must be excluded with reason)
    uns = workspace / f"data_{token}.bin"
    uns.write_bytes(b"\x00\x01binary")
    expected["excluded"][f"data_{token}.bin"] = "unsupported_suffix"

    # Mode-000 file: open before chmod so oracle retains a readable fd
    mode0 = workspace / f"secret_{token}.py"
    mode0_data = f"# mode0 {token}\n".encode()
    mode0.write_bytes(mode0_data)
    fd = os.open(mode0, os.O_RDONLY)
    os.chmod(mode0, 0)
    expected["failed"][f"secret_{token}.py"] = "permission_denied"
    expected["processed_mode0_digest"] = _sha256(mode0_data)

    # Symlinks and specials
    (workspace / f"link_escape_{token}").symlink_to(canary_outside)
    (workspace / f"link_internal_{token}").symlink_to(f"main_{token}.py")
    (workspace / f"link_dangling_{token}").symlink_to(f"missing_{token}.py")
    expected["unsafe"].extend([
        f"link_escape_{token}",
        f"link_internal_{token}",
        f"link_dangling_{token}",
    ])

    # Directory loop
    loop_dir = workspace / f"loop_{token}"
    loop_dir.mkdir()
    (loop_dir / "self").symlink_to("..", target_is_directory=True)
    expected["unsafe"].append(f"loop_{token}/self")

    # FIFO
    fifo = workspace / f"fifo_{token}"
    os.mkfifo(fifo)
    expected["unsafe"].append(f"fifo_{token}")

    fixture = Fixture(
        root=root,
        workspace=workspace,
        decoy_cwd=decoy_cwd,
        outside=outside,
        canary_outside=canary_outside,
        canary_cwd=canary_cwd,
        token=token,
        expected=expected,
        read_fds=[fd],
    )
    return fixture
