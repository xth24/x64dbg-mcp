from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path

from .errors import BridgeError


@dataclass(frozen=True)
class DebuggerSession:
    session_id: str
    arch: str
    pid: int
    pipe: str
    created_at_unix: int
    plugin_version: str
    protocol_version: int = 0

    @classmethod
    def from_json(cls, value: object) -> "DebuggerSession":
        if not isinstance(value, dict):
            raise ValueError("session descriptor is not an object")
        return cls(
            session_id=str(value["session_id"]),
            arch=str(value["arch"]),
            pid=int(value["pid"]),
            pipe=str(value["pipe"]),
            created_at_unix=int(value["created_at_unix"]),
            plugin_version=str(value.get("plugin_version", "unknown")),
            protocol_version=int(value.get("protocol_version", 0)),
        )

    def public(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "arch": self.arch,
            "pid": self.pid,
            "pipe": self.pipe,
            "created_at_unix": self.created_at_unix,
            "plugin_version": self.plugin_version,
            "protocol_version": self.protocol_version,
        }


def session_root() -> Path:
    override = os.getenv("XDBG_MCP_SESSION_DIR")
    if override:
        return Path(override)

    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "xdbg-mcp" / "sessions"

    return Path.home() / "AppData" / "Local" / "xdbg-mcp" / "sessions"


def list_sessions(*, arch: str | None = None, root: Path | None = None) -> list[DebuggerSession]:
    base = root or session_root()
    if not base.exists():
        return []

    sessions: list[DebuggerSession] = []
    for path in base.glob("*.json"):
        try:
            session = DebuggerSession.from_json(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            continue
        if arch and session.arch.lower() != arch.lower():
            continue
        sessions.append(session)

    return sorted(sessions, key=lambda item: item.created_at_unix, reverse=True)


def select_session(
    *,
    arch: str | None = None,
    session_id: str | None = None,
    root: Path | None = None,
) -> DebuggerSession:
    sessions = list_sessions(arch=arch, root=root)
    if session_id:
        for session in sessions:
            if session.session_id == session_id:
                return session
        raise BridgeError(
            "session_not_found",
            f"No xdbg-mcp debugger session matches session_id={session_id!r}.",
            retriable=True,
        )

    if not sessions:
        scope = f" for arch={arch!r}" if arch else ""
        raise BridgeError(
            "no_sessions",
            f"No active xdbg-mcp debugger sessions were found{scope}. Load the plugin in x64dbg or x32dbg.",
            retriable=True,
        )

    return sessions[0]
