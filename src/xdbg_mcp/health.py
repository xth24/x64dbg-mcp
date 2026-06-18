from __future__ import annotations

from typing import Protocol

from .binding import SessionBinder
from .errors import BridgeError
from .info import plugin_protocol_compatible, version_info
from .sessions import DebuggerSession, list_sessions


class BridgeLike(Protocol):
    def call_session(
        self,
        session: DebuggerSession,
        method: str,
        params: dict[str, object],
        *,
        timeout_ms: int | None = None,
    ) -> dict[str, object]:
        ...


def session_health(bridge: BridgeLike, session: DebuggerSession) -> dict[str, object]:
    item: dict[str, object] = {
        "session": session.public(),
        "reachable": False,
        "compatible": False,
    }
    try:
        response = bridge.call_session(session, "get_bridge_info", {}, timeout_ms=1000)
    except BridgeError as exc:
        item["status"] = "unreachable"
        item["error"] = exc.to_dict()
        return item

    item["reachable"] = True
    if not response.get("ok"):
        item["status"] = "bridge_method_failed"
        item["error"] = response.get("error")
        return item

    result = response.get("result")
    plugin = result if isinstance(result, dict) else {}
    protocol_version = plugin.get("protocol_version")
    item["plugin"] = plugin
    item["compatible"] = plugin_protocol_compatible(protocol_version)
    item["status"] = "healthy" if item["compatible"] else "incompatible_protocol"
    return item


def build_health_report(
    bridge: BridgeLike,
    binder: SessionBinder,
    *,
    arch: str | None = None,
    session_id: str | None = None,
    include_all_sessions: bool = False,
) -> dict[str, object]:
    sessions = list_sessions(arch=arch)
    report: dict[str, object] = {
        "ok": True,
        **version_info(),
        "binding": binder.current(),
        "session_count": len(sessions),
        "sessions": [session.public() for session in sessions],
    }

    if not sessions:
        report["healthy"] = False
        report["status"] = "no_sessions"
        return report

    try:
        target = binder.resolve(session_id=session_id, arch=arch)
    except BridgeError as exc:
        report["healthy"] = False
        report["status"] = "session_resolution_failed"
        report["error"] = exc.to_dict()
        return report

    target_health = session_health(bridge, target)
    report["target"] = target_health
    report["healthy"] = bool(target_health.get("reachable") and target_health.get("compatible"))
    report["status"] = target_health.get("status", "unknown")

    if include_all_sessions:
        report["session_health"] = [session_health(bridge, session) for session in sessions]

    return report
