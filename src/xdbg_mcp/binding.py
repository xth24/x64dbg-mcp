from __future__ import annotations

from threading import RLock

from .errors import BridgeError
from .sessions import DebuggerSession, list_sessions, select_session
from .winpipe import DebuggerBridge


class SessionBinder:
    def __init__(self, bridge: DebuggerBridge):
        self._bridge = bridge
        self._session_id: str | None = None
        self._arch: str | None = None
        self._lock = RLock()

    def current(self) -> dict[str, object]:
        with self._lock:
            if not self._session_id:
                return {"bound": False}
            try:
                session = select_session(session_id=self._session_id, arch=self._arch)
            except BridgeError as exc:
                return {"bound": False, "stale": True, "error": exc.to_dict()}
            return {"bound": True, "session": session.public()}

    def unbind(self) -> dict[str, object]:
        with self._lock:
            previous = {"session_id": self._session_id, "arch": self._arch} if self._session_id else None
            self._session_id = None
            self._arch = None
            return {"bound": False, "previous": previous}

    def resolve(self, *, session_id: str | None = None, arch: str | None = None) -> DebuggerSession:
        if session_id or arch:
            return select_session(session_id=session_id, arch=arch)

        with self._lock:
            if self._session_id:
                return select_session(session_id=self._session_id, arch=self._arch)

        return select_session()

    def bind(
        self,
        *,
        session_id: str | None = None,
        arch: str | None = None,
        prefer_debugging: bool = True,
    ) -> dict[str, object]:
        session = self._choose_session(session_id=session_id, arch=arch, prefer_debugging=prefer_debugging)
        status = self._bridge.call_session(session, "get_status", {}, timeout_ms=1000)
        with self._lock:
            self._session_id = session.session_id
            self._arch = session.arch
        return {
            "bound": True,
            "session": session.public(),
            "status": status.get("result"),
        }

    def annotate(self, session: DebuggerSession, info: dict[str, object]) -> dict[str, object]:
        with self._lock:
            info["bound"] = bool(self._session_id == session.session_id)
        return info

    def _choose_session(
        self,
        *,
        session_id: str | None,
        arch: str | None,
        prefer_debugging: bool,
    ) -> DebuggerSession:
        if session_id:
            return select_session(session_id=session_id, arch=arch)

        candidates = list_sessions(arch=arch)
        if not candidates:
            scope = f" for arch={arch!r}" if arch else ""
            raise BridgeError("no_sessions", f"No xdbg-mcp debugger sessions were found{scope}.", retriable=True)

        reachable: list[tuple[DebuggerSession, dict[str, object]]] = []
        errors: list[dict[str, object]] = []
        for session in candidates:
            try:
                status = self._bridge.call_session(session, "get_status", {}, timeout_ms=1000)
            except BridgeError as exc:
                errors.append({"session": session.public(), "error": exc.to_dict()})
                continue
            if status.get("ok"):
                result = status.get("result")
                reachable.append((session, result if isinstance(result, dict) else {}))

        if not reachable:
            raise BridgeError("no_reachable_sessions", "No reachable xdbg-mcp debugger sessions were found.", retriable=True, details=errors)

        if prefer_debugging:
            for session, status in reachable:
                if status.get("debugging") is True:
                    return session

        return reachable[0][0]
