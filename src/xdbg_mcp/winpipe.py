from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
import struct
import uuid

from .errors import BridgeError
from .sessions import DebuggerSession, select_session


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
ERROR_PIPE_BUSY = 231
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None


def _require_windows() -> None:
    if os.name != "nt" or kernel32 is None:
        raise BridgeError("unsupported_platform", "Named-pipe debugger bridge is only available on Windows.")


if kernel32 is not None:
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    ]
    kernel32.GetOverlappedResult.restype = wintypes.BOOL
    kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
    kernel32.CancelIoEx.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.WriteFile.restype = wintypes.BOOL


class _Handle:
    def __init__(self, value: int):
        self.value = value

    def close(self) -> None:
        if self.value and self.value != INVALID_HANDLE_VALUE:
            kernel32.CloseHandle(self.value)
            self.value = 0

    def __enter__(self) -> "_Handle":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def _last_error() -> int:
    return ctypes.get_last_error()


def _event() -> _Handle:
    handle = kernel32.CreateEventW(None, True, False, None)
    if not handle:
        raise BridgeError("win32_error", "CreateEventW failed.", details={"win32": _last_error()})
    return _Handle(handle)


def _wait_io(handle: int, overlapped: OVERLAPPED, timeout_ms: int, operation: str) -> int:
    wait = kernel32.WaitForSingleObject(overlapped.hEvent, timeout_ms)
    if wait == WAIT_TIMEOUT:
        kernel32.CancelIoEx(handle, ctypes.byref(overlapped))
        raise BridgeError("timeout", f"Timed out during named-pipe {operation}.", retriable=True)
    if wait != WAIT_OBJECT_0:
        raise BridgeError("win32_error", f"WaitForSingleObject failed during {operation}.", details={"wait": wait})

    transferred = wintypes.DWORD(0)
    if not kernel32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(transferred), False):
        raise BridgeError("pipe_io_failed", f"Named-pipe {operation} failed.", details={"win32": _last_error()})
    return int(transferred.value)


def _write_all(handle: int, data: bytes, timeout_ms: int) -> None:
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 1024 * 1024]
        with _event() as event:
            overlapped = OVERLAPPED()
            overlapped.hEvent = event.value
            written = wintypes.DWORD(0)
            ok = kernel32.WriteFile(handle, chunk, len(chunk), ctypes.byref(written), ctypes.byref(overlapped))
            if ok:
                offset += int(written.value)
                continue
            if _last_error() != ERROR_IO_PENDING:
                raise BridgeError("pipe_write_failed", "Named-pipe write failed.", details={"win32": _last_error()})
            offset += _wait_io(handle, overlapped, timeout_ms, "write")


def _read_exact(handle: int, size: int, timeout_ms: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        want = min(size - len(out), 1024 * 1024)
        buffer = ctypes.create_string_buffer(want)
        with _event() as event:
            overlapped = OVERLAPPED()
            overlapped.hEvent = event.value
            got = wintypes.DWORD(0)
            ok = kernel32.ReadFile(handle, buffer, want, ctypes.byref(got), ctypes.byref(overlapped))
            if ok:
                transferred = int(got.value)
            elif _last_error() == ERROR_IO_PENDING:
                transferred = _wait_io(handle, overlapped, timeout_ms, "read")
            else:
                raise BridgeError("pipe_read_failed", "Named-pipe read failed.", details={"win32": _last_error()})
        if transferred == 0:
            raise BridgeError("pipe_closed", "Debugger plugin closed the pipe before sending a full response.", retriable=True)
        out.extend(buffer.raw[:transferred])
    return bytes(out)


def _open_pipe(pipe: str, timeout_ms: int) -> _Handle:
    if not kernel32.WaitNamedPipeW(pipe, timeout_ms):
        err = _last_error()
        code = "pipe_busy" if err == ERROR_PIPE_BUSY else "pipe_unavailable"
        raise BridgeError(code, f"Debugger pipe is not ready: {pipe}", retriable=True, details={"win32": err})

    handle = kernel32.CreateFileW(
        pipe,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise BridgeError("pipe_open_failed", f"Failed to open debugger pipe: {pipe}", retriable=True, details={"win32": _last_error()})
    return _Handle(handle)


def send_pipe_request(pipe: str, payload: dict[str, object], *, timeout_ms: int) -> dict[str, object]:
    _require_windows()
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > 16 * 1024 * 1024:
        raise BridgeError("request_too_large", "Debugger request exceeded the 16 MiB bridge limit.")

    with _open_pipe(pipe, timeout_ms) as handle:
        _write_all(handle.value, struct.pack("<I", len(encoded)) + encoded, timeout_ms)
        response_size = struct.unpack("<I", _read_exact(handle.value, 4, timeout_ms))[0]
        if response_size > 16 * 1024 * 1024:
            raise BridgeError("response_too_large", "Debugger response exceeded the 16 MiB bridge limit.")
        response = json.loads(_read_exact(handle.value, response_size, timeout_ms).decode("utf-8"))

    if not isinstance(response, dict):
        raise BridgeError("bad_response", "Debugger bridge returned a non-object response.")
    return response


class DebuggerBridge:
    def __init__(self, *, default_timeout_ms: int = 5000):
        self.default_timeout_ms = default_timeout_ms

    def call(
        self,
        method: str,
        params: dict[str, object] | None = None,
        *,
        arch: str | None = None,
        session_id: str | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, object]:
        session = select_session(arch=arch, session_id=session_id)
        return self.call_session(session, method, params or {}, timeout_ms=timeout_ms)

    def call_session(
        self,
        session: DebuggerSession,
        method: str,
        params: dict[str, object],
        *,
        timeout_ms: int | None = None,
    ) -> dict[str, object]:
        request = {
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params,
        }
        response = send_pipe_request(session.pipe, request, timeout_ms=timeout_ms or self.default_timeout_ms)
        response["session"] = session.public()
        return response
