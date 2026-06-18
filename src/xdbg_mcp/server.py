from __future__ import annotations

from typing import Literal

from .binding import SessionBinder
from .errors import BridgeError
from .health import build_health_report
from .info import version_info
from .sessions import list_sessions
from .winpipe import DebuggerBridge


bridge = DebuggerBridge()
binder = SessionBinder(bridge)


def _result(
    method: str,
    params: dict[str, object] | None = None,
    *,
    arch: str | None = None,
    session_id: str | None = None,
    timeout_ms: int | None = None,
) -> dict[str, object]:
    try:
        session = binder.resolve(session_id=session_id, arch=arch)
        return bridge.call_session(session, method, params or {}, timeout_ms=timeout_ms)
    except BridgeError as exc:
        return {"ok": False, "error": exc.to_dict()}
    except Exception as exc:
        return {
            "ok": False,
            "error": {
                "code": "server_error",
                "message": str(exc),
                "retriable": False,
            },
        }


def create_server():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("xdbg-mcp")

    @mcp.tool()
    def get_capabilities() -> dict:
        """Describe available xdbg-mcp tools and recommended agent workflow."""
        return {
            "ok": True,
            **version_info(),
            "transport": "stdio MCP server to local debugger plugin over named pipes",
            "recommended_start": ["health_check", "list_debugger_sessions", "bind_debugger_session", "get_status", "get_snapshot", "inspect_address", "list_modules"],
            "read_only_tools": [
                "health_check",
                "get_status",
                "get_bridge_info",
                "get_snapshot",
                "get_registers",
                "read_memory",
                "disassemble",
                "parse_expression",
                "evaluate_expressions",
                "get_branch_destination",
                "find_pattern",
                "find_all_patterns",
                "find_strings",
                "find_instructions",
                "list_calls_in_range",
                "list_calls_in_function",
                "analyze_function",
                "analyze_linear_block",
                "list_functions",
                "find_references_to_range",
                "find_references_to_module",
                "inspect_import_thunk",
                "snapshot_break_context",
                "get_call_stack",
                "get_symbol_at",
                "get_string_at",
                "get_xrefs",
                "inspect_address",
                "inspect_instruction",
                "read_pointer",
                "deref_chain",
                "inspect_stack",
                "inspect_call_args",
                "find_pointers_to_range",
                "list_breakpoints",
                "resolve_breakpoints",
                "list_unresolved_breakpoints",
                "list_modules",
                "get_module_at",
                "list_module_sections",
                "list_module_imports",
                "list_module_exports",
                "list_iat",
                "inspect_pe_headers",
                "inspect_clr_metadata",
                "list_threads",
                "get_memory_map",
                "get_page_at",
                "query_symbols",
                "list_labels",
                "wait_for_pause",
            ],
            "mutating_tools": [
                "set_register",
                "write_memory",
                "run",
                "pause",
                "stop",
                "step",
                "run_until",
                "wait_for_module",
                "set_breakpoint",
                "remove_breakpoint",
                "set_hardware_breakpoint",
                "remove_hardware_breakpoint",
                "set_breakpoint_options",
                "set_memory_breakpoint",
                "remove_memory_breakpoint",
                "set_label",
                "set_comment",
                "execute_command",
            ],
            "session_routing": [
                "Call bind_debugger_session once to make later calls use that debugger session by default.",
                "Passing session_id or arch to any debugger tool still overrides the binding for that call.",
                "When no session is bound, tools fall back to the newest discovered session.",
            ],
            "routing_tools": [
                "list_debugger_sessions",
                "bind_debugger_session",
                "get_bound_debugger_session",
                "unbind_debugger_session",
            ],
            "notes": [
                "Prefer get_snapshot for debugger state and inspect_address for one-address orientation.",
                "Use inspect_stack and inspect_call_args when stopped around calls or import thunks.",
                "Pass owner_module to pointer/stack/call tools when raw values should be interpreted as module RVAs.",
                "Use find_strings, list_iat, and analyze_linear_block before manual range walking.",
                "Use evaluate_expressions to resolve multiple addresses/registers in one call.",
                "Use find_instructions for mnemonic, operand, or branch-kind searches over modules/ranges.",
                "Use find_pointers_to_range for data references that code xref scans miss.",
                "Broad analysis tools expose limit/max_instructions; lower limit first on system modules.",
                "For managed modules with non-executable CLR stubs, pass include_readonly_code_like_sections to reference scanners.",
                "Address parameters accept x64dbg expressions directly, including cip and module+offset forms.",
                "Use list_unresolved_breakpoints when persisted module breakpoints do not bind yet.",
                "Use run_until and wait_for_module with explicit timeouts; they return timed_out instead of waiting forever.",
                "Use wait_for_pause after run or manual debugger interaction before inspecting paused context.",
                "Use set_breakpoint_options for conditions, logging, commands, names, singleshot, silent, and fast-resume flags.",
                "Use memory breakpoints for data access/watchpoint cases when four hardware slots are not enough.",
                "Use execute_command only when typed tools do not cover the operation.",
            ],
        }

    @mcp.tool()
    def list_debugger_sessions(arch: Literal["x64", "x32"] | None = None) -> dict:
        """List x64dbg/x32dbg plugin sessions discoverable by this MCP server."""
        sessions = []
        for session in list_sessions(arch=arch):
            info = session.public()
            try:
                status = bridge.call_session(session, "get_status", {}, timeout_ms=1000)
                info["reachable"] = bool(status.get("ok"))
                info["status"] = status.get("result")
            except BridgeError as exc:
                info["reachable"] = False
                info["error"] = exc.to_dict()
            sessions.append(binder.annotate(session, info))
        return {"ok": True, "sessions": sessions}

    @mcp.tool()
    def bind_debugger_session(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None, prefer_debugging: bool = True) -> dict:
        """Bind this MCP server process to one debugger session so later calls can omit session_id and arch."""
        try:
            return {"ok": True, **binder.bind(session_id=session_id, arch=arch, prefer_debugging=prefer_debugging)}
        except BridgeError as exc:
            return {"ok": False, "error": exc.to_dict()}

    @mcp.tool()
    def get_bound_debugger_session() -> dict:
        """Return the debugger session currently used by default for tool calls."""
        return {"ok": True, **binder.current()}

    @mcp.tool()
    def unbind_debugger_session() -> dict:
        """Clear the default debugger session binding."""
        return {"ok": True, **binder.unbind()}

    @mcp.tool()
    def health_check(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None, include_all_sessions: bool = False) -> dict:
        """Check server/plugin versions, session reachability, and bridge protocol compatibility."""
        return build_health_report(bridge, binder, session_id=session_id, arch=arch, include_all_sessions=include_all_sessions)

    @mcp.tool()
    def get_status(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Get debugger state, selected architecture, pid, debuggee state, and current instruction pointer."""
        return _result("get_status", session_id=session_id, arch=arch)

    @mcp.tool()
    def get_bridge_info(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Get plugin version, protocol version, architecture, and lightweight runtime state."""
        return _result("get_bridge_info", session_id=session_id, arch=arch)

    @mcp.tool()
    def get_snapshot(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None, instruction_count: int = 8) -> dict:
        """Get a compact current-context snapshot: status, current module/symbol, registers, disassembly, and stack bytes."""
        return _result("get_snapshot", {"instruction_count": instruction_count}, session_id=session_id, arch=arch)

    @mcp.tool()
    def get_registers(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Read CPU registers and flags in one stable call."""
        return _result("get_registers", session_id=session_id, arch=arch)

    @mcp.tool()
    def set_register(register: str, value: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Set one register. Value accepts numeric strings and x64dbg expressions."""
        return _result("set_register", {"register": register, "value": value}, session_id=session_id, arch=arch)

    @mcp.tool()
    def read_memory(address: str, size: int, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Read debuggee memory. Address accepts x64dbg expressions; size is capped to keep responses bounded."""
        return _result("read_memory", {"address": address, "size": size}, session_id=session_id, arch=arch)

    @mcp.tool()
    def write_memory(address: str, hex_bytes: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Write debuggee memory from hex bytes such as '90 90 CC'. Address accepts expressions. Use carefully."""
        return _result("write_memory", {"address": address, "hex_bytes": hex_bytes}, session_id=session_id, arch=arch)

    @mcp.tool()
    def disassemble(address: str, count: int = 16, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Disassemble up to 128 instructions from an address or x64dbg expression such as cip."""
        return _result("disassemble", {"address": address, "count": count}, session_id=session_id, arch=arch)

    @mcp.tool()
    def parse_expression(expression: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Resolve an x64dbg expression such as cip, module+offset, label, symbol, or [rsp+8]."""
        return _result("parse_expression", {"expression": expression}, session_id=session_id, arch=arch)

    @mcp.tool()
    def evaluate_expressions(expressions: list[str], session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Resolve up to 256 x64dbg expressions in one call, returning per-expression success."""
        return _result("evaluate_expressions", {"expressions": expressions}, session_id=session_id, arch=arch)

    @mcp.tool()
    def get_branch_destination(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Resolve a branch/call/jump target. Falls back to readable indirect memory operands."""
        return _result("get_branch_destination", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def find_pattern(pattern: str, start: str | None = None, size: str | None = None, module: str | None = None, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Find the first memory match for an x64dbg byte pattern. Use either module or start+size."""
        params: dict[str, object] = {"pattern": pattern}
        if module:
            params["module"] = module
        else:
            params["start"] = start or ""
            params["size"] = size or ""
        return _result("find_pattern", params, session_id=session_id, arch=arch, timeout_ms=15000)

    @mcp.tool()
    def find_all_patterns(pattern: str, start: str | None = None, size: str | None = None, module: str | None = None, limit: int = 100, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Find bounded memory matches for an x64dbg byte pattern. Use either module or start+size."""
        params: dict[str, object] = {"pattern": pattern, "limit": limit}
        if module:
            params["module"] = module
        else:
            params["start"] = start or ""
            params["size"] = size or ""
        return _result("find_all_patterns", params, session_id=session_id, arch=arch, timeout_ms=30000)

    @mcp.tool()
    def find_strings(
        start: str | None = None,
        size: str | None = None,
        module: str | None = None,
        ascii: bool = True,
        unicode: bool = True,
        min_length: int = 4,
        contains: str | None = None,
        limit: int = 500,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Find ASCII/UTF-16LE strings in a module or explicit range with filters and bounds."""
        params: dict[str, object] = {
            "ascii": ascii,
            "unicode": unicode,
            "min_length": min_length,
            "contains": contains,
            "limit": limit,
        }
        if module:
            params["module"] = module
        else:
            params["start"] = start or ""
            params["size"] = size or ""
        return _result("find_strings", params, session_id=session_id, arch=arch, timeout_ms=30000)

    @mcp.tool()
    def find_instructions(
        start: str | None = None,
        size: str | None = None,
        module: str | None = None,
        mnemonic: str | None = None,
        contains: str | None = None,
        operand_contains: str | None = None,
        kind: Literal["any", "branch", "call", "jump", "conditional_jump", "return", "memory", "stack", "normal"] = "any",
        executable_only: bool = True,
        case_sensitive: bool = False,
        include_details: bool = False,
        max_instructions: int = 50000,
        limit: int = 500,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Search disassembly by mnemonic, text, operand text, or instruction kind in a module or range."""
        params: dict[str, object] = {
            "mnemonic": mnemonic,
            "contains": contains,
            "operand_contains": operand_contains,
            "kind": kind,
            "executable_only": executable_only,
            "case_sensitive": case_sensitive,
            "include_details": include_details,
            "max_instructions": max_instructions,
            "limit": limit,
        }
        if module:
            params["module"] = module
        else:
            params["start"] = start or ""
            params["size"] = size or ""
        return _result("find_instructions", params, session_id=session_id, arch=arch, timeout_ms=30000)

    @mcp.tool()
    def list_calls_in_range(start: str, size: str, max_instructions: int = 512, limit: int = 200, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Extract calls, jumps, conditional jumps, and returns from a disassembly range."""
        return _result("list_calls_in_range", {"start": start, "size": size, "max_instructions": max_instructions, "limit": limit}, session_id=session_id, arch=arch, timeout_ms=15000)

    @mcp.tool()
    def list_calls_in_function(address: str, max_instructions: int = 1000, limit: int = 200, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Extract calls and branches from the x64dbg-analyzed function containing address."""
        return _result("list_calls_in_function", {"address": address, "max_instructions": max_instructions, "limit": limit}, session_id=session_id, arch=arch, timeout_ms=15000)

    @mcp.tool()
    def analyze_function(address: str, max_instructions: int = 1000, call_limit: int = 200, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Summarize an x64dbg-analyzed function with bounds, context, and branch/call inventory."""
        return _result("analyze_function", {"address": address, "max_instructions": max_instructions, "call_limit": call_limit}, session_id=session_id, arch=arch, timeout_ms=15000)

    @mcp.tool()
    def analyze_linear_block(address: str, max_instructions: int = 128, include_instructions: bool = True, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Linearly disassemble from an address until ret/jmp/invalid/limit; fallback when function bounds are missing."""
        return _result("analyze_linear_block", {"address": address, "max_instructions": max_instructions, "include_instructions": include_instructions}, session_id=session_id, arch=arch, timeout_ms=15000)

    @mcp.tool()
    def list_functions(module: str | None = None, offset: int = 0, limit: int = 500, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List x64dbg-known functions with optional module filter and pagination."""
        return _result("list_functions", {"module": module, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def find_references_to_range(
        start: str,
        size: str,
        scan_module: str | None = None,
        max_instructions: int = 50000,
        limit: int = 500,
        include_readonly_code_like_sections: bool = False,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Scan code pages for operands or branch targets pointing into a target range."""
        return _result(
            "find_references_to_range",
            {
                "start": start,
                "size": size,
                "scan_module": scan_module,
                "max_instructions": max_instructions,
                "limit": limit,
                "include_readonly_code_like_sections": include_readonly_code_like_sections,
            },
            session_id=session_id,
            arch=arch,
            timeout_ms=30000,
        )

    @mcp.tool()
    def find_references_to_module(
        module: str,
        scan_module: str | None = None,
        max_instructions: int = 50000,
        limit: int = 500,
        include_readonly_code_like_sections: bool = False,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Scan code pages for operands or branch targets pointing into a loaded module."""
        return _result(
            "find_references_to_module",
            {
                "module": module,
                "scan_module": scan_module,
                "max_instructions": max_instructions,
                "limit": limit,
                "include_readonly_code_like_sections": include_readonly_code_like_sections,
            },
            session_id=session_id,
            arch=arch,
            timeout_ms=30000,
        )

    @mcp.tool()
    def inspect_import_thunk(address: str, module: str | None = None, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Resolve an IAT slot address to its owning module import record and current pointer value."""
        return _result("inspect_import_thunk", {"address": address, "module": module}, session_id=session_id, arch=arch)

    @mcp.tool()
    def snapshot_break_context(instruction_count: int = 8, stack_slots: int = 8, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Get current paused/break context: snapshot, current inspection, stack slots, and call stack."""
        return _result("snapshot_break_context", {"instruction_count": instruction_count, "stack_slots": stack_slots}, session_id=session_id, arch=arch)

    @mcp.tool()
    def get_call_stack(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Return the current call stack with frame addresses and x64dbg comments."""
        return _result("get_call_stack", session_id=session_id, arch=arch)

    @mcp.tool()
    def get_symbol_at(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Return symbol information for an address or expression when x64dbg has one loaded."""
        return _result("get_symbol_at", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def get_string_at(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Ask x64dbg to decode a string at an address or expression."""
        return _result("get_string_at", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def get_xrefs(address: str, limit: int = 500, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List known xrefs to an address or expression from x64dbg's analysis database."""
        return _result("get_xrefs", {"address": address, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_address(address: str, data_only: bool = False, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Inspect one address. data_only skips disassembly for IAT/data pointers."""
        return _result("inspect_address", {"address": address, "data_only": data_only}, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_instruction(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Decode one instruction with operands, memory operand details, branch target, module, and symbol context."""
        return _result("inspect_instruction", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def read_pointer(address: str, owner_module: str | None = None, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Read a pointer-sized value and annotate the target when non-null."""
        return _result("read_pointer", {"address": address, "owner_module": owner_module}, session_id=session_id, arch=arch)

    @mcp.tool()
    def deref_chain(address: str, depth: int = 4, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Follow pointer-sized reads until null, unreadable memory, or max depth."""
        return _result("deref_chain", {"address": address, "depth": depth}, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_stack(address: str | None = None, slots: int = 32, include_strings: bool = True, owner_module: str | None = None, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Annotate stack slots as pointers, strings, symbols, modules, and possible return addresses."""
        params: dict[str, object] = {"slots": slots, "include_strings": include_strings, "owner_module": owner_module}
        if address:
            params["address"] = address
        return _result("inspect_stack", params, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_call_args(
        address: str | None = None,
        count: int = 6,
        convention: Literal["auto", "cdecl", "stdcall", "thiscall", "fastcall", "windows_x64"] = "auto",
        stack_mode: Literal["callee", "before_call"] = "callee",
        include_strings: bool = True,
        owner_module: str | None = None,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Annotate likely call arguments from current registers and stack slots."""
        params: dict[str, object] = {
            "count": count,
            "convention": convention,
            "stack_mode": stack_mode,
            "include_strings": include_strings,
            "owner_module": owner_module,
        }
        if address:
            params["address"] = address
        return _result("inspect_call_args", params, session_id=session_id, arch=arch)

    @mcp.tool()
    def find_pointers_to_range(
        target_start: str,
        target_size: str,
        scan_module: str | None = None,
        scan_start: str | None = None,
        scan_size: str | None = None,
        include_system: bool = False,
        aligned_only: bool = True,
        limit: int = 500,
        max_scan_bytes: int = 64 * 1024 * 1024,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Scan readable memory for pointer-sized values into a target range."""
        params: dict[str, object] = {
            "target_start": target_start,
            "target_size": target_size,
            "include_system": include_system,
            "aligned_only": aligned_only,
            "limit": limit,
            "max_scan_bytes": max_scan_bytes,
        }
        if scan_module:
            params["scan_module"] = scan_module
        elif scan_start and scan_size:
            params["scan_start"] = scan_start
            params["scan_size"] = scan_size
        return _result("find_pointers_to_range", params, session_id=session_id, arch=arch, timeout_ms=30000)

    @mcp.tool()
    def run(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Resume debuggee execution."""
        return _result("run", session_id=session_id, arch=arch)

    @mcp.tool()
    def pause(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Pause debuggee execution."""
        return _result("pause", session_id=session_id, arch=arch)

    @mcp.tool()
    def stop(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Stop the current debugging session."""
        return _result("stop", session_id=session_id, arch=arch)

    @mcp.tool()
    def step(kind: Literal["into", "over", "out"] = "into", session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Step into, over, or out, then return a fresh snapshot."""
        return _result("step", {"kind": kind}, session_id=session_id, arch=arch)

    @mcp.tool()
    def wait_for_pause(
        timeout_ms: int = 10000,
        poll_ms: int = 25,
        instruction_count: int = 8,
        include_context: bool = True,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Wait bounded time for a running debuggee to pause, returning status and optional break context."""
        return _result(
            "wait_for_pause",
            {
                "timeout_ms": timeout_ms,
                "poll_ms": poll_ms,
                "instruction_count": instruction_count,
                "include_context": include_context,
            },
            session_id=session_id,
            arch=arch,
            timeout_ms=max(timeout_ms, 0) + 5000,
        )

    @mcp.tool()
    def run_until(
        address: str,
        timeout_ms: int = 10000,
        temporary: bool = True,
        keep_breakpoint_on_timeout: bool = False,
        poll_ms: int = 25,
        instruction_count: int = 8,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Set a temporary software breakpoint, run, and wait bounded time for the target address."""
        return _result(
            "run_until",
            {
                "address": address,
                "timeout_ms": timeout_ms,
                "temporary": temporary,
                "keep_breakpoint_on_timeout": keep_breakpoint_on_timeout,
                "poll_ms": poll_ms,
                "instruction_count": instruction_count,
            },
            session_id=session_id,
            arch=arch,
            timeout_ms=max(timeout_ms, 0) + 5000,
        )

    @mcp.tool()
    def wait_for_module(
        module: str,
        timeout_ms: int = 15000,
        poll_ms: int = 100,
        run: bool = True,
        pause_on_found: bool = True,
        instruction_count: int = 8,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Run or poll until a module is loaded, optionally pausing and returning a snapshot when found."""
        return _result(
            "wait_for_module",
            {
                "module": module,
                "timeout_ms": timeout_ms,
                "poll_ms": poll_ms,
                "run": run,
                "pause_on_found": pause_on_found,
                "instruction_count": instruction_count,
            },
            session_id=session_id,
            arch=arch,
            timeout_ms=max(timeout_ms, 0) + 5000,
        )

    @mcp.tool()
    def set_breakpoint(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Set a normal software breakpoint at an address or expression."""
        return _result("set_breakpoint", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def remove_breakpoint(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Remove a normal software breakpoint at an address or expression."""
        return _result("remove_breakpoint", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def set_hardware_breakpoint(address: str, type: Literal["execute", "write", "access"] = "execute", session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Set a CPU hardware breakpoint at an address or expression. Only four slots are available."""
        return _result("set_hardware_breakpoint", {"address": address, "type": type}, session_id=session_id, arch=arch)

    @mcp.tool()
    def remove_hardware_breakpoint(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Remove a CPU hardware breakpoint at an address or expression."""
        return _result("remove_hardware_breakpoint", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def set_breakpoint_options(
        address: str,
        type: Literal["normal", "software", "hardware", "memory"] = "normal",
        name: str | None = None,
        condition: str | None = None,
        log_text: str | None = None,
        log_condition: str | None = None,
        command_text: str | None = None,
        command_condition: str | None = None,
        fast_resume: bool | None = None,
        single_shot: bool | None = None,
        silent: bool | None = None,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Set name, conditions, logging, command, singleshot, silent, or fast-resume flags on a breakpoint."""
        return _result(
            "set_breakpoint_options",
            {
                "address": address,
                "type": type,
                "name": name,
                "condition": condition,
                "log_text": log_text,
                "log_condition": log_condition,
                "command_text": command_text,
                "command_condition": command_condition,
                "fast_resume": fast_resume,
                "single_shot": single_shot,
                "silent": silent,
            },
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def set_memory_breakpoint(
        address: str,
        size: str | None = None,
        type: Literal["access", "read", "write", "execute"] = "access",
        restore: bool = True,
        single_shot: bool = False,
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
    ) -> dict:
        """Set a memory breakpoint. Omit size for region mode; pass size for an exact range."""
        return _result(
            "set_memory_breakpoint",
            {"address": address, "size": size, "type": type, "restore": restore, "single_shot": single_shot},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def remove_memory_breakpoint(address: str | None = None, remove_all: bool = False, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Remove one memory breakpoint. Use remove_all=True only when intentionally clearing all memory breakpoints."""
        return _result("remove_memory_breakpoint", {"address": address, "all": remove_all}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_breakpoints(
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
        type: Literal["all", "normal", "software", "hardware", "memory", "dll", "exception"] = "all",
        enabled_only: bool = False,
        active_only: bool = False,
        module: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> dict:
        """List normal, hardware, memory, DLL, and exception breakpoints with filters and pagination."""
        return _result(
            "list_breakpoints",
            {"type": type, "enabled_only": enabled_only, "active_only": active_only, "module": module, "offset": offset, "limit": limit},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def resolve_breakpoints(
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
        type: Literal["all", "normal", "software", "hardware", "memory", "dll", "exception"] = "all",
        enabled_only: bool = False,
        active_only: bool = False,
        module: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> dict:
        """Resolve breakpoint module+rva records to absolute addresses when their module is loaded."""
        return _result(
            "resolve_breakpoints",
            {"type": type, "enabled_only": enabled_only, "active_only": active_only, "module": module, "offset": offset, "limit": limit},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def list_unresolved_breakpoints(
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
        type: Literal["all", "normal", "software", "hardware", "memory", "dll", "exception"] = "all",
        enabled_only: bool = False,
        active_only: bool = False,
        module: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> dict:
        """List persisted module breakpoints whose target module is not currently loaded."""
        return _result(
            "list_unresolved_breakpoints",
            {"type": type, "enabled_only": enabled_only, "active_only": active_only, "module": module, "offset": offset, "limit": limit},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def list_modules(
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
        module: str | None = None,
        path_contains: str | None = None,
        non_system: bool = False,
        offset: int = 0,
        limit: int = 200,
    ) -> dict:
        """List loaded modules with optional module, path, non-system, offset, and limit filters."""
        return _result(
            "list_modules",
            {"module": module, "path_contains": path_contains, "non_system": non_system, "offset": offset, "limit": limit},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def get_module_at(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Return the loaded module and RVA for an address or x64dbg expression."""
        return _result("get_module_at", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_module_sections(module: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List sections for one loaded module, including VA/RVA, size, and current page protection."""
        return _result("list_module_sections", {"module": module}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_module_imports(module: str, offset: int = 0, limit: int = 500, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List imports for one loaded module with IAT addresses and pagination."""
        return _result("list_module_imports", {"module": module, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_module_exports(module: str, offset: int = 0, limit: int = 500, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List exports for one loaded module with addresses, ordinals, forwarding, and pagination."""
        return _result("list_module_exports", {"module": module, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_iat(module: str, offset: int = 0, limit: int = 500, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List IAT entries with current pointer values and pointer classification."""
        return _result("list_iat", {"module": module, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_pe_headers(module: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Inspect in-memory PE headers, data directories, sections, entrypoint, and CLR directory presence."""
        return _result("inspect_pe_headers", {"module": module}, session_id=session_id, arch=arch)

    @mcp.tool()
    def inspect_clr_metadata(module: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Inspect CLR header and metadata stream table for a managed or mixed-mode module."""
        return _result("inspect_clr_metadata", {"module": module}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_threads(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """List debuggee threads and identify the current thread."""
        return _result("list_threads", session_id=session_id, arch=arch)

    @mcp.tool()
    def get_memory_map(
        session_id: str | None = None,
        arch: Literal["x64", "x32"] | None = None,
        module: str | None = None,
        state: Literal["commit", "reserve", "free"] | None = None,
        type: Literal["image", "mapped", "private"] | None = None,
        protect: str | None = None,
        readable_only: bool = False,
        offset: int = 0,
        limit: int = 500,
    ) -> dict:
        """List mapped memory pages with filters and pagination."""
        return _result(
            "get_memory_map",
            {"module": module, "state": state, "type": type, "protect": protect, "readable_only": readable_only, "offset": offset, "limit": limit},
            session_id=session_id,
            arch=arch,
        )

    @mcp.tool()
    def get_page_at(address: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Return the memory page containing an address or expression."""
        return _result("get_page_at", {"address": address}, session_id=session_id, arch=arch)

    @mcp.tool()
    def query_symbols(module: str, offset: int = 0, limit: int = 5000, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Query symbols for one module. Call list_modules first when unsure of the module name."""
        return _result("query_symbols", {"module": module, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def list_labels(session_id: str | None = None, arch: Literal["x64", "x32"] | None = None, module: str | None = None, contains: str | None = None, offset: int = 0, limit: int = 500) -> dict:
        """List labels currently known to x64dbg/x32dbg with filters and pagination."""
        return _result("list_labels", {"module": module, "contains": contains, "offset": offset, "limit": limit}, session_id=session_id, arch=arch)

    @mcp.tool()
    def set_label(address: str, text: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Set a label at an address or expression."""
        return _result("set_label", {"address": address, "text": text}, session_id=session_id, arch=arch)

    @mcp.tool()
    def set_comment(address: str, text: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Set a disassembly comment at an address or expression."""
        return _result("set_comment", {"address": address, "text": text}, session_id=session_id, arch=arch)

    @mcp.tool()
    def execute_command(command: str, session_id: str | None = None, arch: Literal["x64", "x32"] | None = None) -> dict:
        """Execute one x64dbg command. Prefer typed tools first; use this for expert workflows."""
        return _result("execute_command", {"command": command}, session_id=session_id, arch=arch)

    return mcp


def main() -> None:
    create_server().run()
