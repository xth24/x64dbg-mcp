#include "debugger_tools.h"

#include "json_helpers.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace {

std::vector<BRIDGEBP> breakpoint_list(BPXTYPE type) {
    BPMAP map{};
    std::vector<BRIDGEBP> out;
    const int count = DbgGetBpList(type, &map);
    if (count <= 0 || !map.bp) {
        return out;
    }
    out.reserve(map.count);
    for (int i = 0; i < map.count; ++i) {
        out.push_back(map.bp[i]);
    }
    BridgeFree(map.bp);
    return out;
}

bool has_normal_breakpoint_at(duint address) {
    for (const auto& bp : breakpoint_list(bp_normal)) {
        if (bp.addr == address) {
            return true;
        }
    }
    return false;
}

std::optional<Script::Module::ModuleInfo> safe_find_module_by_name(const std::string& name) {
    try {
        return find_module_by_name(name);
    } catch (const ApiError&) {
        return std::nullopt;
    }
}

std::optional<duint> optional_size_value(const nlohmann::json& params, const char* key) {
    if (!params.contains(key) || params[key].is_null()) {
        return std::nullopt;
    }
    if (params[key].is_number_unsigned()) {
        return static_cast<duint>(params[key].get<unsigned long long>());
    }
    if (params[key].is_number_integer()) {
        const auto value = params[key].get<long long>();
        if (value < 0) {
            throw ApiError("bad_request", std::string("Expected non-negative size parameter: ") + key);
        }
        return static_cast<duint>(value);
    }
    if (params[key].is_string()) {
        return parse_address(params, key);
    }
    throw ApiError("bad_request", std::string("Expected integer or expression size parameter: ") + key);
}

std::string memory_breakpoint_type_code(std::string type) {
    type = lower_ascii(type.empty() ? "access" : type);
    if (type == "access" || type == "all" || type == "a") return "a";
    if (type == "read" || type == "r") return "r";
    if (type == "write" || type == "w") return "w";
    if (type == "execute" || type == "exec" || type == "x") return "x";
    throw ApiError("bad_request", "Memory breakpoint type must be access, read, write, or execute.");
}

std::string memory_breakpoint_type_name(const std::string& code) {
    if (code == "r") return "read";
    if (code == "w") return "write";
    if (code == "x") return "execute";
    return "access";
}

ULONGLONG elapsed_since(ULONGLONG start) {
    return GetTickCount64() - start;
}

nlohmann::json wait_for_pause(int timeout_ms, int poll_ms, int instruction_count) {
    const ULONGLONG start = GetTickCount64();
    const auto timeout = static_cast<ULONGLONG>(timeout_ms);

    while (DbgIsDebugging() && DbgIsRunning()) {
        const ULONGLONG elapsed = elapsed_since(start);
        if (elapsed >= timeout) {
            return {
                {"stopped", false},
                {"timed_out", true},
                {"elapsed_ms", elapsed},
                {"status", tool_get_status({})},
            };
        }
        const ULONGLONG remaining = timeout - elapsed;
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(static_cast<ULONGLONG>(poll_ms), remaining)));
    }

    nlohmann::json out = {
        {"stopped", !DbgIsRunning()},
        {"timed_out", false},
        {"elapsed_ms", elapsed_since(start)},
        {"status", tool_get_status({})},
    };
    if (DbgIsDebugging()) {
        out["snapshot"] = tool_get_snapshot({{"instruction_count", instruction_count}});
    }
    return out;
}

nlohmann::json wait_for_target_or_pause(duint target, int timeout_ms, int poll_ms, int instruction_count) {
    const ULONGLONG start = GetTickCount64();
    const auto timeout = static_cast<ULONGLONG>(timeout_ms);
    bool saw_running = DbgIsRunning();

    while (DbgIsDebugging()) {
        const bool running = DbgIsRunning();
        saw_running = saw_running || running;
        const duint cip = Script::Register::Get(kInstructionPointer);
        if (!running && (saw_running || cip == target)) {
            nlohmann::json out = {
                {"stopped", true},
                {"timed_out", false},
                {"saw_running", saw_running},
                {"elapsed_ms", elapsed_since(start)},
                {"status", tool_get_status({})},
                {"snapshot", tool_get_snapshot({{"instruction_count", instruction_count}})},
            };
            return out;
        }

        const ULONGLONG elapsed = elapsed_since(start);
        if (elapsed >= timeout) {
            return {
                {"stopped", false},
                {"timed_out", true},
                {"saw_running", saw_running},
                {"elapsed_ms", elapsed},
                {"status", tool_get_status({})},
            };
        }
        const ULONGLONG remaining = timeout - elapsed;
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(static_cast<ULONGLONG>(poll_ms), remaining)));
    }

    return {
        {"stopped", false},
        {"timed_out", false},
        {"debugging", false},
        {"saw_running", saw_running},
        {"elapsed_ms", elapsed_since(start)},
        {"status", tool_get_status({})},
    };
}

nlohmann::json memory_breakpoint_json(const BRIDGEBP& bp) {
    return {
        {"type", "memory"},
        {"address", hex_value(bp.addr)},
        {"enabled", bp.enabled != 0},
        {"active", bp.active != 0},
        {"single_shot", bp.singleshoot != 0},
        {"module", bp.mod},
        {"name", bp.name},
        {"hit_count", bp.hitCount},
        {"silent", bp.silent != 0},
        {"fast_resume", bp.fastResume != 0},
        {"slot", bp.slot},
        {"type_ex", bp.typeEx},
        {"hardware_size", bp.hwSize},
        {"break_condition", bp.breakCondition},
        {"log_text", bp.logText},
        {"log_condition", bp.logCondition},
        {"command_text", bp.commandText},
        {"command_condition", bp.commandCondition},
    };
}

nlohmann::json memory_breakpoints_page() {
    const auto breakpoints = breakpoint_list(bp_memory);
    nlohmann::json items = nlohmann::json::array();
    const int limit = 100;
    for (size_t i = 0; i < breakpoints.size() && i < static_cast<size_t>(limit); ++i) {
        items.push_back(memory_breakpoint_json(breakpoints[i]));
    }
    return {
        {"total", breakpoints.size()},
        {"offset", 0},
        {"limit", limit},
        {"count", items.size()},
        {"truncated", breakpoints.size() > static_cast<size_t>(limit)},
        {"breakpoints", items},
    };
}

} // namespace

nlohmann::json tool_wait_for_pause(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const int timeout_ms = parse_int(params, "timeout_ms", 10000, 0, 300000);
    const int poll_ms = parse_int(params, "poll_ms", 25, 10, 1000);
    const int instruction_count = parse_int(params, "instruction_count", 4, 1, 32);
    const bool include_context = parse_bool(params, "include_context", false);
    nlohmann::json result = wait_for_pause(timeout_ms, poll_ms, instruction_count);
    result["action"] = "wait_for_pause";
    if (include_context && DbgIsDebugging() && !DbgIsRunning()) {
        result["break_context"] = tool_snapshot_break_context({{"instruction_count", instruction_count}, {"stack_slots", 4}});
    }
    return result;
}

nlohmann::json tool_run_until(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const duint address = parse_address(params, "address");
    const int timeout_ms = parse_int(params, "timeout_ms", 10000, 0, 300000);
    const int poll_ms = parse_int(params, "poll_ms", 25, 10, 1000);
    const int instruction_count = parse_int(params, "instruction_count", 4, 1, 32);
    const bool temporary = parse_bool(params, "temporary", true);
    const bool keep_on_timeout = parse_bool(params, "keep_breakpoint_on_timeout", false);

    if (!DbgIsRunning() && Script::Register::Get(kInstructionPointer) == address) {
        return {
            {"action", "run_until"},
            {"address", hex_value(address)},
            {"already_at_target", true},
            {"hit", true},
            {"status", tool_get_status({})},
            {"snapshot", tool_get_snapshot({{"instruction_count", instruction_count}})},
        };
    }

    const bool existed = has_normal_breakpoint_at(address);
    const bool breakpoint_set = existed || Script::Debug::SetBreakpoint(address);
    if (!breakpoint_set) {
        throw ApiError("debugger_error", "Failed to set run_until software breakpoint.");
    }

    const bool run_queued = DbgCmdExec("run");
    if (!run_queued) {
        if (temporary && !existed) {
            Script::Debug::DeleteBreakpoint(address);
        }
        throw ApiError("debugger_error", "Failed to queue run command for run_until.");
    }
    nlohmann::json wait = wait_for_target_or_pause(address, timeout_ms, poll_ms, instruction_count);

    bool hit = false;
    if (DbgIsDebugging() && !DbgIsRunning()) {
        hit = Script::Register::Get(kInstructionPointer) == address;
    }

    bool removed = false;
    bool remove_attempted = false;
    const bool should_remove = temporary && !existed && (!wait.value("timed_out", false) || !keep_on_timeout);
    if (should_remove) {
        remove_attempted = true;
        removed = Script::Debug::DeleteBreakpoint(address);
    }

    nlohmann::json out = {
        {"action", "run_until"},
        {"address", hex_value(address)},
        {"hit", hit},
        {"temporary", temporary},
        {"run_queued", run_queued},
        {"breakpoint_existed", existed},
        {"breakpoint_set", breakpoint_set},
        {"breakpoint_remove_attempted", remove_attempted},
        {"breakpoint_removed", removed},
        {"breakpoint_left", temporary ? (existed || !remove_attempted || !removed) : true},
        {"wait", wait},
    };
    if (DbgIsDebugging() && !DbgIsRunning()) {
        out["stop_address"] = hex_value(Script::Register::Get(kInstructionPointer));
        out["stop_reason"] = hit ? "target" : "paused_before_target";
    } else if (wait.value("timed_out", false)) {
        out["stop_reason"] = "timeout";
    }
    return out;
}

nlohmann::json tool_wait_for_module(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const std::string module_name = required_string(params, "module");
    const int timeout_ms = parse_int(params, "timeout_ms", 15000, 0, 300000);
    const int poll_ms = parse_int(params, "poll_ms", 100, 25, 2000);
    const int instruction_count = parse_int(params, "instruction_count", 4, 1, 32);
    const bool run_debuggee = parse_bool(params, "run", true);
    const bool pause_on_found = parse_bool(params, "pause_on_found", true);
    const ULONGLONG start = GetTickCount64();

    bool run_queued = false;
    if (run_debuggee && !DbgIsRunning() && !safe_find_module_by_name(module_name)) {
        run_queued = DbgCmdExec("run");
        if (!run_queued) {
            return {
                {"action", "wait_for_module"},
                {"module", module_name},
                {"found", false},
                {"timed_out", false},
                {"run_queued", false},
                {"reason", "run_queue_failed"},
                {"elapsed_ms", elapsed_since(start)},
                {"status", tool_get_status({})},
            };
        }
    }

    while (DbgIsDebugging()) {
        if (const auto module = safe_find_module_by_name(module_name)) {
            bool pause_requested = false;
            bool pause_queued = false;
            nlohmann::json pause_wait = nullptr;
            if (pause_on_found && DbgIsRunning()) {
                pause_requested = true;
                pause_queued = DbgCmdExec("pause");
                pause_wait = pause_queued
                    ? wait_for_pause(2000, 25, instruction_count)
                    : nlohmann::json({{"stopped", false}, {"timed_out", false}, {"reason", "pause_queue_failed"}});
            }
            nlohmann::json out = {
                {"action", "wait_for_module"},
                {"module", module_name},
                {"found", true},
                {"timed_out", false},
                {"elapsed_ms", elapsed_since(start)},
                {"loaded_module", module_info_json(*module)},
                {"run_queued", run_queued},
                {"pause_requested", pause_requested},
                {"pause_queued", pause_queued},
                {"pause_wait", pause_wait},
                {"status", tool_get_status({})},
            };
            if (DbgIsDebugging() && !DbgIsRunning()) {
                out["snapshot"] = tool_get_snapshot({{"instruction_count", instruction_count}});
            }
            return out;
        }

        const ULONGLONG elapsed = elapsed_since(start);
        if (elapsed >= static_cast<ULONGLONG>(timeout_ms)) {
            return {
                {"action", "wait_for_module"},
                {"module", module_name},
                {"found", false},
                {"timed_out", true},
                {"run_queued", run_queued},
                {"elapsed_ms", elapsed},
                {"status", tool_get_status({})},
            };
        }
        const ULONGLONG remaining = static_cast<ULONGLONG>(timeout_ms) - elapsed;
        Sleep(static_cast<DWORD>(std::min<ULONGLONG>(static_cast<ULONGLONG>(poll_ms), remaining)));
    }

    return {
        {"action", "wait_for_module"},
        {"module", module_name},
        {"found", false},
        {"timed_out", false},
        {"debugging", false},
        {"run_queued", run_queued},
        {"elapsed_ms", elapsed_since(start)},
        {"status", tool_get_status({})},
    };
}

nlohmann::json tool_set_memory_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const duint address = parse_address(params, "address");
    const std::optional<duint> size = optional_size_value(params, "size");
    const std::string type_code = memory_breakpoint_type_code(optional_string(params, "type", "access"));
    bool restore = parse_bool(params, "restore", true);
    const bool single_shot = parse_bool(params, "single_shot", false);
    if ((!size || *size == 0) && single_shot) {
        restore = false;
    }

    std::string command;
    std::string mode;
    if (size && *size > 0) {
        mode = "range";
        command = "bpmrange " + hex_value(address) + ", " + hex_value(*size) + ", " + type_code + (single_shot ? "ss" : "");
    } else {
        mode = "region";
        command = "bpm " + hex_value(address) + ", " + (restore ? "1" : "0") + ", " + type_code;
    }

    const bool success = DbgCmdExecDirect(command.c_str());
    nlohmann::json out = {
        {"action", "set_memory_breakpoint"},
        {"address", hex_value(address)},
        {"mode", mode},
        {"type", memory_breakpoint_type_name(type_code)},
        {"restore", restore},
        {"single_shot", single_shot},
        {"command", command},
        {"success", success},
    };
    if (size) {
        out["size"] = hex_value(*size);
    }
    out["memory_breakpoints"] = memory_breakpoints_page();
    return out;
}

nlohmann::json tool_remove_memory_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const bool remove_all = parse_bool(params, "all", false);
    const std::string address_text = optional_string(params, "address");
    if (remove_all && !address_text.empty()) {
        throw ApiError("bad_request", "Pass either address or all=true, not both.");
    }
    if (address_text.empty() && !remove_all) {
        throw ApiError("bad_request", "Provide address or pass all=true to remove all memory breakpoints.");
    }

    std::string command = "bpmc";
    nlohmann::json out = {
        {"action", "remove_memory_breakpoint"},
        {"all", remove_all},
    };
    if (!remove_all) {
        nlohmann::json address_param = {{"address", address_text}};
        const duint address = parse_address(address_param, "address");
        command += " " + hex_value(address);
        out["address"] = hex_value(address);
    }

    out["command"] = command;
    out["success"] = DbgCmdExecDirect(command.c_str());
    out["memory_breakpoints"] = memory_breakpoints_page();
    return out;
}
