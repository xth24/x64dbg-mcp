#include "debugger_tools.h"

#include "json_helpers.h"
#include "module_utils.h"
#include "sdk.h"

#include <optional>
#include <string>
#include <vector>

namespace {

struct BreakpointRecord {
    BRIDGEBP bp;
    std::string type;
};

const char* breakpoint_type_name(BPXTYPE type) {
    switch (type) {
    case bp_normal: return "normal";
    case bp_hardware: return "hardware";
    case bp_memory: return "memory";
    case bp_dll: return "dll";
    case bp_exception: return "exception";
    default: return "unknown";
    }
}

std::vector<BPXTYPE> breakpoint_types_from_filter(const std::string& filter) {
    const std::string type = lower_ascii(filter.empty() ? "all" : filter);
    if (type == "all") {
        return {bp_normal, bp_hardware, bp_memory, bp_dll, bp_exception};
    }
    if (type == "normal" || type == "software") return {bp_normal};
    if (type == "hardware") return {bp_hardware};
    if (type == "memory") return {bp_memory};
    if (type == "dll") return {bp_dll};
    if (type == "exception") return {bp_exception};
    throw ApiError("bad_request", "Breakpoint type must be all, normal, hardware, memory, dll, or exception.");
}

std::vector<BreakpointRecord> get_breakpoint_records(const std::string& type_filter) {
    std::vector<BreakpointRecord> records;
    for (BPXTYPE type : breakpoint_types_from_filter(type_filter)) {
        BPMAP map{};
        const int count = DbgGetBpList(type, &map);
        if (count <= 0 || !map.bp) {
            continue;
        }
        for (int i = 0; i < map.count; ++i) {
            records.push_back({map.bp[i], breakpoint_type_name(map.bp[i].type)});
        }
        BridgeFree(map.bp);
    }
    return records;
}

std::vector<Script::Module::ModuleInfo> get_loaded_modules_or_empty() {
    try {
        return get_module_list();
    } catch (const ApiError&) {
        return {};
    }
}

std::optional<Script::Module::ModuleInfo> find_loaded_module_by_name(
    const std::vector<Script::Module::ModuleInfo>& modules,
    const std::string& name
) {
    if (name.empty()) {
        return std::nullopt;
    }
    for (const auto& module : modules) {
        if (_stricmp(module.name, name.c_str()) == 0) {
            return module;
        }
    }
    for (const auto& module : modules) {
        if (module_name_or_path_matches(module, name)) {
            return module;
        }
    }
    return std::nullopt;
}

std::optional<Script::Module::ModuleInfo> find_loaded_module_at(
    const std::vector<Script::Module::ModuleInfo>& modules,
    duint address
) {
    for (const auto& module : modules) {
        if (module_contains_address(module, address)) {
            return module;
        }
    }
    return std::nullopt;
}

nlohmann::json breakpoint_json(const BreakpointRecord& record) {
    const BRIDGEBP& bp = record.bp;
    return {
        {"type", record.type},
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

bool breakpoint_matches(
    const BreakpointRecord& record,
    const std::vector<Script::Module::ModuleInfo>& modules,
    bool enabled_only,
    bool active_only,
    const std::string& module_filter
) {
    const BRIDGEBP& bp = record.bp;
    if (enabled_only && !bp.enabled) {
        return false;
    }
    if (active_only && !bp.active) {
        return false;
    }
    if (module_filter.empty()) {
        return true;
    }
    if (contains_ascii_ci(bp.mod, module_filter)) {
        return true;
    }
    if (const auto module = find_loaded_module_at(modules, bp.addr)) {
        return module_name_or_path_matches(*module, module_filter);
    }
    return false;
}

nlohmann::json resolved_breakpoint_json(
    const BreakpointRecord& record,
    const std::vector<Script::Module::ModuleInfo>& modules
) {
    nlohmann::json out = breakpoint_json(record);
    const BRIDGEBP& bp = record.bp;
    const std::string requested_module = bp.mod;

    std::optional<Script::Module::ModuleInfo> module;
    if (!requested_module.empty()) {
        module = find_loaded_module_by_name(modules, requested_module);
    }
    if (!module) {
        module = find_loaded_module_at(modules, bp.addr);
    }

    if (!module) {
        out["resolved"] = false;
        out["reason"] = requested_module.empty() ? "no_loaded_module_for_address" : "module_not_loaded";
        if (!requested_module.empty()) {
            out["rva"] = hex_value(bp.addr);
        }
        return out;
    }

    const bool address_is_absolute = module_contains_address(*module, bp.addr);
    if (!address_is_absolute && bp.addr >= module->size) {
        out["resolved"] = false;
        out["reason"] = "rva_out_of_module";
        out["rva"] = hex_value(bp.addr);
        out["loaded_module"] = module_info_json(*module);
        return out;
    }
    const duint rva = address_is_absolute ? bp.addr - module->base : bp.addr;
    const duint absolute = address_is_absolute ? bp.addr : module->base + bp.addr;
    out["resolved"] = true;
    out["address_kind"] = address_is_absolute ? "absolute" : "rva";
    out["absolute_address"] = hex_value(absolute);
    out["rva"] = hex_value(rva);
    out["loaded_module"] = module_info_json(*module);
    return out;
}

template <typename Emit>
nlohmann::json filtered_breakpoint_response(const nlohmann::json& params, Emit emit) {
    const std::string type_filter = optional_string(params, "type", "all");
    const std::string module_filter = optional_string(params, "module");
    const bool enabled_only = parse_bool(params, "enabled_only", false);
    const bool active_only = parse_bool(params, "active_only", false);
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 500, 1, 5000);
    const auto modules = get_loaded_modules_or_empty();
    const auto records = get_breakpoint_records(type_filter);

    nlohmann::json breakpoints = nlohmann::json::array();
    nlohmann::json type_counts = nlohmann::json::object();
    int matched = 0;
    int emitted = 0;
    int enabled_total = 0;
    int active_total = 0;
    int resolved_total = 0;
    int unresolved_total = 0;
    bool has_resolved_state = false;
    for (const auto& record : records) {
        if (!breakpoint_matches(record, modules, enabled_only, active_only, module_filter)) {
            continue;
        }
        const auto item = emit(record, modules);
        if (item.is_null()) {
            continue;
        }
        type_counts[record.type] = type_counts.value(record.type, 0) + 1;
        if (record.bp.enabled) {
            ++enabled_total;
        }
        if (record.bp.active) {
            ++active_total;
        }
        if (item.contains("resolved") && item["resolved"].is_boolean()) {
            has_resolved_state = true;
            if (item["resolved"].template get<bool>()) {
                ++resolved_total;
            } else {
                ++unresolved_total;
            }
        }
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        breakpoints.push_back(item);
    }

    nlohmann::json summary = {
        {"matched_total", matched},
        {"enabled_total", enabled_total},
        {"active_total", active_total},
        {"type_counts", type_counts},
    };
    if (has_resolved_state) {
        summary["resolved_total"] = resolved_total;
        summary["unresolved_total"] = unresolved_total;
    }

    return {
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", breakpoints.size()},
        {"truncated", matched > offset + static_cast<int>(breakpoints.size())},
        {"summary", summary},
        {"breakpoints", breakpoints},
    };
}

} // namespace

nlohmann::json tool_run(const nlohmann::json&) {
    const bool queued = DbgCmdExec("run");
    nlohmann::json result = ok_status("run", queued);
    result["queued"] = queued;
    result["command"] = "run";
    result["status"] = tool_get_status({});
    return result;
}

nlohmann::json tool_pause(const nlohmann::json&) {
    const bool queued = DbgCmdExec("pause");
    nlohmann::json result = ok_status("pause", queued);
    result["queued"] = queued;
    result["command"] = "pause";
    result["status"] = tool_get_status({});
    return result;
}

nlohmann::json tool_stop(const nlohmann::json&) {
    const bool queued = DbgCmdExec("stop");
    nlohmann::json result = ok_status("stop", queued);
    result["queued"] = queued;
    result["command"] = "stop";
    result["status"] = tool_get_status({});
    return result;
}

nlohmann::json tool_step(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const std::string kind = params.value("kind", "into");
    if (kind == "into") {
        Script::Debug::StepIn();
    } else if (kind == "over") {
        Script::Debug::StepOver();
    } else if (kind == "out") {
        Script::Debug::StepOut();
    } else {
        throw ApiError("bad_request", "Step kind must be one of: into, over, out.");
    }

    nlohmann::json result = ok_status("step", true);
    result["kind"] = kind;
    result["snapshot"] = tool_get_snapshot({{"instruction_count", 8}});
    return result;
}

nlohmann::json tool_set_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    return {
        {"action", "set_breakpoint"},
        {"address", hex_value(address)},
        {"success", Script::Debug::SetBreakpoint(address)},
    };
}

nlohmann::json tool_remove_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    return {
        {"action", "remove_breakpoint"},
        {"address", hex_value(address)},
        {"success", Script::Debug::DeleteBreakpoint(address)},
    };
}

nlohmann::json tool_set_hardware_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const duint address = parse_address(params, "address");
    const std::string type = params.value("type", "execute");
    Script::Debug::HardwareType hardware_type = Script::Debug::HardwareExecute;
    if (type == "access") {
        hardware_type = Script::Debug::HardwareAccess;
    } else if (type == "write") {
        hardware_type = Script::Debug::HardwareWrite;
    } else if (type != "execute") {
        throw ApiError("bad_request", "Hardware breakpoint type must be execute, write, or access.");
    }

    return {
        {"action", "set_hardware_breakpoint"},
        {"address", hex_value(address)},
        {"type", type},
        {"success", Script::Debug::SetHardwareBreakpoint(address, hardware_type)},
    };
}

nlohmann::json tool_remove_hardware_breakpoint(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    return {
        {"action", "remove_hardware_breakpoint"},
        {"address", hex_value(address)},
        {"success", Script::Debug::DeleteHardwareBreakpoint(address)},
    };
}

nlohmann::json tool_list_breakpoints(const nlohmann::json& params) {
    return filtered_breakpoint_response(params, [](const BreakpointRecord& record, const auto&) {
        return breakpoint_json(record);
    });
}

nlohmann::json tool_resolve_breakpoints(const nlohmann::json& params) {
    return filtered_breakpoint_response(params, [](const BreakpointRecord& record, const auto& modules) {
        return resolved_breakpoint_json(record, modules);
    });
}

nlohmann::json tool_list_unresolved_breakpoints(const nlohmann::json& params) {
    return filtered_breakpoint_response(params, [](const BreakpointRecord& record, const auto& modules) -> nlohmann::json {
        const std::string requested_module = record.bp.mod;
        if (requested_module.empty()) {
            return nullptr;
        }
        if (find_loaded_module_by_name(modules, requested_module)) {
            return nullptr;
        }
        nlohmann::json out = breakpoint_json(record);
        out["resolved"] = false;
        out["reason"] = "module_not_loaded";
        out["rva"] = hex_value(record.bp.addr);
        return out;
    });
}

nlohmann::json tool_execute_command(const nlohmann::json& params) {
    const std::string command = required_string(params, "command");
    if (command.empty()) {
        throw ApiError("bad_request", "Command must not be empty.");
    }
    return {
        {"action", "execute_command"},
        {"command", command},
        {"success", DbgCmdExecDirect(command.c_str())},
    };
}
