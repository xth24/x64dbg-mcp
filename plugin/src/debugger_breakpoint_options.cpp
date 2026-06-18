#include "debugger_tools.h"

#include "json_helpers.h"
#include "module_utils.h"
#include "sdk.h"

#include <optional>
#include <string>

namespace {

struct BreakpointOptionCommands {
    std::string name;
    std::string condition;
    std::string log;
    std::string log_condition;
    std::string command;
    std::string command_condition;
    std::string fast_resume;
    std::string single_shot;
    std::string silent;
};

std::string command_string_arg(const std::string& value) {
    std::string out = "\"";
    for (char ch : value) {
        if (ch == '\\' || ch == '"') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

std::optional<bool> optional_bool(const nlohmann::json& params, const char* key) {
    if (!params.contains(key) || params[key].is_null()) {
        return std::nullopt;
    }
    if (!params[key].is_boolean()) {
        throw ApiError("bad_request", std::string("Expected boolean parameter: ") + key);
    }
    return params[key].get<bool>();
}

std::optional<std::string> optional_present_string(const nlohmann::json& params, const char* key) {
    if (!params.contains(key) || params[key].is_null()) {
        return std::nullopt;
    }
    if (!params[key].is_string()) {
        throw ApiError("bad_request", std::string("Expected string parameter: ") + key);
    }
    return params[key].get<std::string>();
}

BreakpointOptionCommands breakpoint_option_commands(std::string type) {
    type = lower_ascii(type.empty() ? "normal" : type);
    if (type == "normal" || type == "software") {
        return {
            "bpname",
            "bpcond",
            "bplog",
            "bplogcondition",
            "SetBreakpointCommand",
            "SetBreakpointCommandCondition",
            "SetBreakpointFastResume",
            "SetBreakpointSingleshoot",
            "SetBreakpointSilent",
        };
    }
    if (type == "hardware") {
        return {
            "bphwname",
            "bphwcond",
            "bphwlog",
            "bphwlogcondition",
            "SetHardwareBreakpointCommand",
            "SetHardwareBreakpointCommandCondition",
            "SetHardwareBreakpointFastResume",
            "SetHardwareBreakpointSingleshoot",
            "SetHardwareBreakpointSilent",
        };
    }
    if (type == "memory") {
        return {
            "bpmname",
            "bpmcond",
            "bpmlog",
            "bpmlogcondition",
            "SetMemoryBreakpointCommand",
            "SetMemoryBreakpointCommandCondition",
            "SetMemoryBreakpointFastResume",
            "SetMemoryBreakpointSingleshoot",
            "SetMemoryBreakpointSilent",
        };
    }
    throw ApiError("bad_request", "Breakpoint type must be normal, hardware, or memory.");
}

void append_string_option(nlohmann::json& commands, const nlohmann::json& params, const char* key, const std::string& command_name, duint address) {
    const auto value = optional_present_string(params, key);
    if (!value) {
        return;
    }
    const std::string command = command_name + " " + hex_value(address) + ", " + command_string_arg(*value);
    commands.push_back({
        {"option", key},
        {"command", command},
        {"success", DbgCmdExecDirect(command.c_str())},
    });
}

void append_bool_option(nlohmann::json& commands, const nlohmann::json& params, const char* key, const std::string& command_name, duint address) {
    const auto value = optional_bool(params, key);
    if (!value) {
        return;
    }
    const std::string command = command_name + " " + hex_value(address) + ", " + (*value ? "1" : "0");
    commands.push_back({
        {"option", key},
        {"command", command},
        {"success", DbgCmdExecDirect(command.c_str())},
    });
}

} // namespace

nlohmann::json tool_set_breakpoint_options(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const duint address = parse_address(params, "address");
    const std::string type = optional_string(params, "type", "normal");
    const BreakpointOptionCommands option_commands = breakpoint_option_commands(type);

    nlohmann::json commands = nlohmann::json::array();
    append_string_option(commands, params, "name", option_commands.name, address);
    append_string_option(commands, params, "condition", option_commands.condition, address);
    append_string_option(commands, params, "log_text", option_commands.log, address);
    append_string_option(commands, params, "log_condition", option_commands.log_condition, address);
    append_string_option(commands, params, "command_text", option_commands.command, address);
    append_string_option(commands, params, "command_condition", option_commands.command_condition, address);
    append_bool_option(commands, params, "fast_resume", option_commands.fast_resume, address);
    append_bool_option(commands, params, "single_shot", option_commands.single_shot, address);
    append_bool_option(commands, params, "silent", option_commands.silent, address);

    if (commands.empty()) {
        throw ApiError("bad_request", "No breakpoint options were provided.");
    }

    bool success = true;
    for (const auto& command : commands) {
        success = success && command.value("success", false);
    }

    return {
        {"action", "set_breakpoint_options"},
        {"address", hex_value(address)},
        {"type", lower_ascii(type)},
        {"success", success},
        {"commands", commands},
    };
}
