#include "debugger_tools.h"

#include "json_helpers.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>
#include <cctype>

namespace {

Script::Register::RegisterEnum register_from_name(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (name == "eax") return Script::Register::EAX;
    if (name == "ebx") return Script::Register::EBX;
    if (name == "ecx") return Script::Register::ECX;
    if (name == "edx") return Script::Register::EDX;
    if (name == "esi") return Script::Register::ESI;
    if (name == "edi") return Script::Register::EDI;
    if (name == "ebp") return Script::Register::EBP;
    if (name == "esp") return Script::Register::ESP;
    if (name == "eip") return Script::Register::EIP;
#ifdef _WIN64
    if (name == "rax") return Script::Register::RAX;
    if (name == "rbx") return Script::Register::RBX;
    if (name == "rcx") return Script::Register::RCX;
    if (name == "rdx") return Script::Register::RDX;
    if (name == "rsi") return Script::Register::RSI;
    if (name == "rdi") return Script::Register::RDI;
    if (name == "rbp") return Script::Register::RBP;
    if (name == "rsp") return Script::Register::RSP;
    if (name == "rip") return Script::Register::RIP;
    if (name == "r8") return Script::Register::R8;
    if (name == "r9") return Script::Register::R9;
    if (name == "r10") return Script::Register::R10;
    if (name == "r11") return Script::Register::R11;
    if (name == "r12") return Script::Register::R12;
    if (name == "r13") return Script::Register::R13;
    if (name == "r14") return Script::Register::R14;
    if (name == "r15") return Script::Register::R15;
#endif
    throw ApiError("bad_register", "Unknown or unsupported register name.");
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0f]);
    }
    return out;
}

} // namespace

nlohmann::json tool_get_bridge_info(const nlohmann::json&) {
    return {
        {"name", "xdbg-mcp"},
        {"arch", kDebuggerArch},
        {"plugin_version", kPluginVersionText},
        {"plugin_version_number", kPluginVersion},
        {"protocol_version", kBridgeProtocolVersion},
        {"debugging", DbgIsDebugging()},
        {"running", DbgIsRunning()},
        {"pid", GetCurrentProcessId()},
    };
}

nlohmann::json tool_get_status(const nlohmann::json&) {
    const bool debugging = DbgIsDebugging();
    const bool running = DbgIsRunning();
    nlohmann::json status = {
        {"arch", kDebuggerArch},
        {"debugging", debugging},
        {"running", running},
        {"plugin_version", kPluginVersionText},
        {"protocol_version", kBridgeProtocolVersion},
    };
    if (debugging) {
        status["cip"] = hex_value(Script::Register::Get(kInstructionPointer));
        status["csp"] = hex_value(Script::Register::Get(kStackPointer));
    }
    return status;
}

nlohmann::json tool_get_registers(const nlohmann::json&) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    return register_dump_json();
}

nlohmann::json tool_set_register(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const auto reg = register_from_name(required_string(params, "register"));
    const duint value = parse_address(params, "value");
    return ok_status("set_register", Script::Register::Set(reg, value));
}

nlohmann::json tool_read_memory(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    const int size = parse_int(params, "size", 64, 1, 1024 * 1024);

    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    duint read = 0;
    if (!Script::Memory::Read(address, buffer.data(), buffer.size(), &read)) {
        throw ApiError("memory_read_failed", "Failed to read debuggee memory.");
    }
    buffer.resize(static_cast<size_t>(read));

    return {
        {"address", hex_value(address)},
        {"requested_size", size},
        {"size", read},
        {"hex", bytes_to_hex(buffer)},
    };
}

nlohmann::json tool_write_memory(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    const auto bytes = parse_hex_bytes(required_string(params, "hex_bytes"));
    if (bytes.size() > 64 * 1024) {
        throw ApiError("request_too_large", "Memory writes are capped at 64 KiB per call.");
    }

    duint written = 0;
    const bool success = Script::Memory::Write(address, const_cast<unsigned char*>(bytes.data()), bytes.size(), &written);
    return {
        {"action", "write_memory"},
        {"success", success},
        {"address", hex_value(address)},
        {"size", written},
    };
}

nlohmann::json tool_disassemble(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }
    const duint address = parse_address(params, "address");
    const int count = parse_int(params, "count", 16, 1, 128);
    return {
        {"address", hex_value(address)},
        {"instructions", disassemble_json(address, count)},
    };
}

nlohmann::json tool_get_snapshot(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        return {{"status", tool_get_status(params)}};
    }

    const int count = parse_int(params, "instruction_count", 8, 1, 32);
    const duint cip = Script::Register::Get(kInstructionPointer);
    const duint csp = Script::Register::Get(kStackPointer);
    nlohmann::json current = {
        {"address", hex_value(cip)},
        {"module_found", false},
        {"symbol_found", false},
    };

    if (const auto module = find_module_at(cip)) {
        current["module_found"] = true;
        current["rva"] = hex_value(cip - module->base);
        current["module"] = module_info_json(*module);
    }

    SYMBOLINFOCPP symbol{};
    if (DbgGetSymbolInfoAt(cip, &symbol)) {
        current["symbol_found"] = true;
        current["symbol"] = symbol_info_json(symbol);
    }

    nlohmann::json snapshot = {
        {"status", tool_get_status(params)},
        {"current", current},
        {"registers", register_dump_json()},
        {"disassembly", disassemble_json(cip, count)},
    };

    try {
        snapshot["stack"] = tool_read_memory({{"address", hex_value(csp)}, {"size", 128}});
    } catch (const ApiError&) {
        snapshot["stack"] = nullptr;
    }

    return snapshot;
}
