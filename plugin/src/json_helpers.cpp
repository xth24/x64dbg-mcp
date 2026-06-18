#include "json_helpers.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

ApiError::ApiError(std::string code, std::string message)
    : std::runtime_error(message), code_(std::move(code)) {}

std::string required_string(const nlohmann::json& params, const char* key) {
    if (!params.contains(key) || !params[key].is_string()) {
        throw ApiError("bad_request", std::string("Missing string parameter: ") + key);
    }
    return params[key].get<std::string>();
}

duint parse_address(const nlohmann::json& params, const char* key) {
    const std::string value = required_string(params, key);
    try {
        size_t consumed = 0;
        const auto parsed = std::stoull(value, &consumed, 0);
        if (consumed != value.size()) {
            throw std::invalid_argument("trailing input");
        }
        return static_cast<duint>(parsed);
    } catch (...) {
        duint parsed = 0;
        if (Script::Misc::ParseExpression(value.c_str(), &parsed)) {
            return parsed;
        }
        throw ApiError("bad_address", std::string("Invalid address or expression parameter: ") + key);
    }
}

bool parse_bool(const nlohmann::json& params, const char* key, bool fallback) {
    if (!params.contains(key)) {
        return fallback;
    }
    if (!params[key].is_boolean()) {
        throw ApiError("bad_request", std::string("Expected boolean parameter: ") + key);
    }
    return params[key].get<bool>();
}

int parse_int(const nlohmann::json& params, const char* key, int fallback, int min_value, int max_value) {
    int value = fallback;
    if (params.contains(key)) {
        if (!params[key].is_number_integer()) {
            throw ApiError("bad_request", std::string("Expected integer parameter: ") + key);
        }
        value = params[key].get<int>();
    }
    return std::clamp(value, min_value, max_value);
}

std::string optional_string(const nlohmann::json& params, const char* key, const std::string& fallback) {
    if (!params.contains(key) || params[key].is_null()) {
        return fallback;
    }
    if (!params[key].is_string()) {
        throw ApiError("bad_request", std::string("Expected string parameter: ") + key);
    }
    return params[key].get<std::string>();
}

std::string hex_value(duint value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << value;
    return out.str();
}

std::vector<unsigned char> parse_hex_bytes(const std::string& value) {
    std::string compact;
    compact.reserve(value.size());
    for (char ch : value) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            compact.push_back(ch);
        }
    }
    if (compact.empty() || compact.size() % 2 != 0) {
        throw ApiError("bad_hex", "Hex byte input must contain an even number of digits.");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(compact.size() / 2);
    for (size_t i = 0; i < compact.size(); i += 2) {
        const std::string piece = compact.substr(i, 2);
        try {
            bytes.push_back(static_cast<unsigned char>(std::stoul(piece, nullptr, 16)));
        } catch (...) {
            throw ApiError("bad_hex", "Hex byte input contains invalid digits.");
        }
    }
    return bytes;
}

nlohmann::json ok_status(const char* action, bool success) {
    return {{"action", action}, {"success", success}};
}

namespace {

const char* symbol_type_name(SYMBOLTYPE type) {
    switch (type) {
    case sym_import: return "import";
    case sym_export: return "export";
    case sym_symbol: return "symbol";
    default: return "unknown";
    }
}

} // namespace

nlohmann::json symbol_info_json(const SYMBOLINFO& info) {
    return {
        {"address", hex_value(info.addr)},
        {"decorated", info.decoratedSymbol ? info.decoratedSymbol : ""},
        {"undecorated", info.undecoratedSymbol ? info.undecoratedSymbol : ""},
        {"type", symbol_type_name(info.type)},
        {"ordinal", info.ordinal},
    };
}

nlohmann::json register_dump_json() {
    REGDUMP_AVX512 dump{};
    if (!DbgGetRegDumpEx(&dump, sizeof(dump))) {
        throw ApiError("debugger_error", "Failed to read register dump.");
    }

    const auto flags = static_cast<duint>(dump.regcontext.eflags);
    auto flag = [flags](unsigned bit) { return ((flags >> bit) & 1) != 0; };

    nlohmann::json registers = {
        {"cax", hex_value(dump.regcontext.cax)},
        {"ccx", hex_value(dump.regcontext.ccx)},
        {"cdx", hex_value(dump.regcontext.cdx)},
        {"cbx", hex_value(dump.regcontext.cbx)},
        {"csp", hex_value(dump.regcontext.csp)},
        {"cbp", hex_value(dump.regcontext.cbp)},
        {"csi", hex_value(dump.regcontext.csi)},
        {"cdi", hex_value(dump.regcontext.cdi)},
        {"cip", hex_value(dump.regcontext.cip)},
        {"eflags", hex_value(dump.regcontext.eflags)},
        {"gs", hex_value(dump.regcontext.gs)},
        {"fs", hex_value(dump.regcontext.fs)},
        {"es", hex_value(dump.regcontext.es)},
        {"ds", hex_value(dump.regcontext.ds)},
        {"cs", hex_value(dump.regcontext.cs)},
        {"ss", hex_value(dump.regcontext.ss)},
        {"dr0", hex_value(dump.regcontext.dr0)},
        {"dr1", hex_value(dump.regcontext.dr1)},
        {"dr2", hex_value(dump.regcontext.dr2)},
        {"dr3", hex_value(dump.regcontext.dr3)},
        {"dr6", hex_value(dump.regcontext.dr6)},
        {"dr7", hex_value(dump.regcontext.dr7)},
        {"flags", {
            {"ZF", flag(6)},
            {"OF", flag(11)},
            {"CF", flag(0)},
            {"PF", flag(2)},
            {"SF", flag(7)},
            {"TF", flag(8)},
            {"AF", flag(4)},
            {"DF", flag(10)},
            {"IF", flag(9)},
        }},
        {"last_error", dump.lastError},
        {"last_status", dump.lastStatus},
    };

#ifdef _WIN64
    registers["r8"] = hex_value(dump.regcontext.r8);
    registers["r9"] = hex_value(dump.regcontext.r9);
    registers["r10"] = hex_value(dump.regcontext.r10);
    registers["r11"] = hex_value(dump.regcontext.r11);
    registers["r12"] = hex_value(dump.regcontext.r12);
    registers["r13"] = hex_value(dump.regcontext.r13);
    registers["r14"] = hex_value(dump.regcontext.r14);
    registers["r15"] = hex_value(dump.regcontext.r15);
#endif

    return registers;
}

nlohmann::json disassemble_json(duint address, int count) {
    nlohmann::json instructions = nlohmann::json::array();
    duint current = address;
    for (int i = 0; i < count; ++i) {
        DISASM_INSTR instruction{};
        DbgDisasmAt(current, &instruction);
        if (instruction.instr_size <= 0) {
            break;
        }
        instructions.push_back({
            {"address", hex_value(current)},
            {"instruction", instruction.instruction},
            {"size", instruction.instr_size},
        });
        current += instruction.instr_size;
    }
    return instructions;
}
