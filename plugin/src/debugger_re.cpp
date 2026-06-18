#include "debugger_tools.h"

#include "import_utils.h"
#include "instruction_utils.h"
#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace {

struct ScanRange {
    duint start;
    duint size;
};

bool is_ascii_text(unsigned char ch) {
    return ch >= 0x20 && ch <= 0x7e;
}

std::string clipped_text(const std::string& text) {
    static constexpr size_t kMaxText = 512;
    if (text.size() <= kMaxText) {
        return text;
    }
    return text.substr(0, kMaxText);
}

nlohmann::json address_context_json(duint address) {
    nlohmann::json out = {{"address", hex_value(address)}, {"module_found", false}, {"symbol_found", false}};
    if (const auto module = find_module_at(address)) {
        out["module_found"] = true;
        out["rva"] = hex_value(address - module->base);
        out["module"] = module_info_json(*module);
    }
    SYMBOLINFOCPP symbol{};
    if (DbgGetSymbolInfoAt(address, &symbol)) {
        out["symbol_found"] = true;
        out["symbol"] = symbol_info_json(symbol);
    }
    return out;
}

nlohmann::json pointer_read_json(duint address) {
    duint value = 0;
    duint read = 0;
    if (!Script::Memory::Read(address, &value, sizeof(value), &read) || read != sizeof(value)) {
        return {{"address", hex_value(address)}, {"readable", false}, {"pointer_size", sizeof(value)}};
    }
    nlohmann::json out = {
        {"address", hex_value(address)},
        {"readable", true},
        {"pointer_size", sizeof(value)},
        {"value", hex_value(value)},
        {"is_null", value == 0},
    };
    if (value != 0) {
        out["target"] = address_context_json(value);
    }
    return out;
}

std::vector<ScanRange> readable_ranges_for_bounds(duint start, duint size) {
    std::vector<ScanRange> ranges;
    const duint end = start + size;
    for (const auto& page : get_memory_pages()) {
        if (!is_readable_page(page)) {
            continue;
        }
        const auto page_start = reinterpret_cast<duint>(page.mbi.BaseAddress);
        const auto page_size = static_cast<duint>(page.mbi.RegionSize);
        const duint page_end = page_start + page_size;
        const duint scan_start = std::max(start, page_start);
        const duint scan_end = std::min(end, page_end);
        if (scan_end > scan_start) {
            ranges.push_back({scan_start, scan_end - scan_start});
        }
    }
    return ranges;
}

std::vector<ScanRange> ranges_from_params(const nlohmann::json& params, duint& start, duint& size, nlohmann::json& module_json) {
    if (params.contains("module") && params["module"].is_string()) {
        const std::string module_name = params["module"].get<std::string>();
        const auto module = find_module_by_name(module_name);
        if (!module) {
            throw ApiError("module_not_found", "Module was not found: " + module_name);
        }
        start = module->base;
        size = module->size;
        module_json = module_info_json(*module);
    } else {
        start = parse_address(params, "start");
        size = parse_address(params, "size");
    }
    if (size > static_cast<duint>(256ull * 1024ull * 1024ull)) {
        throw ApiError("range_too_large", "Range scans are capped at 256 MiB per call.");
    }
    return readable_ranges_for_bounds(start, size);
}

bool string_matches_filter(const std::string& text, const std::string& contains) {
    return contains.empty() || contains_ascii_ci(text, contains);
}

nlohmann::json string_hit_json(duint address, const std::string& encoding, const std::string& text) {
    nlohmann::json item = {
        {"address", hex_value(address)},
        {"encoding", encoding},
        {"length", text.size()},
        {"text", clipped_text(text)},
    };
    if (const auto module = find_module_at(address)) {
        item["module"] = module->name;
        item["rva"] = hex_value(address - module->base);
    }
    return item;
}

void scan_ascii_strings(const std::vector<unsigned char>& bytes, duint base, int min_length, const std::string& contains, int limit, nlohmann::json& out) {
    size_t i = 0;
    while (i < bytes.size() && static_cast<int>(out.size()) < limit) {
        if (!is_ascii_text(bytes[i])) {
            ++i;
            continue;
        }
        const size_t begin = i;
        std::string text;
        while (i < bytes.size() && is_ascii_text(bytes[i])) {
            text.push_back(static_cast<char>(bytes[i++]));
        }
        if (static_cast<int>(text.size()) >= min_length && string_matches_filter(text, contains)) {
            out.push_back(string_hit_json(base + static_cast<duint>(begin), "ascii", text));
        }
    }
}

void scan_utf16_strings(const std::vector<unsigned char>& bytes, duint base, int min_length, const std::string& contains, int limit, nlohmann::json& out) {
    for (size_t alignment = 0; alignment < 2 && static_cast<int>(out.size()) < limit; ++alignment) {
        size_t i = alignment;
        while (i + 1 < bytes.size() && static_cast<int>(out.size()) < limit) {
            if (!is_ascii_text(bytes[i]) || bytes[i + 1] != 0) {
                i += 2;
                continue;
            }
            const size_t begin = i;
            std::string text;
            while (i + 1 < bytes.size() && is_ascii_text(bytes[i]) && bytes[i + 1] == 0) {
                text.push_back(static_cast<char>(bytes[i]));
                i += 2;
            }
            if (static_cast<int>(text.size()) >= min_length && string_matches_filter(text, contains)) {
                out.push_back(string_hit_json(base + static_cast<duint>(begin), "utf16le", text));
            }
        }
    }
}

std::string branch_kind(const std::string& instruction) {
    const std::string text = lower_ascii(instruction);
    if (text == "ret" || text.rfind("ret ", 0) == 0 || text.rfind("retn", 0) == 0 || text.rfind("retf", 0) == 0) return "return";
    if (text.rfind("call", 0) == 0) return "call";
    if (text.rfind("jmp", 0) == 0) return "jump";
    if (text.size() >= 2 && text[0] == 'j') return "conditional_jump";
    return "";
}

const char* function_type_name(FUNCTYPE type) {
    switch (type) {
    case FUNC_BEGIN: return "begin";
    case FUNC_MIDDLE: return "middle";
    case FUNC_END: return "end";
    case FUNC_SINGLE: return "single";
    case FUNC_NONE:
    default: return "none";
    }
}

const char* breakpoint_type_name(BPXTYPE type) {
    switch (type) {
    case bp_normal: return "normal";
    case bp_hardware: return "hardware";
    case bp_memory: return "memory";
    case bp_dll: return "dll";
    case bp_exception: return "exception";
    case bp_none:
    default: return "none";
    }
}

nlohmann::json collect_calls_in_range(duint start, duint size, int max_instructions, int limit) {
    nlohmann::json calls = nlohmann::json::array();
    const duint end = start + size;
    duint current = start;
    int scanned = 0;
    int branches = 0;
    int returns = 0;

    while (current < end && scanned < max_instructions) {
        DISASM_INSTR instruction{};
        DbgDisasmAt(current, &instruction);
        if (instruction.instr_size <= 0) {
            break;
        }
        ++scanned;
        const std::string kind = branch_kind(instruction.instruction);
        if (!kind.empty()) {
            ++branches;
            if (kind == "return") {
                ++returns;
            }
            if (static_cast<int>(calls.size()) < limit) {
                calls.push_back({
                    {"address", hex_value(current)},
                    {"instruction", instruction.instruction},
                    {"kind", kind},
                    {"size", instruction.instr_size},
                    {"branch", branch_destination_json(current)},
                });
            }
        }
        current += static_cast<duint>(instruction.instr_size);
    }

    return {
        {"start", hex_value(start)},
        {"size", hex_value(size)},
        {"instructions_scanned", scanned},
        {"branches_seen", branches},
        {"returns_seen", returns},
        {"limit", limit},
        {"count", calls.size()},
        {"truncated", branches > static_cast<int>(calls.size())},
        {"calls", calls},
    };
}

bool function_bounds(duint address, duint& start, duint& end, duint& instruction_count) {
    start = 0;
    end = 0;
    instruction_count = 0;
    return Script::Function::Get(address, &start, &end, &instruction_count);
}

} // namespace

nlohmann::json tool_find_strings(const nlohmann::json& params) {
    duint start = 0;
    duint size = 0;
    nlohmann::json module = nullptr;
    const auto ranges = ranges_from_params(params, start, size, module);
    const bool ascii = parse_bool(params, "ascii", true);
    const bool unicode = parse_bool(params, "unicode", true);
    const int min_length = parse_int(params, "min_length", 4, 1, 1024);
    const int limit = parse_int(params, "limit", 100, 1, 10000);
    const std::string contains = optional_string(params, "contains");

    nlohmann::json hits = nlohmann::json::array();
    static constexpr duint kChunkSize = 64 * 1024;
    for (const auto& range : ranges) {
        duint offset = 0;
        while (offset < range.size && static_cast<int>(hits.size()) < limit) {
            const duint to_read = std::min(kChunkSize, range.size - offset);
            std::vector<unsigned char> bytes(static_cast<size_t>(to_read));
            duint read = 0;
            if (Script::Memory::Read(range.start + offset, bytes.data(), to_read, &read) && read > 0) {
                bytes.resize(static_cast<size_t>(read));
                if (ascii) {
                    scan_ascii_strings(bytes, range.start + offset, min_length, contains, limit, hits);
                }
                if (unicode && static_cast<int>(hits.size()) < limit) {
                    scan_utf16_strings(bytes, range.start + offset, min_length, contains, limit, hits);
                }
            }
            offset += to_read;
        }
        if (static_cast<int>(hits.size()) >= limit) {
            break;
        }
    }

    nlohmann::json result = {
        {"start", hex_value(start)},
        {"size", hex_value(size)},
        {"ascii", ascii},
        {"unicode", unicode},
        {"min_length", min_length},
        {"contains", contains},
        {"limit", limit},
        {"count", hits.size()},
        {"truncated", static_cast<int>(hits.size()) >= limit},
        {"strings", hits},
    };
    if (!module.is_null()) {
        result["module"] = module;
    }
    return result;
}

nlohmann::json tool_list_calls_in_range(const nlohmann::json& params) {
    const duint start = parse_address(params, "start");
    const duint size = parse_address(params, "size");
    const int max_instructions = parse_int(params, "max_instructions", 512, 1, 20000);
    const int limit = parse_int(params, "limit", 100, 1, 5000);
    if (size > static_cast<duint>(64ull * 1024ull * 1024ull)) {
        throw ApiError("range_too_large", "Call extraction ranges are capped at 64 MiB per call.");
    }
    return collect_calls_in_range(start, size, max_instructions, limit);
}

nlohmann::json tool_list_calls_in_function(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const int max_instructions = parse_int(params, "max_instructions", 1000, 1, 20000);
    const int limit = parse_int(params, "limit", 100, 1, 5000);
    duint start = 0;
    duint end = 0;
    duint instruction_count = 0;
    if (!function_bounds(address, start, end, instruction_count)) {
        return {{"address", hex_value(address)}, {"function_found", false}, {"calls", nlohmann::json::array()}};
    }
    nlohmann::json result = collect_calls_in_range(start, end >= start ? end - start + 16 : 0, max_instructions, limit);
    result["address"] = hex_value(address);
    result["function_found"] = true;
    result["function_start"] = hex_value(start);
    result["function_end"] = hex_value(end);
    result["known_instruction_count"] = static_cast<unsigned long long>(instruction_count);
    return result;
}

nlohmann::json tool_analyze_function(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const int max_instructions = parse_int(params, "max_instructions", 1000, 1, 20000);
    const int call_limit = parse_int(params, "call_limit", 100, 1, 5000);
    duint start = 0;
    duint end = 0;
    duint instruction_count = 0;
    if (!function_bounds(address, start, end, instruction_count)) {
        return {
            {"address", hex_value(address)},
            {"function_found", false},
            {"function_type", function_type_name(DbgGetFunctionTypeAt(address))},
            {"context", address_context_json(address)},
        };
    }

    nlohmann::json calls = collect_calls_in_range(start, end >= start ? end - start + 16 : 0, max_instructions, call_limit);
    return {
        {"address", hex_value(address)},
        {"function_found", true},
        {"start", hex_value(start)},
        {"end", hex_value(end)},
        {"size", hex_value(end >= start ? end - start : 0)},
        {"known_instruction_count", static_cast<unsigned long long>(instruction_count)},
        {"context", address_context_json(start)},
        {"calls", calls},
    };
}

nlohmann::json tool_inspect_import_thunk(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const std::string module_filter = optional_string(params, "module");
    const auto modules = get_module_list();
    for (const auto& module : modules) {
        if (!module_filter.empty() && !module_name_or_path_matches(module, module_filter)) {
            continue;
        }
        ListInfo list{};
        if (!Script::Module::GetImports(&module, &list) || !list.data) {
            continue;
        }
        auto* imports = static_cast<Script::Module::ModuleImport*>(list.data);
        for (size_t i = 0; i < list.count; ++i) {
            const duint slot_start = imports[i].iatVa;
            const duint slot_end = slot_start + sizeof(duint);
            if (address >= slot_start && address < slot_end) {
                nlohmann::json result = {
                    {"address", hex_value(address)},
                    {"found", true},
                    {"slot_offset", address - slot_start},
                    {"import", import_record_json(imports[i], module)},
                    {"pointer", import_pointer_json(slot_start)},
                    {"pointer_classification", classify_import_pointer(slot_start, module)},
                };
                BridgeFree(list.data);
                return result;
            }
        }
        BridgeFree(list.data);
    }
    return {{"address", hex_value(address)}, {"found", false}};
}

nlohmann::json tool_snapshot_break_context(const nlohmann::json& params) {
    nlohmann::json result = {{"status", tool_get_status({})}};
    if (!DbgIsDebugging()) {
        result["debugging"] = false;
        return result;
    }

    const int instruction_count = parse_int(params, "instruction_count", 4, 1, 32);
    const int stack_slots = parse_int(params, "stack_slots", 4, 0, 64);
    const duint cip = Script::Register::Get(kInstructionPointer);
    const duint csp = Script::Register::Get(kStackPointer);
    result["debugging"] = true;
    result["running"] = DbgIsRunning();
    result["cip"] = hex_value(cip);
    result["csp"] = hex_value(csp);
    result["breakpoint_type"] = breakpoint_type_name(DbgGetBpxTypeAt(cip));
    result["current"] = tool_inspect_address({{"address", hex_value(cip)}});
    result["snapshot"] = tool_get_snapshot({{"instruction_count", instruction_count}});

    nlohmann::json stack = nlohmann::json::array();
    for (int i = 0; i < stack_slots; ++i) {
        const duint slot = csp + static_cast<duint>(i * sizeof(duint));
        nlohmann::json item = pointer_read_json(slot);
        item["slot"] = i;
        stack.push_back(item);
    }
    result["stack_slots"] = stack;
    try {
        result["call_stack"] = tool_get_call_stack({});
    } catch (const ApiError& exc) {
        result["call_stack_error"] = {{"code", exc.code()}, {"message", exc.what()}};
    }
    return result;
}
