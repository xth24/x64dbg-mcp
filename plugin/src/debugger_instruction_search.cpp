#include "debugger_tools.h"

#include "instruction_utils.h"
#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

struct ScanRange {
    duint start;
    duint size;
};

std::string branch_kind(const std::string& instruction) {
    const std::string text = lower_ascii(instruction);
    if (text == "ret" || text.rfind("ret ", 0) == 0 || text.rfind("retn", 0) == 0 || text.rfind("retf", 0) == 0) return "return";
    if (text.rfind("call", 0) == 0) return "call";
    if (text.rfind("jmp", 0) == 0) return "jump";
    if (text.size() >= 2 && text[0] == 'j') return "conditional_jump";
    return "";
}

bool is_executable_page(const MEMPAGE& page) {
    const DWORD protect = page.mbi.Protect & 0xff;
    return is_readable_page(page) &&
           (protect == PAGE_EXECUTE ||
            protect == PAGE_EXECUTE_READ ||
            protect == PAGE_EXECUTE_READWRITE ||
            protect == PAGE_EXECUTE_WRITECOPY);
}

std::vector<ScanRange> ranges_for_bounds(duint start, duint size, bool executable_only) {
    std::vector<ScanRange> ranges;
    const duint end = start + size;
    for (const auto& page : get_memory_pages()) {
        if (executable_only ? !is_executable_page(page) : !is_readable_page(page)) {
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
    const bool executable_only = parse_bool(params, "executable_only", true);
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
    if (size > static_cast<duint>(128ull * 1024ull * 1024ull)) {
        throw ApiError("range_too_large", "Instruction searches are capped at 128 MiB per call.");
    }
    return ranges_for_bounds(start, size, executable_only);
}

std::string instruction_mnemonic(const std::string& instruction) {
    const size_t space = instruction.find(' ');
    return lower_ascii(space == std::string::npos ? instruction : instruction.substr(0, space));
}

std::string instruction_operands(const std::string& instruction) {
    const size_t space = instruction.find(' ');
    return space == std::string::npos ? "" : instruction.substr(space + 1);
}

std::string instruction_kind(const DISASM_INSTR& instruction) {
    const std::string branch = branch_kind(instruction.instruction);
    if (!branch.empty()) {
        return branch;
    }
    if (instruction.type == instr_stack) {
        return "stack";
    }
    for (int i = 0; i < instruction.argcount && i < 3; ++i) {
        if (instruction.arg[i].type == arg_memory) {
            return "memory";
        }
    }
    return "normal";
}

bool string_filter_matches(const std::string& text, const std::string& filter, bool case_sensitive) {
    if (filter.empty()) {
        return true;
    }
    if (case_sensitive) {
        return text.find(filter) != std::string::npos;
    }
    return contains_ascii_ci(text, filter);
}

bool kind_filter_matches(const std::string& actual, std::string expected) {
    expected = lower_ascii(expected);
    if (expected.empty() || expected == "any") {
        return true;
    }
    if (expected == "branch") {
        return actual == "call" || actual == "jump" || actual == "conditional_jump";
    }
    return actual == expected;
}

bool instruction_matches_filters(
    const DISASM_INSTR& instruction,
    const std::string& mnemonic,
    const std::string& contains,
    const std::string& operand_contains,
    const std::string& kind,
    bool case_sensitive
) {
    const std::string text = instruction.instruction;
    if (!mnemonic.empty() && instruction_mnemonic(text) != lower_ascii(mnemonic)) {
        return false;
    }
    if (!string_filter_matches(text, contains, case_sensitive)) {
        return false;
    }
    if (!string_filter_matches(instruction_operands(text), operand_contains, case_sensitive)) {
        return false;
    }
    return kind_filter_matches(instruction_kind(instruction), kind);
}

nlohmann::json instruction_hit_json(duint address, const DISASM_INSTR& instruction, bool include_details) {
    nlohmann::json item = {
        {"address", hex_value(address)},
        {"instruction", instruction.instruction},
        {"mnemonic", instruction_mnemonic(instruction.instruction)},
        {"kind", instruction_kind(instruction)},
        {"size", instruction.instr_size},
    };
    if (const auto module = find_module_at(address)) {
        item["module"] = module->name;
        item["rva"] = hex_value(address - module->base);
    }
    if (include_details) {
        item["details"] = instruction_json(address);
    }
    return item;
}

} // namespace

nlohmann::json tool_find_instructions(const nlohmann::json& params) {
    duint start = 0;
    duint size = 0;
    nlohmann::json module = nullptr;
    const auto ranges = ranges_from_params(params, start, size, module);
    const std::string mnemonic = optional_string(params, "mnemonic");
    const std::string contains = optional_string(params, "contains");
    const std::string operand_contains = optional_string(params, "operand_contains");
    const std::string kind = optional_string(params, "kind", "any");
    const bool case_sensitive = parse_bool(params, "case_sensitive", false);
    const bool executable_only = parse_bool(params, "executable_only", true);
    const bool include_details = parse_bool(params, "include_details", false);
    const int max_instructions = parse_int(params, "max_instructions", 50000, 1, 500000);
    const int limit = parse_int(params, "limit", 500, 1, 10000);

    nlohmann::json hits = nlohmann::json::array();
    int decode_attempts = 0;
    int instructions_scanned = 0;
    int invalid_decodes = 0;

    for (const auto& range : ranges) {
        duint current = range.start;
        const duint end = range.start + range.size;
        while (current < end && decode_attempts < max_instructions && static_cast<int>(hits.size()) < limit) {
            ++decode_attempts;
            DISASM_INSTR instruction{};
            DbgDisasmAt(current, &instruction);
            if (instruction.instr_size <= 0) {
                ++invalid_decodes;
                ++current;
                continue;
            }
            ++instructions_scanned;
            if (instruction_matches_filters(instruction, mnemonic, contains, operand_contains, kind, case_sensitive)) {
                hits.push_back(instruction_hit_json(current, instruction, include_details));
            }
            current += static_cast<duint>(instruction.instr_size);
        }
        if (decode_attempts >= max_instructions || static_cast<int>(hits.size()) >= limit) {
            break;
        }
    }

    nlohmann::json result = {
        {"start", hex_value(start)},
        {"size", hex_value(size)},
        {"scan_ranges", ranges.size()},
        {"executable_only", executable_only},
        {"mnemonic", mnemonic},
        {"contains", contains},
        {"operand_contains", operand_contains},
        {"kind", kind},
        {"case_sensitive", case_sensitive},
        {"max_instructions", max_instructions},
        {"decode_attempts", decode_attempts},
        {"instructions_scanned", instructions_scanned},
        {"invalid_decodes", invalid_decodes},
        {"limit", limit},
        {"count", hits.size()},
        {"truncated", decode_attempts >= max_instructions || static_cast<int>(hits.size()) >= limit},
        {"instructions", hits},
    };
    if (!module.is_null()) {
        result["module"] = module;
    }
    return result;
}
