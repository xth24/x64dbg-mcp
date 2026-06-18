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
    std::string module;
    std::string source;
    std::string section;
};

std::string branch_kind(const std::string& instruction) {
    const std::string text = lower_ascii(instruction);
    if (text == "ret" || text.rfind("ret ", 0) == 0 || text.rfind("retn", 0) == 0 || text.rfind("retf", 0) == 0) return "return";
    if (text.rfind("call", 0) == 0) return "call";
    if (text.rfind("jmp", 0) == 0) return "jump";
    if (text.size() >= 2 && text[0] == 'j') return "conditional_jump";
    return "";
}

bool is_terminal_linear_instruction(const std::string& kind) {
    return kind == "return" || kind == "jump";
}

bool is_executable_page(const MEMPAGE& page) {
    const DWORD protect = page.mbi.Protect & 0xff;
    return is_readable_page(page) &&
           (protect == PAGE_EXECUTE ||
            protect == PAGE_EXECUTE_READ ||
            protect == PAGE_EXECUTE_READWRITE ||
            protect == PAGE_EXECUTE_WRITECOPY);
}

template <typename T>
bool read_struct(duint address, T& out) {
    duint read = 0;
    return Script::Memory::Read(address, &out, sizeof(T), &read) && read == sizeof(T);
}

std::string pe_section_name(const IMAGE_SECTION_HEADER& section) {
    char name[9]{};
    for (size_t i = 0; i < 8; ++i) {
        name[i] = static_cast<char>(section.Name[i]);
    }
    return name;
}

bool is_code_like_section(const IMAGE_SECTION_HEADER& section) {
    if ((section.Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
        return true;
    }
    const std::string name = lower_ascii(pe_section_name(section));
    return name.find("text") != std::string::npos ||
           name.find("code") != std::string::npos ||
           name.find("stub") != std::string::npos;
}

void append_scan_range(std::vector<ScanRange>& ranges, duint start, duint size, const std::string& module, const std::string& source, const std::string& section = "") {
    if (size == 0) {
        return;
    }
    ranges.push_back({start, size, module, source, section});
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

bool in_range(duint value, duint start, duint size) {
    return size != 0 && value >= start && value < start + size;
}

std::vector<ScanRange> executable_ranges_for_module(const Script::Module::ModuleInfo& module) {
    std::vector<ScanRange> ranges;
    const duint module_end_value = module_end(module);
    for (const auto& page : get_memory_pages()) {
        if (!is_executable_page(page)) {
            continue;
        }
        const auto page_start = reinterpret_cast<duint>(page.mbi.BaseAddress);
        const auto page_size = static_cast<duint>(page.mbi.RegionSize);
        const duint page_end = page_start + page_size;
        const duint scan_start = std::max(module.base, page_start);
        const duint scan_end = std::min(module_end_value, page_end);
        if (scan_end > scan_start) {
            append_scan_range(ranges, scan_start, scan_end - scan_start, module.name, "executable_page");
        }
    }
    return ranges;
}

std::vector<ScanRange> readonly_code_like_ranges_for_module(const Script::Module::ModuleInfo& module) {
    std::vector<ScanRange> ranges;
    IMAGE_DOS_HEADER dos{};
    if (!read_struct(module.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return ranges;
    }

    const duint nt_address = module.base + static_cast<duint>(dos.e_lfanew);
    DWORD signature = 0;
    if (!read_struct(nt_address, signature) || signature != IMAGE_NT_SIGNATURE) {
        return ranges;
    }

    IMAGE_FILE_HEADER file{};
    if (!read_struct(nt_address + sizeof(DWORD), file)) {
        return ranges;
    }

    const duint optional_address = nt_address + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const duint section_address = optional_address + file.SizeOfOptionalHeader;
    const auto pages = get_memory_pages();
    const duint module_end_value = module_end(module);
    for (WORD i = 0; i < file.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!read_struct(section_address + static_cast<duint>(i) * sizeof(IMAGE_SECTION_HEADER), section) || !is_code_like_section(section)) {
            continue;
        }
        const duint section_start = module.base + section.VirtualAddress;
        const duint section_size = std::max(static_cast<duint>(section.Misc.VirtualSize), static_cast<duint>(section.SizeOfRawData));
        const duint section_end = std::min(module_end_value, section_start + section_size);
        if (section_end <= section_start) {
            continue;
        }
        for (const auto& page : pages) {
            if (!is_readable_page(page) || is_executable_page(page)) {
                continue;
            }
            const auto page_start = reinterpret_cast<duint>(page.mbi.BaseAddress);
            const auto page_size = static_cast<duint>(page.mbi.RegionSize);
            const duint page_end = page_start + page_size;
            const duint scan_start = std::max(section_start, page_start);
            const duint scan_end = std::min(section_end, page_end);
            if (scan_end > scan_start) {
                append_scan_range(ranges, scan_start, scan_end - scan_start, module.name, "readonly_code_like_section", pe_section_name(section));
            }
        }
    }
    return ranges;
}

std::vector<ScanRange> scan_ranges_for_module(const Script::Module::ModuleInfo& module, bool include_readonly_code_like_sections) {
    auto ranges = executable_ranges_for_module(module);
    if (include_readonly_code_like_sections) {
        auto readonly_ranges = readonly_code_like_ranges_for_module(module);
        ranges.insert(ranges.end(), readonly_ranges.begin(), readonly_ranges.end());
    }
    return ranges;
}

std::vector<ScanRange> reference_scan_ranges(const nlohmann::json& params) {
    const std::string scan_module = optional_string(params, "scan_module");
    const bool include_readonly_code_like_sections = parse_bool(params, "include_readonly_code_like_sections", false);
    std::vector<ScanRange> ranges;
    if (!scan_module.empty()) {
        const auto module = find_module_by_name(scan_module);
        if (!module) {
            throw ApiError("module_not_found", "Scan module was not found: " + scan_module);
        }
        return scan_ranges_for_module(*module, include_readonly_code_like_sections);
    }

    for (const auto& module : get_module_list()) {
        if (is_system_module_path(module.path)) {
            continue;
        }
        auto module_ranges = scan_ranges_for_module(module, include_readonly_code_like_sections);
        ranges.insert(ranges.end(), module_ranges.begin(), module_ranges.end());
    }
    return ranges;
}

nlohmann::json instruction_references_json(const DISASM_INSTR& instruction, duint target_start, duint target_size) {
    nlohmann::json refs = nlohmann::json::array();
    for (int i = 0; i < instruction.argcount && i < 3; ++i) {
        const DISASM_ARG& arg = instruction.arg[i];
        auto maybe_add = [&](const char* field, duint value) {
            if (value != 0 && in_range(value, target_start, target_size)) {
                refs.push_back({
                    {"operand", i},
                    {"field", field},
                    {"value", hex_value(value)},
                    {"context", address_context_json(value)},
                });
            }
        };
        maybe_add("constant", arg.constant);
        maybe_add("value", arg.value);
        maybe_add("memvalue", arg.memvalue);
    }
    return refs;
}

} // namespace

nlohmann::json tool_analyze_linear_block(const nlohmann::json& params) {
    const duint start = parse_address(params, "address");
    const int max_instructions = parse_int(params, "max_instructions", 128, 1, 5000);
    const bool include_instructions = parse_bool(params, "include_instructions", true);

    duint current = start;
    int scanned = 0;
    std::string stop_reason = "max_instructions";
    nlohmann::json instructions = nlohmann::json::array();
    nlohmann::json branches = nlohmann::json::array();
    nlohmann::json strings = nlohmann::json::array();
    nlohmann::json memory_operands = nlohmann::json::array();

    while (scanned < max_instructions) {
        DISASM_INSTR instruction{};
        DbgDisasmAt(current, &instruction);
        if (instruction.instr_size <= 0) {
            stop_reason = "invalid_instruction";
            break;
        }

        const std::string kind = branch_kind(instruction.instruction);
        if (include_instructions) {
            instructions.push_back(instruction_json(current));
        }
        if (!kind.empty()) {
            branches.push_back({
                {"address", hex_value(current)},
                {"kind", kind},
                {"instruction", instruction.instruction},
                {"branch", branch_destination_json(current)},
            });
        }
        for (int i = 0; i < instruction.argcount && i < 3; ++i) {
            const DISASM_ARG& arg = instruction.arg[i];
            if (arg.type != arg_memory || arg.value == 0) {
                continue;
            }
            nlohmann::json item = {
                {"address", hex_value(current)},
                {"operand", i},
                {"memory_address", hex_value(arg.value)},
                {"memory_value", hex_value(arg.memvalue)},
            };
            memory_operands.push_back(item);
            char text[MAX_STRING_SIZE]{};
            if (DbgGetStringAt(arg.value, text)) {
                strings.push_back({{"address", hex_value(arg.value)}, {"referenced_at", hex_value(current)}, {"string", text}});
            }
        }

        ++scanned;
        current += static_cast<duint>(instruction.instr_size);
        if (is_terminal_linear_instruction(kind)) {
            stop_reason = kind;
            break;
        }
    }

    return {
        {"start", hex_value(start)},
        {"end", hex_value(current)},
        {"instructions_scanned", scanned},
        {"stop_reason", stop_reason},
        {"context", address_context_json(start)},
        {"instructions", instructions},
        {"branches", branches},
        {"memory_operands", memory_operands},
        {"strings", strings},
    };
}

nlohmann::json tool_list_functions(const nlohmann::json& params) {
    const std::string module_filter = optional_string(params, "module");
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 100, 1, 50000);

    ListInfo list{};
    if (!Script::Function::GetList(&list) || !list.data) {
        return {{"total", 0}, {"functions", nlohmann::json::array()}};
    }

    auto* functions = static_cast<Script::Function::FunctionInfo*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;
    for (size_t i = 0; i < list.count; ++i) {
        const std::string mod = functions[i].mod;
        if (!module_filter.empty() && !contains_ascii_ci(mod, module_filter)) {
            continue;
        }
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        nlohmann::json item = {
            {"module", mod},
            {"rva_start", hex_value(functions[i].rvaStart)},
            {"rva_end", hex_value(functions[i].rvaEnd)},
            {"manual", functions[i].manual},
            {"instruction_count", static_cast<unsigned long long>(functions[i].instructioncount)},
        };
        if (const auto module = find_module_by_name(mod)) {
            item["start"] = hex_value(module->base + functions[i].rvaStart);
            item["end"] = hex_value(module->base + functions[i].rvaEnd);
        }
        out.push_back(item);
    }
    BridgeFree(list.data);
    return {
        {"module_filter", module_filter},
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", matched > offset + static_cast<int>(out.size())},
        {"functions", out},
    };
}

nlohmann::json tool_find_references_to_range(const nlohmann::json& params) {
    const duint target_start = parse_address(params, "start");
    const duint target_size = parse_address(params, "size");
    const int max_instructions = parse_int(params, "max_instructions", 20000, 1, 500000);
    const int limit = parse_int(params, "limit", 100, 1, 10000);
    const bool include_readonly_code_like_sections = parse_bool(params, "include_readonly_code_like_sections", false);
    const auto ranges = reference_scan_ranges(params);

    nlohmann::json refs = nlohmann::json::array();
    nlohmann::json range_sources = nlohmann::json::object();
    int scanned = 0;
    for (const auto& range : ranges) {
        range_sources[range.source] = range_sources.value(range.source, 0) + 1;
        duint current = range.start;
        const duint end = range.start + range.size;
        while (current < end && scanned < max_instructions && static_cast<int>(refs.size()) < limit) {
            DISASM_INSTR instruction{};
            DbgDisasmAt(current, &instruction);
            if (instruction.instr_size <= 0) {
                ++current;
                continue;
            }
            ++scanned;
            nlohmann::json operands = instruction_references_json(instruction, target_start, target_size);
            const duint branch = DbgGetBranchDestination(current);
            if (branch != 0 && in_range(branch, target_start, target_size)) {
                operands.push_back({{"operand", nullptr}, {"field", "branch_destination"}, {"value", hex_value(branch)}, {"context", address_context_json(branch)}});
            }
            if (!operands.empty()) {
                nlohmann::json item = {
                    {"address", hex_value(current)},
                    {"module", range.module},
                    {"scan_source", range.source},
                    {"section", range.section},
                    {"instruction", instruction.instruction},
                    {"references", operands},
                    {"scan_confidence", range.source == "readonly_code_like_section" ? "low" : "normal"},
                };
                if (range.source == "readonly_code_like_section") {
                    item["confidence_reason"] = "non_executable_section_disassembly";
                }
                refs.push_back(item);
            }
            current += static_cast<duint>(instruction.instr_size);
        }
        if (scanned >= max_instructions || static_cast<int>(refs.size()) >= limit) {
            break;
        }
    }

    return {
        {"target_start", hex_value(target_start)},
        {"target_size", hex_value(target_size)},
        {"scan_ranges", ranges.size()},
        {"range_sources", range_sources},
        {"include_readonly_code_like_sections", include_readonly_code_like_sections},
        {"instructions_scanned", scanned},
        {"limit", limit},
        {"count", refs.size()},
        {"truncated", scanned >= max_instructions || static_cast<int>(refs.size()) >= limit},
        {"references", refs},
    };
}

nlohmann::json tool_find_references_to_module(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }
    nlohmann::json range_params = params;
    range_params["start"] = hex_value(module->base);
    range_params["size"] = hex_value(module->size);
    nlohmann::json result = tool_find_references_to_range(range_params);
    result["target_module"] = module_info_json(*module);
    return result;
}
