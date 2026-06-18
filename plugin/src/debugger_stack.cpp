#include "debugger_tools.h"

#include "import_utils.h"
#include "instruction_utils.h"
#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace {

struct ScanRange {
    duint start;
    duint size;
    std::string module;
};

bool is_executable_address(duint address) {
    const auto page = find_memory_page_at(address);
    if (!page) {
        return false;
    }
    const DWORD protect = page->mbi.Protect & 0xff;
    return protect == PAGE_EXECUTE ||
           protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE ||
           protect == PAGE_EXECUTE_WRITECOPY;
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
    if (const auto page = find_memory_page_at(address)) {
        out["page_found"] = true;
        out["page"] = memory_page_json(*page);
        out["executable"] = is_executable_address(address);
    } else {
        out["page_found"] = false;
        out["executable"] = false;
    }
    return out;
}

nlohmann::json value_json(duint value, bool include_strings, const Script::Module::ModuleInfo* owner_module) {
    nlohmann::json out = {
        {"value", hex_value(value)},
        {"is_null", value == 0},
        {"pointer_classification", classify_pointer_value(value, owner_module)},
    };
    if (value == 0) {
        return out;
    }

    out["target"] = address_context_json(value);
    if (include_strings) {
        char text[MAX_STRING_SIZE]{};
        const bool string_found = DbgGetStringAt(value, text);
        out["string_found"] = string_found;
        out["string"] = string_found ? text : "";
    }
    return out;
}

nlohmann::json pointer_slot_json(duint address, bool include_strings, const Script::Module::ModuleInfo* owner_module) {
    duint value = 0;
    duint read = 0;
    if (!Script::Memory::Read(address, &value, sizeof(value), &read) || read != sizeof(value)) {
        return {
            {"address", hex_value(address)},
            {"readable", false},
            {"pointer_size", sizeof(value)},
        };
    }

    nlohmann::json out = {
        {"address", hex_value(address)},
        {"readable", true},
        {"pointer_size", sizeof(value)},
        {"value", hex_value(value)},
        {"is_null", value == 0},
    };
    if (value != 0) {
        out["value_info"] = value_json(value, include_strings, owner_module);
        out["possible_return_address"] = is_executable_address(value);
    }
    out["pointer_classification"] = classify_pointer_value(value, owner_module);
    return out;
}

nlohmann::json register_arg_json(int index, const char* name, Script::Register::RegisterEnum reg, bool include_strings, const Script::Module::ModuleInfo* owner_module) {
    const duint value = Script::Register::Get(reg);
    nlohmann::json out = value_json(value, include_strings, owner_module);
    out["index"] = index;
    out["source"] = "register";
    out["register"] = name;
    return out;
}

nlohmann::json stack_arg_json(int index, duint slot, bool include_strings, const Script::Module::ModuleInfo* owner_module) {
    nlohmann::json out = pointer_slot_json(slot, include_strings, owner_module);
    out["index"] = index;
    out["source"] = "stack";
    out["stack_slot"] = hex_value(slot);
    return out;
}

std::optional<Script::Module::ModuleInfo> owner_module_from_params(const nlohmann::json& params) {
    const std::string owner_module = optional_string(params, "owner_module");
    if (owner_module.empty()) {
        return std::nullopt;
    }
    const auto module = find_module_by_name(owner_module);
    if (!module) {
        throw ApiError("module_not_found", "Owner module was not found: " + owner_module);
    }
    return module;
}

std::vector<ScanRange> readable_ranges_for_bounds(duint start, duint size, const std::string& module) {
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
            ranges.push_back({scan_start, scan_end - scan_start, module});
        }
    }
    return ranges;
}

std::vector<ScanRange> pointer_scan_ranges(const nlohmann::json& params, duint max_scan_bytes, duint& total_bytes, bool& capped_by_bytes) {
    std::vector<ScanRange> ranges;
    total_bytes = 0;

    const std::string scan_module = optional_string(params, "scan_module");
    if (!scan_module.empty()) {
        const auto module = find_module_by_name(scan_module);
        if (!module) {
            throw ApiError("module_not_found", "Scan module was not found: " + scan_module);
        }
        ranges = readable_ranges_for_bounds(module->base, module->size, module->name);
    } else if (params.contains("scan_start") && params["scan_start"].is_string()) {
        const duint scan_start = parse_address(params, "scan_start");
        const duint scan_size = parse_address(params, "scan_size");
        ranges = readable_ranges_for_bounds(scan_start, scan_size, "");
    } else {
        const bool include_system = parse_bool(params, "include_system", false);
        for (const auto& module : get_module_list()) {
            if (!include_system && is_system_module_path(module.path)) {
                continue;
            }
            auto module_ranges = readable_ranges_for_bounds(module.base, module.size, module.name);
            ranges.insert(ranges.end(), module_ranges.begin(), module_ranges.end());
        }
    }

    std::vector<ScanRange> capped;
    capped_by_bytes = false;
    for (const auto& range : ranges) {
        if (total_bytes >= max_scan_bytes) {
            capped_by_bytes = true;
            break;
        }
        const duint remaining = max_scan_bytes - total_bytes;
        const duint size = std::min(range.size, remaining);
        if (size < range.size) {
            capped_by_bytes = true;
        }
        if (size != 0) {
            capped.push_back({range.start, size, range.module});
            total_bytes += size;
        }
    }
    return capped;
}

bool in_range(duint value, duint start, duint size) {
    return size != 0 && value >= start && value < start + size;
}

nlohmann::json pointer_hit_json(duint address, duint value, const std::string& module, duint target_start) {
    nlohmann::json hit = {
        {"address", hex_value(address)},
        {"value", hex_value(value)},
        {"target_offset", hex_value(value - target_start)},
        {"target", address_context_json(value)},
    };
    if (!module.empty()) {
        hit["module"] = module;
        if (const auto owner = find_module_by_name(module)) {
            hit["rva"] = hex_value(address - owner->base);
        }
    }
    return hit;
}

} // namespace

nlohmann::json tool_inspect_stack(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const std::string address_expr = optional_string(params, "address");
    const duint csp = Script::Register::Get(kStackPointer);
    const duint start = address_expr.empty() ? csp : parse_address(params, "address");
    const int slots = parse_int(params, "slots", 12, 1, 512);
    const bool include_strings = parse_bool(params, "include_strings", false);
    const auto owner_module = owner_module_from_params(params);

    nlohmann::json out = nlohmann::json::array();
    for (int i = 0; i < slots; ++i) {
        const duint slot = start + static_cast<duint>(i) * sizeof(duint);
        const auto slot_owner = owner_module ? owner_module : find_module_at(slot);
        nlohmann::json item = pointer_slot_json(slot, include_strings, slot_owner ? &*slot_owner : nullptr);
        item["slot"] = i;
        item["offset_from_start"] = hex_value(slot - start);
        if (slot >= csp) {
            item["offset_from_csp"] = hex_value(slot - csp);
        }
        out.push_back(item);
    }

    return {
        {"start", hex_value(start)},
        {"csp", hex_value(csp)},
        {"slots", slots},
        {"pointer_size", sizeof(duint)},
        {"include_strings", include_strings},
        {"owner_module", owner_module ? module_info_json(*owner_module) : nlohmann::json(nullptr)},
        {"stack", out},
    };
}

nlohmann::json tool_inspect_call_args(const nlohmann::json& params) {
    if (!DbgIsDebugging()) {
        throw ApiError("not_debugging", "No debuggee is currently active.");
    }

    const std::string address_expr = optional_string(params, "address");
    const duint cip = Script::Register::Get(kInstructionPointer);
    const duint csp = Script::Register::Get(kStackPointer);
    const duint address = address_expr.empty() ? cip : parse_address(params, "address");
    const int count = parse_int(params, "count", 6, 0, 32);
    const bool include_strings = parse_bool(params, "include_strings", false);
    const std::string stack_mode = optional_string(params, "stack_mode", "callee");
    const bool before_call = stack_mode == "before_call";
    const std::string convention = optional_string(params, "convention", "auto");
    const auto owner_module = owner_module_from_params(params);
    const auto* owner = owner_module ? &*owner_module : nullptr;

    nlohmann::json args = nlohmann::json::array();

#ifdef _WIN64
    if (count > 0) args.push_back(register_arg_json(0, "rcx", Script::Register::RCX, include_strings, owner));
    if (count > 1) args.push_back(register_arg_json(1, "rdx", Script::Register::RDX, include_strings, owner));
    if (count > 2) args.push_back(register_arg_json(2, "r8", Script::Register::R8, include_strings, owner));
    if (count > 3) args.push_back(register_arg_json(3, "r9", Script::Register::R9, include_strings, owner));
    const duint stack_base = csp + (before_call ? 0x20 : 0x28);
    for (int i = 4; i < count; ++i) {
        args.push_back(stack_arg_json(i, stack_base + static_cast<duint>(i - 4) * sizeof(duint), include_strings, owner));
    }
    const std::string effective_convention = "windows_x64";
#else
    const bool thiscall = convention == "thiscall";
    const bool fastcall = convention == "fastcall";
    int index = 0;
    if ((thiscall || fastcall) && index < count) {
        args.push_back(register_arg_json(index++, "ecx", Script::Register::ECX, include_strings, owner));
    }
    if (fastcall && index < count) {
        args.push_back(register_arg_json(index++, "edx", Script::Register::EDX, include_strings, owner));
    }
    const duint stack_base = csp + (before_call ? 0 : sizeof(duint));
    while (index < count) {
        args.push_back(stack_arg_json(index, stack_base + static_cast<duint>(index - (fastcall ? 2 : thiscall ? 1 : 0)) * sizeof(duint), include_strings, owner));
        ++index;
    }
    const std::string effective_convention = thiscall ? "thiscall" : fastcall ? "fastcall" : "cdecl_stdcall";
#endif

    nlohmann::json result = {
        {"address", hex_value(address)},
        {"cip", hex_value(cip)},
        {"csp", hex_value(csp)},
        {"arch", kDebuggerArch},
        {"requested_convention", convention},
        {"effective_convention", effective_convention},
        {"stack_mode", before_call ? "before_call" : "callee"},
        {"count", count},
        {"include_strings", include_strings},
        {"owner_module", owner_module ? module_info_json(*owner_module) : nlohmann::json(nullptr)},
        {"instruction", instruction_json(address)},
        {"args", args},
        {"note", "Registers and stack values are current debugger state; non-current addresses are not emulated."},
    };
    if (!before_call) {
        result["return_address"] = pointer_slot_json(csp, include_strings, owner);
    }
#ifndef _WIN64
    result["register_candidates"] = {
        {"ecx", value_json(Script::Register::Get(Script::Register::ECX), include_strings, owner)},
        {"edx", value_json(Script::Register::Get(Script::Register::EDX), include_strings, owner)},
    };
#endif
    return result;
}

nlohmann::json tool_find_pointers_to_range(const nlohmann::json& params) {
    const duint target_start = parse_address(params, "target_start");
    const duint target_size = parse_address(params, "target_size");
    const int limit = parse_int(params, "limit", 100, 1, 10000);
    const int max_scan_bytes_int = parse_int(params, "max_scan_bytes", 64 * 1024 * 1024, 1, 512 * 1024 * 1024);
    const duint max_scan_bytes = static_cast<duint>(max_scan_bytes_int);
    const bool aligned_only = parse_bool(params, "aligned_only", true);

    duint total_bytes = 0;
    bool capped_by_bytes = false;
    const auto ranges = pointer_scan_ranges(params, max_scan_bytes, total_bytes, capped_by_bytes);
    nlohmann::json hits = nlohmann::json::array();
    duint scanned_bytes = 0;
    static constexpr duint kChunkSize = 64 * 1024;

    for (const auto& range : ranges) {
        duint offset = 0;
        while (offset < range.size && static_cast<int>(hits.size()) < limit) {
            const duint to_read = std::min(kChunkSize, range.size - offset);
            std::vector<unsigned char> bytes(static_cast<size_t>(to_read));
            duint read = 0;
            if (Script::Memory::Read(range.start + offset, bytes.data(), to_read, &read) && read >= sizeof(duint)) {
                const duint base = range.start + offset;
                const duint step = aligned_only ? sizeof(duint) : 1;
                duint start_index = 0;
                if (aligned_only) {
                    const duint misalignment = base % sizeof(duint);
                    start_index = misalignment == 0 ? 0 : sizeof(duint) - misalignment;
                }
                for (duint i = start_index; i + sizeof(duint) <= read && static_cast<int>(hits.size()) < limit; i += step) {
                    duint value = 0;
                    std::memcpy(&value, bytes.data() + i, sizeof(value));
                    if (in_range(value, target_start, target_size)) {
                        hits.push_back(pointer_hit_json(base + i, value, range.module, target_start));
                    }
                }
                scanned_bytes += read;
            }
            offset += to_read;
        }
        if (static_cast<int>(hits.size()) >= limit) {
            break;
        }
    }

    return {
        {"target_start", hex_value(target_start)},
        {"target_size", hex_value(target_size)},
        {"scan_ranges", ranges.size()},
        {"scanned_bytes", hex_value(scanned_bytes)},
        {"max_scan_bytes", hex_value(max_scan_bytes)},
        {"aligned_only", aligned_only},
        {"limit", limit},
        {"count", hits.size()},
        {"truncated", static_cast<int>(hits.size()) >= limit || capped_by_bytes},
        {"capped_by_max_scan_bytes", capped_by_bytes},
        {"pointers", hits},
    };
}
