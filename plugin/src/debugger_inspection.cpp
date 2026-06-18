#include "debugger_tools.h"

#include "import_utils.h"
#include "instruction_utils.h"
#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <optional>

namespace {

const char* xref_type_name(XREFTYPE type) {
    switch (type) {
    case XREF_DATA: return "data";
    case XREF_JMP: return "jump";
    case XREF_CALL: return "call";
    case XREF_NONE:
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

nlohmann::json address_context_json(duint address) {
    nlohmann::json out = {{"address", hex_value(address)}};
    if (const auto module = find_module_at(address)) {
        out["module_found"] = true;
        out["rva"] = hex_value(address - module->base);
        out["module"] = module_info_json(*module);
    } else {
        out["module_found"] = false;
    }

    SYMBOLINFOCPP symbol{};
    if (DbgGetSymbolInfoAt(address, &symbol)) {
        out["symbol_found"] = true;
        out["symbol"] = symbol_info_json(symbol);
    } else {
        out["symbol_found"] = false;
    }
    return out;
}

nlohmann::json pointer_read_json(duint address, const Script::Module::ModuleInfo* owner_module) {
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
        out["target"] = address_context_json(value);
    }
    out["pointer_classification"] = classify_pointer_value(value, owner_module);
    return out;
}

std::optional<Script::Module::ModuleInfo> pointer_owner_module(const nlohmann::json& params, duint address) {
    const std::string owner_module = optional_string(params, "owner_module");
    if (!owner_module.empty()) {
        const auto module = find_module_by_name(owner_module);
        if (!module) {
            throw ApiError("module_not_found", "Owner module was not found: " + owner_module);
        }
        return module;
    }
    return find_module_at(address);
}

} // namespace

nlohmann::json tool_read_pointer(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const auto owner = pointer_owner_module(params, address);
    return pointer_read_json(address, owner ? &*owner : nullptr);
}

nlohmann::json tool_deref_chain(const nlohmann::json& params) {
    const duint start = parse_address(params, "address");
    duint address = start;
    const int depth = parse_int(params, "depth", 4, 1, 32);

    nlohmann::json steps = nlohmann::json::array();
    std::string stop_reason;
    for (int i = 0; i < depth; ++i) {
        const auto owner = find_module_at(address);
        nlohmann::json step = pointer_read_json(address, owner ? &*owner : nullptr);
        step["depth"] = i;
        steps.push_back(step);
        if (!steps.back().value("readable", false)) {
            stop_reason = "unreadable";
            break;
        }
        const std::string value = steps.back().value("value", "");
        if (value.empty() || steps.back().value("is_null", false)) {
            stop_reason = "null";
            break;
        }
        address = parse_address({{"address", value}}, "address");
    }
    if (stop_reason.empty() && static_cast<int>(steps.size()) >= depth) {
        stop_reason = "max_depth";
    }
    return {{"start", hex_value(start)}, {"depth", depth}, {"stop_reason", stop_reason}, {"steps", steps}};
}

nlohmann::json tool_inspect_instruction(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    nlohmann::json out = instruction_json(address);
    out["context"] = address_context_json(address);
    return out;
}

nlohmann::json tool_inspect_address(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const bool data_only = parse_bool(params, "data_only", false);
    nlohmann::json out = address_context_json(address);
    out["data_only"] = data_only;

    if (const auto page = find_memory_page_at(address)) {
        out["page_found"] = true;
        out["page"] = memory_page_json(*page);
    } else {
        out["page_found"] = false;
    }

    char label[MAX_LABEL_SIZE]{};
    const bool label_found = DbgGetLabelAt(address, SEG_DEFAULT, label);
    out["label_found"] = label_found;
    out["label"] = label_found ? label : "";

    char comment[MAX_COMMENT_SIZE]{};
    const bool comment_found = DbgGetCommentAt(address, comment);
    out["comment_found"] = comment_found;
    out["comment"] = comment_found ? comment : "";

    char text[MAX_STRING_SIZE]{};
    const bool string_found = DbgGetStringAt(address, text);
    out["string_found"] = string_found;
    out["string"] = string_found ? text : "";

    out["bookmark"] = DbgGetBookmarkAt(address);
    out["breakpoint_type"] = breakpoint_type_name(DbgGetBpxTypeAt(address));
    out["xref_count"] = static_cast<unsigned long long>(DbgGetXrefCountAt(address));
    out["xref_type"] = xref_type_name(DbgGetXrefTypeAt(address));
    const auto owner = pointer_owner_module(params, address);
    out["pointer"] = pointer_read_json(address, owner ? &*owner : nullptr);
    if (data_only) {
        out["instruction_skipped"] = true;
        out["instruction"] = nullptr;
    } else {
        out["instruction_skipped"] = false;
        out["instruction"] = instruction_json(address);
    }
    return out;
}
