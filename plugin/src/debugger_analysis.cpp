#include "debugger_tools.h"

#include "instruction_utils.h"
#include "json_helpers.h"
#include "module_utils.h"
#include "pattern_utils.h"
#include "sdk.h"

#include <vector>

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

} // namespace

nlohmann::json tool_parse_expression(const nlohmann::json& params) {
    const std::string expression = required_string(params, "expression");
    duint value = 0;
    if (!Script::Misc::ParseExpression(expression.c_str(), &value)) {
        throw ApiError("parse_failed", "x64dbg could not parse the expression.");
    }
    return {
        {"expression", expression},
        {"value", hex_value(value)},
        {"value_decimal", static_cast<unsigned long long>(value)},
    };
}

nlohmann::json tool_get_branch_destination(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    return branch_destination_json(address);
}

nlohmann::json tool_find_pattern(const nlohmann::json& params) {
    duint start = 0;
    duint size = 0;
    if (params.contains("module") && params["module"].is_string()) {
        const std::string module_name = params["module"].get<std::string>();
        const auto module = find_module_by_name(module_name);
        if (!module) {
            throw ApiError("module_not_found", "Module was not found: " + module_name);
        }
        start = module->base;
        size = module->size;
    } else {
        start = parse_address(params, "start");
        size = parse_address(params, "size");
    }

    const std::string pattern = required_string(params, "pattern");
    if (size > static_cast<duint>(256ull * 1024ull * 1024ull)) {
        throw ApiError("range_too_large", "Pattern searches are capped at 256 MiB per call.");
    }

    const bool module_search = params.contains("module") && params["module"].is_string();
    std::vector<duint> hits;
    if (module_search) {
        const auto module = find_module_at(start);
        hits = module ? find_pattern_hits_in_module(*module, pattern, 1) : find_pattern_hits_in_range(start, size, pattern, 1);
    } else {
        hits = find_pattern_hits_in_range(start, size, pattern, 1);
    }
    const bool matched = !hits.empty();
    nlohmann::json result = {
        {"pattern", pattern},
        {"start", hex_value(start)},
        {"size", hex_value(size)},
        {"found", matched},
        {"address", matched ? hex_value(hits.front()) : ""},
        {"search_mode", module_search ? "module_pages" : "range_chunks"},
    };
    if (module_search) {
        if (const auto module = find_module_at(start)) {
            result["module"] = module_info_json(*module);
        }
    }
    return result;
}

nlohmann::json tool_find_all_patterns(const nlohmann::json& params) {
    duint start = 0;
    duint size = 0;
    const bool module_search = params.contains("module") && params["module"].is_string();
    if (module_search) {
        const std::string module_name = params["module"].get<std::string>();
        const auto module = find_module_by_name(module_name);
        if (!module) {
            throw ApiError("module_not_found", "Module was not found: " + module_name);
        }
        start = module->base;
        size = module->size;
    } else {
        start = parse_address(params, "start");
        size = parse_address(params, "size");
    }

    const std::string pattern = required_string(params, "pattern");
    const int limit = parse_int(params, "limit", 100, 1, 5000);
    if (size > static_cast<duint>(256ull * 1024ull * 1024ull)) {
        throw ApiError("range_too_large", "Pattern searches are capped at 256 MiB per call.");
    }

    std::vector<duint> hits;
    if (module_search) {
        const auto module = find_module_at(start);
        hits = module ? find_pattern_hits_in_module(*module, pattern, limit) : find_pattern_hits_in_range(start, size, pattern, limit);
    } else {
        hits = find_pattern_hits_in_range(start, size, pattern, limit);
    }

    nlohmann::json out = nlohmann::json::array();
    for (duint hit : hits) {
        nlohmann::json item = {{"address", hex_value(hit)}};
        if (const auto module = find_module_at(hit)) {
            item["module"] = module->name;
            item["rva"] = hex_value(hit - module->base);
        }
        out.push_back(item);
    }

    nlohmann::json result = {
        {"pattern", pattern},
        {"start", hex_value(start)},
        {"size", hex_value(size)},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", static_cast<int>(out.size()) >= limit},
        {"search_mode", module_search ? "module_pages" : "range_chunks"},
        {"hits", out},
    };
    if (module_search) {
        if (const auto module = find_module_at(start)) {
            result["module"] = module_info_json(*module);
        }
    }
    return result;
}

nlohmann::json tool_get_call_stack(const nlohmann::json&) {
    const DBGFUNCTIONS* functions = DbgFunctions();
    if (!functions || (!functions->GetCallStackEx && !functions->GetCallStack)) {
        throw ApiError("unsupported", "Call stack API is not available in this x64dbg build.");
    }

    DBGCALLSTACK stack{};
    if (functions->GetCallStackEx) {
        functions->GetCallStackEx(&stack, true);
    } else {
        functions->GetCallStack(&stack);
    }

    nlohmann::json entries = nlohmann::json::array();
    for (int i = 0; i < stack.total && stack.entries; ++i) {
        const DBGCALLSTACKENTRY& entry = stack.entries[i];
        entries.push_back({
            {"address", hex_value(entry.addr)},
            {"from", hex_value(entry.from)},
            {"to", hex_value(entry.to)},
            {"comment", entry.comment},
        });
    }

    if (stack.entries) {
        BridgeFree(stack.entries);
    }

    return {{"count", entries.size()}, {"frames", entries}};
}

nlohmann::json tool_get_symbol_at(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    SYMBOLINFOCPP info;
    if (!DbgGetSymbolInfoAt(address, &info)) {
        return {{"address", hex_value(address)}, {"found", false}};
    }
    return {{"address", hex_value(address)}, {"found", true}, {"symbol", symbol_info_json(info)}};
}

nlohmann::json tool_get_string_at(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    char text[MAX_STRING_SIZE]{};
    const bool found = DbgGetStringAt(address, text);
    return {
        {"address", hex_value(address)},
        {"found", found},
        {"string", found ? text : ""},
    };
}

nlohmann::json tool_get_xrefs(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const int limit = parse_int(params, "limit", 500, 1, 5000);

    XREF_INFO info{};
    if (!DbgXrefGet(address, &info)) {
        return {{"address", hex_value(address)}, {"count", 0}, {"xrefs", nlohmann::json::array()}};
    }

    nlohmann::json refs = nlohmann::json::array();
    const duint count = info.refcount < static_cast<duint>(limit) ? info.refcount : static_cast<duint>(limit);
    for (duint i = 0; i < count && info.references; ++i) {
        refs.push_back({
            {"address", hex_value(info.references[i].addr)},
            {"type", xref_type_name(info.references[i].type)},
        });
    }

    if (info.references) {
        BridgeFree(info.references);
    }

    return {
        {"address", hex_value(address)},
        {"total", static_cast<unsigned long long>(info.refcount)},
        {"returned", refs.size()},
        {"xrefs", refs},
    };
}
