#include "debugger_tools.h"

#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <algorithm>

nlohmann::json tool_list_modules(const nlohmann::json& params) {
    const std::string module_filter = optional_string(params, "module");
    const std::string path_filter = optional_string(params, "path_contains");
    const bool non_system = parse_bool(params, "non_system", false);
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 200, 1, 5000);

    const auto modules = get_module_list();
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;
    for (const auto& module : modules) {
        const std::string path = module.path;
        if (!module_filter.empty() && !contains_ascii_ci(module.name, module_filter)) {
            continue;
        }
        if (!path_filter.empty() && !contains_ascii_ci(path, path_filter)) {
            continue;
        }
        if (non_system && is_system_module_path(path)) {
            continue;
        }
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        out.push_back(module_info_json(module));
    }
    return {
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", matched > offset + static_cast<int>(out.size())},
        {"modules", out},
    };
}

nlohmann::json tool_get_module_at(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const auto module = find_module_at(address);
    if (!module) {
        return {{"address", hex_value(address)}, {"found", false}};
    }
    return {
        {"address", hex_value(address)},
        {"found", true},
        {"rva", hex_value(address - module->base)},
        {"module", module_info_json(*module)},
    };
}

nlohmann::json tool_list_module_sections(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }

    ListInfo list{};
    if (!Script::Module::SectionListFromAddr(module->base, &list) || !list.data) {
        return {{"module", module_info_json(*module)}, {"count", 0}, {"sections", nlohmann::json::array()}};
    }

    auto* sections = static_cast<Script::Module::ModuleSectionInfo*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    for (size_t i = 0; i < list.count; ++i) {
        const duint addr = sections[i].addr;
        nlohmann::json item = {
            {"name", sections[i].name},
            {"address", hex_value(addr)},
            {"rva", addr >= module->base ? hex_value(addr - module->base) : ""},
            {"size", hex_value(sections[i].size)},
            {"end", hex_value(addr + sections[i].size)},
        };
        if (const auto page = find_memory_page_at(addr)) {
            item["page"] = memory_page_json(*page);
        }
        out.push_back(item);
    }
    BridgeFree(list.data);
    return {{"module", module_info_json(*module)}, {"count", out.size()}, {"sections", out}};
}

nlohmann::json tool_list_module_exports(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 500, 1, 50000);
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }

    ListInfo list{};
    if (!Script::Module::GetExports(&*module, &list) || !list.data) {
        return {{"module", module_info_json(*module)}, {"total", 0}, {"exports", nlohmann::json::array()}};
    }

    auto* exports = static_cast<Script::Module::ModuleExport*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;
    for (size_t i = 0; i < list.count; ++i) {
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        out.push_back({
            {"ordinal", static_cast<unsigned long long>(exports[i].ordinal)},
            {"rva", hex_value(exports[i].rva)},
            {"address", hex_value(exports[i].va)},
            {"name", exports[i].name},
            {"undecorated", exports[i].undecoratedName},
            {"forwarded", exports[i].forwarded},
            {"forward_name", exports[i].forwardName},
        });
    }
    BridgeFree(list.data);
    return {
        {"module", module_info_json(*module)},
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", matched > offset + static_cast<int>(out.size())},
        {"exports", out},
    };
}

nlohmann::json tool_list_module_imports(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 500, 1, 50000);
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }

    ListInfo list{};
    if (!Script::Module::GetImports(&*module, &list) || !list.data) {
        return {{"module", module_info_json(*module)}, {"total", 0}, {"imports", nlohmann::json::array()}};
    }

    auto* imports = static_cast<Script::Module::ModuleImport*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;
    for (size_t i = 0; i < list.count; ++i) {
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        const bool ordinal_valid = imports[i].ordinal != static_cast<duint>(-1);
        out.push_back({
            {"iat_rva", hex_value(imports[i].iatRva)},
            {"iat_address", hex_value(imports[i].iatVa)},
            {"ordinal", ordinal_valid ? nlohmann::json(static_cast<unsigned long long>(imports[i].ordinal)) : nlohmann::json(nullptr)},
            {"name", imports[i].name},
            {"undecorated", imports[i].undecoratedName},
        });
    }
    BridgeFree(list.data);
    return {
        {"module", module_info_json(*module)},
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", matched > offset + static_cast<int>(out.size())},
        {"imports", out},
    };
}

nlohmann::json tool_list_threads(const nlohmann::json&) {
    THREADLIST list{};
    DbgGetThreadList(&list);

    nlohmann::json threads = nlohmann::json::array();
    for (int i = 0; i < list.count; ++i) {
        const THREADALLINFO& t = list.list[i];
        threads.push_back({
            {"thread_number", t.BasicInfo.ThreadNumber},
            {"thread_id", t.BasicInfo.ThreadId},
            {"thread_name", t.BasicInfo.threadName},
            {"start_address", hex_value(t.BasicInfo.ThreadStartAddress)},
            {"teb", hex_value(t.BasicInfo.ThreadLocalBase)},
            {"cip", hex_value(t.ThreadCip)},
            {"suspend_count", t.SuspendCount},
            {"last_error", t.LastError},
            {"cycles", t.Cycles},
        });
    }

    if (list.list) {
        BridgeFree(list.list);
    }

    return {
        {"count", threads.size()},
        {"current_thread", list.CurrentThread},
        {"threads", threads},
    };
}

nlohmann::json tool_get_memory_map(const nlohmann::json&) {
    const auto map = get_memory_pages();
    nlohmann::json pages = nlohmann::json::array();
    for (const auto& page : map) {
        pages.push_back(memory_page_json(page));
    }

    return {{"count", pages.size()}, {"pages", pages}};
}

nlohmann::json tool_get_page_at(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const auto page = find_memory_page_at(address);
    if (!page) {
        return {{"address", hex_value(address)}, {"found", false}};
    }
    return {{"address", hex_value(address)}, {"found", true}, {"page", memory_page_json(*page)}};
}

nlohmann::json tool_query_symbols(const nlohmann::json& params) {
    const std::string module = required_string(params, "module");
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 5000, 1, 50000);

    ListInfo list{};
    if (!Script::Symbol::GetList(&list) || !list.data) {
        throw ApiError("debugger_error", "Failed to enumerate symbols.");
    }

    auto* symbols = static_cast<Script::Symbol::SymbolInfo*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;

    for (size_t i = 0; i < list.count; ++i) {
        if (_stricmp(symbols[i].mod, module.c_str()) != 0) {
            continue;
        }
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }

        const char* type = "unknown";
        if (symbols[i].type == Script::Symbol::Function) type = "function";
        if (symbols[i].type == Script::Symbol::Import) type = "import";
        if (symbols[i].type == Script::Symbol::Export) type = "export";

        out.push_back({
            {"rva", hex_value(symbols[i].rva)},
            {"name", symbols[i].name},
            {"manual", symbols[i].manual != 0},
            {"type", type},
        });
    }

    BridgeFree(list.data);
    return {
        {"module", module},
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"symbols", out},
    };
}

nlohmann::json tool_list_labels(const nlohmann::json&) {
    ListInfo list{};
    if (!Script::Label::GetList(&list) || !list.data) {
        return {{"count", 0}, {"labels", nlohmann::json::array()}};
    }

    auto* labels = static_cast<Script::Label::LabelInfo*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    for (size_t i = 0; i < list.count; ++i) {
        out.push_back({
            {"module", labels[i].mod},
            {"rva", hex_value(labels[i].rva)},
            {"text", labels[i].text},
            {"manual", labels[i].manual != 0},
        });
    }
    BridgeFree(list.data);
    return {{"count", out.size()}, {"labels", out}};
}

nlohmann::json tool_set_label(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const std::string text = required_string(params, "text");
    return {
        {"action", "set_label"},
        {"address", hex_value(address)},
        {"text", text},
        {"success", Script::Label::Set(address, text.c_str(), true, false)},
    };
}

nlohmann::json tool_set_comment(const nlohmann::json& params) {
    const duint address = parse_address(params, "address");
    const std::string text = required_string(params, "text");
    return {
        {"action", "set_comment"},
        {"address", hex_value(address)},
        {"text", text},
        {"success", Script::Comment::Set(address, text.c_str(), true)},
    };
}
