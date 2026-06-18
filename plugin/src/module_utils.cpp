#include "module_utils.h"

#include "json_helpers.h"

#include <algorithm>
#include <cctype>

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool contains_ascii_ci(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) {
        return true;
    }
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

bool is_system_module_path(const std::string& path) {
    const std::string lower = lower_ascii(path);
    return lower.find("\\windows\\") != std::string::npos ||
           lower.find("\\system32\\") != std::string::npos ||
           lower.find("\\syswow64\\") != std::string::npos ||
           lower.find("\\winsxs\\") != std::string::npos;
}

duint module_end(const Script::Module::ModuleInfo& module) {
    return module.base + module.size;
}

bool module_contains_address(const Script::Module::ModuleInfo& module, duint address) {
    return address >= module.base && address < module_end(module);
}

bool module_name_or_path_matches(const Script::Module::ModuleInfo& module, const std::string& needle) {
    return contains_ascii_ci(module.name, needle) || contains_ascii_ci(module.path, needle);
}

nlohmann::json module_info_json(const Script::Module::ModuleInfo& module) {
    const std::string path = module.path;
    return {
        {"name", module.name},
        {"base", hex_value(module.base)},
        {"size", hex_value(module.size)},
        {"end", hex_value(module_end(module))},
        {"entry", hex_value(module.entry)},
        {"section_count", module.sectionCount},
        {"path", path},
        {"system", is_system_module_path(path)},
    };
}

std::vector<Script::Module::ModuleInfo> get_module_list() {
    ListInfo list{};
    if (!Script::Module::GetList(&list) || !list.data) {
        throw ApiError("debugger_error", "Failed to list modules.");
    }

    auto* modules = static_cast<Script::Module::ModuleInfo*>(list.data);
    std::vector<Script::Module::ModuleInfo> out;
    out.reserve(list.count);
    for (size_t i = 0; i < list.count; ++i) {
        out.push_back(modules[i]);
    }
    BridgeFree(list.data);
    return out;
}

std::optional<Script::Module::ModuleInfo> find_module_by_name(const std::string& name) {
    const auto modules = get_module_list();

    for (const auto& module : modules) {
        if (_stricmp(module.name, name.c_str()) == 0) {
            return module;
        }
    }

    for (const auto& module : modules) {
        if (module_name_or_path_matches(module, name)) {
            return module;
        }
    }

    return std::nullopt;
}

std::optional<Script::Module::ModuleInfo> find_module_at(duint address) {
    const auto modules = get_module_list();
    for (const auto& module : modules) {
        if (module_contains_address(module, address)) {
            return module;
        }
    }
    return std::nullopt;
}
