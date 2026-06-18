#pragma once

#include "sdk.h"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

std::string lower_ascii(std::string value);
bool contains_ascii_ci(const std::string& haystack, const std::string& needle);
bool is_system_module_path(const std::string& path);
duint module_end(const Script::Module::ModuleInfo& module);
bool module_contains_address(const Script::Module::ModuleInfo& module, duint address);
bool module_name_or_path_matches(const Script::Module::ModuleInfo& module, const std::string& needle);
nlohmann::json module_info_json(const Script::Module::ModuleInfo& module);
std::vector<Script::Module::ModuleInfo> get_module_list();
std::optional<Script::Module::ModuleInfo> find_module_by_name(const std::string& name);
std::optional<Script::Module::ModuleInfo> find_module_at(duint address);
