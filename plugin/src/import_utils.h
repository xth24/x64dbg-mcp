#pragma once

#include "sdk.h"

#include <nlohmann/json.hpp>

nlohmann::json import_record_json(const Script::Module::ModuleImport& import, const Script::Module::ModuleInfo& module);
nlohmann::json import_pointer_json(duint slot);
nlohmann::json classify_import_pointer(duint slot, const Script::Module::ModuleInfo& module);
