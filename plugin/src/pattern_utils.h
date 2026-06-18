#pragma once

#include "sdk.h"

#include <string>
#include <vector>

bool pattern_address_valid(duint address);
std::vector<duint> find_pattern_hits_in_range(duint start, duint size, const std::string& pattern, int limit);
std::vector<duint> find_pattern_hits_in_module(const Script::Module::ModuleInfo& module, const std::string& pattern, int limit);
