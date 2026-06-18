#pragma once

#include "sdk.h"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

std::string memory_state_name(DWORD state);
std::string memory_type_name(DWORD type);
std::string protection_name(DWORD protect);
bool is_readable_page(const MEMPAGE& page);
nlohmann::json memory_page_json(const MEMPAGE& page);
std::vector<MEMPAGE> get_memory_pages();
std::optional<MEMPAGE> find_memory_page_at(duint address);
