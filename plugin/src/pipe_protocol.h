#pragma once

#include <Windows.h>
#include <nlohmann/json.hpp>

nlohmann::json read_json_frame(HANDLE pipe);
void write_json_frame(HANDLE pipe, const nlohmann::json& value);
