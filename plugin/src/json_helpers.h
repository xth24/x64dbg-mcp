#pragma once

#include "sdk.h"

#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

class ApiError : public std::runtime_error {
public:
    ApiError(std::string code, std::string message);

    const std::string& code() const { return code_; }

private:
    std::string code_;
};

duint parse_address(const nlohmann::json& params, const char* key);
bool parse_bool(const nlohmann::json& params, const char* key, bool fallback);
int parse_int(const nlohmann::json& params, const char* key, int fallback, int min_value, int max_value);
std::string optional_string(const nlohmann::json& params, const char* key, const std::string& fallback = "");
std::string required_string(const nlohmann::json& params, const char* key);
std::string hex_value(duint value);
std::vector<unsigned char> parse_hex_bytes(const std::string& value);
nlohmann::json ok_status(const char* action, bool success);
nlohmann::json symbol_info_json(const SYMBOLINFO& info);
nlohmann::json register_dump_json();
nlohmann::json disassemble_json(duint address, int count);
