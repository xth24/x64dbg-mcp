#pragma once

#include <string>

std::string wide_to_utf8(const std::wstring& value);
std::wstring utf8_to_wide(const std::string& value);
