#pragma once

#include <nlohmann/json.hpp>

nlohmann::json dispatch_request(const nlohmann::json& request);
