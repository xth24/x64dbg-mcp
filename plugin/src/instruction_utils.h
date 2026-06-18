#pragma once

#include "sdk.h"

#include <nlohmann/json.hpp>

nlohmann::json instruction_json(duint address);
nlohmann::json branch_destination_json(duint address);
