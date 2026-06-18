#include "import_utils.h"

#include "json_helpers.h"
#include "module_utils.h"

namespace {

nlohmann::json address_context_json(duint address) {
    nlohmann::json out = {{"address", hex_value(address)}, {"module_found", false}, {"symbol_found", false}};
    if (const auto module = find_module_at(address)) {
        out["module_found"] = true;
        out["rva"] = hex_value(address - module->base);
        out["module"] = module_info_json(*module);
    }
    SYMBOLINFOCPP symbol{};
    if (DbgGetSymbolInfoAt(address, &symbol)) {
        out["symbol_found"] = true;
        out["symbol"] = symbol_info_json(symbol);
    }
    return out;
}

} // namespace

nlohmann::json import_record_json(const Script::Module::ModuleImport& import, const Script::Module::ModuleInfo& module) {
    const bool ordinal_valid = import.ordinal != static_cast<duint>(-1);
    return {
        {"owner_module", module_info_json(module)},
        {"iat_rva", hex_value(import.iatRva)},
        {"iat_address", hex_value(import.iatVa)},
        {"ordinal", ordinal_valid ? nlohmann::json(static_cast<unsigned long long>(import.ordinal)) : nlohmann::json(nullptr)},
        {"name", import.name},
        {"undecorated", import.undecoratedName},
    };
}

nlohmann::json import_pointer_json(duint slot) {
    duint value = 0;
    duint read = 0;
    if (!Script::Memory::Read(slot, &value, sizeof(value), &read) || read != sizeof(value)) {
        return {{"address", hex_value(slot)}, {"readable", false}, {"pointer_size", sizeof(value)}};
    }
    nlohmann::json out = {
        {"address", hex_value(slot)},
        {"readable", true},
        {"pointer_size", sizeof(value)},
        {"value", hex_value(value)},
        {"is_null", value == 0},
    };
    if (value != 0) {
        out["target"] = address_context_json(value);
    }
    return out;
}

nlohmann::json classify_pointer_value(duint value, const Script::Module::ModuleInfo* owner_module) {
    if (value == 0) {
        return {{"kind", "null"}, {"value", hex_value(value)}};
    }
    if (find_module_at(value)) {
        return {{"kind", "absolute_loaded_address"}, {"value", hex_value(value)}, {"target", address_context_json(value)}};
    }
    if (owner_module && value >= 0x1000 && value < owner_module->size) {
        const duint absolute = owner_module->base + value;
        nlohmann::json result = {
            {"kind", "owner_module_rva"},
            {"value", hex_value(value)},
            {"rva", hex_value(value)},
            {"absolute_address", hex_value(absolute)},
        };
        result["target"] = address_context_json(absolute);
        return result;
    }
    return {{"kind", "raw_unresolved"}, {"value", hex_value(value)}};
}

nlohmann::json classify_pointer_at(duint slot, const Script::Module::ModuleInfo* owner_module) {
    duint value = 0;
    duint read = 0;
    if (!Script::Memory::Read(slot, &value, sizeof(value), &read) || read != sizeof(value)) {
        return {{"kind", "unreadable"}};
    }
    return classify_pointer_value(value, owner_module);
}

nlohmann::json classify_import_pointer(duint slot, const Script::Module::ModuleInfo& module) {
    return classify_pointer_at(slot, &module);
}
