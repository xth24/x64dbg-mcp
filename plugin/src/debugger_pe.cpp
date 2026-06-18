#include "debugger_tools.h"

#include "import_utils.h"
#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"
#include "sdk.h"

#include <array>
#include <string>

namespace {

struct ClrHeader {
    DWORD cb;
    WORD major_runtime_version;
    WORD minor_runtime_version;
    IMAGE_DATA_DIRECTORY metadata;
    DWORD flags;
    DWORD entry_point_token_or_rva;
    IMAGE_DATA_DIRECTORY resources;
    IMAGE_DATA_DIRECTORY strong_name_signature;
    IMAGE_DATA_DIRECTORY code_manager_table;
    IMAGE_DATA_DIRECTORY vtable_fixups;
    IMAGE_DATA_DIRECTORY export_address_table_jumps;
    IMAGE_DATA_DIRECTORY managed_native_header;
};

template <typename T>
bool read_struct(duint address, T& out) {
    duint read = 0;
    return Script::Memory::Read(address, &out, sizeof(T), &read) && read == sizeof(T);
}

bool read_bytes(duint address, void* data, duint size) {
    duint read = 0;
    return Script::Memory::Read(address, data, size, &read) && read == size;
}

std::string section_name(const IMAGE_SECTION_HEADER& section) {
    char name[9]{};
    for (size_t i = 0; i < 8; ++i) {
        name[i] = static_cast<char>(section.Name[i]);
    }
    return name;
}

const char* directory_name(size_t index) {
    static constexpr std::array<const char*, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> names = {
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "base_reloc",
        "debug",
        "architecture",
        "global_ptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "clr",
        "reserved",
    };
    return index < names.size() ? names[index] : "unknown";
}

const char* subsystem_name(WORD subsystem) {
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE: return "native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "windows_gui";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "windows_cui";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "efi_application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "efi_boot_service_driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "efi_runtime_driver";
    default: return "unknown";
    }
}

nlohmann::json directory_json(const IMAGE_DATA_DIRECTORY& dir, size_t index, duint base) {
    return {
        {"index", index},
        {"name", directory_name(index)},
        {"rva", hex_value(dir.VirtualAddress)},
        {"size", hex_value(dir.Size)},
        {"address", dir.VirtualAddress ? hex_value(base + dir.VirtualAddress) : ""},
        {"present", dir.VirtualAddress != 0 && dir.Size != 0},
    };
}

nlohmann::json section_json(const IMAGE_SECTION_HEADER& section, duint base) {
    const duint address = base + section.VirtualAddress;
    nlohmann::json out = {
        {"name", section_name(section)},
        {"rva", hex_value(section.VirtualAddress)},
        {"address", hex_value(address)},
        {"virtual_size", hex_value(section.Misc.VirtualSize)},
        {"raw_size", hex_value(section.SizeOfRawData)},
        {"characteristics", hex_value(section.Characteristics)},
    };
    if (const auto page = find_memory_page_at(address)) {
        out["page"] = memory_page_json(*page);
    }
    return out;
}

nlohmann::json clr_flags_json(DWORD flags) {
    return {
        {"raw", hex_value(flags)},
        {"il_only", (flags & 0x1) != 0},
        {"requires_32bit", (flags & 0x2) != 0},
        {"il_library", (flags & 0x4) != 0},
        {"strong_name_signed", (flags & 0x8) != 0},
        {"native_entrypoint", (flags & 0x10) != 0},
        {"prefers_32bit", (flags & 0x20000) != 0},
    };
}

nlohmann::json pe_headers_for_module(const Script::Module::ModuleInfo& module) {
    IMAGE_DOS_HEADER dos{};
    if (!read_struct(module.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        throw ApiError("bad_pe", "Module does not have a readable DOS header.");
    }
    const duint nt_address = module.base + static_cast<duint>(dos.e_lfanew);
    DWORD signature = 0;
    if (!read_struct(nt_address, signature) || signature != IMAGE_NT_SIGNATURE) {
        throw ApiError("bad_pe", "Module does not have a readable NT header.");
    }

    IMAGE_FILE_HEADER file{};
    if (!read_struct(nt_address + sizeof(DWORD), file)) {
        throw ApiError("bad_pe", "Module does not have a readable PE file header.");
    }

    const duint optional_address = nt_address + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    WORD optional_magic = 0;
    if (!read_struct(optional_address, optional_magic)) {
        throw ApiError("bad_pe", "Module does not have a readable optional header.");
    }

    nlohmann::json directories = nlohmann::json::array();
    nlohmann::json optional;
    bool is_64 = false;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (!read_struct(optional_address, opt)) {
            throw ApiError("bad_pe", "Failed to read PE32+ optional header.");
        }
        is_64 = true;
        optional = {
            {"format", "pe32_plus"},
            {"image_base", hex_value(static_cast<duint>(opt.ImageBase))},
            {"entry_rva", hex_value(opt.AddressOfEntryPoint)},
            {"entry_address", hex_value(module.base + opt.AddressOfEntryPoint)},
            {"size_of_image", hex_value(opt.SizeOfImage)},
            {"size_of_headers", hex_value(opt.SizeOfHeaders)},
            {"subsystem", subsystem_name(opt.Subsystem)},
            {"subsystem_raw", opt.Subsystem},
            {"dll_characteristics", hex_value(opt.DllCharacteristics)},
        };
        for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            directories.push_back(directory_json(opt.DataDirectory[i], i, module.base));
        }
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (!read_struct(optional_address, opt)) {
            throw ApiError("bad_pe", "Failed to read PE32 optional header.");
        }
        optional = {
            {"format", "pe32"},
            {"image_base", hex_value(static_cast<duint>(opt.ImageBase))},
            {"entry_rva", hex_value(opt.AddressOfEntryPoint)},
            {"entry_address", hex_value(module.base + opt.AddressOfEntryPoint)},
            {"size_of_image", hex_value(opt.SizeOfImage)},
            {"size_of_headers", hex_value(opt.SizeOfHeaders)},
            {"subsystem", subsystem_name(opt.Subsystem)},
            {"subsystem_raw", opt.Subsystem},
            {"dll_characteristics", hex_value(opt.DllCharacteristics)},
        };
        for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            directories.push_back(directory_json(opt.DataDirectory[i], i, module.base));
        }
    } else {
        throw ApiError("bad_pe", "Unknown PE optional header magic.");
    }

    nlohmann::json sections = nlohmann::json::array();
    const duint section_address = optional_address + file.SizeOfOptionalHeader;
    for (WORD i = 0; i < file.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!read_struct(section_address + static_cast<duint>(i) * sizeof(IMAGE_SECTION_HEADER), section)) {
            break;
        }
        sections.push_back(section_json(section, module.base));
    }

    return {
        {"module", module_info_json(module)},
        {"dos_header", {{"e_lfanew", hex_value(static_cast<duint>(dos.e_lfanew))}}},
        {"file_header", {
            {"machine", hex_value(file.Machine)},
            {"sections", file.NumberOfSections},
            {"time_date_stamp", file.TimeDateStamp},
            {"characteristics", hex_value(file.Characteristics)},
            {"size_of_optional_header", file.SizeOfOptionalHeader},
        }},
        {"optional_header", optional},
        {"is_64_bit", is_64},
        {"data_directories", directories},
        {"sections", sections},
    };
}

std::string read_metadata_version(duint address, DWORD length) {
    if (length == 0 || length > 1024) {
        return "";
    }
    std::string version;
    version.resize(length);
    if (!read_bytes(address, version.data(), length)) {
        return "";
    }
    while (!version.empty() && version.back() == '\0') {
        version.pop_back();
    }
    return version;
}

duint align4(duint value) {
    return (value + 3) & ~static_cast<duint>(3);
}

} // namespace

nlohmann::json tool_inspect_pe_headers(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }
    return pe_headers_for_module(*module);
}

nlohmann::json tool_inspect_clr_metadata(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }

    const auto pe = pe_headers_for_module(*module);
    const auto& dirs = pe.at("data_directories");
    const auto& clr_dir = dirs.at(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if (!clr_dir.value("present", false)) {
        return {{"module", module_info_json(*module)}, {"clr_found", false}};
    }

    const duint clr_address = module->base + std::stoull(clr_dir.at("rva").get<std::string>(), nullptr, 16);
    ClrHeader clr{};
    if (!read_struct(clr_address, clr) || clr.cb < sizeof(ClrHeader)) {
        return {{"module", module_info_json(*module)}, {"clr_found", false}, {"reason", "unreadable_clr_header"}};
    }

    const duint metadata_address = module->base + clr.metadata.VirtualAddress;
    DWORD signature = 0;
    WORD major = 0;
    WORD minor = 0;
    DWORD reserved = 0;
    DWORD version_length = 0;
    if (!read_struct(metadata_address, signature) || signature != 0x424A5342 ||
        !read_struct(metadata_address + 4, major) ||
        !read_struct(metadata_address + 6, minor) ||
        !read_struct(metadata_address + 8, reserved) ||
        !read_struct(metadata_address + 12, version_length)) {
        return {{"module", module_info_json(*module)}, {"clr_found", true}, {"metadata_found", false}};
    }

    const duint version_address = metadata_address + 16;
    const std::string version = read_metadata_version(version_address, version_length);
    const duint stream_count_address = align4(version_address + version_length) + 2;
    WORD stream_count = 0;
    if (!read_struct(stream_count_address, stream_count)) {
        stream_count = 0;
    }

    nlohmann::json streams = nlohmann::json::array();
    duint stream_header = stream_count_address + 2;
    for (WORD i = 0; i < stream_count && i < 32; ++i) {
        DWORD offset = 0;
        DWORD size = 0;
        if (!read_struct(stream_header, offset) || !read_struct(stream_header + 4, size)) {
            break;
        }
        std::string name;
        duint name_address = stream_header + 8;
        for (int j = 0; j < 64; ++j) {
            char ch = 0;
            if (!read_struct(name_address + static_cast<duint>(j), ch) || ch == 0) {
                break;
            }
            name.push_back(ch);
        }
        streams.push_back({
            {"name", name},
            {"offset", hex_value(offset)},
            {"size", hex_value(size)},
            {"address", hex_value(metadata_address + offset)},
        });
        stream_header = align4(name_address + static_cast<duint>(name.size()) + 1);
    }

    return {
        {"module", module_info_json(*module)},
        {"clr_found", true},
        {"clr_header", {
            {"address", hex_value(clr_address)},
            {"size", hex_value(clr.cb)},
            {"runtime_version_major", clr.major_runtime_version},
            {"runtime_version_minor", clr.minor_runtime_version},
            {"flags", clr_flags_json(clr.flags)},
            {"entry_point", hex_value(clr.entry_point_token_or_rva)},
            {"entry_point_kind", (clr.flags & 0x10) ? "native_rva" : "metadata_token"},
            {"metadata_rva", hex_value(clr.metadata.VirtualAddress)},
            {"metadata_size", hex_value(clr.metadata.Size)},
            {"metadata_address", hex_value(metadata_address)},
        }},
        {"metadata_found", true},
        {"metadata", {
            {"signature", "BSJB"},
            {"major", major},
            {"minor", minor},
            {"version", version},
            {"stream_count", stream_count},
            {"streams", streams},
        }},
    };
}

nlohmann::json tool_list_iat(const nlohmann::json& params) {
    const std::string module_name = required_string(params, "module");
    const int offset = parse_int(params, "offset", 0, 0, 100000000);
    const int limit = parse_int(params, "limit", 500, 1, 50000);
    const auto module = find_module_by_name(module_name);
    if (!module) {
        throw ApiError("module_not_found", "Module was not found: " + module_name);
    }

    ListInfo list{};
    if (!Script::Module::GetImports(&*module, &list) || !list.data) {
        return {{"module", module_info_json(*module)}, {"total", 0}, {"iat", nlohmann::json::array()}};
    }

    auto* imports = static_cast<Script::Module::ModuleImport*>(list.data);
    nlohmann::json out = nlohmann::json::array();
    int matched = 0;
    int emitted = 0;
    for (size_t i = 0; i < list.count; ++i) {
        if (matched++ < offset) {
            continue;
        }
        if (emitted++ >= limit) {
            continue;
        }
        out.push_back({
            {"import", import_record_json(imports[i], *module)},
            {"pointer", import_pointer_json(imports[i].iatVa)},
            {"pointer_classification", classify_import_pointer(imports[i].iatVa, *module)},
        });
    }
    BridgeFree(list.data);
    return {
        {"module", module_info_json(*module)},
        {"total", matched},
        {"offset", offset},
        {"limit", limit},
        {"count", out.size()},
        {"truncated", matched > offset + static_cast<int>(out.size())},
        {"iat", out},
    };
}
