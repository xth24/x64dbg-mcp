#include "memory_utils.h"

#include "json_helpers.h"

std::string memory_state_name(DWORD state) {
    if (state == MEM_COMMIT) return "commit";
    if (state == MEM_RESERVE) return "reserve";
    if (state == MEM_FREE) return "free";
    return "unknown";
}

std::string memory_type_name(DWORD type) {
    if (type == MEM_IMAGE) return "image";
    if (type == MEM_MAPPED) return "mapped";
    if (type == MEM_PRIVATE) return "private";
    return "unknown";
}

std::string protection_name(DWORD protect) {
    protect &= 0xff;
    if (protect == PAGE_EXECUTE_READWRITE) return "execute_read_write";
    if (protect == PAGE_EXECUTE_READ) return "execute_read";
    if (protect == PAGE_EXECUTE_WRITECOPY) return "execute_write_copy";
    if (protect == PAGE_EXECUTE) return "execute";
    if (protect == PAGE_READWRITE) return "read_write";
    if (protect == PAGE_READONLY) return "read_only";
    if (protect == PAGE_WRITECOPY) return "write_copy";
    if (protect == PAGE_NOACCESS) return "no_access";
    return "unknown";
}

bool is_readable_page(const MEMPAGE& page) {
    const DWORD protect = page.mbi.Protect & 0xff;
    return page.mbi.State == MEM_COMMIT &&
           protect != PAGE_NOACCESS &&
           !(page.mbi.Protect & PAGE_GUARD);
}

nlohmann::json memory_page_json(const MEMPAGE& page) {
    const auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
    const auto size = static_cast<duint>(page.mbi.RegionSize);
    return {
        {"base", hex_value(base)},
        {"size", hex_value(size)},
        {"end", hex_value(base + size)},
        {"state", memory_state_name(page.mbi.State)},
        {"protect", protection_name(page.mbi.Protect)},
        {"protect_raw", page.mbi.Protect},
        {"type", memory_type_name(page.mbi.Type)},
        {"info", page.info},
        {"readable", is_readable_page(page)},
    };
}

std::vector<MEMPAGE> get_memory_pages() {
    MEMMAP map{};
    if (!DbgMemMap(&map) || !map.page) {
        throw ApiError("debugger_error", "Failed to read memory map.");
    }

    std::vector<MEMPAGE> pages;
    pages.reserve(static_cast<size_t>(map.count));
    for (int i = 0; i < map.count; ++i) {
        pages.push_back(map.page[i]);
    }
    BridgeFree(map.page);
    return pages;
}

std::optional<MEMPAGE> find_memory_page_at(duint address) {
    const auto pages = get_memory_pages();
    for (const auto& page : pages) {
        const auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
        const auto size = static_cast<duint>(page.mbi.RegionSize);
        if (address >= base && address < base + size) {
            return page;
        }
    }
    return std::nullopt;
}
