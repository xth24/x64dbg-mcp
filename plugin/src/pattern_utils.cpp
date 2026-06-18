#include "pattern_utils.h"

#include "json_helpers.h"
#include "memory_utils.h"
#include "module_utils.h"

#include <algorithm>

bool pattern_address_valid(duint address) {
    return address != 0 && address != static_cast<duint>(-1);
}

std::vector<duint> find_pattern_hits_in_range(duint start, duint size, const std::string& pattern, int limit) {
    static constexpr duint kChunkSize = 64 * 1024;
    static constexpr duint kOverlap = 256;

    std::vector<duint> hits;
    if (size == 0 || limit <= 0) {
        return hits;
    }

    const duint end = start + size;
    for (duint current = start; current < end && static_cast<int>(hits.size()) < limit;) {
        const duint chunk_end = std::min(end, current + kChunkSize);
        duint scan = current;
        while (scan < chunk_end && static_cast<int>(hits.size()) < limit) {
            const duint found = Script::Pattern::FindMem(scan, chunk_end - scan, pattern.c_str());
            if (!pattern_address_valid(found) || found < scan || found >= chunk_end) {
                break;
            }
            if (hits.empty() || hits.back() != found) {
                hits.push_back(found);
            }
            if (found == static_cast<duint>(-1)) {
                break;
            }
            scan = found + 1;
        }
        if (chunk_end == end) {
            break;
        }
        current = chunk_end > kOverlap ? chunk_end - kOverlap : chunk_end;
    }
    return hits;
}

std::vector<duint> find_pattern_hits_in_module(const Script::Module::ModuleInfo& module, const std::string& pattern, int limit) {
    std::vector<duint> hits;
    if (limit <= 0) {
        return hits;
    }

    const duint module_start = module.base;
    const duint module_end_value = module_end(module);
    std::vector<MEMPAGE> pages;
    try {
        pages = get_memory_pages();
    } catch (const ApiError&) {
        return find_pattern_hits_in_range(module_start, module.size, pattern, limit);
    }

    for (const auto& page : pages) {
        if (static_cast<int>(hits.size()) >= limit || !is_readable_page(page)) {
            continue;
        }
        const auto page_start = reinterpret_cast<duint>(page.mbi.BaseAddress);
        const auto page_size = static_cast<duint>(page.mbi.RegionSize);
        const duint page_end = page_start + page_size;
        const duint scan_start = std::max(module_start, page_start);
        const duint scan_end = std::min(module_end_value, page_end);
        if (scan_end <= scan_start) {
            continue;
        }
        auto page_hits = find_pattern_hits_in_range(scan_start, scan_end - scan_start, pattern, limit - static_cast<int>(hits.size()));
        hits.insert(hits.end(), page_hits.begin(), page_hits.end());
    }
    return hits;
}
