#include "pipe_protocol.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr DWORD kChunkSize = 1024 * 1024;
constexpr uint32_t kMaxFrameSize = 16 * 1024 * 1024;

void read_exact(HANDLE pipe, void* data, DWORD size) {
    auto* cursor = static_cast<unsigned char*>(data);
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD got = 0;
        const DWORD want = remaining > kChunkSize ? kChunkSize : remaining;
        if (!ReadFile(pipe, cursor, want, &got, nullptr) || got == 0) {
            throw std::runtime_error("pipe read failed");
        }
        cursor += got;
        remaining -= got;
    }
}

void write_exact(HANDLE pipe, const void* data, DWORD size) {
    const auto* cursor = static_cast<const unsigned char*>(data);
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD written = 0;
        const DWORD want = remaining > kChunkSize ? kChunkSize : remaining;
        if (!WriteFile(pipe, cursor, want, &written, nullptr) || written == 0) {
            throw std::runtime_error("pipe write failed");
        }
        cursor += written;
        remaining -= written;
    }
}

} // namespace

nlohmann::json read_json_frame(HANDLE pipe) {
    uint32_t size = 0;
    read_exact(pipe, &size, sizeof(size));
    if (size == 0 || size > kMaxFrameSize) {
        throw std::runtime_error("invalid frame size");
    }

    std::string payload(size, '\0');
    read_exact(pipe, payload.data(), size);
    return nlohmann::json::parse(payload);
}

void write_json_frame(HANDLE pipe, const nlohmann::json& value) {
    const std::string payload = value.dump();
    if (payload.size() > kMaxFrameSize) {
        throw std::runtime_error("response too large");
    }

    const uint32_t size = static_cast<uint32_t>(payload.size());
    write_exact(pipe, &size, sizeof(size));
    write_exact(pipe, payload.data(), size);
}
