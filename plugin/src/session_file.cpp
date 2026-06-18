#include "session_file.h"

#include "sdk.h"
#include "text.h"

#include <Windows.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <nlohmann/json.hpp>

using nlohmann::json;

std::filesystem::path SessionFile::session_dir() const {
    if (const char* override_dir = std::getenv("XDBG_MCP_SESSION_DIR")) {
        return std::filesystem::path(override_dir);
    }
    if (const char* local_app_data = std::getenv("LOCALAPPDATA")) {
        return std::filesystem::path(local_app_data) / "xdbg-mcp" / "sessions";
    }
    return std::filesystem::temp_directory_path() / "xdbg-mcp" / "sessions";
}

bool SessionFile::create() {
    const DWORD pid = GetCurrentProcessId();
    session_id_ = std::string(kDebuggerArch) + "-" + std::to_string(pid);
    pipe_name_ = L"\\\\.\\pipe\\xdbg-mcp-" + utf8_to_wide(session_id_);
    path_ = session_dir() / (session_id_ + ".json");

    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);
    if (ec) {
        return false;
    }

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    const json descriptor = {
        {"session_id", session_id_},
        {"arch", kDebuggerArch},
        {"pid", pid},
        {"pipe", wide_to_utf8(pipe_name_)},
        {"created_at_unix", seconds},
        {"plugin_version", kPluginVersionText},
        {"protocol_version", kBridgeProtocolVersion},
    };

    std::ofstream out(path_, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out << descriptor.dump(2);
    return true;
}

void SessionFile::remove() {
    if (path_.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::remove(path_, ec);
}
