#include "dispatcher.h"
#include "pipe_server.h"
#include "sdk.h"
#include "session_file.h"

#include <memory>

namespace {

int g_plugin_handle = 0;
SessionFile g_session;
std::unique_ptr<PipeServer> g_pipe_server;

bool command_mcp_status(int, char**) {
    _plugin_logprintf("xdbg-mcp session=%s pipe=%S\n", g_session.session_id().c_str(), g_session.pipe_name().c_str());
    return true;
}

void register_commands() {
    _plugin_registercommand(g_plugin_handle, "mcpsession", command_mcp_status, "Show xdbg-mcp session information");
}

} // namespace

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init_struct) {
    init_struct->pluginVersion = kPluginVersion;
    init_struct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(init_struct->pluginName, "xdbg-mcp", _TRUNCATE);
    g_plugin_handle = init_struct->pluginHandle;

    register_commands();

    if (!g_session.create()) {
        _plugin_logputs("xdbg-mcp failed to create session descriptor");
        return false;
    }

    g_pipe_server = std::make_unique<PipeServer>(g_session.pipe_name(), dispatch_request);
    if (!g_pipe_server->start()) {
        _plugin_logputs("xdbg-mcp failed to start named-pipe server");
        g_session.remove();
        return false;
    }

    _plugin_logprintf("xdbg-mcp loaded session=%s pipe=%S\n", g_session.session_id().c_str(), g_session.pipe_name().c_str());
    return true;
}

extern "C" __declspec(dllexport) void plugstop() {
    if (g_pipe_server) {
        g_pipe_server->stop();
        g_pipe_server.reset();
    }
    g_session.remove();
    _plugin_logputs("xdbg-mcp stopped");
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT*) {
}
