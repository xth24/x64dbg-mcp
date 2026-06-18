# xdbg-mcp

MCP server for x64dbg and x32dbg.

It uses a small debugger plugin and a local stdio MCP server.

## Install

1. Install the Python server:

```powershell
py -3.11 -m pip install .
```

2. Copy the debugger plugin:

```text
xdbg_mcp.dp64 -> x64dbg\release\x64\plugins\xdbg_mcp.dp64
xdbg_mcp.dp32 -> x64dbg\release\x32\plugins\xdbg_mcp.dp32
```

Prebuilt `dp64` and `dp32` files are provided with releases. Use the one matching the debugger you run.

3. Add the MCP server to your MCP client:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "xdbg-mcp"
    }
  }
}
```

Restart x64dbg or x32dbg after copying the plugin.

## Build

Requirements:

- Windows
- Python 3.11+
- Visual Studio C++ tools
- CMake 3.20+

Build the Python package:

```powershell
py -3.11 -m pip install -e .
```

Build both debugger plugins:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -DXDBG_MCP_FETCH_SDK=ON
cmake --build build --target plugins --config Release
```

Outputs:

```text
build\x64\Release\xdbg_mcp.dp64
build\x32\Release\xdbg_mcp.dp32
```

If you already have the x64dbg plugin SDK:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -DXDBG_SDK_DIR=C:\path\to\pluginsdk
```

## Use

Start x64dbg or x32dbg, then start your MCP client.

Good first calls:

```text
health_check
list_debugger_sessions
bind_debugger_session
get_snapshot
inspect_address
```

Call `bind_debugger_session` once so later calls do not need the session id or architecture.

## License

GPLv3.
