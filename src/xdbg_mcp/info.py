from __future__ import annotations

SERVER_NAME = "xdbg-mcp"
SERVER_VERSION = "0.1.0"
BRIDGE_PROTOCOL_VERSION = 1
MIN_PLUGIN_PROTOCOL_VERSION = 1


def version_info() -> dict[str, object]:
    return {
        "server": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
        "bridge_protocol": {
            "version": BRIDGE_PROTOCOL_VERSION,
            "min_plugin_version": MIN_PLUGIN_PROTOCOL_VERSION,
        },
    }


def plugin_protocol_compatible(value: object) -> bool:
    try:
        protocol = int(value)
    except (TypeError, ValueError):
        return False
    return MIN_PLUGIN_PROTOCOL_VERSION <= protocol <= BRIDGE_PROTOCOL_VERSION
