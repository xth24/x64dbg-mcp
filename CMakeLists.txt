cmake_minimum_required(VERSION 3.20)
project(xdbg_mcp LANGUAGES CXX)

option(XDBG_MCP_BUILD_BOTH "Build x32dbg and x64dbg plugins with MSVC" ON)
option(XDBG_MCP_FETCH_DEPS "Fetch C++ dependencies during configure" ON)
option(XDBG_MCP_FETCH_SDK "Download the x64dbg plugin SDK during configure" OFF)
option(XDBG_DEPS_TLS_VERIFY "Verify TLS certificates when downloading C++ dependencies with CMake" OFF)
option(XDBG_SDK_TLS_VERIFY "Verify TLS certificates when downloading the x64dbg SDK with CMake" OFF)
set(XDBG_SDK_DIR "${CMAKE_SOURCE_DIR}/deps/x64dbg-pluginsdk" CACHE PATH "x64dbg plugin SDK directory")

if(XDBG_MCP_BUILD_BOTH AND MSVC)
    include(ExternalProject)

    ExternalProject_Add(xdbg_mcp_x32
        SOURCE_DIR "${CMAKE_SOURCE_DIR}/plugin"
        BINARY_DIR "${CMAKE_BINARY_DIR}/x32"
        CMAKE_ARGS
            -G "${CMAKE_GENERATOR}"
            -A Win32
            -DXDBG_SDK_DIR=${XDBG_SDK_DIR}
            -DXDBG_MCP_FETCH_DEPS=${XDBG_MCP_FETCH_DEPS}
            -DXDBG_MCP_FETCH_SDK=${XDBG_MCP_FETCH_SDK}
            -DXDBG_DEPS_TLS_VERIFY=${XDBG_DEPS_TLS_VERIFY}
            -DXDBG_SDK_TLS_VERIFY=${XDBG_SDK_TLS_VERIFY}
        INSTALL_COMMAND ""
    )

    ExternalProject_Add(xdbg_mcp_x64
        SOURCE_DIR "${CMAKE_SOURCE_DIR}/plugin"
        BINARY_DIR "${CMAKE_BINARY_DIR}/x64"
        CMAKE_ARGS
            -G "${CMAKE_GENERATOR}"
            -A x64
            -DXDBG_SDK_DIR=${XDBG_SDK_DIR}
            -DXDBG_MCP_FETCH_DEPS=${XDBG_MCP_FETCH_DEPS}
            -DXDBG_MCP_FETCH_SDK=${XDBG_MCP_FETCH_SDK}
            -DXDBG_DEPS_TLS_VERIFY=${XDBG_DEPS_TLS_VERIFY}
            -DXDBG_SDK_TLS_VERIFY=${XDBG_SDK_TLS_VERIFY}
        INSTALL_COMMAND ""
    )

    add_custom_target(plugins DEPENDS xdbg_mcp_x32 xdbg_mcp_x64)
else()
    add_subdirectory(plugin)
endif()
