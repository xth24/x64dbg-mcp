cmake_minimum_required(VERSION 3.20)
project(xdbg_mcp_plugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    message(FATAL_ERROR "The xdbg-mcp plugin must be built with MSVC because the x64dbg plugin SDK exports C++ symbols with MSVC ABI.")
endif()

option(XDBG_MCP_FETCH_DEPS "Fetch C++ dependencies during configure" ON)
option(XDBG_MCP_FETCH_SDK "Download the x64dbg plugin SDK during configure" OFF)
option(XDBG_DEPS_TLS_VERIFY "Verify TLS certificates when downloading C++ dependencies with CMake" OFF)
option(XDBG_SDK_TLS_VERIFY "Verify TLS certificates when downloading the x64dbg SDK with CMake" OFF)
set(XDBG_SDK_DIR "${CMAKE_SOURCE_DIR}/../deps/x64dbg-pluginsdk" CACHE PATH "x64dbg plugin SDK directory")
set(XDBG_SDK_URL "https://github.com/x64dbg/x64dbg/releases/download/2025.08.19/x64dbg-pluginsdk.zip" CACHE STRING "x64dbg plugin SDK zip URL")

if(NOT EXISTS "${XDBG_SDK_DIR}/bridgemain.h")
    if(XDBG_MCP_FETCH_SDK)
        file(MAKE_DIRECTORY "${XDBG_SDK_DIR}")
        set(_sdk_zip "${CMAKE_BINARY_DIR}/x64dbg-pluginsdk.zip")
        file(DOWNLOAD "${XDBG_SDK_URL}" "${_sdk_zip}" TLS_VERIFY ${XDBG_SDK_TLS_VERIFY} STATUS _sdk_download_status)
        list(GET _sdk_download_status 0 _sdk_download_code)
        if(NOT _sdk_download_code EQUAL 0)
            list(GET _sdk_download_status 1 _sdk_download_message)
            message(FATAL_ERROR "Failed to download x64dbg plugin SDK: ${_sdk_download_message}")
        endif()
        execute_process(
            COMMAND "${CMAKE_COMMAND}" -E tar xf "${_sdk_zip}"
            WORKING_DIRECTORY "${XDBG_SDK_DIR}"
            RESULT_VARIABLE _sdk_extract_result
        )
        if(NOT _sdk_extract_result EQUAL 0)
            message(FATAL_ERROR "Failed to extract x64dbg plugin SDK")
        endif()
    endif()
endif()

if(NOT EXISTS "${XDBG_SDK_DIR}/bridgemain.h")
    message(FATAL_ERROR "Missing x64dbg plugin SDK at ${XDBG_SDK_DIR}")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(XDBG_ARCH "x64")
    set(XDBG_PLUGIN_SUFFIX ".dp64")
    set(XDBG_IMPORT_LIB "x64dbg.lib")
else()
    set(XDBG_ARCH "x32")
    set(XDBG_PLUGIN_SUFFIX ".dp32")
    set(XDBG_IMPORT_LIB "x32dbg.lib")
endif()

find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    if(NOT XDBG_MCP_FETCH_DEPS)
        message(FATAL_ERROR "nlohmann_json not found. Reconfigure with -DXDBG_MCP_FETCH_DEPS=ON or install it.")
    endif()
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        TLS_VERIFY ${XDBG_DEPS_TLS_VERIFY}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

set(SOURCES
    src/debugger_analysis.cpp
    src/debugger_breakpoint_options.cpp
    src/debugger_context.cpp
    src/debugger_execution.cpp
    src/debugger_instruction_search.cpp
    src/debugger_inspection.cpp
    src/debugger_linear.cpp
    src/debugger_metadata.cpp
    src/debugger_pe.cpp
    src/debugger_re.cpp
    src/debugger_run_control.cpp
    src/debugger_stack.cpp
    src/dispatcher.cpp
    src/import_utils.cpp
    src/instruction_utils.cpp
    src/json_helpers.cpp
    src/memory_utils.cpp
    src/module_utils.cpp
    src/pattern_utils.cpp
    src/pipe_protocol.cpp
    src/pipe_server.cpp
    src/plugin_main.cpp
    src/session_file.cpp
    src/text.cpp
)

add_library(xdbg_mcp SHARED ${SOURCES})

target_include_directories(xdbg_mcp PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/compat"
    "${XDBG_SDK_DIR}"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    file(GLOB XDBG_IMPORT_LIBS CONFIGURE_DEPENDS
        "${XDBG_SDK_DIR}/*_x64.lib"
        "${XDBG_SDK_DIR}/x64*.lib"
    )
else()
    file(GLOB XDBG_IMPORT_LIBS CONFIGURE_DEPENDS
        "${XDBG_SDK_DIR}/*_x86.lib"
        "${XDBG_SDK_DIR}/x32*.lib"
    )
endif()

if(NOT XDBG_IMPORT_LIBS)
    set(XDBG_IMPORT_LIBS "${XDBG_SDK_DIR}/${XDBG_IMPORT_LIB}")
endif()

target_link_directories(xdbg_mcp PRIVATE "${XDBG_SDK_DIR}")
target_link_libraries(xdbg_mcp PRIVATE nlohmann_json::nlohmann_json ${XDBG_IMPORT_LIBS})

target_compile_definitions(xdbg_mcp PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(xdbg_mcp PROPERTIES
    PREFIX ""
    SUFFIX "${XDBG_PLUGIN_SUFFIX}"
)
