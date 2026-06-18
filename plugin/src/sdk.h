#pragma once

#include <Windows.h>

#include "bridgemain.h"
#include "_plugins.h"
#include "_scriptapi_assembler.h"
#include "_scriptapi_comment.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_function.h"
#include "_scriptapi_label.h"
#include "_scriptapi_memory.h"
#include "_scriptapi_misc.h"
#include "_scriptapi_module.h"
#include "_scriptapi_pattern.h"
#include "_scriptapi_register.h"
#include "_scriptapi_stack.h"
#include "_scriptapi_symbol.h"

#ifdef _WIN64
inline constexpr const char* kDebuggerArch = "x64";
inline constexpr auto kInstructionPointer = Script::Register::RIP;
inline constexpr auto kStackPointer = Script::Register::RSP;
#else
inline constexpr const char* kDebuggerArch = "x32";
inline constexpr auto kInstructionPointer = Script::Register::EIP;
inline constexpr auto kStackPointer = Script::Register::ESP;
#endif

inline constexpr int kPluginVersion = 1;
inline constexpr const char* kPluginVersionText = "0.1.0";
inline constexpr int kBridgeProtocolVersion = 1;
