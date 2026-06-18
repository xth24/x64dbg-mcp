#include "dispatcher.h"

#include "debugger_tools.h"
#include "json_helpers.h"

#include <functional>
#include <string>
#include <unordered_map>

namespace {

using Tool = std::function<nlohmann::json(const nlohmann::json&)>;

const std::unordered_map<std::string, Tool>& tools() {
    static const std::unordered_map<std::string, Tool> table = {
        {"get_status", tool_get_status},
        {"get_bridge_info", tool_get_bridge_info},
        {"get_snapshot", tool_get_snapshot},
        {"get_registers", tool_get_registers},
        {"set_register", tool_set_register},
        {"read_memory", tool_read_memory},
        {"write_memory", tool_write_memory},
        {"disassemble", tool_disassemble},
        {"parse_expression", tool_parse_expression},
        {"evaluate_expressions", tool_evaluate_expressions},
        {"get_branch_destination", tool_get_branch_destination},
        {"find_pattern", tool_find_pattern},
        {"find_all_patterns", tool_find_all_patterns},
        {"find_strings", tool_find_strings},
        {"find_instructions", tool_find_instructions},
        {"list_calls_in_range", tool_list_calls_in_range},
        {"list_calls_in_function", tool_list_calls_in_function},
        {"analyze_function", tool_analyze_function},
        {"analyze_linear_block", tool_analyze_linear_block},
        {"list_functions", tool_list_functions},
        {"find_references_to_range", tool_find_references_to_range},
        {"find_references_to_module", tool_find_references_to_module},
        {"inspect_import_thunk", tool_inspect_import_thunk},
        {"snapshot_break_context", tool_snapshot_break_context},
        {"get_call_stack", tool_get_call_stack},
        {"get_symbol_at", tool_get_symbol_at},
        {"get_string_at", tool_get_string_at},
        {"get_xrefs", tool_get_xrefs},
        {"inspect_address", tool_inspect_address},
        {"inspect_instruction", tool_inspect_instruction},
        {"read_pointer", tool_read_pointer},
        {"deref_chain", tool_deref_chain},
        {"inspect_stack", tool_inspect_stack},
        {"inspect_call_args", tool_inspect_call_args},
        {"find_pointers_to_range", tool_find_pointers_to_range},
        {"run", tool_run},
        {"pause", tool_pause},
        {"stop", tool_stop},
        {"step", tool_step},
        {"wait_for_pause", tool_wait_for_pause},
        {"run_until", tool_run_until},
        {"wait_for_module", tool_wait_for_module},
        {"set_breakpoint", tool_set_breakpoint},
        {"remove_breakpoint", tool_remove_breakpoint},
        {"set_breakpoint_enabled", tool_set_breakpoint_enabled},
        {"set_hardware_breakpoint", tool_set_hardware_breakpoint},
        {"remove_hardware_breakpoint", tool_remove_hardware_breakpoint},
        {"set_breakpoint_options", tool_set_breakpoint_options},
        {"set_memory_breakpoint", tool_set_memory_breakpoint},
        {"remove_memory_breakpoint", tool_remove_memory_breakpoint},
        {"list_breakpoints", tool_list_breakpoints},
        {"resolve_breakpoints", tool_resolve_breakpoints},
        {"list_unresolved_breakpoints", tool_list_unresolved_breakpoints},
        {"execute_command", tool_execute_command},
        {"list_modules", tool_list_modules},
        {"get_module_at", tool_get_module_at},
        {"list_module_sections", tool_list_module_sections},
        {"list_module_imports", tool_list_module_imports},
        {"list_module_exports", tool_list_module_exports},
        {"list_iat", tool_list_iat},
        {"inspect_pe_headers", tool_inspect_pe_headers},
        {"inspect_clr_metadata", tool_inspect_clr_metadata},
        {"list_threads", tool_list_threads},
        {"get_memory_map", tool_get_memory_map},
        {"get_page_at", tool_get_page_at},
        {"query_symbols", tool_query_symbols},
        {"list_labels", tool_list_labels},
        {"set_label", tool_set_label},
        {"set_comment", tool_set_comment},
    };
    return table;
}

} // namespace

nlohmann::json dispatch_request(const nlohmann::json& request) {
    const nlohmann::json id = request.value("id", nlohmann::json(nullptr));

    try {
        if (!request.is_object()) {
            throw ApiError("bad_request", "Request must be a JSON object.");
        }
        const std::string method = request.value("method", "");
        if (method.empty()) {
            throw ApiError("bad_request", "Request is missing method.");
        }

        const auto found = tools().find(method);
        if (found == tools().end()) {
            throw ApiError("unknown_method", "Unknown debugger bridge method: " + method);
        }

        nlohmann::json params = nlohmann::json::object();
        if (request.contains("params")) {
            if (!request["params"].is_object()) {
                throw ApiError("bad_request", "Request params must be an object.");
            }
            params = request["params"];
        }

        return {
            {"id", id},
            {"ok", true},
            {"result", found->second(params)},
        };
    } catch (const ApiError& exc) {
        return {
            {"id", id},
            {"ok", false},
            {"error", {
                {"code", exc.code()},
                {"message", exc.what()},
            }},
        };
    } catch (const std::exception& exc) {
        return {
            {"id", id},
            {"ok", false},
            {"error", {
                {"code", "internal_error"},
                {"message", exc.what()},
            }},
        };
    }
}
