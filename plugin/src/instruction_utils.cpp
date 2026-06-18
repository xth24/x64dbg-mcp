#include "instruction_utils.h"

#include "import_utils.h"
#include "json_helpers.h"
#include "module_utils.h"

#include <optional>
#include <string>

namespace {

const char* instruction_type_name(DISASM_INSTRTYPE type) {
    switch (type) {
    case instr_branch: return "branch";
    case instr_stack: return "stack";
    case instr_normal:
    default: return "normal";
    }
}

bool instruction_is_return(const DISASM_INSTR& instruction) {
    const std::string text = lower_ascii(instruction.instruction);
    return text == "ret" || text.rfind("ret ", 0) == 0 || text.rfind("retn", 0) == 0 || text.rfind("retf", 0) == 0;
}

bool is_register_operand(const std::string& operand) {
    const std::string op = lower_ascii(operand);
    if (op == "eax" || op == "ebx" || op == "ecx" || op == "edx" || op == "esi" || op == "edi" || op == "ebp" || op == "esp") return true;
    if (op == "rax" || op == "rbx" || op == "rcx" || op == "rdx" || op == "rsi" || op == "rdi" || op == "rbp" || op == "rsp") return true;
    if (op == "al" || op == "ah" || op == "bl" || op == "bh" || op == "cl" || op == "ch" || op == "dl" || op == "dh") return true;
    if (op == "ax" || op == "bx" || op == "cx" || op == "dx" || op == "si" || op == "di" || op == "bp" || op == "sp") return true;
    if (op.size() >= 2 && op[0] == 'r' && op[1] >= '8' && op[1] <= '9') return true;
    if (op.size() >= 3 && op[0] == 'r' && op[1] == '1' && op[2] >= '0' && op[2] <= '5') return true;
    return false;
}

const char* argument_type_name(DISASM_ARGTYPE type) {
    switch (type) {
    case arg_memory: return "memory";
    case arg_normal:
    default: return "normal";
    }
}

const char* segment_name(SEGMENTREG segment) {
    switch (segment) {
    case SEG_ES: return "es";
    case SEG_DS: return "ds";
    case SEG_FS: return "fs";
    case SEG_GS: return "gs";
    case SEG_CS: return "cs";
    case SEG_SS: return "ss";
    case SEG_DEFAULT:
    default: return "default";
    }
}

nlohmann::json address_context_json(duint address) {
    nlohmann::json out = {{"address", hex_value(address)}, {"module_found", false}};
    if (const auto module = find_module_at(address)) {
        out["module_found"] = true;
        out["rva"] = hex_value(address - module->base);
        out["module"] = module_info_json(*module);
    }
    SYMBOLINFOCPP symbol{};
    if (DbgGetSymbolInfoAt(address, &symbol)) {
        out["symbol_found"] = true;
        out["symbol"] = symbol_info_json(symbol);
    } else {
        out["symbol_found"] = false;
    }
    return out;
}

template <typename T>
bool read_struct(duint address, T& out) {
    duint read = 0;
    return Script::Memory::Read(address, &out, sizeof(T), &read) && read == sizeof(T);
}

std::optional<duint> preferred_image_base(const Script::Module::ModuleInfo& module) {
    IMAGE_DOS_HEADER dos{};
    if (!read_struct(module.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    const duint nt_address = module.base + static_cast<duint>(dos.e_lfanew);
    DWORD signature = 0;
    if (!read_struct(nt_address, signature) || signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    const duint optional_address = nt_address + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    if (!read_struct(optional_address, magic)) {
        return std::nullopt;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (read_struct(optional_address, opt)) {
            return static_cast<duint>(opt.ImageBase);
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (read_struct(optional_address, opt)) {
            return static_cast<duint>(opt.ImageBase);
        }
    }
    return std::nullopt;
}

nlohmann::json rebase_info_json(const Script::Module::ModuleInfo& module, duint preferred_base, duint original, duint rebased) {
    return {
        {"owner_module", module_info_json(module)},
        {"preferred_image_base", hex_value(preferred_base)},
        {"original_memory_address", hex_value(original)},
        {"rebased_memory_address", hex_value(rebased)},
        {"rva", hex_value(original - preferred_base)},
    };
}

std::optional<duint> rebased_image_address(duint instruction_address, duint memory_address, nlohmann::json& rebase) {
    const auto module = find_module_at(instruction_address);
    if (!module) {
        return std::nullopt;
    }

    const auto preferred_base = preferred_image_base(*module);
    if (!preferred_base || memory_address < *preferred_base) {
        return std::nullopt;
    }

    const duint rva = memory_address - *preferred_base;
    if (rva >= module->size) {
        return std::nullopt;
    }

    const duint rebased = module->base + rva;
    rebase = rebase_info_json(*module, *preferred_base, memory_address, rebased);
    return rebased;
}

nlohmann::json unreadable_memory_operand_json(const DISASM_INSTR& instruction, duint memory_address, const nlohmann::json& rebase = nullptr) {
    nlohmann::json out = {
        {"resolved", false},
        {"destination", ""},
        {"source", "memory_operand"},
        {"reason", "memory_operand_unreadable"},
        {"memory_address", hex_value(memory_address)},
        {"instruction", instruction.instruction},
    };
    if (!rebase.is_null()) {
        out["rebase"] = rebase;
    }
    return out;
}

nlohmann::json argument_json(const DISASM_ARG& arg) {
    nlohmann::json out = {
        {"type", argument_type_name(arg.type)},
        {"segment", segment_name(arg.segment)},
        {"mnemonic", arg.mnemonic},
        {"constant", hex_value(arg.constant)},
        {"value", hex_value(arg.value)},
        {"memvalue", hex_value(arg.memvalue)},
    };
    if (arg.type == arg_memory && arg.value != 0) {
        out["memory_address"] = address_context_json(arg.value);
        if (arg.memvalue != 0) {
            out["memory_value"] = address_context_json(arg.memvalue);
        }
    }
    return out;
}

nlohmann::json indirect_branch_destination_json(duint address, const DISASM_INSTR& instruction) {
    if (instruction.instr_size <= 0 || instruction.type != instr_branch) {
        return {{"resolved", false}, {"source", "unresolved"}, {"reason", "not_a_branch"}};
    }

    for (int i = 0; i < instruction.argcount && i < 3; ++i) {
        const DISASM_ARG& arg = instruction.arg[i];
        if (arg.type != arg_memory || arg.value == 0) {
            continue;
        }
        duint target = arg.memvalue;
        std::string target_source = "disasm_memvalue";
        duint memory_address = arg.value;
        nlohmann::json rebase = nullptr;
        duint read = 0;
        if (target == 0) {
            if (Script::Memory::Read(memory_address, &target, sizeof(target), &read) && read == sizeof(target)) {
                target_source = "read_memory";
            } else {
                if (const auto rebased = rebased_image_address(address, memory_address, rebase)) {
                    duint rebased_read = 0;
                    duint rebased_target = 0;
                    if (!Script::Memory::Read(*rebased, &rebased_target, sizeof(rebased_target), &rebased_read) || rebased_read != sizeof(rebased_target)) {
                        return unreadable_memory_operand_json(instruction, memory_address, rebase);
                    }
                    memory_address = *rebased;
                    target = rebased_target;
                    target_source = "rebased_image_read_memory";
                } else {
                    return unreadable_memory_operand_json(instruction, memory_address);
                }
            }
        }
        if (target == 0) {
            nlohmann::json result = {
                {"resolved", false},
                {"destination", hex_value(target)},
                {"source", "unresolved"},
                {"reason", "indirect_target_null"},
                {"target_source", target_source},
                {"memory_address", hex_value(memory_address)},
                {"instruction", instruction.instruction},
            };
            if (!rebase.is_null()) {
                result["rebase"] = rebase;
            }
            return result;
        }
        nlohmann::json result = {
            {"resolved", true},
            {"destination", hex_value(target)},
            {"source", "memory_operand"},
            {"target_source", target_source},
            {"memory_address", hex_value(memory_address)},
            {"instruction", instruction.instruction},
        };
        result["target"] = address_context_json(target);
        if (!rebase.is_null()) {
            result["rebase"] = rebase;
            result["confidence"] = "best_effort";
        }
        if (const auto module = find_module_at(address)) {
            const nlohmann::json classification = classify_import_pointer(memory_address, *module);
            result["pointer_classification"] = classification;
            if (classification.value("kind", "") == "owner_module_rva" && classification.contains("absolute_address")) {
                result["raw_destination"] = result["destination"];
                result["destination"] = classification.at("absolute_address");
                result["source"] = "memory_operand_classified";
                result["target"] = classification.value("target", nlohmann::json::object());
                result["confidence"] = "best_effort";
            }
        }
        return result;
    }

    for (int i = 0; i < instruction.argcount && i < 3; ++i) {
        const DISASM_ARG& arg = instruction.arg[i];
        if (arg.type != arg_normal || !is_register_operand(arg.mnemonic)) {
            continue;
        }
        nlohmann::json result = {
            {"resolved", false},
            {"destination", arg.value != 0 ? hex_value(arg.value) : ""},
            {"source", "register_operand"},
            {"reason", "register_indirect_unresolved"},
            {"register", arg.mnemonic},
            {"register_value", hex_value(arg.value)},
            {"instruction", instruction.instruction},
        };
        if (arg.value != 0) {
            result["target"] = address_context_json(arg.value);
        }
        return result;
    }

    return {{"resolved", false}, {"source", "unresolved"}, {"reason", "no_readable_memory_operand"}, {"instruction", instruction.instruction}};
}

} // namespace

nlohmann::json branch_destination_json(duint address) {
    DISASM_INSTR instruction{};
    DbgDisasmAt(address, &instruction);
    if (instruction.instr_size > 0 && instruction_is_return(instruction)) {
        return {
            {"address", hex_value(address)},
            {"destination", ""},
            {"resolved", false},
            {"source", "return"},
            {"reason", "return_target_from_stack"},
            {"instruction", instruction.instruction},
        };
    }

    const duint destination = DbgGetBranchDestination(address);
    if (destination != 0) {
        nlohmann::json result = {
            {"address", hex_value(address)},
            {"destination", hex_value(destination)},
            {"resolved", true},
            {"source", "debugger"},
        };
        result["target"] = address_context_json(destination);
        return result;
    }

    nlohmann::json indirect = indirect_branch_destination_json(address, instruction);
    indirect["address"] = hex_value(address);
    nlohmann::json result = {
        {"address", indirect["address"]},
        {"destination", indirect.value("destination", "")},
        {"resolved", indirect.value("resolved", false)},
        {"source", indirect.value("source", "unresolved")},
        {"fallback", indirect},
    };
    if (indirect.contains("reason")) {
        result["reason"] = indirect["reason"];
    }
    if (indirect.contains("target_source")) {
        result["target_source"] = indirect["target_source"];
    }
    if (indirect.contains("confidence")) {
        result["confidence"] = indirect["confidence"];
    }
    if (indirect.contains("memory_address")) {
        result["memory_address"] = indirect["memory_address"];
    }
    return result;
}

nlohmann::json instruction_json(duint address) {
    DISASM_INSTR instruction{};
    DbgDisasmAt(address, &instruction);
    if (instruction.instr_size <= 0) {
        return {{"address", hex_value(address)}, {"valid", false}};
    }

    nlohmann::json args = nlohmann::json::array();
    for (int i = 0; i < instruction.argcount && i < 3; ++i) {
        args.push_back(argument_json(instruction.arg[i]));
    }

    nlohmann::json out = {
        {"address", hex_value(address)},
        {"valid", true},
        {"instruction", instruction.instruction},
        {"type", instruction_is_return(instruction) ? "return" : instruction_type_name(instruction.type)},
        {"size", instruction.instr_size},
        {"arg_count", instruction.argcount},
        {"args", args},
    };
    if (instruction.type == instr_branch || instruction_is_return(instruction)) {
        out["branch"] = branch_destination_json(address);
    }
    return out;
}
