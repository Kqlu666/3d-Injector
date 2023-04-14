#pragma once
#include "disassembly.h"

namespace Hooks
{
    struct JmpRipCode
    {
        size_t hook_size;
        size_t orig_bytes_size;
        void* original_bytes;
        uint8_t* hook_code;

        JmpRipCode()
        {
        }

        JmpRipCode(uintptr_t hook_address, uintptr_t jmp_target)
        {
            hook_size = Disasm::LengthOfInstructions((void*)hook_address, 14);
            orig_bytes_size = hook_size + 14;      /*  because orig_bytes includes jmp back code   */

            auto jmp_back_location = hook_address + hook_size;

            char jmp_rip[14] = "\xFF\x25\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC";

            original_bytes = (uint8_t*)ExAllocatePool(NonPagedPool, orig_bytes_size);

            memcpy(original_bytes, (void*)hook_address, hook_size);
            memcpy((uint8_t*)original_bytes + hook_size, jmp_rip, 14);
            memcpy((uint8_t*)original_bytes + hook_size + 6, &jmp_back_location, sizeof(uintptr_t));

            hook_code = (uint8_t*)ExAllocatePool(NonPagedPool, hook_size);

            memcpy(jmp_rip + 6, &jmp_target, sizeof(uintptr_t));
            memcpy(hook_code, jmp_rip, 14);
        }
    };
};