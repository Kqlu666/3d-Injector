#include "be_hook.h"
#include "manual_map.h"
#include "hooking.h"
#include "aethervisor_kernel.h"
#include "image_load_notify.h"
#include "kernel_exports.h"

namespace ShadowEye
{
    uintptr_t beclient_base;
    uintptr_t beclient_size;

    void InjectShadowEye()
    {
        uint8_t* eac_spy_dll_mapped = NULL;
        uint8_t* eac_spy_dll = NULL;

        Utils::LoadFileIntoMemory(&eac_spy_dll, SHADOWEYE_DLL);

        auto spy_size = PE::RemapImage(eac_spy_dll, &eac_spy_dll_mapped, PsGetProcessPeb(PsGetCurrentProcess()));

        if (!spy_size)
        {
            return;
        }

        uintptr_t beclient_entry = beclient_base + OFFSET::beclient_entry_point;

        auto spy_entry = PE::GetExport((uintptr_t)eac_spy_dll_mapped, "EacEntryPointHook");

        auto spy_params = (DllParams**)PE::GetExport((uintptr_t)eac_spy_dll_mapped, "dll_params");

        auto entry_point_hk = (Hooks::JmpRipCode**)PE::GetExport((uintptr_t)eac_spy_dll_mapped, "entry_point_hk");

        ULONG_PTR dllparams_size = sizeof(DllParams);

        auto status2 = ZwAllocateVirtualMemory(NtCurrentProcess(),
            (void**)spy_params, 0, &dllparams_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        DbgPrint("ZwAllocateVirtualMemory status2 %p \n", status2);

        ULONG_PTR entry_point_hk_size = sizeof(Hooks::JmpRipCode);

        status2 = ZwAllocateVirtualMemory(NtCurrentProcess(),
            (void**)entry_point_hk, 0, &entry_point_hk_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        DbgPrint("ZwAllocateVirtualMemory status2 %p \n", status2);

        **spy_params = DllParams{
            0x12345678,
            (uintptr_t)eac_spy_dll_mapped,
            spy_size,
            beclient_base,
            beclient_size,
            beclient_entry,
            NULL
        };
         
        **entry_point_hk = Hooks::JmpRipCode{ beclient_entry, (uintptr_t)spy_entry };

        Aether::NptHook::Set(beclient_entry, (uint8_t*)(*entry_point_hk)->hook_code, (*entry_point_hk)->hook_size);

        DbgPrint("orig_eac_entry at +0x%p \n", beclient_entry - beclient_base);
        DbgPrint("spy_entry %p \n", spy_entry);
        DbgPrint("spy_params %p \n", spy_params);
    }

    void Init()
    {
        PLOAD_IMAGE_NOTIFY_ROUTINE codecave;

        SetImageLoadNotifyTrampoline(BEClientLoadCallback, &codecave);
    
        //eac_mapimage_hk = Hooks::JmpRipCode{ eac_driver_base + EAC_OFFSET::map_dll_fn, (uintptr_t)MapImageHandler };

        //Aether::NptHook::Set(eac_driver_base + EAC_OFFSET::map_dll_fn, 
        //    (uint8_t*)"\xCC", 1);

        //eac_mapshellcode_hk = Hooks::JmpRipCode{ eac_driver_base + EAC_OFFSET::map_shellcode_fn, (uintptr_t)MapShellcodeHandler };

        //Aether::NptHook::Set(eac_driver_base + EAC_OFFSET::map_shellcode_fn,
        //    (uint8_t*)"\xCC", 1);
        
     /*   eac_ntallocate_hk = Hooks::JmpRipCode{ eac_driver_base + EAC_OFFSET::ntallocate, (uintptr_t)NtAllocate };

        Aether::NptHook::Set(eac_driver_base + EAC_OFFSET::ntallocate, (uint8_t*)"\xCC", eac_ntallocate_hk.hook_size);*/

        // KeBugCheckEx(MANUALLY_INITIATED_CRASH, 123, 142, 123, 444);
    }
}