#pragma once
#include "includes.h"
#include "hooking.h"
#include "aethervisor_kernel.h"

namespace ShadowEye
{
    extern uintptr_t beclient_base;
    extern uintptr_t beclient_size;

    struct DllParams
    {
        uint32_t header;
        uintptr_t dll_base;
        size_t dll_size;
        uintptr_t be_base;
        size_t be_size;
        uintptr_t beclient_entry_point;
        int o_present_bytes_size;
        uint8_t original_present_bytes[20];
    };

    enum OFFSET : uintptr_t
    {
        beclient_entry_point = 0x449CE8,
    };

#define SHADOWEYE_DLL L"\\??\\C:\\Users\\hualu\\Desktop\\testing_drivers\\ShadowEye.dll"
#define BECLIENT_DUMP_DLL L"\\??\\C:\\Users\\hualu\\Desktop\\testing_drivers\\BEClient_dump.dll"

    void InjectShadowEye();

    void Init();
};

