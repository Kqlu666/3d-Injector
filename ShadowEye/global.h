#pragma once
#include "includes.h"

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

namespace Global
{
	extern "C" __declspec(dllexport) extern DllParams * dll_params;
};

#define PAGE_SIZE 0x1000