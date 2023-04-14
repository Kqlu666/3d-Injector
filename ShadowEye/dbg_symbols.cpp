#include "dbg_symbols.h"
#include "portable_executable.h"
#include <DbgHelp.h>

namespace Symbols
{
    void Init()
    {
        LoadLibrary(L"dbghelp");

        auto result = SymInitialize(GetCurrentProcess(), "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols", FALSE);

#define LDR_IMAGESIZE 0x40
#define BASE_DLL_NAME 0x58

        auto peb = (PPEB)__readgsqword(0x60);

        LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

        LIST_ENTRY curr = head;

        while (curr.Flink != head.Blink)
        {
            auto dll = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
          
            std::wstring wide_name = ((PUNICODE_STRING)((uintptr_t)dll + BASE_DLL_NAME))->Buffer;

            LoadSymbolsForModule(
                std::string(wide_name.begin(), wide_name.end()), (uintptr_t)dll->DllBase, *(uintptr_t*)((uintptr_t)dll + LDR_IMAGESIZE));

            curr = *curr.Flink;
        }

        return;
    }

    uintptr_t LoadSymbolsForModule(std::string image_name, uintptr_t mapped_base, uintptr_t image_size)
    {
        auto result = SymLoadModuleEx(GetCurrentProcess(), NULL, image_name.c_str(), NULL, mapped_base, image_size, NULL, 0);
        return result;
    }

    ULONG GetSymAddr(ULONG Index, uintptr_t module_base, bool* Status)
    {
        ULONG Offset = 0;
        BOOL SymStatus = SymGetTypeInfo(GetCurrentProcess(), module_base, Index, TI_GET_OFFSET, &Offset);
        if (Status) *Status = SymStatus;
        return Offset;
    }

    std::string GetSymFromAddr(uintptr_t addr)
    {
        struct 
        {
            SYMBOL_INFO info;
            char name_buf[128];
        } symbol_info;

        symbol_info.info.SizeOfStruct = sizeof(symbol_info.info);
        symbol_info.info.MaxNameLen = sizeof(symbol_info.name_buf);
        
        auto result = SymFromAddr(GetCurrentProcess(), addr, NULL, &symbol_info.info);

        if (!result)
        {
            printf("SymFromAddr GetLastError %i \n", GetLastError());

            return std::string("");
        }

        return std::string(symbol_info.info.Name);
    }
};