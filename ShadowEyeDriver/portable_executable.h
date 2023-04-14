#pragma once
#include "util.h"

#define PeHeader(image) ((IMAGE_NT_HEADERS64*)((uint64_t)image + ((IMAGE_DOS_HEADER*)image)->e_lfanew))

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + ((IMAGE_NT_HEADERS64*)(ntheader))->FileHeader.SizeOfOptionalHeader))

#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_REL_BASED_DIR64 10

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;