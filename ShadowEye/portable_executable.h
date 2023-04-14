#pragma once
#include "utils.h"

#define PE_HEADER(image) ((IMAGE_NT_HEADERS64*)((uint64_t)image + ((IMAGE_DOS_HEADER*)image)->e_lfanew))

namespace PE
{
	void* GetExport(
		uintptr_t base,
		const char* export_name
	);

	bool ResolveImports(uint8_t* base);
}