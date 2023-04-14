#include "portable_executable.h"

namespace PE
{
	void* GetExport(uintptr_t base, const char* export_name)
	{
		auto pe_hdr = PE_HEADER(base);

		IMAGE_DATA_DIRECTORY data_dir =
			pe_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		auto export_dir = (IMAGE_EXPORT_DIRECTORY*)(data_dir.VirtualAddress + base);

		auto function_array = (int*)(export_dir->AddressOfFunctions + base);
		auto name_array = (int*)(export_dir->AddressOfNames + base);
		auto ordinal_array = (int16_t*)(export_dir->AddressOfNameOrdinals + base);

		for (int i = 0; i < export_dir->NumberOfFunctions; ++i)
		{
			char* name = (char*)(name_array[i] + base);

			if (!strcmp(export_name, name))
			{
				int ordinal = ordinal_array[i];
				return (void*)((uint8_t*)function_array[ordinal] + base);
			}
		}

		return NULL;
	}

	bool ResolveImports(uint8_t* base)
	{
		auto pe_hdr = PE_HEADER(base);

		auto rva = pe_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		if (!rva)
		{
			return false;
		}

		auto import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + rva);

		for (; import_desc->FirstThunk; ++import_desc)
		{
			auto mod_name = (char*)(base + import_desc->Name);

			if (!mod_name)
			{
				break;
			}

			HMODULE module = LoadLibraryA(mod_name);

			bool manualmap_dependency = false;

			for (auto of_thunk = (IMAGE_THUNK_DATA*)(base + import_desc->OriginalFirstThunk),
				thunk = (IMAGE_THUNK_DATA*)(base + import_desc->FirstThunk);
				of_thunk->u1.AddressOfData;
				++of_thunk, ++thunk)
			{
				auto import_by_name = (IMAGE_IMPORT_BY_NAME*)(base + of_thunk->u1.AddressOfData);

				if (Utils::IsAddressValid(import_by_name))
				{
					thunk->u1.Function = (uintptr_t)GetProcAddress(module, import_by_name->Name);
				}
				else
				{
					thunk->u1.Function = NULL;
				}
			}
		}

		return true;
	}
}