#include "manual_map.h"

namespace PE
{
	struct RelocationEntry
	{
		uint16_t offset : 12;
		uint16_t type : 4;
	};

	int64_t	RvaToOffset(IMAGE_DOS_HEADER* base, uintptr_t rva)
	{
		auto pe_hdr = PeHeader(base);

		auto section_header = IMAGE_FIRST_SECTION(pe_hdr);
		auto section_count = pe_hdr->FileHeader.NumberOfSections;

		for (auto i = 0; i < section_count; i++)
		{
			if (section_header->VirtualAddress <= rva)
			{
				if ((section_header->VirtualAddress + section_header->Misc.VirtualSize) > rva)
				{
					rva -= section_header->VirtualAddress;
					rva += section_header->PointerToRawData;

					return rva;
				}
			}

			section_header++;
		}

		return -1;
	}

	/*	can only be used after imports resolved	*/
	void ForEachImport(
		uint8_t* image_base,
		void(*IATCallback)(
			char* module_name,
			const char* import_name,
			uintptr_t function_addr,
			void* callback_data
			),
		void* callback_data
	)
	{
		auto nt_header = PeHeader(image_base);

		auto import_dir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		auto import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(import_dir.VirtualAddress + image_base);

		while (import_desc->Name != NULL)
		{
			auto o_first_thunk = (IMAGE_THUNK_DATA*)(image_base + import_desc->OriginalFirstThunk);

			auto first_thunk = (IMAGE_THUNK_DATA*)(image_base + import_desc->FirstThunk);

			for (o_first_thunk, first_thunk; o_first_thunk->u1.AddressOfData; ++o_first_thunk, ++first_thunk)
			{
				auto import_by_name = (IMAGE_IMPORT_BY_NAME*)(image_base + o_first_thunk->u1.AddressOfData);

				IATCallback(
					(char*)(image_base + import_desc->Name),
					import_by_name->Name,
					first_thunk->u1.Function,
					callback_data
				);
			}

			import_desc += 1;
		}
		return;
	}

	bool ResolveImports(uint8_t* base, PPEB peb)
	{
		auto pe_hdr = PeHeader(base);

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

			ANSI_STRING ansi_name;
			UNICODE_STRING wide_name;

			RtlInitAnsiString(&ansi_name, mod_name);
			RtlAnsiStringToUnicodeString(&wide_name, &ansi_name, TRUE);
			
			/*	if the module isn't mapped globally, then you have to manually  */

			auto module_base = Utils::GetUserModule(PsGetCurrentProcess(), &wide_name, peb);
			
			RtlFreeUnicodeString(&wide_name);

			DbgPrint("%s base %p \n", mod_name, module_base);

			if (!module_base)
			{
				continue;
			}

			for (auto of_thunk = (IMAGE_THUNK_DATA*)(base + import_desc->OriginalFirstThunk),
				thunk = (IMAGE_THUNK_DATA*)(base + import_desc->FirstThunk);
				of_thunk->u1.AddressOfData;
				++of_thunk, ++thunk)
			{
				auto import_by_name = (IMAGE_IMPORT_BY_NAME*)(base + of_thunk->u1.AddressOfData);

				if (MmIsAddressValid(import_by_name))
				{
					thunk->u1.Function = (uintptr_t)PE::GetExport((uintptr_t)module_base, import_by_name->Name);

					DbgPrint("%s import: %p \n", import_by_name->Name, thunk->u1.Function);
				}
				else
				{
					DbgPrint("Import thunk is destroyed! \n");
					thunk->u1.Function = NULL;
				}
			}
		}

		return true;
	}

	void ForEachSection(uint8_t* image_base, void(*SectionCallback)(IMAGE_SECTION_HEADER*, uintptr_t base, void* callback_data), void* callback_data)
	{
		auto pe_hdr = PeHeader(image_base);

		auto section = (IMAGE_SECTION_HEADER*)(pe_hdr + 1);

		for (int i = 0; i < pe_hdr->FileHeader.NumberOfSections; ++i)
		{
			SectionCallback(&section[i], (uintptr_t)image_base, callback_data);
		}
	}


	void CopyHeaders(uint8_t* src, uint8_t* dest)
	{
		auto pe_hdr = PeHeader(src);

		auto section = (IMAGE_SECTION_HEADER*)(pe_hdr + 1);

		memcpy(dest, src, pe_hdr->OptionalHeader.SizeOfHeaders);
	}

	void ResolveRelocations(uint8_t* image_buffer, uint8_t* load_destination)
	{
		auto pe_hdr = PeHeader(image_buffer);

		auto& reloc_dir = pe_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (!reloc_dir.VirtualAddress)
		{
			return;
		}

		auto reloc = (IMAGE_BASE_RELOCATION*)(image_buffer + reloc_dir.VirtualAddress);

		for (auto cur_size = 0; cur_size < reloc_dir.Size; )
		{
			auto reloc_count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(int16_t);
			auto reloc_data = (int16_t*)((char*)reloc + sizeof(IMAGE_BASE_RELOCATION));
			auto reloc_base = (char*)(image_buffer + reloc->VirtualAddress);

			for (auto i = 0; i < reloc_count; ++i, ++reloc_data)
			{
				auto entry = (RelocationEntry*)reloc_data;

				if (entry->type == IMAGE_REL_BASED_DIR64)
				{
					*(uint8_t**)(reloc_base + entry->offset) +=
						(load_destination - (uint8_t*)pe_hdr->OptionalHeader.ImageBase);
				}
			}

			cur_size += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)reloc_data;
		}
	}

	void* GetExport(uintptr_t base, const char* export_name)
	{
		auto pe_hdr = PeHeader(base);

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
	}	

	size_t RemapImage(uint8_t* unmapped_pe, uint8_t** out_buffer, PPEB peb)
	{
		auto pe_header = PeHeader(unmapped_pe);

		ULONG_PTR virtual_size = pe_header->OptionalHeader.SizeOfImage;

		uintptr_t address = NULL;

		auto status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(), (void**)out_buffer,	0, (SIZE_T*)&virtual_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ZwAllocateVirtualMemory failed %p \n", status);
			return NULL;
		}

		memset(*out_buffer, 0x00, virtual_size);

		PE::CopyHeaders(unmapped_pe, *out_buffer);

		/*	SizeOfRawData & PointerToRawData are 0 in VMP packed bins	*/

		PE::ForEachSection(unmapped_pe,
			[](IMAGE_SECTION_HEADER* section, uintptr_t unmapped_bin, void* out_buffer) -> void {

				memcpy(*(uint8_t**)out_buffer + section->VirtualAddress,
					(char*)unmapped_bin + section->PointerToRawData,
					section->SizeOfRawData
				);
			},
			out_buffer
		);

		PE::ResolveRelocations(*out_buffer, (uint8_t*)*out_buffer);

		if (!PE::ResolveImports(*out_buffer, peb))
		{
			DbgPrint("Failed to resolve imports!!!!\n");
		}

		return virtual_size;
	}
};