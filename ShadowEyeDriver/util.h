#pragma once
#include "includes.h"
#include "kernel_structs.h"

#define	RELATIVE_ADDR(insn, operand_offset, size) (ULONG64)(*(int*)((BYTE*)insn + operand_offset) + (BYTE*)insn + (int)size)

namespace Utils
{
	PT_ENTRY_64* GetPte(void* virtual_address, uintptr_t pml4_base_pa, int (*page_table_callback)(PT_ENTRY_64*));

	uint32_t Random();

    void SwapEndianess(
		PCHAR dest, 
		PCHAR src
	);

	uintptr_t FindPattern(
		uintptr_t region_base,
		size_t region_size,
		const char* pattern,
		size_t pattern_size,
		char wildcard
	);
	
	NTSTATUS WriteMem(
		int32_t target_pid, 
		uintptr_t address, 
		void* buffer, 
		size_t size
	);

	NTSTATUS ReadMem(
		int32_t target_pid, 
		uintptr_t address,
		void* buffer, 
		size_t size
	);

	HANDLE GetProcessId(
		const char* process_name
	);

	PVOID WriteFile(
		PVOID buffer, 
		const wchar_t* FileName, 
		ULONG64 size
	);

	PVOID GetKernelModule(
		OUT PULONG pSize, 
		UNICODE_STRING DriverName
	);

	LDR_DATA_TABLE_ENTRY* ForEachKernelModule(
		bool (*callback)(LDR_DATA_TABLE_ENTRY*, void* parameter),
		void* parameter
	);

	PVOID CreateFile(
		PVOID buffer, 
		const wchar_t* FileName, ULONG64 size
	);

	void* GetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, PPEB peb = NULL);

	int ZwGetRunningSystemProcess(
		LPWSTR ProcessName
	);

	uint8_t* LoadFileIntoMemory(uint8_t** buffer, const wchar_t* FileName);

	KIRQL DisableWP();

	void EnableWP(
		KIRQL tempirql
	);

	inline PMDL LockPages(PVOID VirtualAddress, LOCK_OPERATION  operation, int size = PAGE_SIZE)
	{
		PMDL mdl = IoAllocateMdl(VirtualAddress, size, FALSE, FALSE, nullptr);

		MmProbeAndLockPages(mdl, KernelMode, operation);

		return mdl;
	}

	NTSTATUS UnlockPages(PMDL mdl);
	
	KAPC_STATE AttachToProcess(int32_t pid);
}