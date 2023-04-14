#include "includes.h"

#define LOG_FILE "C:\\Users\\hualu\\Documents\\Battleye_reversal\\be_logs.txt"
#define BRANCH_LOG_FILE "C:\\Users\\hualu\\Documents\\Battleye_reversal\\beclient2_run_branches.txt"

namespace Utils
{
	PVOID ModuleFromAddress(uintptr_t address, PUNICODE_STRING out_name);

	void DumpMemory(const char* path, uintptr_t range_base, size_t range_size);

	void WriteToReadOnly(void* address, uint8_t* bytes, size_t len);

	size_t LoadFileIntoMemory(const wchar_t* path, char** buffer);

	bool IsAddressValid(void* address);
		

	void LogToFile(const char* file_name, const char* format, ...);

#pragma optimize( "", off )

	uintptr_t FindPattern(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard);

#pragma optimize( "", on )

}