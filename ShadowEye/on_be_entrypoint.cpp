#include "be_spy.h"
#include "utils.h"
#include "dbg_symbols.h"
#include "crash_handler.h"

__declspec(dllexport) DllParams* Global::dll_params = 0;

namespace BE
{
#define MAPPED_DLL_HEADER 0x12345678
#define DUMP_PATH "C:\\Users\\hualu\\Documents\\Battleye_reversal\\BEClient_x64_dump.dll"

	__declspec(dllexport) Hooks::JmpRipCode * entry_point_hk;

	bool entry_not_called = true;

	extern "C" __declspec(dllexport) __int64 __fastcall  EacEntryPointHook(int64_t a1, int64_t a2, int64_t a3)
    {
		Aether::NptHook::Remove(Global::dll_params->beclient_entry_point);

		auto status = static_cast<decltype(&EacEntryPointHook)>((void*)(Global::dll_params->beclient_entry_point))(
			a1, a2, a3
		);

		Utils::DumpMemory(DUMP_PATH, Global::dll_params->be_base, Global::dll_params->be_size);

		PE::ResolveImports((uint8_t*)Global::dll_params->dll_base);

		Disasm::Init();
		Symbols::Init();

		SetUnhandledExceptionFilter(CrashHandler);

		BE::Init();

        return status;
    }
}