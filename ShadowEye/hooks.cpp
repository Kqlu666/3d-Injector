#include "hooks.h"
#include "portable_executable.h"
#include "be_spy.h"

namespace Hooks
{
	Hooks::JmpRipCode* hk_LoadLibraryA;
	Hooks::JmpRipCode* hk_BEClient2Run;

	void __fastcall BEClient2Run_hk(uintptr_t a1, uintptr_t report_fn)
	{
		Aether::NptHook::Remove((uintptr_t)BE::beclient2_run);

		Utils::LogToFile(LOG_FILE,
			"BEClient2!Run called at %p (be_base + 0x%p) a1 0x%p report_fn 0x%p \n",
			_ReturnAddress(), (uintptr_t)_ReturnAddress() - Global::dll_params->be_base, a1, report_fn
		);

		auto beclient2 = (uintptr_t)GetModuleHandleA("BEClient2.dll");

		Aether::BranchTracer::Init();

		Aether::SetCallback(Aether::branch, BE::BranchHook);
		Aether::SetCallback(Aether::branch_trace_finished, BE::BranchTraceFinished);

		Aether::BranchTracer::Trace((uint8_t*)BE::beclient2_run, beclient2, PE_HEADER(beclient2)->OptionalHeader.SizeOfImage); //	trace BEClient2!Run()
		
		static_cast<decltype(&BEClient2Run_hk)>(BE::beclient2_run)(a1, report_fn);
	}

	HMODULE __stdcall LoadLibraryA_hk(LPCSTR lpLibFileName)
	{
		auto result = (uintptr_t)static_cast<decltype(&LoadLibraryA_hk)>((void*)hk_LoadLibraryA->original_bytes)(lpLibFileName);

		Utils::LogToFile(LOG_FILE,
			"LoadLibraryA called at %p (be_base + 0x%p)	 lpLibFileName %s  returned DLL base 0x%p \n",
			_ReturnAddress(), (uintptr_t)_ReturnAddress() - Global::dll_params->be_base, lpLibFileName, result);

		if (strstr(lpLibFileName, "BEClient2"))
		{
			BE::beclient2 = result;
			BE::beclient2_run = PE::GetExport(BE::beclient2, "Run");

			Utils::LogToFile(LOG_FILE, "Run() address 0x%p \n", BE::beclient2_run);

			SET_NPT_HOOK(JmpRipCode, BEClient2Run, (uintptr_t)BE::beclient2_run, false);
		}

		return (HMODULE)result;
	}
};