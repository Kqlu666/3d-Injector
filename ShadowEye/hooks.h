#pragma once
#include "utils.h"
#include "hook_shellcode.h"
#include "address_info.h"
#include "global.h"
#include "aethervisor.h"

namespace Hooks
{
	extern Hooks::JmpRipCode* hk_LoadLibraryA;

	HMODULE __stdcall LoadLibraryA_hk(LPCSTR lpLibFileName);

	extern Hooks::JmpRipCode* hk_BEClient2Run;

	void __fastcall BEClient2Run_hk(uintptr_t a1, uintptr_t report_fn);
};


#define SET_NPT_HOOK( shellcode_type, name, function_address, global_page )  Hooks::hk_##name = new Hooks::##shellcode_type((uintptr_t)function_address, (uintptr_t)Hooks::name##_hk); \
 Aether::NptHook::Set(function_address, (uint8_t*)Hooks::hk_##name->hook_code, Hooks::hk_##name->hook_size, Aether::primary, global_page);
