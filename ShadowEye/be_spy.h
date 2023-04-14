#pragma once
#include "global.h"
#include "portable_executable.h"
#include "utils.h"
#include "hook_shellcode.h"

namespace BE
{
	extern "C"  __declspec(dllexport) extern Hooks::JmpRipCode * entry_point_hk;

	extern 	void* beclient2_run;
	extern	uintptr_t beclient2;

	void BranchTraceFinished();
	void BranchHook(GuestRegisters* registers, void* return_address, void* o_guest_rip, void* LastBranchFromIP);

	void Init();
}