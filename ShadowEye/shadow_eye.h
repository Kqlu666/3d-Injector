#pragma once
#include "global.h"
#include "portable_executable.h"
#include "utils.h"
#include "hook_shellcode.h"

namespace EAC
{
	extern "C"  __declspec(dllexport) extern Hooks::JmpRipCode * entry_point_hk;

	void Init();
}