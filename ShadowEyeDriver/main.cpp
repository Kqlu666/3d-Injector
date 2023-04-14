#include "disassembly.h"
#include "kernel_structs.h"
#include "hooking.h"
#include "aethervisor_kernel.h"
#include "util.h"
#include "memory_hiding.h"
#include "be_hook.h"

NTSTATUS DriverEntry(uintptr_t driver_base, uintptr_t driver_size)
{
	DbgPrint("hello, driver_base %p, driver_size %p \n", driver_base, driver_size);

	Disasm::Init();

	HANDLE thread_handle;

	PsCreateSystemThread(&thread_handle, 
		GENERIC_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)ShadowEye::Init, NULL);

    return STATUS_SUCCESS;
}

NTSTATUS MapperEntry(uintptr_t driver_base, uintptr_t driver_size)
{
    return DriverEntry(driver_base, driver_size);
}