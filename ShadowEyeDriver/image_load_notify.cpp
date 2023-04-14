#include "image_load_notify.h"

PCREATE_PROCESS_NOTIFY_ROUTINE trampoline = 0;

BYTE shellcode[] =
{
	0x50,                                                        // push rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, TARGET
	0x48, 0x87, 0x04, 0x24,                                      // xchg QWORD PTR[rsp], rax
	0xC3                                                         // ret
};

uintptr_t notify_routine_trampoline;

void BEClientLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (wcsstr(FullImageName->Buffer, L"BEClient_x64.dll"))
	{
		ShadowEye::beclient_base = (uintptr_t)ImageInfo->ImageBase;
		ShadowEye::beclient_size = ImageInfo->ImageSize;

		DbgPrint("BEClient.dll base 0x%p BEClient.dll size 0x%p CR3 0x%p \n",
			ImageInfo->ImageBase, ImageInfo->ImageSize, __readcr3());

		LARGE_INTEGER interval;
		interval.QuadPart = -1 * 1000 * 100 * 500; /* 5 second */
		KeDelayExecutionThread(KernelMode, FALSE, &interval);

		ShadowEye::InjectShadowEye();
	}
}


NTSTATUS SetImageLoadNotifyTrampoline(IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine, OUT PLOAD_IMAGE_NOTIFY_ROUTINE* TrampolineBase)
{
	NTSTATUS status;

	Utils::ForEachKernelModule(
		[](LDR_DATA_TABLE_ENTRY* entry, void* parameter) -> bool {

			if (wcslen(entry->BaseDllName.Buffer) < 10 ||
				wcsstr(entry->BaseDllName.Buffer, _wcslwr(L"win32kbase")) ||
				wcsstr(entry->BaseDllName.Buffer, _wcslwr(L"clfs")))
			{
				return true;	// continue search
			}

			*(uintptr_t*)parameter = Utils::FindPattern((uintptr_t)entry->DllBase,
				entry->SizeOfImage, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", sizeof(shellcode),0xAA);

			// found codecave
			if (*(uintptr_t*)parameter)
			{
				DbgPrint("Found codecave in %wZ \n", &entry->BaseDllName);
				return false; // stop search
			}
		}, 
		& notify_routine_trampoline
	);

	// This is not supposed to happen

	if (!notify_routine_trampoline)
	{
		DbgPrint("Unable to find any suitable code cave, aborting... \n");
		return STATUS_UNSUCCESSFUL;
	}

	//	Prepare shellcode with our routine address
	*(UINT_PTR*)(shellcode + 3) = (UINT_PTR)NotifyRoutine;

	// Write shellcode in the found code cave
	Aether::NptHook::Set(notify_routine_trampoline, shellcode, sizeof(shellcode));

	// Out address
	*TrampolineBase = (PLOAD_IMAGE_NOTIFY_ROUTINE)notify_routine_trampoline;

	// Call PsSetCreateProcessNotifyRoutine to register the callback
	if (!NT_SUCCESS(status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)notify_routine_trampoline)))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutine failed with status 0x%X  \n", status);
		return status;
	}

	// Ok
	DbgPrint("SetCreateProcessNotifyRoutine succeeded  \n");

	return STATUS_SUCCESS;
}
