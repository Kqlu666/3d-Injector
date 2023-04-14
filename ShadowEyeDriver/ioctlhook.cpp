#include "aethervisor_kernel.h"
#include "hooking.h"
#include "hwid_spoof.h"

namespace Interface
{
    Hooks::JmpRipCode ioctl_hk;

    NTSTATUS NTAPI NtDeviceIoControlFile_handler(
            _In_ HANDLE FileHandle,
            _In_opt_ HANDLE Event,
            _In_opt_ PIO_APC_ROUTINE ApcRoutine,
            _In_opt_ PVOID ApcContext,
            _Out_ PIO_STATUS_BLOCK IoStatusBlock,
            _In_ ULONG IoControlCode,
            _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
            _In_ ULONG InputBufferLength,
            _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
            _In_ ULONG OutputBufferLength
    )
    {
        auto status = static_cast<decltype(&NtDeviceIoControlFile_handler)>((void*)ioctl_hk.original_bytes)(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength
        );

        Spoofer::Get()->SpoofDisk(IoControlCode, InputBuffer, OutputBuffer, OutputBufferLength);

        return status;
    }


	bool Init()
	{
        UNICODE_STRING NtDeviceIoControlFile_name = RTL_CONSTANT_STRING(L"NtDeviceIoControlFile");
        
        auto NtDeviceIoControl = MmGetSystemRoutineAddress(&NtDeviceIoControlFile_name);

        ioctl_hk = Hooks::JmpRipCode{ (uintptr_t)NtDeviceIoControl, (uintptr_t)NtDeviceIoControlFile_handler };

        Aether::NptHook::Set((uintptr_t)NtDeviceIoControl, (uint8_t*)ioctl_hk.hook_code, ioctl_hk.hook_size);

        return true;
	}
}
