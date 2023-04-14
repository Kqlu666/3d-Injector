#include "includes.h"
#include "kernel_exports.h"
#include "portable_executable.h"
#include "be_hook.h"
#include "aethervisor_kernel.h"

NTSTATUS SetImageLoadNotifyTrampoline(
	IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
	OUT PLOAD_IMAGE_NOTIFY_ROUTINE* TrampolineBase
);

void BEClientLoadCallback(
	PUNICODE_STRING FullImageName, 
	HANDLE ProcessId, 
	PIMAGE_INFO ImageInfo
);
