#include "crash_handler.h"

void CreateMinidump(struct _EXCEPTION_POINTERS* exception_info, const char* dump_name, MINIDUMP_TYPE minidump_type)
{
	auto dbghelp = LoadLibraryA("dbghelp");

	auto pDump = static_cast<decltype(&MiniDumpWriteDump)>((void*)GetProcAddress(dbghelp, ("MiniDumpWriteDump")));

	HANDLE  hfile = ::CreateFileA(dump_name, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	_MINIDUMP_EXCEPTION_INFORMATION minidump_info;

	minidump_info.ThreadId = ::GetCurrentThreadId();
	minidump_info.ExceptionPointers = exception_info;
	minidump_info.ClientPointers = FALSE;

	pDump(GetCurrentProcess(), GetCurrentProcessId(), hfile, minidump_type, &minidump_info, NULL, NULL);

	::CloseHandle(hfile);
}

LONG CrashHandler(_EXCEPTION_POINTERS* exception_info)
{
	auto rip = exception_info->ContextRecord->Rip;

	if (exception_info->ExceptionRecord->ExceptionCode != 0x406D1388)
	{
		if (exception_info->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
		{
			// for OutputDebugString
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		CreateMinidump(exception_info, ("C:\\Users\\hualu\\Desktop\\testing_drivers\\normaldump.dmp"), MiniDumpNormal);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}