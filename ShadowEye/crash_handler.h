#pragma once
#include "utils.h"
#include "global.h"
#include <DbgHelp.h>

typedef BOOL(WINAPI* MiniDumpWriteDump_t)(HANDLE hProcess, DWORD dwPid, HANDLE hFile, MINIDUMP_TYPE DumpType, CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam, CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

void CreateMinidump(struct _EXCEPTION_POINTERS* exception_info, const char* dump_name, MINIDUMP_TYPE minidump_type);

LONG CrashHandler(_EXCEPTION_POINTERS* ExceptionInfo);
