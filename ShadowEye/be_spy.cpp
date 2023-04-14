#include "address_info.h"
#include "disassembly.h"
#include "dbg_symbols.h"
#include "be_spy.h"
#include "hook_shellcode.h"
#include "hooks.h"
#include "crash_handler.h"

using namespace Aether;
using namespace Aether::BranchTracer;

namespace BE
{
	void* beclient2_run;
	uintptr_t beclient2;

	/*	log out-of-module function calls and jmps		*/

	void ExecuteHook(GuestRegisters* registers, void* return_address, void* o_guest_rip)
	{
		Utils::LogToFile(LOG_FILE, "[EXECUTE]\n");
		Utils::LogToFile(LOG_FILE, "return address = ", AddressInfo{ return_address }.Format().c_str());


		Utils::LogToFile(LOG_FILE, "RIP = ", AddressInfo{ o_guest_rip }.Format().c_str());

		Utils::LogToFile(LOG_FILE, "\n\n");
	}


	/*	log specific reads and writes		*/

	void ReadWriteHook(GuestRegisters* registers, void* o_guest_rip)
	{
		ZydisDecodedOperand operands[5] = { 0 };

		auto instruction = Disasm::Disassemble((uint8_t*)o_guest_rip, operands);

		Utils::LogToFile(LOG_FILE, "[READ/WRITE]\n");
		Utils::LogToFile(LOG_FILE, "RIP = ", AddressInfo{ o_guest_rip }.Format().c_str());

		ZydisRegisterContext context;

		Disasm::MyRegContextToZydisRegContext(registers, &context, o_guest_rip);

		for (int i = 0; i < instruction.operand_count_visible; ++i)
		{
			auto mem_target =
				Disasm::GetMemoryAccessTarget(instruction, &operands[i], (ZyanU64)o_guest_rip, &context);

			if (operands[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
			{
				Utils::LogToFile(LOG_FILE, "[write => 0x%02x]\n", mem_target);
			}
			else if (operands[i].actions & ZYDIS_OPERAND_ACTION_MASK_READ)
			{
				Utils::LogToFile(LOG_FILE, "[read => 0x%02x]\n", mem_target);
			}
		}

		Utils::LogToFile(LOG_FILE, "\n\n");
	}

	/*  test_branch_trace.h:  Trace a function until return and log APIs called from the thread.    */

	std::vector<BranchTracer::LogEntry> traced_branches;

	static bool first_branch = true;

	void BranchHook(GuestRegisters* registers, void* return_address, void* o_guest_rip, void* LastBranchFromIP)
	{
		if (first_branch)
		{
			Utils::DumpMemory("C:\\Users\\hualu\\Documents\\Battleye_reversal\\BEClient2_dump.dll", (uintptr_t)beclient2, PE_HEADER(beclient2)->OptionalHeader.SizeOfImage);

			auto context = new EXCEPTION_POINTERS;

			context->ContextRecord = new CONTEXT;

			context->ContextRecord->Rcx = registers->rcx;
			context->ContextRecord->Rax = registers->rax;
			context->ContextRecord->Rdx = registers->rdx;
			context->ContextRecord->Rbx = registers->rbx;

			context->ContextRecord->Rsi = registers->rsi;
			context->ContextRecord->Rdi = registers->rdi;

			context->ContextRecord->Rbp = registers->rbp;
			context->ContextRecord->R8 = registers->r8;
			context->ContextRecord->R9 = registers->r9;

			context->ContextRecord->R10 = registers->r10;
			context->ContextRecord->R11 = registers->r11;
			context->ContextRecord->R12 = registers->r12;
			context->ContextRecord->R13 = registers->r13;
			context->ContextRecord->R14 = registers->r14;
			context->ContextRecord->R15 = registers->r15;
			context->ContextRecord->EFlags = *((uintptr_t*)registers + 16);
			context->ContextRecord->Rsp = (uintptr_t)((uintptr_t*)registers + 18);
			context->ContextRecord->Rip = (uintptr_t)o_guest_rip;

			context->ExceptionRecord = new EXCEPTION_RECORD;

			CreateMinidump(context, "start_context.dmp",
				(MINIDUMP_TYPE)(int)(MINIDUMP_TYPE::MiniDumpWithFullMemoryInfo | MINIDUMP_TYPE::MiniDumpWithFullMemory | MINIDUMP_TYPE::MiniDumpIgnoreInaccessibleMemory));

			first_branch = false;
		}

		if (traced_branches.size() > 30000000)
		{
			for (auto entry : traced_branches)
			{
				if ((entry.branch_target < beclient2) || ((entry.branch_target + PE_HEADER(beclient2)->OptionalHeader.SizeOfImage) < entry.branch_target))
				{
					Utils::LogToFile(BRANCH_LOG_FILE, "[BRANCH] FOUND API CALL!!! entry.branch_address %p entry.branch_target %p	\n",
						entry.branch_address,
						entry.branch_target
					);

					Utils::LogToFile(BRANCH_LOG_FILE, "[branch] API CALL %s -> %s \n",
						AddressInfo{ (void*)entry.branch_address }.Format().c_str(),
						AddressInfo{ (void*)entry.branch_target }.Format().c_str()
					);
				}
			}

			for (auto entry : traced_branches)
			{
				Utils::LogToFile(BRANCH_LOG_FILE, "[BRANCH]	%s -> %s \n",
					AddressInfo{ (void*)entry.branch_address }.Format().c_str(),
					AddressInfo{ (void*)entry.branch_target }.Format().c_str()
				);
			}

			traced_branches.clear();
		}

		if (log_buffer.size() == log_buffer.capacity())
		{
			traced_branches.insert(traced_branches.end(), BranchTracer::log_buffer.begin(), BranchTracer::log_buffer.end());
		}
	}

	static bool not_inited = true;

	void BranchTraceFinished()
	{
		if (not_inited)
		{
			not_inited = false;
		}

		traced_branches.insert(traced_branches.end(), BranchTracer::log_buffer.begin(), BranchTracer::log_buffer.end());

	// std::cout << "Finished tracing Foo()! dumping branch log! \n";

		for (auto entry : traced_branches)
		{
			Utils::LogToFile(BRANCH_LOG_FILE, "[BRANCH]	%s -> %s \n",
				AddressInfo{ (void*)entry.branch_address }.Format().c_str(),
				AddressInfo{ (void*)entry.branch_target }.Format().c_str()
			);
		}
	}


	void Init()
	{
#define BASE_DLL_NAME 0x58

		auto peb = (PPEB)__readgsqword(0x60);

		LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

		LIST_ENTRY curr = head;

		while (curr.Flink != head.Blink)
		{
			_LDR_DATA_TABLE_ENTRY* dll = (_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			Utils::LogToFile(LOG_FILE, "[+] DLL %wZ base at %p, size %i \n",
				(PUNICODE_STRING)((uintptr_t)dll + BASE_DLL_NAME), dll->DllBase, PE_HEADER(dll->DllBase)->OptionalHeader.SizeOfImage);

			curr = *curr.Flink;
		}

	//	MessageBoxA(NULL, "ShadowEye INJECTED!", "BEClient_x64.dll found at 0x07FFCD76E0000 !", MB_OK);

		Utils::LogToFile(LOG_FILE, "[+] BE base at %p \n", Global::dll_params->be_base);
		Utils::LogToFile(LOG_FILE, "[+] BE size at %p \n", Global::dll_params->be_size);

		// SET_NPT_HOOK(JmpRipCode, EacGetExport, Global::dll_params->eac_base + 0x4FDD8, false)

		SET_NPT_HOOK(JmpRipCode, LoadLibraryA, (uintptr_t)GetModuleHandle(L"KernelBase.dll") + 0x78CA0, true)

		// Aether::BranchTracer::Init();

	}
}