#include "address_info.h"
#include "disassembly.h"
#include "dbg_symbols.h"
#include "eac_spy.h"
#include "hook_shellcode.h"
#include "hooks.h"

using namespace Aether;
using namespace Aether::BranchTracer;

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

void BranchHook(GuestRegisters* registers, void* return_address, void* o_guest_rip, void* LastBranchFromIP)
{
	/* std::cout << std::hex << "[BranchHook]  return_address 0x" << (uintptr_t)return_address << " LastBranchFromIP 0x"
		 << (uintptr_t)LastBranchFromIP << " o_guest_rip 0x" << (uintptr_t)o_guest_rip << std::endl;*/

		 // std::cout << "LastBranchFromIP 0x" << std::hex << LastBranchFromIP << std::endl;

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
		Symbols::Init();

		not_inited = false;
	}

	traced_branches.insert(traced_branches.end(), BranchTracer::log_buffer.begin(), BranchTracer::log_buffer.end());

	std::cout << "Finished tracing Foo()! dumping branch log! \n";

	for (auto entry : traced_branches)
	{
		std::cout << "[BRANCH]  " << AddressInfo{ (void*)entry.branch_address }.Format()
			<< " -> " << AddressInfo{ (void*)entry.branch_target }.Format() << "\n";
	}
}
namespace EAC
{
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
				(PUNICODE_STRING)((uintptr_t)dll + BASE_DLL_NAME), dll->DllBase, PeHeader(dll->DllBase)->OptionalHeader.SizeOfImage);

			curr = *curr.Flink;
		}

		Utils::LogToFile(LOG_FILE, "[+] EAC base at %p \n", Global::dll_params->eac_base);
		Utils::LogToFile(LOG_FILE, "[+] EAC size at %p \n", Global::dll_params->eac_size);
		
		// SET_NPT_HOOK(JmpRipCode, EacGetExport, Global::dll_params->eac_base + 0x4FDD8, false)
		// SET_NPT_HOOK(JmpRipCode, RtlAddVEH, (uintptr_t)GetModuleHandle(L"ntdll.dll") + 0x81790, true)

		// Aether::BranchTracer::Init();

	}
}
