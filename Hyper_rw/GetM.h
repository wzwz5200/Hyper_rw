#pragma once
#include "rw.h"
#include <iostream>

struct UNICODE_STRING_RAW {
	unsigned short Length;
	unsigned short MaximumLength;
	uint64_t Buffer;
};

namespace Offsets {

	constexpr uint64_t UniqueProcessId = 0x1d0;
	constexpr uint64_t ActiveProcessLinks = 0x1d8;
	constexpr uint64_t DirectoryTableBase = 0x028;
	constexpr uint64_t Peb = 0x2e0;
	constexpr uint64_t OwnerProcessId = 0x2d8;

	constexpr uint64_t Ldr = 0x018;
	constexpr uint64_t InLoadOrderLinks = 0x010;
	constexpr uint64_t DllBase = 0x030; // _LDR_DATA_TABLE_ENTRY.DllBase
	constexpr uint64_t BaseDllName = 0x058; // _LDR_DATA_TABLE_ENTRY.BaseDllName


}


uint64_t GetProcessCr3(uint64_t target_pid, uint64_t ps_active_process_head_addr);
uint64_t FindProcessEProcessBase(uint64_t target_pid, uint64_t ps_active_process_head_addr);

uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const char* wanted_name);
uint64_t FindPebByCr3_Raw(uint64_t target_cr3, uint64_t ps_active_process_head_addr);