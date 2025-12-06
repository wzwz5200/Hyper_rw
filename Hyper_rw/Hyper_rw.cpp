#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <cstdio>     
#include <memory>    
#include "HyperCall/call.h"
#include "GetM.h"

#include <chrono>
#include <thread>
using namespace std;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID  MappedBase;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// 定义未公开枚举值
typedef enum _SYSTEM_INFORMATION_CLASS_EX {
	SystemModuleInformation_Ex = 11 // SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS_EX;

// NtQuerySystemInformation 函数指针类型
typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);



/**
 * @brief 动态查找 ntoskrnl.exe 的当前加载基地址。
 * 通过调用未公开的 NtQuerySystemInformation API 实现。
 * @return 成功返回 ntoskrnl.exe 的基地址 (uint64_t)，失败返回 0。
 */
uint64_t GetNtoskrnlBaseAddress() {
	// 1. 动态加载 NtQuerySystemInformation
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == nullptr) return 0;

	TNtQuerySystemInformation NtQuerySystemInformation =
		(TNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) return 0;

	ULONG size = 0;

	NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemModuleInformation_Ex,
		nullptr,
		0,
		&size
	);


	if (size == 0 || size > 0x100000) {
		return 0;
	}


	std::unique_ptr<RTL_PROCESS_MODULES, void(*)(void*)> buffer(
		(PRTL_PROCESS_MODULES)malloc(size),
		free
	);

	if (buffer == nullptr) return 0;

	NTSTATUS status = NtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)SystemModuleInformation_Ex,
		buffer.get(),
		size,
		&size
	);

	if (!NT_SUCCESS(status)) {

		return 0;
	}

	for (ULONG i = 0; i < buffer->NumberOfModules; i++) {
		const char* name =
			(const char*)buffer.get()->Modules[i].FullPathName +
			buffer.get()->Modules[i].OffsetToFileName;


		if (_stricmp(name, "ntoskrnl.exe") == 0 ||
			_stricmp(name, "ntkrnlmp.exe") == 0 ||
			_stricmp(name, "ntkrnlpa.exe") == 0 ||
			_stricmp(name, "ntkrpamp.exe") == 0)
		{

			return (uint64_t)buffer.get()->Modules[i].ImageBase;
		}
	}

	return 0;
}


static inline uint64_t now_ns() {
	return chrono::duration_cast<chrono::nanoseconds>(
		chrono::high_resolution_clock::now().time_since_epoch()
	).count();
}



void test_speed(uint64_t va, uint64_t cr3, size_t size) {
	vector<uint8_t> buf(size);


	hypercall::read_guest_virtual_memory(buf.data(), va, cr3, 4096);

	uint64_t t1 = now_ns();

	hypercall::read_guest_virtual_memory(buf.data(), va, cr3, size);

	uint64_t t2 = now_ns();

	double sec = (t2 - t1) / 1e9;
	double mbps = (size / (1024.0 * 1024.0)) / sec;

	cout << "Size: " << (size / 1024 / 1024)
		<< " MB, Time: " << sec << " sec, Speed: "
		<< mbps << " MB/s" << endl;
}

void worker_thread(uint64_t va, uint64_t cr3, size_t size,
	atomic<uint64_t>& total_bytes,
	atomic<bool>& running)
{
	vector<uint8_t> buf(size);

	while (running.load()) {
		hypercall::read_guest_virtual_memory(buf.data(), va, cr3, size);
		total_bytes.fetch_add(size, memory_order_relaxed);
	}
}


int main() {
	size_t chunk_size = 8 * 1024 * 1024; // 8MB per read
	uint64_t ntoskrnl_base = GetNtoskrnlBaseAddress();

	if (ntoskrnl_base != 0) {
		std::cout << "动态获取 ntoskrnl.exe 基址成功!" << std::endl;
		std::cout << "Base Address: 0x" << std::hex << ntoskrnl_base << std::endl;


		const uint64_t STATIC_PS_ACTIVE_PROCESS_HEAD_OFFSET = 0xF05790;//PsActiveProcessHead 静态偏移量

		uint64_t ps_active_process_head_addr = ntoskrnl_base + STATIC_PS_ACTIVE_PROCESS_HEAD_OFFSET;

		std::cout << "PsActiveProcessHead 动态地址: 0x" << std::hex << ps_active_process_head_addr << std::endl;

	}
	else {
		std::cout << "无法获取 ntoskrnl.exe 基址。请检查权限或系统版本。" << std::endl;
	}

	uint64_t kernel_head_addr = GetNtoskrnlBaseAddress() + 0xF05790; //PsActiveProcessHead 静态偏移量

	uint64_t target_pid = 20528; //cs2 pid
	uint64_t target_address = 0x18f32c3b070; // 读取游戏/程序内存地址
	int value_buffer = 0;

	//获取目标的 CR3
	uint64_t target_cr3 = GetProcessCr3(target_pid, kernel_head_addr);


	if (target_cr3 == 0)
	{
		std::cout << "未找到进程，CR3 为: 0x" << std::hex << target_cr3 << std::endl;

		return 0;

	}
	std::cout << "找到进程，CR3 为: 0x" << std::hex << target_cr3 << std::endl;


	uint64_t target_peb = FindPebByCr3_Raw(target_cr3, kernel_head_addr);

	if (target_peb != 0) {

		uint64_t base = GetModuleBase_Raw(target_cr3, target_peb, "client.dll");

		if (base != 0) {
			std::cout << "找到DLL 为: 0x" << std::hex << base << std::endl;

		}
	}

	return 0;
}