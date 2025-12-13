#pragma once
#include "rw.h"
#include <iostream>
#include <Windows.h>

#include <vector>

#include <dbghelp.h>

#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "dbghelp.lib")
struct UNICODE_STRING_RAW {
	unsigned short Length;
	unsigned short MaximumLength;
	uint64_t Buffer;
};
namespace Offsets {
	inline uint64_t UniqueProcessId;
	inline uint64_t ActiveProcessLinks;
	inline uint64_t DirectoryTableBase;
	inline uint64_t Peb;
	inline uint64_t OwnerProcessId;

	inline uint64_t Ldr;
	inline uint64_t InLoadOrderLinks;
	inline uint64_t DllBase;
	inline uint64_t BaseDllName;
}
//
//namespace Offsets {
//
//
//
//	constexpr uint64_t UniqueProcessId = 0x1d0;
//
//	constexpr uint64_t ActiveProcessLinks = 0x1d8;
//
//	constexpr uint64_t DirectoryTableBase = 0x028;
//
//	constexpr uint64_t Peb = 0x2e0;
//
//	constexpr uint64_t OwnerProcessId = 0x2d8;
//
//
//
//	constexpr uint64_t Ldr = 0x018;
//
//	constexpr uint64_t InLoadOrderLinks = 0x010;
//
//	constexpr uint64_t DllBase = 0x030; // _LDR_DATA_TABLE_ENTRY.DllBase
//
//	constexpr uint64_t BaseDllName = 0x058; // _LDR_DATA_TABLE_ENTRY.BaseDllName
//
//
//
//
//
//}



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





uint64_t GetNtoskrnlBaseAddress();



uint64_t GetProcessCr3(uint64_t target_pid, uint64_t ps_active_process_head_addr);
uint64_t FindProcessEProcessBase(uint64_t target_pid, uint64_t ps_active_process_head_addr);

uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const char* wanted_name);
uint64_t FindPebByCr3_Raw(uint64_t target_cr3, uint64_t ps_active_process_head_addr);


// 读取系统ntoskrnl 路径
std::string GetRealNtoskrnlPath();

void LogError(const std::string& funcName);

bool PreloadDebugLibraries(const std::string& dirPath);

bool InitSymbolEngine(HANDLE hProcess, const std::string& searchPath);

//获取系统 ntoskrnl的完整路径
std::string GetKernelImagePath();


//模块加载基址
DWORD64 LoadKernelModule(HANDLE hProcess);

//获取符号的RVA

DWORD64 ResolveSymbolRVA(HANDLE hProcess, DWORD64 moduleBase, const std::string& symbolName);


std::string GetCurrentExeDirectory();

//获取结构体成员的偏移量
DWORD GetFieldOffset(HANDLE hProcess, DWORD64 moduleBase, const std::string& structName, const std::string& memberName);