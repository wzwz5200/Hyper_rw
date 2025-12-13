#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <cstdio>      
#include <memory>     
#include "HyperCall/call.h"
#include "GetM.h"
#include <dbghelp.h>

#include <chrono>
#include <thread>

using namespace std;


void LogOffset(const std::string& name, uint64_t value) {
	std::cout << "  "
		<< std::left << std::setw(30) << name
		<< " = 0x"
		<< std::hex << std::uppercase << value
		<< std::dec << std::endl;               // 必须复位流状态，不然影响后面输出
}

void PrintAllOffsets() {
	std::cout << "\n================ [ Offsets Dump ] ================" << std::endl;

	std::cout << "[+] Kernel Structs (ntoskrnl.exe / _EPROCESS):" << std::endl;
	LogOffset("UniqueProcessId", Offsets::UniqueProcessId);
	LogOffset("ActiveProcessLinks", Offsets::ActiveProcessLinks);
	LogOffset("DirectoryTableBase", Offsets::DirectoryTableBase);
	LogOffset("Peb", Offsets::Peb);
	LogOffset("OwnerProcessId", Offsets::OwnerProcessId);

	std::cout << "\n[+] User Structs (ntdll.dll / _PEB & _LDR):" << std::endl;
	LogOffset("Ldr", Offsets::Ldr);
	LogOffset("InLoadOrderLinks", Offsets::InLoadOrderLinks);
	LogOffset("DllBase", Offsets::DllBase);
	LogOffset("BaseDllName", Offsets::BaseDllName);

	std::cout << "==================================================\n" << std::endl;
}



class KernelCheatEngine {
private:
	HANDLE hProcess;
	uint64_t runtimeKernelBase;
	uint64_t psActiveProcessHeadAddr;

	uint64_t targetPid;
	uint64_t targetCr3;
	uint64_t targetPeb;
	uint64_t clientDllBase;

	// 微软官方源，国内网速慢的话记得挂代理
	const std::string SYMBOL_STORE_PATH = "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";

public:

	KernelCheatEngine()
		: hProcess(GetCurrentProcess()), runtimeKernelBase(0), psActiveProcessHeadAddr(0),
		targetPid(0), targetCr3(0), targetPeb(0), clientDllBase(0)
	{
		std::string currentDir = GetCurrentExeDirectory();
		std::cout << "当前运行目录: " << currentDir << std::endl;
		// 系统自带的版本往往太老，解析新版 PDB 会失败
		if (!PreloadDebugLibraries(currentDir)) {
			std::cerr << "警告: 在当前目录下未找到 DLL，尝试使用系统版本 (可能会炸)..." << std::endl;
		}

		if (!InitSymbolEngine(hProcess, SYMBOL_STORE_PATH)) {
			throw std::runtime_error("符号引擎初始化失败，检查路径或权限");
		}
	}

	~KernelCheatEngine() {
		if (hProcess) {
			SymCleanup(hProcess);
		}
	}

	bool InitializeSystem() {
		runtimeKernelBase = GetNtoskrnlBaseAddress();

		if (runtimeKernelBase != 0) {
			std::cout << "动态获取 ntoskrnl.exe 基址成功!" << std::endl;
			std::cout << "Base Address: 0x" << std::hex << runtimeKernelBase << std::endl;


		}
		else {
			std::cout << "无法获取 ntoskrnl.exe 基址。请检查权限或系统版本。" << std::endl;
			return false;
		}


		DWORD64 kernelSymbolBase = LoadKernelModule(hProcess);
		if (kernelSymbolBase) {
			std::cout << "[*] 正在解析内核结构体偏移..." << std::endl;
			Offsets::UniqueProcessId = GetFieldOffset(hProcess, kernelSymbolBase, "_EPROCESS", "UniqueProcessId");
			Offsets::ActiveProcessLinks = GetFieldOffset(hProcess, kernelSymbolBase, "_EPROCESS", "ActiveProcessLinks");
			Offsets::Peb = GetFieldOffset(hProcess, kernelSymbolBase, "_EPROCESS", "Peb");
			Offsets::DirectoryTableBase = GetFieldOffset(hProcess, kernelSymbolBase, "_KPROCESS", "DirectoryTableBase");
			Offsets::OwnerProcessId = GetFieldOffset(hProcess, kernelSymbolBase, "_EPROCESS", "InheritedFromUniqueProcessId");
		}
		else {
			return false;
		}

		char sysDir[MAX_PATH];
		GetSystemDirectoryA(sysDir, MAX_PATH);
		std::string ntdllPath = std::string(sysDir) + "\\ntdll.dll";
		DWORD64 ntdllBase = SymLoadModuleEx(hProcess, NULL, ntdllPath.c_str(), NULL, 0, 0, NULL, 0);

		if (ntdllBase) {
			std::cout << "[*] 正在解析用户态结构体偏移..." << std::endl;
			Offsets::Ldr = GetFieldOffset(hProcess, ntdllBase, "_PEB", "Ldr");
			Offsets::InLoadOrderLinks = GetFieldOffset(hProcess, ntdllBase, "_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks");
			Offsets::DllBase = GetFieldOffset(hProcess, ntdllBase, "_LDR_DATA_TABLE_ENTRY", "DllBase");
			Offsets::BaseDllName = GetFieldOffset(hProcess, ntdllBase, "_LDR_DATA_TABLE_ENTRY", "BaseDllName");
		}

		// 拿全局变量 RVA
		DWORD64 rva = ResolveSymbolRVA(hProcess, kernelSymbolBase, "PsActiveProcessHead");

		PrintAllOffsets();

		// 算出最终的链表头地址
		psActiveProcessHeadAddr = runtimeKernelBase + rva;

		return true;
	}

	bool AttachToProcess(uint64_t pid) {
		this->targetPid = pid;

		//CR3
		targetCr3 = GetProcessCr3(targetPid, psActiveProcessHeadAddr);
		if (targetCr3 == 0) {
			std::cout << "未找到进程 (或读不到 CR3): 0x" << std::hex << targetCr3 << std::endl;
			return false;
		}
		std::cout << "找到进程，CR3 为: 0x" << std::hex << targetCr3 << std::endl;

		//PEB
		targetPeb = FindPebByCr3_Raw(targetCr3, psActiveProcessHeadAddr);
		return (targetPeb != 0);
	}

	bool FindModule(const char* moduleName) {
		if (targetPeb == 0) return false;

		// 遍历 PEB->Ldr 链表
		clientDllBase = GetModuleBase_Raw(targetCr3, targetPeb, moduleName);

		if (clientDllBase != 0) {
			std::cout << "找到 DLL 基址: 0x" << std::hex << clientDllBase << std::endl;
			return true;
		}
		else {
			std::cout << "未找到模块: " << moduleName << std::endl;
			return false;
		}
	}

	void Run() {
		if (clientDllBase == 0) return;

		GuestMemory mem(targetCr3);
		/*int health = 0;
		uint64_t local_player_addr = 0;*/

		/*
		// 第一次读取 LocalPlayer
		mem.ReadValue<uint64_t>(clientDllBase + 0x1BEDF28, local_player_addr);

		// 循环读取健康值
		while (true) {
			if (mem.ReadValue<int>(local_player_addr + 0x34c, health)) {
				printf("当前血量: %d\n", health);
			}
			else {
				printf("读取失败: %d\n");
			}
			Sleep(1000);
		}
		*/
	}
};