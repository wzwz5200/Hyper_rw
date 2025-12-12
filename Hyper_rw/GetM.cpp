#include "GetM.h"

#include <filesystem>





uint64_t GetProcessCr3(uint64_t target_pid, uint64_t ps_active_process_head_addr) {
	// -----------------------------------------------------
	// 1. 关键修正：使用 System Process 的 DirBase (您需要手动替换)
	// 假设您查到的 System CR3 地址是 0x18f45a000
	// -----------------------------------------------------
	const uint64_t SYSTEM_CR3_HARDCODED = hypercall::read_guest_cr3();
	uint64_t system_cr3 = SYSTEM_CR3_HARDCODED;
	// 调试输出头部信息
	std::cout << "\n--- 进程链表遍历开始 ---" << std::endl;

	std::cout << "目标 PID: " << std::dec << target_pid << std::endl;
	std::cout << "PsActiveProcessHead 地址: 0x" << ps_active_process_head_addr << std::endl;
	std::cout << "使用 System CR3: 0x" << system_cr3 << std::endl;
	std::cout << "ActiveProcessLinks 偏移: 0x" << Offsets::ActiveProcessLinks << std::endl;
	std::cout << "-------------------------" << std::endl;

	// 2. 从链表头开始
	uint64_t current_list_entry = ps_active_process_head_addr;

	// 设置最大循环次数防止死循环
	for (int i = 0; i < 5000; i++) {
		std::cout << "\n[LOOP " << std::dec << i << "]" << std::endl;
		std::cout << std::hex;

		// 读取当前 LIST_ENTRY 的 Flink (指向下一个节点)
		uint64_t flink_addr = current_list_entry;
		uint64_t next_entry = 0;

		// 尝试读取 Flink 地址
		if (hypercall::read_guest_virtual_memory(
			&next_entry,
			flink_addr,
			system_cr3,
			sizeof(next_entry)
		) == 0) {
			std::cout << " ERROR: 无法读取 Flink 地址: 0x" << flink_addr << std::endl;
			break;
		}

		std::cout << "  当前链表节点 (Flink): 0x" << flink_addr << std::endl;
		std::cout << "  下一个链表节点 (Next Entry): 0x" << next_entry << std::endl;

		// 如果链表断了或回到起点，则结束
		if (next_entry == 0 || next_entry == ps_active_process_head_addr) {
			std::cout << " 链表遍历结束 (回到起点或断链)." << std::endl;
			break;
		}

		//计算 EPROCESS 的基地址
		// EPROCESS 基址 = LIST_ENTRY 地址 - ActiveProcessLinks 偏移量
		uint64_t eprocess_base = next_entry - Offsets::ActiveProcessLinks;
		std::cout << "  EPROCESS 基址: 0x" << eprocess_base << std::endl;

		// 读取这个进程的 PID
		uint64_t current_pid = 0;
		if (hypercall::read_guest_virtual_memory(
			&current_pid,
			eprocess_base + Offsets::UniqueProcessId,
			system_cr3,
			sizeof(current_pid)
		) == 0) {
			std::cout << " ERROR: 无法读取 PID (地址: 0x" << eprocess_base + Offsets::UniqueProcessId << ")" << std::endl;
			break;
		}

		// 进程 PID 经常只占用低 32 位，但读取 64 位也无妨。
		std::cout << "  读取到的 PID: " << std::dec << current_pid << std::endl;

		// 5. 找到目标 PID！读取它的 DirectoryTableBase (CR3)
		if (current_pid == target_pid) {
			uint64_t target_cr3 = 0;
			if (hypercall::read_guest_virtual_memory(
				&target_cr3,
				eprocess_base + Offsets::DirectoryTableBase,
				system_cr3,
				sizeof(target_cr3)
			) == 0) {
				std::cout << "找到 PID 但无法读取 CR3!" << std::endl;
				return 0;
			}
			std::cout << " 找到目标进程! CR3: 0x" << std::hex << target_cr3 << std::endl;
			return target_cr3;
		}

		// 继续下一个
		current_list_entry = next_entry;
	}

	std::cout << "\n--- 遍历结束，未找到 PID ---" << std::endl;
	return 0; // 未找到
}


// 辅助函数：查找指定 PID 的 EPROCESS 基地址
uint64_t FindProcessEProcessBase(uint64_t target_pid, uint64_t ps_active_process_head_addr) {
	const uint64_t SYSTEM_CR3_HARDCODED = 0x001ae000;
	uint64_t system_cr3 = SYSTEM_CR3_HARDCODED;
	uint64_t current_list_entry = ps_active_process_head_addr;

	for (int i = 0; i < 5000; i++) {
		uint64_t flink_addr = current_list_entry;
		uint64_t next_entry = 0;

		if (hypercall::read_guest_virtual_memory(&next_entry, flink_addr, system_cr3, sizeof(next_entry)) == 0) {
			return 0;
		}
		if (next_entry == 0 || next_entry == ps_active_process_head_addr) {
			break;
		}

		uint64_t eprocess_base = next_entry - Offsets::ActiveProcessLinks;
		uint64_t current_pid = 0;

		if (hypercall::read_guest_virtual_memory(&current_pid, eprocess_base + Offsets::UniqueProcessId, system_cr3, sizeof(current_pid)) == 0) {
			break;
		}

		if (current_pid == target_pid) {
			// 找到目标，返回 EPROCESS 基址
			return eprocess_base;
		}

		current_list_entry = next_entry;
	}
	return 0; // 未找到
}






uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const char* wanted_name) {
	if (!peb_address) return 0;

	// 读取 PEB -> Ldr
	uint64_t ldr_address = 0;
	hypercall::read_guest_virtual_memory(&ldr_address, peb_address + Offsets::Ldr, target_cr3, 8);
	if (!ldr_address) return 0;

	//获取 InLoadOrderModuleList 头节点
	// 头节点本身不包含 DLL 信息，它的 Flink 指向第一个模块
	uint64_t head_node = ldr_address + Offsets::InLoadOrderLinks;

	uint64_t current_node = 0;
	hypercall::read_guest_virtual_memory(&current_node, head_node, target_cr3, 8);

	int safety_check = 200;

	while (current_node != head_node && current_node != 0 && safety_check-- > 0) {
		//在 InLoadOrder 中，LDR_DATA_TABLE_ENTRY 的基址就是 current_node
		uint64_t entry_address = current_node;

		//读取 BaseDllName (UNICODE_STRING)
		UNICODE_STRING_RAW uStr = { 0 };
		hypercall::read_guest_virtual_memory(&uStr, entry_address + Offsets::BaseDllName, target_cr3, sizeof(UNICODE_STRING_RAW));

		if (uStr.Length > 0 && uStr.Buffer != 0) {
			// 读取实际的字符串内容 (宽字符)
			// 限制一下长度防止溢出，最大读 128 个字符 (256 字节)
			size_t read_len = (uStr.Length > 256) ? 256 : uStr.Length;
			std::vector<wchar_t> name_buf(read_len / 2 + 1);

			hypercall::read_guest_virtual_memory(name_buf.data(), uStr.Buffer, target_cr3, read_len);
			name_buf[read_len / 2] = 0; // 确保 0 结尾

			// 宽字符转普通 char 并转小写进行比较
			std::string current_name_str;
			for (wchar_t wc : name_buf) {
				if (wc == 0) break;
				current_name_str += (char)std::tolower(wc);
			}

			// 准备目标名字的小写版
			std::string wanted_lower = wanted_name;
			std::transform(wanted_lower.begin(), wanted_lower.end(), wanted_lower.begin(), ::tolower);

			// 5. 比较名字
			if (current_name_str == wanted_lower) {
				// 匹配成功！读取 DllBase
				uint64_t dll_base = 0;
				hypercall::read_guest_virtual_memory(&dll_base, entry_address + Offsets::DllBase, target_cr3, 8);
				return dll_base;
			}
		}

		// 6. 移动到下一个节点
		uint64_t next_node = 0;
		hypercall::read_guest_virtual_memory(&next_node, current_node, target_cr3, 8);
		current_node = next_node;
	}

	return 0;
}

uint64_t FindPebByCr3_Raw(uint64_t target_cr3, uint64_t ps_active_process_head_addr) {
	// 1. 自动获取 System CR3 (内核上下文)
	const uint64_t system_cr3 = hypercall::read_guest_cr3();

	std::cout << "\n--- CR3 反查 PEB 开始 ---" << std::endl;
	std::cout << "目标 CR3: 0x" << std::hex << target_cr3 << std::endl;
	std::cout << "链表头 (PsActiveProcessHead): 0x" << ps_active_process_head_addr << std::endl;
	std::cout << "当前 System CR3: 0x" << system_cr3 << std::endl;

	if (ps_active_process_head_addr == 0) {
		std::cout << "ERROR: 链表头地址无效" << std::endl;
		return 0;
	}

	// 2. 初始化遍历
	// ps_active_process_head_addr 本身是一个 LIST_ENTRY 结构
	// 我们从它指向的下一个节点开始遍历
	uint64_t current_list_entry = ps_active_process_head_addr;

	// 简单的死循环保护
	for (int i = 0; i < 5000; i++) {
		// 读取当前节点的 Flink (Next)
		uint64_t next_entry = 0;
		if (hypercall::read_guest_virtual_memory(
			&next_entry,
			current_list_entry,
			system_cr3,
			sizeof(next_entry)
		) == 0) {
			std::cout << "  ERROR: 读取链表节点失败: 0x" << current_list_entry << std::endl;
			break;
		}

		// 检查是否回到起点或断链
		if (next_entry == 0 || next_entry == ps_active_process_head_addr) {
			std::cout << "遍历结束" << std::endl;
			break;
		}

		// 计算 EPROCESS 基址
		// ActiveProcessLinks 位于 EPROCESS 内部，所以要减去偏移
		uint64_t eprocess_base = next_entry - Offsets::ActiveProcessLinks;

		// 读取当前进程的 DirectoryTableBase (CR3)
		uint64_t current_dirbase = 0;
		if (hypercall::read_guest_virtual_memory(
			&current_dirbase,
			eprocess_base + Offsets::DirectoryTableBase,
			system_cr3,
			sizeof(current_dirbase)
		) == 0) {
			// 读取失败通常意味着页面未映射，跳过
			current_list_entry = next_entry;
			continue;
		}

		// 关键比对：检查 CR3 是否匹配
		constexpr uint64_t PFN_MASK = ~0xFFFull;

		if ((current_dirbase & PFN_MASK) == (target_cr3 & PFN_MASK)) {
			std::cout << "     发现目标进程!" << std::endl;
			std::cout << "     EPROCESS: 0x" << eprocess_base << std::endl;
			std::cout << "     Found CR3: 0x" << current_dirbase << std::endl;

			// 6. 匹配成功，读取 PEB

			uint64_t target_peb = 0;
			if (hypercall::read_guest_virtual_memory(
				&target_peb,
				eprocess_base + Offsets::Peb,
				system_cr3,
				sizeof(target_peb)
			) != 0) {
				std::cout << "     PEB 地址: 0x" << target_peb << std::endl;
				return target_peb;
			}
			else {
				std::cout << "      ERROR: 无法读取 PEB" << std::endl;
				return 0;
			}
		}

		// 移动到下一个节点
		current_list_entry = next_entry;
	}

	std::cout << "--- 未找到匹配该 CR3 的进程 ---" << std::endl;
	return 0;
}



std::string GetRealNtoskrnlPath()
{
	char sysDir[MAX_PATH] = { 0 };
	GetSystemDirectoryA(sysDir, MAX_PATH);

	std::string path = std::string(sysDir) + "\\ntoskrnl.exe";

	return path;
}


void LogError(const std::string& funcName) {
	DWORD err = GetLastError();
	std::cerr << "[!] " << funcName << " 失败, Error Code: " << err << std::endl;
}

bool PreloadDebugLibraries(const std::string& dirPath) {
	std::string dbghelpPath = dirPath + "dbghelp.dll";
	std::string symsrvPath = dirPath + "symsrv.dll";

	std::cout << "[*] 尝试加载 DLL 路径: " << dirPath << std::endl;

	// symsrv 必须先加载，不然 dbghelp 可能会用系统默认的，导致解析符号失败
	HMODULE hSymSrv = LoadLibraryA(symsrvPath.c_str());
	HMODULE hDbgHelp = LoadLibraryA(dbghelpPath.c_str());

	if (hDbgHelp && hSymSrv) {
		std::cout << "[+] 自定义 DLL 加载成功。" << std::endl;
		return true;
	}
	else {
		if (!hSymSrv) std::cerr << "[!] 无法加载 symsrv.dll (路径: " << symsrvPath << ")" << std::endl;
		if (!hDbgHelp) std::cerr << "[!] 无法加载 dbghelp.dll (路径: " << dbghelpPath << ")" << std::endl;
		return false;
	}
}

bool InitSymbolEngine(HANDLE hProcess, const std::string& searchPath) {
	DWORD options = SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS;
	SymSetOptions(options);
	if (!SymInitialize(hProcess, searchPath.c_str(), FALSE)) {
		LogError("SymInitialize");
		return false;
	}
	return true;
}

std::string GetKernelImagePath() {
	char sysDir[MAX_PATH] = { 0 };
	GetSystemDirectoryA(sysDir, MAX_PATH);
	return std::string(sysDir) + "\\ntoskrnl.exe";
}

DWORD64 LoadKernelModule(HANDLE hProcess) {
	std::string ntosPath = GetKernelImagePath();
	std::cout << "[*] 正在加载内核镜像: " << ntosPath << std::endl;

	DWORD64 base = SymLoadModuleEx(
		hProcess,
		NULL,
		ntosPath.c_str(),
		NULL,
		0,
		0,
		NULL,
		0
	);

	if (base == 0) {
		LogError("SymLoadModuleEx");
	}
	else {
		std::cout << "[+] 模块加载基址 (Virtual): 0x" << std::hex << base << std::endl;
	}

	return base;
}


DWORD64 ResolveSymbolRVA(HANDLE hProcess, DWORD64 moduleBase, const std::string& symbolName) {
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
	PSYMBOL_INFO pSym = (PSYMBOL_INFO)buffer;

	pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSym->MaxNameLen = MAX_SYM_NAME;

	if (!SymFromName(hProcess, symbolName.c_str(), pSym)) {
		std::cerr << "[!] 找不到符号: " << symbolName << std::endl;
		LogError("SymFromName");
		return 0;
	}

	DWORD64 rva = pSym->Address - moduleBase;

	std::cout << "\n[RESULT] 符号解析成功: " << symbolName << std::endl;
	std::cout << "    > Virtual Address: 0x" << std::hex << pSym->Address << std::endl;
	std::cout << "    > Module Base:     0x" << std::hex << moduleBase << std::endl;
	std::cout << "    > RVA (Offset):    0x" << std::hex << rva << std::endl;

	return rva;
}


std::string GetCurrentExeDirectory() {
	char buffer[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, buffer, MAX_PATH);

	std::filesystem::path path(buffer);
	std::string dir = path.parent_path().string();

	if (!dir.empty() && dir.back() != '\\') {
		dir += "\\";
	}

	return dir;
}



