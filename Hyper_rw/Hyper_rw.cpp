#include "Hyper_rw.h"
#include "GetM.h"


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


const std::string SYMBOL_STORE_PATH = "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols";


struct SymbolCleaner {
	HANDLE hProc;
	SymbolCleaner(HANDLE h) : hProc(h) {}
	~SymbolCleaner() { SymCleanup(hProc); }
};


int main() {
	try {

		KernelCheatEngine engine;

		//获取内核基址解析PDB更新Offsets
		if (!engine.InitializeSystem()) {
			return 1;
		}


		uint64_t targetPid = 23608; // cs2 pid
		if (!engine.AttachToProcess(targetPid)) {
			return 0;
		}

		//查找目标模块
		if (engine.FindModule("client.dll")) {

			engine.Run();
		}

	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}