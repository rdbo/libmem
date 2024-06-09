#include <libmem/libmem.hpp>
#include <iostream>
#include <valarray>

void separator()
{
	std::cout << "--------------------------------" << std::endl;
}

int main()
{
	std::cout << "[*] Process Enumeration: " << std::endl;
	auto processes = LM::EnumProcesses().value();
	for (auto process: std::vector(processes.begin(), processes.begin() + 3)) {
		std::cout << " - " << process.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto process: std::vector(processes.end() - 3, processes.end())) {
		std::cout << " - " << process.to_string() << std::endl;
	}

	separator();

	auto cur_process = LM::GetProcess().value();
	std::cout << "[*] Current Process: " << cur_process.to_string() << std::endl;

	separator();

	std::cout << "[*] Current Process (by PID): " << LM::GetProcess(cur_process.pid).value().to_string() << std::endl;

	separator();
	
	auto process = LM::FindProcess("target").value();
	std::cout << "[*] Target Process: " << process.to_string() << std::endl;

	separator();

	std::cout << "[*] Is Target Process Alive? " << (LM::IsProcessAlive(&process) ? "Yes" : "No") << std::endl;

	separator();

	std::cout << "[*] Bits: " << LM::GetBits() << std::endl;
	std::cout << "[*] System Bits: " << LM::GetSystemBits() << std::endl;

	separator();

	std::cout << "[*] Thread Enumeration: " << std::endl;
	auto threads = LM::EnumThreads().value();

	for (auto thread: threads) {
		std::cout << " - " << thread.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Remote Thread Enumeration: " << std::endl;
	threads = LM::EnumThreads(&process).value();

	for (auto thread: threads) {
		std::cout << " - " << thread.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Current Thread: " << LM::GetThread().value().to_string() << std::endl;

	separator();

	auto thread = LM::GetThread(&process).value();
	std::cout << "[*] Remote Thread: " << thread.to_string() << std::endl;

	separator();

	std::cout << "[*] Remote Thread Owner Process: " << LM::GetThreadProcess(&thread).value().to_string() << std::endl;

	separator();

	return 0;
}
