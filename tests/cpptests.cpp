#include <libmem/libmem.hpp>
#include <iostream>

int main()
{
	auto processes = LM::EnumProcesses().value();
	for (auto process: processes) {
		std::cout << process.to_string() << std::endl;
	}
	
	auto process = LM::FindProcess("st").value();
	std::cout << process.to_string() << std::endl;
	return 0;
}
