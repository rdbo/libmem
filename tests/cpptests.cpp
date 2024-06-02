#include <libmem/libmem.hpp>
#include <iostream>

int main()
{
	auto processes = lm::enum_processes().value();
	for (auto process: processes) {
		std::cout << process.to_string() << std::endl;
	}
	
	auto process = lm::find_process("st").value();
	std::cout << process.to_string() << std::endl;
	return 0;
}
