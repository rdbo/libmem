#include "TestDLL.h"
#include <iostream>

void Function1() {
    std::cout << "Function1 called." << std::endl;
}

int Function2(int value) {
    std::cout << "Function2 called with value: " << value << std::endl;
    return value * 2;
}
