#!/bin/bash

error=0
tests=$(find build/tests -type f -executable -name "unit*")

for test in $tests; do
    echo "Running $test"
    strace $test
    if [ $? -ne 0 ]; then
        error=$((error + $?))
    fi
done

mkdir -p build/coverage
cd build

gcovr -r ../src --html --html-details -o build/coverage/index.html --verbose

exit $error
