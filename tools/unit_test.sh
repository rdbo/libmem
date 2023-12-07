#!/bin/bash

error=0
tests=$(find build/tests -type f -executable -name "unit*")

for test in $tests; do
    echo "Running $test"
    $test
    if [ $? -ne 0 ]; then
        error=$((error + $?))
    fi
done

mkdir -p build/coverage

source_files=$(find src -name "*.c")

for source_file in $source_files; do
    echo "Processing gcov for $source_file"
    gcov "$source_file".c
done

gcovr -r . --html --html-details -o build/coverage/index.html

exit $error
