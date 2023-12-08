#!/bin/bash

error=0
tests=$(find build/tests -type f -executable -name "unit*")

for test in $tests; do
    target=$(find build/tests -type f -executable -name "target*")
    echo "Running $target"
    ./$target &

    echo "Running $test"
    $test
    if [ $? -ne 0 ]; then
        error=$((error + $?))
    fi
    
    pkill -f "$target"
done

mkdir -p build/coverage

gcda_files=$(find src -name "*.gcda")

for gcda_file in $gcda_files; do
    echo "Processing gcov for $gcda_file"
    gcov "$gcda_file"
done

gcovr -r . --html --html-details -o build/coverage/index.html

exit $error
