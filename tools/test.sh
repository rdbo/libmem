#!/bin/bash

error=0
tests=$(find build/tests -type f -executable -name "test*" -o -name "unit*")

for test in $tests; do
    echo "Running $test"
    $test
    if [ $? -ne 0 ]; then
        error=$((error + $?))
    fi
done

gcovr -r . --html --html-details -o coverage.html

exit $error
