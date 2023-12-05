#!/bin/bash

error=0
for test in $(find build/tests -type f -executable); do
    echo "Running $test"
    $test
    if [ $? -ne 0 ]; then
        error+=$?
    fi
done

gcovr -r . --html --html-details -o coverage.html

exit $error
