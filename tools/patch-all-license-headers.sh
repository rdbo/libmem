#!/bin/sh

patch_script="$(pwd)/tools/patch-license-header.sh"

if [ ! -f "$patch_script" ]; then
    echo "run from the project root directory"
    exit 1
fi

function patch_dir_files {
    for f in $(find "$1" -type f); do
        echo "patching ${f}..."
        $patch_script "$f"
    done
}

function patch_dirs {
    for d in $@; do
        patch_dir_files "$d"
    done
}

patch_dirs "include" "src" "bindings"
