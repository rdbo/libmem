#!/bin/sh

mv libmem.a libmem_partial.a
ln -s capstone-engine-prefix/src/capstone-engine-build/libcapstone.a ./libcapstone.a
ln -s keystone-engine-prefix/src/keystone-engine-build/llvm/lib/libkeystone.a ./libkeystone.a
ln -s lief-project-prefix/src/lief-project-build/libLIEF.a ./libLIEF.a
ar -M << EOM
	CREATE libmem.a
	ADDLIB libmem_partial.a
	ADDLIB libcapstone.a
	ADDLIB libkeystone.a
	ADDLIB libLIEF.a
	SAVE
	END
EOM
