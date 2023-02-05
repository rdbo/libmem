#!/bin/sh

mv liblibmem.a liblibmem_partial.a

if [ ! -f ./libcapstone.a ]; then
	ln -s capstone-engine-prefix/src/capstone-engine-build/libcapstone.a ./libcapstone.a
fi
if [ ! -f ./libkeystone.a ]; then
	ln -s keystone-engine-prefix/src/keystone-engine-build/llvm/lib/libkeystone.a ./libkeystone.a
fi
if [ ! -f ./libLIEF.a ]; then
	ln -s lief-project-prefix/src/lief-project-build/libLIEF.a ./libLIEF.a
fi
ar -M << EOM
	CREATE liblibmem.a
	ADDLIB liblibmem_partial.a
	ADDLIB libcapstone.a
	ADDLIB libkeystone.a
	ADDLIB libLIEF.a
	SAVE
	END
EOM
