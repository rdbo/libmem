/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "demangler.h"
#include <string>
#include <assert.h>
#include <stdlib.h>
#include <llvm/Demangle/Demangle.h>

extern "C" char *
demangle(const char *symbol_name, char *demangled_buf, size_t demangled_size)
{
	std::string demangled;

	assert(symbol_name != NULL && (demangled_buf == NULL || demangled_size > 0));

	demangled = llvm::demangle(symbol_name);
	if (demangled.length() == 0)
		return NULL;

	if (!demangled_buf) {
		demangled_size = demangled.length() + 1;
		demangled_buf = (char *)calloc(sizeof(char), demangled_size);
	}

	snprintf(demangled_buf, demangled_size, "%s", demangled.c_str());

	return demangled_buf;
}
