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

#include "posixutils.h"
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mman.h>

size_t
get_system_bits()
{
	size_t bits = sizeof(void *) * 8; /* Assumes system bits == pointer size by default */
	struct utsname utsbuf;
	const char *machines64[] = { "x86_64", "amd64", "aarch64" };
	size_t machines64_len = sizeof(machines64) / sizeof(machines64[0]);
	size_t i;

	if (uname(&utsbuf))
		return bits;

	for (i = 0; i < machines64_len; ++i) {
		if (!strcmp(utsbuf.machine, machines64[i])) {
			bits = 64;
			break;
		}
	}

	return bits;
}

size_t
get_name_from_path(char *path, char *namebuf, size_t namesize)
{
	char *last_separator;
	char *name;
	size_t namelen;

	assert(path != NULL && namebuf != NULL && namesize > 0);

	last_separator = strrchr(path, '/');

    /* if forwardslash not found, check for windows path */
	if (last_separator == NULL) {
        last_separator = strrchr(path, '\\');
    }

    if (last_separator == NULL) {
        name = path;
    } else {
		name = &last_separator[1]; /* 'name' starts at 'last path separator + 1' */
    }
	namelen = strlen(name);

	/* Truncate name if necessary */
	if (namelen >= namesize)
		namelen = namesize - 1;

	strncpy(namebuf, name, namelen);
	namebuf[namelen] = '\0';

	return namelen;
}

int
get_os_prot(lm_prot_t prot)
{
	int osprot = 0;
	prot = (prot & LM_PROT_XRW);

	if (prot & LM_PROT_X)
		osprot |= PROT_EXEC;
	if (prot & LM_PROT_R)
		osprot |= PROT_READ;
	if (prot & LM_PROT_W)
		osprot |= PROT_WRITE;

	return osprot;
}

lm_prot_t
get_prot(int osprot)
{
	lm_prot_t prot = 0;

	osprot = (osprot & (PROT_EXEC | PROT_READ | PROT_WRITE));

	if (osprot & PROT_EXEC)
		prot |= LM_PROT_X;
	if (osprot & PROT_READ)
		prot |= LM_PROT_R;
	if (osprot & PROT_WRITE)
		prot |= LM_PROT_W;

	return prot;
}
