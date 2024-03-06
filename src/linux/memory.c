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

#include <libmem/libmem.h>
#include <sys/uio.h>

LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size)
{
	struct iovec iosrc;
	struct iovec iodst;
	ssize_t rdsize;

	if (!process || source == LM_ADDRESS_BAD || !dest || size == 0)
		return 0;

	/* TODO: Consider replacing this technique, because casting to `void *`
	 *       prevents reading from a 64 bit process as a 32 bit process */
	iodst.iov_base = (void *)dest;
	iodst.iov_len  = size;
	iosrc.iov_base = (void *)source;
	iosrc.iov_len  = size;
	rdsize = process_vm_readv((pid_t)process->pid, &iodst, 1, &iosrc, 1, 0);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size)
{
	struct iovec iosrc;
	struct iovec iodst;
	ssize_t wrsize;

	if (!process || dest == LM_ADDRESS_BAD || !source || size == 0)
		return 0;

	iosrc.iov_base = (void *)source;
	iosrc.iov_len = size;
	iodst.iov_base = (void *)dest;
	iodst.iov_len = size;
	wrsize = process_vm_writev((pid_t)process->pid, &iosrc, 1, &iodst, 1, 0);

	if (wrsize == -1)
		return 0;

	return (lm_size_t)wrsize;
}
