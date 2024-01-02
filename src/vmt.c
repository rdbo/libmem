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

#include "internal.h"

LM_PRIVATE lm_vmt_entry_t *
_LM_VmtSearch(const lm_vmt_t *pvmt,
	      lm_size_t       hkindex)
{
	lm_vmt_entry_t *entry = LM_NULLPTR;

	for (entry = pvmt->hkentries; entry != LM_NULLPTR; entry = entry->next) {
		if (entry->index == hkindex)
			break;
	}

	return entry;
}

LM_PRIVATE lm_vmt_entry_t *
_LM_VmtSearchPrev(lm_vmt_t       *pvmt,
		  lm_vmt_entry_t *next)
{
	lm_vmt_entry_t *entry = LM_NULLPTR;

	for (entry = pvmt->hkentries; entry != LM_NULLPTR; entry = entry->next) {
		if (entry->next == next)
			break;
	}

	return entry;
}

LM_API lm_void_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmtbuf)
{
	if (!vtable || !vmtbuf)
		return;

	vmtbuf->vtable = vtable;
	vmtbuf->hkentries = LM_NULLPTR;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *pvmt,
	   lm_size_t    fnindex,
	   lm_address_t dst)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *head;

	if (!pvmt)
		return LM_FALSE;

	/* check if the function has been hooked before; if not, create a new hook entry */
	if (!(entry = _LM_VmtSearch(pvmt, fnindex))) {
		entry = (lm_vmt_entry_t *)LM_MALLOC(sizeof(lm_vmt_entry_t));
		if (!entry)
			return LM_FALSE;

		entry->orig_func = pvmt->vtable[fnindex];
		entry->index = fnindex;

		/* append the new entry to the start of the list (easier than at the end, i guess) */
		head = pvmt->hkentries;
		entry->next = head;
		pvmt->hkentries = entry;
	}

	pvmt->vtable[fnindex] = dst;

	return LM_TRUE;
}

/********************************/

LM_API lm_void_t LM_CALL
LM_VmtUnhook(lm_vmt_t *pvmt,
	     lm_size_t fnindex)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *prev;

	if (!pvmt)
		return;

	entry = _LM_VmtSearch(pvmt, fnindex);

	if (!entry)
		return;

	pvmt->vtable[fnindex] = entry->orig_func;

	prev = _LM_VmtSearchPrev(pvmt, entry);
	if (prev) {
		prev->next = entry->next;
	} else {
		pvmt->hkentries = entry->next;
	}

	LM_FREE(entry);
}

/********************************/

LM_API lm_address_t LM_CALL
LM_VmtGetOriginal(const lm_vmt_t *pvmt,
		  lm_size_t       fnindex)
{
	lm_vmt_entry_t *entry;

	if (!pvmt)
		return LM_ADDRESS_BAD;

	entry = _LM_VmtSearch(pvmt, fnindex);
	if (entry)
		return entry->orig_func;

	return pvmt->vtable[fnindex];
}

/********************************/

LM_API lm_void_t LM_CALL
LM_VmtReset(lm_vmt_t *pvmt)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *next;

	if (!pvmt)
		return;

	for (entry = pvmt->hkentries; entry != LM_NULLPTR; entry = next) {
		pvmt->vtable[entry->index] = entry->orig_func;
		next = entry->next;
		LM_FREE(entry);
	}

	pvmt->hkentries = LM_NULLPTR;
}

/********************************/

LM_API lm_void_t LM_CALL
LM_VmtFree(lm_vmt_t *pvmt)
{
	LM_VmtReset(pvmt);
}

