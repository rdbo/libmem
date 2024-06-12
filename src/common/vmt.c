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
#include <assert.h>

lm_vmt_entry_t *
vmt_search(const lm_vmt_t *vmt, lm_size_t hkindex)
{
	lm_vmt_entry_t *entry;

	assert(vmt);

	for (entry = vmt->hkentries; entry != LM_NULLPTR; entry = entry->next) {
		if (entry->index == hkindex)
			break;
	}

	return entry;
}

/* TODO: Use doubly linked list to avoid having to search for the previous node */
lm_vmt_entry_t *
vmt_search_prev(lm_vmt_t *vmt, lm_vmt_entry_t *next)
{
	lm_vmt_entry_t *entry;

	for (entry = vmt->hkentries; entry != LM_NULLPTR; entry = entry->next) {
		if (entry->next == next)
			break;
	}

	return entry;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmt_out)
{
	if (!vtable || !vmt_out)
		return LM_FALSE;

	vmt_out->vtable = vtable;
	vmt_out->hkentries = LM_NULLPTR;

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *vmt,
	   lm_size_t    from_fn_index,
	   lm_address_t to)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *head;
	lm_prot_t old_prot;

	if (!vmt)
		return LM_FALSE;

	if (LM_ProtMemory((lm_address_t)&vmt->vtable[from_fn_index], sizeof(vmt->vtable[0]), LM_PROT_XRW, &old_prot) != LM_TRUE)
		return LM_FALSE;

	/* Check if the function has been hooked before; if not, create a new hook entry */
	if (!(entry = vmt_search(vmt, from_fn_index))) {
		entry = (lm_vmt_entry_t *)malloc(sizeof(lm_vmt_entry_t));
		if (!entry)
			return LM_FALSE;

		entry->orig_func = vmt->vtable[from_fn_index];
		entry->index = from_fn_index;

		/* Append the new entry to the start of the list */
		head = vmt->hkentries;
		entry->next = head;
		vmt->hkentries = entry;
	}

	vmt->vtable[from_fn_index] = to;
	LM_ProtMemory((lm_address_t)&vmt->vtable[from_fn_index], sizeof(vmt->vtable[0]), old_prot, LM_NULLPTR);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_VmtUnhook(lm_vmt_t *vmt,
	     lm_size_t fn_index)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *prev;
	lm_prot_t old_prot;

	if (!vmt)
		return LM_FALSE;

	if (LM_ProtMemory((lm_address_t)&vmt->vtable[fn_index], sizeof(vmt->vtable[0]), LM_PROT_XRW, &old_prot) != LM_TRUE)
		return LM_FALSE;

	entry = vmt_search(vmt, fn_index);
	if (!entry)
		return LM_TRUE;

	vmt->vtable[fn_index] = entry->orig_func;
	LM_ProtMemory((lm_address_t)&vmt->vtable[fn_index], sizeof(vmt->vtable[0]), old_prot, LM_NULLPTR);

	prev = vmt_search_prev(vmt, entry);
	if (prev) {
		prev->next = entry->next;
	} else {
		vmt->hkentries = entry->next;
	}

	free(entry);

	return LM_TRUE;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_VmtGetOriginal(const lm_vmt_t *vmt,
		  lm_size_t       fn_index)
{
	lm_vmt_entry_t *entry;

	if (!vmt)
		return LM_ADDRESS_BAD;

	entry = vmt_search(vmt, fn_index);
	if (entry)
		return entry->orig_func;

	return vmt->vtable[fn_index];
}

/********************************/

LM_API lm_void_t LM_CALL
LM_VmtReset(lm_vmt_t *vmt)
{
	lm_vmt_entry_t *entry;
	lm_vmt_entry_t *next;
	lm_prot_t old_prot;

	if (!vmt)
		return;

	/* TODO: Optimize VMT memory protection (not necessary to protect for each entry) */
	for (entry = vmt->hkentries; entry != LM_NULLPTR; entry = next) {
		LM_ProtMemory((lm_address_t)&vmt->vtable[entry->index], sizeof(vmt->vtable[0]), LM_PROT_XRW, &old_prot);

		vmt->vtable[entry->index] = entry->orig_func;
		next = entry->next;
		free(entry);

		LM_ProtMemory((lm_address_t)&vmt->vtable[entry->index], sizeof(vmt->vtable[0]), old_prot, LM_NULLPTR);
	}

	vmt->hkentries = LM_NULLPTR;
}

/********************************/

LM_API lm_void_t LM_CALL
LM_VmtFree(lm_vmt_t *vmt)
{
	LM_VmtReset(vmt);
}
