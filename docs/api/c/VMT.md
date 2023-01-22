# VMT

```c
LM_API lm_void_t
LM_VmtNew(lm_address_t *vtable,
      lm_vmt_t     *vmtbuf);

LM_API lm_bool_t
LM_VmtHook(lm_vmt_t    *pvmt,
       lm_size_t    fnindex,
       lm_address_t dst);

LM_API lm_void_t
LM_VmtUnhook(lm_vmt_t *pvmt,
         lm_size_t fnindex);

LM_API lm_address_t
LM_VmtGetOriginal(lm_vmt_t *pvmt,
          lm_size_t fnindex);

LM_API lm_void_t
LM_VmtReset(lm_vmt_t *pvmt);

LM_API lm_void_t
LM_VmtFree(lm_vmt_t *pvmt);
```

# Description

APIs to interact with Virtual Method Tables (VMTs) from OOP objects.

- `LM_VmtNew`: Creates a new VMT manager from the VMT at `vtable` into `vmtbuf`.
- `LM_VmtHook`: Hooks the VMT function at index `fnindex`, changing it to `dst`.
- `LM_VmtUnhook`: Unhooks the VMT function at index `fnindex`.
- `LM_VmtReset`: Resets all the VMT functions back to their original addresses.
- `LM_VmtFree`: Frees the VMT manager, restoring everything.

