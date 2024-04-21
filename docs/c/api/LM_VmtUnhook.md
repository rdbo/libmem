# LM_VmtUnhook

```c
LM_API lm_void_t LM_CALL
LM_VmtUnhook(lm_vmt_t *vmt,
	     lm_size_t fn_index);
```

# Description
The function `LM_VmtUnhook` unhooks the VMT function at index `fn_index` in the VMT managed by `vmt`,
restoring the original function.

# Parameters
 - `vmt`: The `vmt` parameter is a pointer to a valid VMT manager.
 - `fn_index`: The `fn_index` parameter is the index of the VMT function to unhook

# Return Value
The function does not return a value
