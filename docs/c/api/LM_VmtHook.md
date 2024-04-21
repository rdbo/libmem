# LM_VmtHook

```c
LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *vmt,
	   lm_size_t    from_fn_index,
	   lm_address_t to);
```

# Description
The function `LM_VmtHook` hooks the VMT function at index `from_fn_index` in the VMT managed by `vmt`,
changing it to `to`.

# Parameters
 - `vmt`: The `vmt` parameter is a pointer to a valid VMT manager.
 - `from_fn_index`: The `from_fn_index` parameter is the index of the VMT function to hook.
 - `to`: The `to` parameter is the pointer to the function that will replace the original VMT function.

# Return Value
On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
