# LM_VmtHook

```c
LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *vmt,
	   lm_size_t    from_fn_index,
	   lm_address_t to);
```

# Description
The function hooks the VMT function at index `from_fn_index` in the VMT managed by `vmt`,
changing it to `to`.

# Parameters
 - `vmt`: The VMT manager.
 - `from_fn_index`: The index of the VMT function to hook.
 - `to`: The function that will replace the original VMT function.

# Return Value
On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
