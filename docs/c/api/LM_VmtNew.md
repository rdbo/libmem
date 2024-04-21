# LM_VmtNew

```c
LM_API lm_bool_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmt_out);
```

# Description
The function `LM_VmtNew` creates a new VMT manager from the VMT at `vtable` into `vmt_out`.

# Parameters
 - `vtable`: The `vtable` parameter is a pointer to the VMT array to manage.
 - `vmt_out`: The `vmt_out` parameter is a pointer to an uninitialized `lm_vmt_t` structure that will receive the VMT manager.

# Return Value
On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
