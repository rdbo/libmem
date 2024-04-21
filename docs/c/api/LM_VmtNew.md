# LM_VmtNew

```c
LM_API lm_bool_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmt_out);
```

# Description
The function creates a new VMT manager from the VMT at `vtable`.

# Parameters
 - `vtable`: The virtual method table to manage.
 - `vmt_out`: A pointer to the VMT manager that will be populated by this function.

# Return Value
On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
