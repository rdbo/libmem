# LM_ProtMemoryEx

```c
LM_API lm_bool_t LM_CALL
LM_ProtMemoryEx(const lm_process_t *process,
		lm_address_t        address,
		lm_size_t           size,
		lm_prot_t           prot,
		lm_prot_t          *oldprot_out);
```

# Description
The function `LM_ProtMemoryEx` is used to modify memory protection flags for a specified address
range in a given process.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory flags will be modified from.
 - `address`: The `address` parameter represents the memory address to be protected or modified.
 - `size`: The `size` parameter in the `LM_ProtMemoryEx` function represents the size of memory to be
protected or modified. If the `size` parameter is set to 0, the function will default to using the
system's page size for the operation.
 - `prot`: The `prot` parameter in the `LM_ProtMemoryEx` function represents the new protection
flags that you want to apply to the memory region starting at the specified address. It is of
type `lm_prot_t`, which is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 - `oldprot_out`: The `oldprot_out` parameter in the `LM_ProtMemoryEx` function is a pointer to a
`lm_prot_t` type variable. This parameter is used to store the old protection flags of a memory
segment before they are updated with the new protection settings specified by the `prot` parameter.

# Return Value
The function `LM_ProtMemoryEx` returns a boolean value indicating whether the memory
protection operation was successful or not. It returns `LM_TRUE` if the operation was successful and
`LM_FALSE` if it was not.
