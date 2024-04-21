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
The function modifies memory protection flags for a specified address range in a given
process.

# Parameters
 - `process`: A pointer to the process that the memory flags will be modified from.
 - `address`: The memory address to be protected.
 - `size`: The size of memory to be protected. If the size is 0,
the function will default to using the system's page size for the operation.
 - `prot`: The new protection flags that will be applied to the memory region
starting at the specified address. It is a bit mask of `LM_PROT_X`
(execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 - `oldprot_out`: A pointer to a `lm_prot_t` type variable that will be used to
store the old protection flags of a memory segment before they are updated with
the new protection settings specified by the `prot` parameter.

# Return Value
The function returns a boolean value indicating whether the memory
protection operation was successful or not. It returns `LM_TRUE` if the
operation was successful and `LM_FALSE` if it was not.
