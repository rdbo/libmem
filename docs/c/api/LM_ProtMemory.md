# LM_ProtMemory

```c
LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot_out);
```

# Description
The function sets memory protection flags for a specified memory address range.

# Parameters
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
The function returns a boolean value, either `LM_TRUE` or `LM_FALSE`, based on the
success of the memory protection operation.
