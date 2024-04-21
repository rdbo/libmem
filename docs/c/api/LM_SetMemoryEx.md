# LM_SetMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size);
```

# Description
Sets a specified memory region to a given byte value in a target
process.

# Parameters
 - `process`: A pointer to the process that the memory will be set.
 - `dest`: The destination address in the target process where the
`byte` value will be written to.
 - `byte`: The value of the byte that will be written to the memory
locations starting from the `dest` address.
 - `size`: The number of bytes to set in the memory starting from
the `dest` address.

# Return Value
The number of bytes that were successfully set to the
specified value `byte` in the memory region starting at address
`dest` in the target process. If there are any errors, it returns 0.
