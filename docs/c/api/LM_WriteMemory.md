# LM_WriteMemory

```c
LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size);
```

# Description
Writes data from a source address to a destination address in memory.

# Parameters
 - `dest`: The destination memory address where the data from the
`source` array will be written to.
 - `source`: A pointer to the data that needs to be written to the
memory starting at the destination address `dest`.
 - `size`: The number of bytes to be written from the `source`
array to the memory starting at the `dest` address.

# Return Value
The number of bytes written to the destination memory
address.
