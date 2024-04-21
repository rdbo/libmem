# LM_WriteMemory

```c
LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size);
```

# Description
The LM_WriteMemory function writes data from a source array to a destination address in memory.

# Parameters
 - `dest`: The `dest` parameter in the `LM_WriteMemory` function represents the destination memory
address where the data from the `source` array will be written to.
 - `source`: The `source` parameter in the `LM_WriteMemory` function is used to provide the
data that needs to be written to the memory starting at the destination address `dest`.
 - `size`: The `size` parameter in the `LM_WriteMemory` function represents the number of bytes to
be written from the `source` array to the memory starting at the `dest` address. It specifies the
size of the data to be copied from the source array to the destination memory location.

# Return Value
The function `LM_WriteMemory` returns the number of bytes written to the destination memory
address.
