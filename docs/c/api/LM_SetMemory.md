# LM_SetMemory

```c
LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size);
```

# Description
Sets a specified memory region to a given byte value.

# Parameters
 - `dest`: The destination memory address where the `byte` value will
be written to, starting from this address.
 - `byte`: The value of the byte that will be written to the memory
locations starting from the `dest` address.
 - `size`: The number of bytes to set in the memory starting from
the `dest` address.

# Return Value
The number of bytes that were successfully set to the
specified value `byte` in the memory region starting at address
`dest`.
