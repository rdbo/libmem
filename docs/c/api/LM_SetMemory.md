# LM_SetMemory

```c
LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size);
```

# Description
The function `LM_SetMemory` sets a specified memory region to a given byte value.

# Parameters
 - `dest`: The `dest` parameter is the destination memory address where the `byte` value will be
written to, starting from this address.
 - `byte`: The `byte` parameter in the `LM_SetMemory` function represents the value of the byte
that will be written to the memory locations starting from the `dest` address.
 - `size`: The `size` parameter in the `LM_SetMemory` function represents the number of bytes to
set in the memory starting from the `dest` address. It specifies the size of the memory block that
will be filled with the specified `byte` value.

# Return Value
The function `LM_SetMemory` returns the number of bytes that were successfully set to the
specified value `byte` in the memory region starting at address `dest`.
