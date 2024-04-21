# LM_SetMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size);
```

# Description
The function `LM_SetMemoryEx` sets a specified memory region to a given byte value in a target process.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory will be set to.
 - `dest`: The `dest` parameter is the destination memory address where the `byte` value will be
written to, starting from this address.
 - `byte`: The `byte` parameter in the `LM_SetMemoryEx` function represents the value of the byte
that will be written to the memory locations starting from the `dest` address.
 - `size`: The `size` parameter in the `LM_SetMemoryEx` function represents the number of bytes to
set in the memory starting from the `dest` address. It specifies the size of the memory block that
will be filled with the specified `byte` value.

# Return Value
The function `LM_SetMemoryEx` returns a value of type `lm_size_t`, which represents the size
of the memory that was successfully written. If there are any errors or invalid parameters, it
returns `0`.
