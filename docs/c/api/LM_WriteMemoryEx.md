# LM_WriteMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size);
```

# Description
The function `LM_WriteMemoryEx` writes data from a source bytearray to a destination address in a
specified process.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory will be written to.
 - `dest`: The `dest` parameter in the `LM_WriteMemoryEx` function represents the destination
address in the target process where the data from the `source` array will be written to.
 - `source`: The `source` parameter in the `LM_WriteMemoryEx` is used to provide
the data that needs to be written to the memory of the target process.
 - `size`: The `size` parameter in the `LM_WriteMemoryEx` function represents the number of bytes
to be written from the `source` bytearray to the memory address specified by `dest`. It indicates
the size of the data to be written in bytes.

# Return Value
The function `LM_WriteMemoryEx` returns the number of bytes that were successfully written
to the destination address in the process's memory. If an error occurs during the write operation,
it returns `0`.
