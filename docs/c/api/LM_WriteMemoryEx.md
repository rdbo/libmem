# LM_WriteMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size);
```

# Description
Writes data from a source address to a destination address in a
specified process.

# Parameters
 - `process`: A pointer to a structure representing a process in the
system.
 - `dest`: The destination address in the target process where the
data from the `source` array will be written to.
 - `source`: A pointer to the data that needs to be written to the
memory of the target process.
 - `size`: The number of bytes to be written from the `source`
bytearray to the memory address specified by `dest`.

# Return Value
The number of bytes that were successfully written to the
destination address in the process's memory. If an error occurs
during the write operation, it returns 0.
