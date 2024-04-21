# LM_ReadMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size);
```

# Description
Reads memory from a process and returns the number of bytes read.

# Parameters
 - `process`: A pointer to the process that the memory will be read from.
 - `source`: The starting address in the target process from which
you want to read memory.
 - `dest`: A pointer to the destination buffer where the memory read
operation will store the data read from the specified source address.
 - `size`: The number of bytes to read from the memory location
specified by the `source` address.

# Return Value
The number of bytes successfully read from the specified
memory address in the target process. If an error occurs during the
read operation, it returns 0.
