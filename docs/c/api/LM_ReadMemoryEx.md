# LM_ReadMemoryEx

```c
LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size);
```

# Description
The function `LM_ReadMemoryEx` reads memory from a process and returns the number of bytes read.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the memory will be read from.
 - `source`: The `source` parameter in the `LM_ReadMemoryEx` function represents the starting
address in the target process from which you want to read memory. It is of type `lm_address_t`,
which is a memory address in the target process's address space.
 - `dest`: The `dest` parameter in the `LM_ReadMemoryEx` function is a pointer to the destination
buffer where the memory read operation will store the data read from the specified source address.
 - `size`: The `size` parameter in the `LM_ReadMemoryEx` function represents the number of bytes to
read from the memory location specified by the `source` address. It indicates the amount of data
that should be read from the source address and copied into the destination buffer pointed to by the
`dest`

# Return Value
The function `LM_ReadMemoryEx` returns the number of bytes successfully read from the
specified memory address in the target process. If an error occurs during the read operation, it
returns `0`.
