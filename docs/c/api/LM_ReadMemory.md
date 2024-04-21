# LM_ReadMemory

```c
LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size);
```

# Description
Reads memory from a source address and copies it to a destination
address.

# Parameters
 - `source`: The memory address from which data will be read.
 - `dest`: A pointer to a memory location where the data read from the
source address will be stored.
 - `size`: The number of bytes to read from the memory starting at the
source address and write into the dest buffer.

# Return Value
The number of bytes read from memory.
