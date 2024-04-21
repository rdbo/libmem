# LM_ReadMemory

```c
LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size);
```

# Description
The function `LM_ReadMemory` reads memory from a source address and copies it to a destination
address.

# Parameters
 - `source`: The `source` parameter is of type `lm_address_t`, which represents the memory address
from which data will be read.
 - `dest`: The `dest` parameter in the `LM_ReadMemory` function is a pointer to a memory location
where the data read from the source address will be stored.
 - `size`: The `size` parameter in the `LM_ReadMemory` function represents the number of bytes to
read from the memory starting at the `source` address and write into the `dest` buffer. It specifies
the size of the memory block to be read.

# Return Value
The function `LM_ReadMemory` returns the number of bytes read from memory.
