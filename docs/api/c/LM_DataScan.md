# LM_DataScan

```c
LM_API lm_address_t
LM_DataScan(lm_bytearr_t data,
        lm_size_t    size,
        lm_address_t addr,
        lm_size_t    scansize);
```

# Description

Searches for specific bytes in a memory region in the current process.

# Parameters

- data: the bytes to search for.
- size: the size of the `data`, in bytes.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns the address of the first match found. On failure, it returns `LM_ADDRESS_BAD`.

