# LM_DataScanEx

```python
def LM_DataScanEx(pproc : lm_process_t, data : bytearray, addr : int, scansize : int)
```

# Description

Searches for specific bytes in a memory region in a remote process.

# Parameters

- pproc: valid process which will be searched.
- data: the bytes to search for.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns a valid `lm_address_t` containing the first match found. On failure, it returns `None`.

