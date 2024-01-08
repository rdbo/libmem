# LM_PatternScanEx

```python
def LM_PatternScanEx(pproc : lm_process_t : pproc : lm_process_t, pattern : bytearray : pattern : bytearray, mask : str : mask : str, addr : int : addr : int, scansize : int : scansize : int) -> Optional[None]:
```

# Description

Searches for specific bytes with a mask filter in a memory region in a remote process.

# Parameters

- pproc: valid process which will be searched.
- pattern: the bytes to search for (it is common practice to leave unknown bytes as 0).
- mask: a mask filter to apply to the pattern. Use 'x' for a known byte and '?' for an unknown byte. Example: `"xxxx???x?xxx"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns a valid address (`int`) containing the first match found. On failure, it returns `None`.

