# LM_DataScan

```python
def LM_DataScan(data : bytearray : data : bytearray, addr : int : addr : int, scansize : int : scansize : int) -> Optional[None]:
```

# Description

Searches for specific bytes in a memory region in the current process.

# Parameters

- data: the bytes to search for.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns a valid address (`int`) containing the first match found. On failure, it returns `None`.

