# LM_DataScanEx

```rust
pub fn LM_DataScanEx(pproc : &lm_process_t, data : &[lm_byte_t], addr : lm_address_t, scansize : lm_size_t) -> Option<lm_address_t>
```

# Description

Searches for specific bytes in a memory region in a remote process.

# Parameters

- pproc: immutable reference to a valid process that will be searched.
- data: the bytes to search for.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns `Some(address)`, where `address` is a valid `lm_address_t` containing the first match found. On failure, it returns `None`.

