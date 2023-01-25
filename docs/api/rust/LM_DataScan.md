# LM_DataScan

```rust
pub unsafe fn LM_DataScan(data : &[lm_byte_t], addr : lm_address_t, scansize : lm_size_t) -> Option<lm_address_t>
```

# Description

Searches for specific bytes in a memory region in the current process.

# Parameters

- data: the bytes to search for.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns `Some(address)`, where `address` is a valid `lm_address_t` containing the first match found. On failure, it returns `None`.

