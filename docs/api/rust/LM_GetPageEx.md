# LM_GetPageEx

```rust
pub fn LM_GetPageEx(pproc : &lm_process_t, addr : lm_address_t) -> Option<lm_page_t>
```

# Description

Gets a page in a remote process from a virtual address.

# Parameters

- pproc: immutable reference to a valid process which the page will be taken from.
- addr: the virtual address that the page will be looked up from.

# Return Value

On success, it returns `Some(page)`, where `page` is a valid `lm_page_t`. On failure, it returns `None`.

