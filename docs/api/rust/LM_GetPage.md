# LM_GetPage

```rust
pub fn LM_GetPage(addr : lm_address_t) -> Option<lm_page_t>
```

# Description

Gets a page in the calling process from a virtual address.

# Parameters

- addr: the virtual address that the page will be looked up from.

# Return Value

On success, it returns `Some(page)`, where `page` is a valid `lm_page_t`. On failure, it returns `None`.

