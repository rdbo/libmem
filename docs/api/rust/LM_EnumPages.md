# LM_EnumPages

```rust
pub fn LM_EnumPages() -> Option<Vec<lm_page_t>>
```

# Description

Enumerates all the pages in the calling process, returning them on a vector.

# Return Value

On success, it returns a `Some(page_list)`, where `page_list` is a vector containing all valid pages; On failure, it returns `None`.

