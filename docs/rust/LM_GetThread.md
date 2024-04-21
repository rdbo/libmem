# LM_GetThread

```rust
pub fn LM_GetThread() -> Option<lm_thread_t>
```

# Description

Gets information about the calling thread.

# Return Value

On success it returns `Some(thread)`, where `thread` is a valid `lm_thread_t`. On failure, it returns `None`.

