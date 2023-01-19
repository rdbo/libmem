# LM_GetProcess

```rust
pub fn LM_GetProcess() -> Option<lm_process_t>
```

# Description

Gets information about the calling process

# Return Value

On success it returns `Some(process)`, where `process` is a valid `lm_process_t`. On failure, it returns `None`.

