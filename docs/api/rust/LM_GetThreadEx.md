# LM_GetThreadEx

```rust
pub fn LM_GetThreadEx(pproc : &lm_process_t) -> Option<lm_thread_t>
```

# Description

Gets information about a thread in a remote process.

# Parameters

- pproc: immutable reference to a valid process that will be searched for a thread

# Return Value

On success it returns `Some(thread)`, where `thread` is a valid `lm_thread_t`. On failure, it returns `None`.

