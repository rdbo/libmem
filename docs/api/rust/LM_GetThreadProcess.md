# LM_GetThreadProcess

```rust
pub fn LM_GetThreadProcess(pthr : &lm_thread_t) -> Option<lm_process_t>
```

# Description

Gets an `lm_process_t` from an `lm_thread_t`. It is especially useful when you want to interact with a specific thread of a process.

# Parameters

- pthr: immutable reference to a valid `lm_thread_t` that will be used to find a process.

# Return Value

On success it returns `Some(process)`, where `process` is a valid `lm_process_t`. On failure, it returns `None`.

