# LM_GetThreadProcess

```rust
def LM_GetThreadProcess(pthr : lm_thread_t : pthr : lm_thread_t) -> Optional[None]:
```

# Description

Gets an `lm_process_t` from an `lm_thread_t`. It is especially useful when you want to interact with a specific thread of a process.

# Parameters

- pthr: valid `lm_thread_t` that will be used to find a process.

# Return Value

On success it returns a valid `lm_process_t`. On failure, it returns `None`.

