# LM_EnumThreads

```rust
pub fn LM_EnumThreads() -> Option<Vec<lm_thread_t>>
```

# Description

Enumerates all the threads in the calling processes, returning them on a vector.

#  Return Value

On success, it returns a `Some(thread_list)`, where `thread_list` is a vector containing all valid threads; On failure, it returns `None`.

