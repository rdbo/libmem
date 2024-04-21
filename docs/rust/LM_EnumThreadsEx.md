# LM_EnumThreadsEx

```rust
pub fn LM_EnumThreadsEx(pproc : &lm_process_t) -> Option<Vec<lm_thread_t>>
```

# Description

Enumerates all the threads in a remote process, returning them on a vector.

# Parameters

- pproc: immutable reference to a valid process that will be searched for threads.

#  Return Value

On success, it returns a `Some(thread_list)`, where `thread_list` is a vector containing all valid threads; On failure, it returns `None`.

