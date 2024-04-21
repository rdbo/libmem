# LM_EnumThreadsEx

```c
LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg);
```

# Description
Enumerates threads of a given process and invokes a callback
function for each thread.

# Parameters
 - `process`: The process you want to enumerate the threads from.
 - `callback`: The callback function that will receive the current
thread in the enumeration and an extra argument. This function
should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
to stop it.
 - `arg`: The user-defined data that can be passed to the callback
function. It allows you to provide additional information or
context to the callback function when iterating over threads in a
process.

# Return Value
The function `LM_EnumThreadsEx` returns a boolean value,
either `LM_TRUE` or `LM_FALSE`, depending on the success of the
operation.
