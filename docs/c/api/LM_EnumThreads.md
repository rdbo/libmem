# LM_EnumThreads

```c
LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					     lm_void_t   *arg),
	       lm_void_t          *arg);
```

# Description
Enumerates threads in the current process and calls a callback
function for each thread found.

# Parameters
 - `callback`: The callback function that will receive the current
thread in the enumeration and an extra argument. This function
should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
to stop it.
 - `arg`: The user-defined data structure that will be passed to
the callback function `callback` during thread enumeration. This
allows you to pass additional information or context to the
callback function if needed.

# Return Value
The function `LM_EnumThreads` returns a boolean value of
type `lm_bool_t`, containing `LM_TRUE` if it succeeds, or
`LM_FALSE` if it fails.
