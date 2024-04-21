# LM_EnumProcesses

```c
LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg);
```

# Description
Enumerates processes on a system and calls a callback function for each process found.

# Parameters
 - `callback`: The callback function that will receive the current
process in the enumeration and an extra argument. This function
should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
to stop it.
 - `arg`: The user-defined data structure that will be passed to the
callback function along with the `lm_process_t` structure.

# Return Value
`LM_TRUE` on success, or `LM_FALSE` on failure.
