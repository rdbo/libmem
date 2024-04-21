# LM_EnumSegmentsEx

```c
LM_API lm_bool_t LM_CALL
LM_EnumSegmentsEx(const lm_process_t *process,
                  lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
						lm_void_t    *arg),
		  lm_void_t          *arg);
```

# Description
Enumerates the memory segments of a given process and invokes a callback function for each segment.

# Parameters
 - `process`: A pointer to a structure containing information about the process whose segments
will be enumerated.
 - `callback`: A function pointer that will receive each segment in the enumeration and an extra argument.
The callback function should return `LM_TRUE` to continue the enumeration or `LM_FALSE` to stop it.
 - `arg`: A pointer to user-defined data that can be passed to the callback function.
It allows you to provide additional information or context to the callback function when iterating over segments.

# Return Value
The function returns `LM_TRUE` if the enumeration was successful, or `LM_FALSE` otherwise.
