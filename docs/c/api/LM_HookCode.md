# LM_HookCode

```c
LM_API lm_size_t LM_CALL
LM_HookCode(lm_address_t  from,
	    lm_address_t  to,
	    lm_address_t *trampoline_out);
```

# Description
The function `LM_HookCode` places a hook/detour onto the address `from`, redirecting it to the address `to`.
Optionally, it generates a trampoline in `trampoline_out` to call the original function.

# Parameters
 - `from`: The `from` parameter is the address where the hook will be placed.
 - `to`: The `to` parameter is the address where the hook will jump to.
 - `trampoline_out`: Optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the original function.

# Return Value
On success, it returns the amount of bytes occupied by the hook (aligned to the nearest instruction). On failure, it returns `0`.
