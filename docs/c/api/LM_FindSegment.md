# LM_FindSegment

```c
LM_API lm_bool_t LM_CALL
LM_FindSegment(lm_address_t  address,
	       lm_segment_t *segment_out);
```

# Description
The function `LM_FindSegment` searches for a memory segment that a given address is within and populates the
`segment_out` parameter with the result.

# Parameters
 - `address`: The `address` parameter is of type `lm_address_t`, which is used to specify a memory
address to search for.
 - `segment_out`: The `segment_out` parameter is a pointer to a `lm_segment_t` structure. This
function `LM_FindSegment` takes an address and populates the `segment_out` structure with
information about the segment that contains that address.

# Return Value
The function returns `LM_TRUE` if the enumeration was successful or `LM_FALSE` if it failed.
