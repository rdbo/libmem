# LM_FindSegmentEx

```c
LM_API lm_bool_t LM_CALL
LM_FindSegmentEx(const lm_process_t *process,
		 lm_address_t        address,
		 lm_segment_t       *segment_out);
```

# Description
The function `LM_FindSegment` searches for a memory segment that a given address is within and populates the
`segment_out` parameter with the result.

# Parameters
 - `process`: A pointer to a structure containing information about the process whose memory
segments will be searched.
 - `address`: The address to search for.
 - `segment_out`: A pointer to an `lm_segment_t` structure to populate with information about the
segment that contains the specified address.

# Return Value
The function returns `LM_TRUE` if the specified address is found within a segment, or `LM_FALSE` otherwise.
