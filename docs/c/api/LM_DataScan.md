# LM_DataScan

```c
LM_API lm_address_t LM_CALL
LM_DataScan(lm_bytearray_t data,
	    lm_size_t      datasize,
	    lm_address_t   address,
	    lm_size_t      scansize);
```

# Description
The function scans a specified memory address range for a specific data
pattern and returns the address where the data is found.

# Parameters
 - `data`: The data to be scanned for in memory.
 - `datasize`: The size of the data array. It indicates the number of
bytes that need to match consecutively in order to consider it a match.
 - `address`: The starting memory address where the scanning operation
will begin. The function will scan a range of memory starting from this
address to find the data.
 - `scansize`: The size of the memory region to scan starting from the
specified `address`. It determines the range within which the function will
search for a match with the provided `data` array.

# Return Value
The function returns the memory address where a match for the
provided data was found. If no match is found, it returns
`LM_ADDRESS_BAD`.
