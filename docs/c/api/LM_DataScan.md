# LM_DataScan

```c
LM_API lm_address_t LM_CALL
LM_DataScan(lm_bytearray_t data,
	    lm_size_t      datasize,
	    lm_address_t   address,
	    lm_size_t      scansize);
```

# Description
The function `LM_DataScan` scans a specified memory address range for a specific data pattern and
returns the address where the pattern is found.

# Parameters
 - `data`: The `data` parameter is a byte array containing the data to be scanned for in memory.
 - `datasize`: The `datasize` parameter in the `LM_DataScan` function represents the size of the
data array that you are searching for within the memory range specified by `address` and `scansize`.
It indicates the number of bytes that need to match consecutively in order to consider it a match.
 - `address`: The `address` parameter in the `LM_DataScan` function represents the starting memory
address where the scanning operation will begin. The function will scan a range of memory starting
from this address to find the data.
 - `scansize`: The `scansize` parameter in the `LM_DataScan` function represents the size of the
memory region to scan starting from the specified `address`. It determines the range within which
the function will search for a match with the provided `data` array.

# Return Value
The function `LM_DataScan` returns an `lm_address_t` value, which represents the memory
address where a match for the provided data was found. If no match is found, it returns the value
`LM_ADDRESS_BAD`.
