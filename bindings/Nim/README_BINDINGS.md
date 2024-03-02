# libmem Nim Bindings

This README provides information on how to integrate and use the Nim bindings for the `libmem` C library in your Nim projects. These bindings allow Nim applications to leverage the functionality of `libmem`, a C library, with ease. The bindings were primarily generated using Futhark and subsequently refined for better integration and usage in Nim.

## Quick Start

To use the `libmem` bindings in your Nim project, follow these simple steps:

1. **Include the Nim Wrapper**: Copy the `release/nimlibmem.nim` file into your project directory. This file contains the necessary Nim wrapper code to interact with the `libmem` C library.

2. **Add the DLL**: Place the `libmem.dll` from the `src` directory into an appropriate location in your project. Typically, this would be alongside your binary executables or within a directory that's included in your system's PATH environment variable.

3. **Adjust the DLL Path**: Depending on your project's structure, you may need to adjust the path to `libmem.dll` within the `release/nimlibmem.nim` file to ensure the library is correctly loaded at runtime.

## Testing

Comprehensive tests have been created and are located in the `tests` directory. These tests verify the functionality and correctness of the bindings. To run the tests, navigate to the `tests` directory and execute the test scripts using your preferred Nim testing approach.

## Generating Bindings (Coming Soon)

Documentation on how to generate the bindings yourself will be provided soon. This will offer insights into the process of generating Nim bindings from C libraries using Futhark, including steps to refine and adapt the generated code for optimal use in Nim projects.

## Contributions

Contributions to the `libmem` Nim bindings are welcome. Whether it's improving the wrapper, adding more tests, or enhancing documentation, your input is valuable. Please submit pull requests or open issues on the project's repository to contribute.

## License

The `libmem` Nim bindings are distributed under the same license as the `libmem` C library. Please refer to the license file in the root directory for more information.

## Acknowledgements

Special thanks to the developers of Futhark for providing the tooling that facilitated the generation of these bindings, and to all contributors who have refined and tested the bindings to ensure they meet the needs of Nim developers.
And also thank you, @Rdbo, for the original C library.
