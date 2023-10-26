# Reflective Loading 
Reflective loading is a technique used to load a PE file without relying on the traditional Windows loader functions. Instead, it manually maps the PE file into memory, resolves imports, and executes it. This technique is commonly used in various security applications, such as malware analysis, penetration testing, and research.

## Usage

1. **Compilation**: Compile the C code using a C compiler such as GCC. Ensure you link against the necessary libraries, including `Dbghelp.lib` and `Kernel32.lib`. Example compilation command:

   ```bash
   gcc reflective_loader.c -o reflective_loader.exe -lDbghelp -lKernel32
   ```

2. **Run the Reflective Loader**: Once compiled, you can run the Reflective PE Loader by providing two command-line arguments:

    ```bash
    reflective_loader.exe <DLL Path> <Target Process Name>
    ```


- `<DLL Path>`: The path to the PE file (DLL) you want to load reflectively.
- `<Target Process Name>`: The name of the target process into which you want to reflectively load the DLL.

## Execution 
The reflective loader will perform the following steps:

- Memory map the provided PE file.
- Find and open the target process.
- Allocate memory within the target process for the PE file.
- Copy the PE file content into the remote process's memory space.
- Resolve necessary imports and adjust the PE headers.
- Execute the entry point of the loaded DLL reflectively.

## License

This code is provided under the [MIT License](./LICENSE). You are free to use, modify, and distribute it as needed. However, please keep in mind that this code is for educational purposes and should be used responsibly and in compliance with applicable laws.

## Disclaimer

This tool should be used for educational purposes and ethical tasks only. Unauthorized injection or reflective loading into processes can be illegal and harmful. Use with caution and ensure you have the necessary permissions and legal rights to perform such actions.





