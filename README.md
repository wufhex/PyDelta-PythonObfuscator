# PyDelta

PyDelta is a Python script designed to obfuscate Python source code, making it more difficult to understand and reverse-engineer.

## Features:
* Anti-Debugger: Adds anti-debugger code to the source to deter debugging attempts.
* Code Compression and Encryption: Compresses and encrypts the code to make it harder to analyze.
* String Encryption: Encrypts strings within the code to prevent easy extraction of sensitive information.
* Inline Imports: Converts imports to inline imports to reduce readability.
* Name Refactoring: Refactors variable and function names to further obfuscate the code.

## Usage:
PyDelta was intended to run in a browser but it is indeed possible to run it locally.

### Example Usage:
```py
from PyDelta import run_obfuscation

source_code = """
# Your Python source code here
print('Hello')
"""

obfuscated_code = run_obfuscation(source_code)
print(obfuscated_code)
```
Or you can use the online version [here](https://wolfhex.com/pydelta)

### Parameters:
* source_code: Source code to obfuscate
* add_anti_dbg: Whether to add anti-debugger code (default: True).
* inline_imports: Whether to convert imports to inline imports (default: True).
* refactor_names: Whether to refactor variable and function names (default: True).
* encrypt_str: Whether to encrypt strings in the code (default: True).
* compress_encrypt: Whether to compress and encrypt the entire code (default: True).
* str_encryption_amount: Number of times to encrypt strings (default: 3).
* compress_encrypt_amount: Number of times to compress and encrypt the code (default: 30).

### Notes
* This version of PyDelta is still in development and some features may not be fully functional.
* Python's `__annotations__` attribute is broken and will be fixed in future releases.

### License
This project is licensed under the MIT License.

### Donating
MetaMask wallet address: `0x1E5a982BD1E54d3CD4EcD7A74642ed808783D506`

<a href='https://ko-fi.com/D1D3NTABI' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>