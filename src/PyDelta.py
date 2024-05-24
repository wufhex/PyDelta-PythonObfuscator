# Author: WolfHex
# Last Update: 5/25/24 1:40 AM

# PyDelta v0.1.0 
# Annotation string references are currently broken

from anti_debugger import AddAntiDebugger
from code_compressor_and_encryptor import CodeCompressorAndEncryptor
from ids_refactor import RefactorNames
from import2inlineimport import ImportToInlineImport
from string_encryption import StringEncryptor

from dataclasses import dataclass

@dataclass
class ObfuscationConfig:
    add_anti_dbg: bool = True
    inline_imports: bool = True
    refactor_names: bool = True
    encrypt_str: bool = True
    compress_encrypt: bool = True
    str_encryption_amount: int = 3
    compress_encrypt_amount: int = 30

def __run_obfuscation(source_code, config: ObfuscationConfig):
    name_refactor = RefactorNames()
    str_refactor = StringEncryptor()
    imp_2_inline_imp = ImportToInlineImport()
    anti_dbg = AddAntiDebugger()
    comp_n_comp = CodeCompressorAndEncryptor()

    refactor_in_compression_cap = 3  # Cap to avoid over-encrypting strings in the code encryption

    if config.add_anti_dbg:
        source_code = anti_dbg.add_anti_debugger_code(source_code)

    if config.inline_imports:
        source_code = imp_2_inline_imp.imports_to_inline_imports(source_code)

    for _ in range(config.str_encryption_amount):
        if config.encrypt_str:
            source_code = str_refactor.find_and_encrypt_strings(source_code)

        if config.refactor_names:
            source_code = name_refactor.refactor_code(source_code)

    refactor_in_compression_count = 0
    for _ in range(config.compress_encrypt_amount):
        if config.compress_encrypt:
            source_code = comp_n_comp.encrypt_and_compress_code(source_code)

        if refactor_in_compression_count > refactor_in_compression_cap:
            if config.encrypt_str:
                source_code = str_refactor.find_and_encrypt_strings(source_code)
                refactor_in_compression_count += 1

        if config.refactor_names:
            source_code = name_refactor.refactor_code(source_code)

    return source_code

def run_obfuscation(source_code, config: ObfuscationConfig = ObfuscationConfig()):
    try:
        result = __run_obfuscation(source_code, config)
        return result
    except Exception as e:
        return f"Error: {str(e)}"