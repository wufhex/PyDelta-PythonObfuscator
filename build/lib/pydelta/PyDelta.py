# Author: WolfHex
# Last Update: 5/25/24 1:40 AM

# PyDelta v0.1.0 
# Annotation string references are currently broken

import argparse

from dataclasses import dataclass

from .anti_debugger import AddAntiDebugger
from .code_compressor_and_encryptor import CodeCompressorAndEncryptor
from .ids_refactor import RefactorNames
from .import2inlineimport import ImportToInlineImport
from .string_encryption import StringEncryptor

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

def delta_obfuscate(source_code, config: ObfuscationConfig = ObfuscationConfig()):
	try:
		result = __run_obfuscation(source_code, config)
		return result
	except Exception as e:
		raise Exception(f"An error occurred: {str(e)}")
	
def obfuscate_cli():
	parser = argparse.ArgumentParser(description='Obfuscate source code with specified configuration.')

	parser.add_argument('input_file', type=str, help='Path to the input source code file.')
	parser.add_argument('output_file', type=str, help='Path to the output file where obfuscated code will be saved.')
	
	parser.add_argument('--no-add-anti-dbg', action='store_false', help='Disables add anti-debugging measures.')
	parser.add_argument('--no-inline-imports', action='store_false', help='Disable inline imports conversion.')
	parser.add_argument('--no-refactor-names', action='store_false', help='Disables refactoring variable, function and args names.')
	parser.add_argument('--no-encrypt-str', action='store_false', help='Disables encrypting strings.')
	parser.add_argument('--no-compress-encrypt', action='store_false', help='Disables compression and encryption of the code.')
	parser.add_argument('--str-encryption-amount', type=int, default=3, help='Amount of times to encrypt strings.')
	parser.add_argument('--compress-encrypt-amount', type=int, default=30, help='Amount of times to compress and encrypt the code.')

	args = parser.parse_args()

	try:
		with open(args.input_file, 'r') as infile:
			source_code = infile.read()
	except Exception as e:
		raise Exception(f"Could not read input file: {str(e)}")
	
	config = ObfuscationConfig(
		add_anti_dbg=args.no_add_anti_dbg,
		inline_imports=args.no_inline_imports,
		refactor_names=args.no_refactor_names,
		encrypt_str=args.no_encrypt_str,
		compress_encrypt=args.no_compress_encrypt,
		str_encryption_amount=args.str_encryption_amount,
		compress_encrypt_amount=args.compress_encrypt_amount
	)

	obfuscated_code = delta_obfuscate(source_code, config)
	
	try:
		with open(args.output_file, 'w') as outfile:
			outfile.write(obfuscated_code)
	except Exception as e:
		raise Exception(f"Could not write to file: {str(e)}")