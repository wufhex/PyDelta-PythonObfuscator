# Author: WolfHex
# Last Update: 5/25/24 12:09 AM

# PyDelta v 0.1.0 
# Annotation string references are currently broken

from anti_debugger import AddAntiDebugger
from code_compressor_and_encryptor import CodeCompressorAndEncryptor
from ids_refactor import RefactorNames
from import2inlineimport import ImportToInlineImport
from string_encryption import StringEncryptor

def __run_obfuscation(source_code, add_anti_dbg, inline_imports, refactor_names, encrypt_str, compress_encrypt, str_refactor_amount, compress_encrypt_amount):
	name_refactor 	 = RefactorNames()
	str_refactor 	 = StringEncryptor()
	imp_2_inline_imp = ImportToInlineImport()
	anti_dbg 		 = AddAntiDebugger()
	comp_n_comp 	 = CodeCompressorAndEncryptor()
 
	str_refactor_cap = 5
	compress_encrypt_cap = 255
	refactor_in_compression_cap = 3

	if str_refactor_amount > str_refactor_cap:
		return f"String refactor amount exceeded, cap is set to {str_refactor_cap}"

	if compress_encrypt_amount > compress_encrypt_cap:
		return f"Code encryption amount exceeded, cap is set to {compress_encrypt_cap}"

	if add_anti_dbg:
		source_code = anti_dbg.add_anti_debugger_code(source_code)

	if inline_imports:
		source_code	= imp_2_inline_imp.imports_to_inline_imports(source_code)

	for _ in range(str_refactor_amount):
		if encrypt_str:
			source_code = str_refactor.find_and_encrypt_strings(source_code)

		if refactor_names:
			source_code = name_refactor.refactor_code(source_code)
	
	refactor_in_compression_count = 0
	for _ in range(compress_encrypt_amount):
		if compress_encrypt:
			source_code = comp_n_comp.encrypt_and_compress_code(source_code)
  
		if refactor_in_compression_count > refactor_in_compression_cap:
			if encrypt_str:
				source_code = str_refactor.find_and_encrypt_strings(source_code)
				refactor_in_compression_count += 1

		if refactor_names:
			source_code = name_refactor.refactor_code(source_code)
   
	return source_code

def run_obfuscation(source_code, add_anti_dbg=True, inline_imports=True, refactor_names=True, encrypt_str=True, compress_encrypt=True, str_encryption_amount=3, compress_encrypt_amount=30):
	try:
		result = __run_obfuscation(source_code, add_anti_dbg, inline_imports, refactor_names, encrypt_str, compress_encrypt, str_encryption_amount, compress_encrypt_amount)
		return result
	except Exception as e:
		return f"Error: {str(e)}"