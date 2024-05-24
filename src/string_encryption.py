import ast
import os
import base64
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Cryptography was used because it seems to work faster with pyscript and left here
# pycryptodome seems to be faster and safer locally

class StringEncryptor:
	def __init__(self):
		self.encrypted_strings = []
		
		# 								string		  				  key			 			   iv
		self.obfstr_var_id = ['_________lithium_________', '_________carbon_________', '_________hydrogen_________']
		
	def encrypt_string(self, s):
		key = os.urandom(32)
		iv = os.urandom(16)

		# Encrypting string
		padder = padding.PKCS7(algorithms.AES.block_size).padder()
		padded_data = padder.update(s.encode('utf-8')) + padder.finalize()

		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

		# Encoding encrypted data key and iv
		encoded_string = base64.b64encode(encrypted_data).decode('utf-8')
		key = base64.b64encode(key).decode('utf-8')
		iv = base64.b64encode(iv).decode('utf-8')

		return encoded_string, key, iv
		
	
	# This function adds a lambda function called __bb01 to the code which is used to decrypt
	# the encrypted strings, its intentionally obfuscated but it
	# basically reverses what the encrypt_string function does
	def find_and_encrypt_strings(self, code):
		tree = ast.parse(code)
		transformer = StringTransformer(self.encrypt_string, self.encrypted_strings, self.obfstr_var_id)
		new_tree = transformer.visit(tree)
		
		# Arrays to contains assignments
		encstr_assignment_arr = []
		key_assignment_arr = []
		iv_assignment_arr = []
	
		# For every encrypted string key and iv enumerate them and add a new variable to the code
		for i, (encrypted_string, key, iv) in enumerate(transformer.encrypted_strings, start=1):
			encstr_assignment = ast.Assign(
				targets=[ast.Name(id=self.obfstr_var_id[0] + str(i), ctx=ast.Store())],
				value=ast.Constant(encrypted_string)
			)
			key_assignment = ast.Assign(
				targets=[ast.Name(id=self.obfstr_var_id[1] + str(i), ctx=ast.Store())],
				value=ast.Constant(key)
			)
			iv_assignment = ast.Assign(
				targets=[ast.Name(id=self.obfstr_var_id[2] + str(i), ctx=ast.Store())],
				value=ast.Constant(iv)
			)
			
			# Appeand them to the assignments array
			encstr_assignment_arr.append(encstr_assignment)
			key_assignment_arr.append(key_assignment)
			iv_assignment_arr.append(iv_assignment)
		
		# Shuffle the variable order in the code
		random.shuffle(encstr_assignment_arr)
		random.shuffle(key_assignment_arr)
		random.shuffle(iv_assignment_arr)
		
		# Insert the shuffled variables to the code
		for encrypted_string, key, iv in zip(encstr_assignment_arr, key_assignment_arr, iv_assignment_arr):
			new_tree.body.insert(0, encrypted_string)
			new_tree.body.insert(0, key)
			new_tree.body.insert(0, iv)
		
		ast.fix_missing_locations(new_tree)
		
		# Add decryption and settostring code
		with open('runtime_code/SetToString.py', 'r') as file1:
			set2str = file1.read()

		with open('runtime_code/StringDecryptCode.py', 'r') as file2:
			str_dec_code = file2.read()
		
		new_code = ast.unparse(new_tree)
		new_code = f"{set2str}\n{str_dec_code}\n{new_code}"
		return new_code

class StringTransformer(ast.NodeTransformer):
	def __init__(self, encrypt_string, encrypted_strings, obf_var_id):
		self.obfstr_var_id = obf_var_id
		self.encrypt_string = encrypt_string
		self.encrypted_strings = encrypted_strings
		self.decrypt_func_name = "__bb01"
		self.set_unpacker_func_name = "__rfs"
		self.str_len_cap = 2048
		self.in_del_method = False
  
	def visit_FunctionDef(self, node):
		if node.name == "__del__":
			self.in_del_method = True
			self.generic_visit(node)
			self.in_del_method = False
		else:
			self.generic_visit(node)
		return node

	# Adds a call to the decryptor functiona and references the encrypted strings keys and iv variables
	def visit_Constant(self, node):
		if isinstance(node.value, str) and not self.in_del_method:
			original_string = node.value
			# String length check
			if len(original_string) >= self.str_len_cap:
				return node

			encrypted_string, key, iv = self.encrypt_string(original_string)
			self.encrypted_strings.append((encrypted_string, key, iv))
			enc_var = ast.Name(id=self.obfstr_var_id[0] + str(len(self.encrypted_strings)), ctx=ast.Load())
			key_var = ast.Name(id=self.obfstr_var_id[1] + str(len(self.encrypted_strings)), ctx=ast.Load())
			iv_var = ast.Name(id=self.obfstr_var_id[2] + str(len(self.encrypted_strings)), ctx=ast.Load())
			return ast.Call(
				func=ast.Name(id=self.decrypt_func_name, ctx=ast.Load()),
				args=[enc_var, key_var, iv_var],
				keywords=[]
			)
		return node

	# Convert every f-string into a plus concatenated string, this also transforms
	# variables become sets so thats why we need the settostr function
	def visit_JoinedStr(self, node):
		if self.in_del_method:
			return self.generic_visit(node)

		new_values = []
		for value in node.values:
			if isinstance(value, ast.Constant):
				new_values.append(ast.Constant(value=value.value))
			else:
				new_values.append(ast.Call(
					func=ast.Name(id=self.set_unpacker_func_name, ctx=ast.Load()),
					args=[value],
					keywords=[]
				))

		concat_expr = new_values[0]
		for val in new_values[1:]:
			concat_expr = ast.BinOp(left=concat_expr, op=ast.Add(), right=val)

		return self.visit(concat_expr)