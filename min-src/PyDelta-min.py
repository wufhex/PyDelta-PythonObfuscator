import ast
import os
import zlib
import gzip
import random
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class Reserved:
    reserved_init_names = [
        "__init__",
        "__del__",
        "__repr__",
        "__str__",
        "__len__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__iter__",
        "__next__",
        "__call__",
    ]
    
class RuntimeCode:
	dec_code = """__bb01 = (lambda f: lambda x, y, z: f(f)(x, y, z))(lambda f: lambda x, y, z: __import__('Crypto.Util.Padding', fromlist=['unpad']).unpad(__import__('Crypto.Cipher', fromlist=['AES']).AES.new(__import__('base64').b64decode(y), __import__('Crypto.Cipher', fromlist=['AES']).AES.MODE_CBC, __import__('base64').b64decode(z)).decrypt(__import__('base64').b64decode(x)), __import__('Crypto.Cipher', fromlist=['AES']).AES.block_size).decode('utf-8'))"""
	decompressor = """___=lambda x, k, i: __import__('zlib').decompress(__import__('gzip').decompress(__import__('Crypto.Cipher.AES',fromlist="new").new(__import__('base64').b64decode(k),__import__('Crypto.Cipher',fromlist="AES").AES.MODE_CBC,__import__('base64').b64decode(i)).decrypt(__import__('base64').b64decode(x))[:-__import__('Crypto.Cipher.AES',fromlist="new").new(__import__('base64').b64decode(k),__import__('Crypto.Cipher',fromlist="AES").AES.MODE_CBC,__import__('base64').b64decode(i)).decrypt(__import__('base64').b64decode(x))[-1]]))"""
	set_to_string = """__rfs = (lambda f: lambda a: str(f(f)(a)))(lambda f: lambda a: next(iter(a)))"""
	anti_debug = """_ = lambda: (exit() if (('Microsoft' in __import__('platform').release() or 'hyperv' in __import__('platform').release() or 'VMware' in __import__('platform').release() or 'vmware' in __import__('platform').version() or 'VirtualBox' in __import__('platform').release() or 'VirtualBox' in __import__('platform').version() or 'Xen' in __import__('platform').release() or 'xen' in __import__('platform').version()) or __import__('sys').gettrace() is not None) else (exit() if (__import__('platform').system() == 'Windows' and __import__('ctypes').windll.kernel32.IsDebuggerPresent()) else (exit() if (__import__('platform').system() == 'Darwin' and __import__('ctypes').cdll.LoadLibrary(None).ptrace(31, 0, 0, 0) == 0) else (exit() if (__import__('platform').system() == 'Linux' and 'TracerPid:\t0' not in open('/proc/self/status').read()) else (exit() if any(process.name() in ["ida64.exe", "ida.exe", "x64dbg.exe", "x86dbg.exe", "windbg.exe", "ollydbg.exe", "ollydbg64.exe", "immunitydebugger.exe", "dbg.exe", "gdb.exe", "gdb", "lldb.exe", "lldb"] for process in __import__('psutil').process_iter(['name'])) else None)))));_()"""

class RandomUtil:
	@staticmethod
	def generate_random_string(length=32):
		rnd_str = ''.join(random.choice(['I', 'l']) for _ in range(length))
		return rnd_str

class NameVisitor(ast.NodeVisitor):
	def __init__(self):
		self.funcs = set()
		self.classes = set()
		self.args = set()
		self.local_vars = set()
		self.self_attrs = set()
		self.decorated_funcs = set()
		self.class_attrs = {}

	def visit_FunctionDef(self, node):
		if not node.decorator_list:
			if node.name not in Reserved.reserved_init_names:
				self.funcs.add(node.name)
		else:
			self.decorated_funcs.add(node.name)
		self._extract_args(node)
		self.generic_visit(node)

	def visit_AsyncFunctionDef(self, node):
		if not node.decorator_list:
			if node.name not in Reserved.reserved_init_names:
				self.funcs.add(node.name)
		else:
			self.decorated_funcs.add(node.name)
		self._extract_args(node)
		self.generic_visit(node)

	def visit_ClassDef(self, node):
		self.classes.add(node.name)
		self.class_attrs[node.name] = set()
		for stmt in node.body:
			if isinstance(stmt, ast.Assign):
				for target in stmt.targets:
					if isinstance(target, ast.Name):
						self.class_attrs[node.name].add(target.id)
		self.generic_visit(node)

	def visit_Name(self, node):
		if isinstance(node.ctx, (ast.Store, ast.Param)):
			self.local_vars.add(node.id)
		self.generic_visit(node)

	def visit_Attribute(self, node):
		if isinstance(node.value, ast.Name):
			if node.value.id == 'self':
				self.self_attrs.add(node.attr)
			elif node.value.id in self.classes and node.attr in self.class_attrs.get(node.value.id, set()):
				self.local_vars.add(node.attr)
		self.generic_visit(node)

	def _extract_args(self, node):
		if node.args.args:
			for arg in node.args.args:
				if arg.arg != "self":
					self.args.add(arg.arg)
		if node.args.kwonlyargs:
			for arg in node.args.kwonlyargs:
				self.args.add(arg.arg)
		if node.args.vararg:
			self.args.add(node.args.vararg.arg)
		if node.args.kwarg:
			self.args.add(node.args.kwarg.arg)
			
class RefactorNames:
	def __init__(self):
		self.mapping = {}
		self.decorated_funcs = set()

	def refactor_code(self, source_code):
		parsed = ast.parse(source_code)
		visitor = NameVisitor()
		visitor.visit(parsed)
		self.decorated_funcs = visitor.decorated_funcs
		self.class_attrs = visitor.class_attrs
		for name_set in [visitor.funcs, visitor.classes, visitor.args, visitor.local_vars, visitor.self_attrs]:
			for name in name_set:
				new_name = RandomUtil.generate_random_string()
				self.mapping[name] = new_name

		return self._replace_identifiers(parsed)

	def _replace_identifiers(self, node):
		if isinstance(node, ast.Name):
			if node.id in self.mapping:
				node.id = self.mapping[node.id]
		elif isinstance(node, ast.Attribute):
			if isinstance(node.value, ast.Name) and node.value.id == 'self' and node.attr in self.mapping:
				node.attr = self.mapping[node.attr]
			elif isinstance(node.value, ast.Name) and node.value.id in self.class_attrs:
				if node.attr in self.mapping:
					node.attr = self.mapping[node.attr]
		elif isinstance(node, ast.arg):
			if node.arg in self.mapping:
				node.arg = self.mapping[node.arg]
		elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
			if node.name in self.mapping and node.name not in self.decorated_funcs:
				node.name = self.mapping[node.name]
			for arg in node.args.args:
				if arg.arg in self.mapping:
					arg.arg = self.mapping[arg.arg]
		elif isinstance(node, ast.ClassDef):
			if node.name in self.mapping:
				node.name = self.mapping[node.name]
			for base in node.bases:
				self._replace_identifiers(base)
			for keyword in node.keywords:
				self._replace_identifiers(keyword)
			for stmt in node.body:
				if isinstance(stmt, ast.Assign):
					for target in stmt.targets:
						if isinstance(target, ast.Name) and target.id in self.mapping:
							target.id = self.mapping[target.id]
		for child in ast.iter_child_nodes(node):
			self._replace_identifiers(child)
		return ast.unparse(node)
	
class StringEncryptor:
	def __init__(self):
		self.encrypted_strings = []
		self.obfstr_var_id = ['_________lithium_________', '_________carbon_________', '_________hydrogen_________']
		
	def encrypt_string(self, s):
		key = os.urandom(32)
		iv = os.urandom(16)

		padder = padding.PKCS7(algorithms.AES.block_size).padder()
		padded_data = padder.update(s.encode('utf-8')) + padder.finalize()

		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()
		encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

		encoded_string = base64.b64encode(encrypted_data).decode('utf-8')
		key = base64.b64encode(key).decode('utf-8')
		iv = base64.b64encode(iv).decode('utf-8')

		return encoded_string, key, iv
		
	def find_and_encrypt_strings(self, code):
		tree = ast.parse(code)
		transformer = StringTransformer(self.encrypt_string, self.encrypted_strings, self.obfstr_var_id)
		new_tree = transformer.visit(tree)
		
		encstr_assignment_arr = []
		key_assignment_arr = []
		iv_assignment_arr = []
	
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
			
			encstr_assignment_arr.append(encstr_assignment)
			key_assignment_arr.append(key_assignment)
			iv_assignment_arr.append(iv_assignment)
		
		random.shuffle(encstr_assignment_arr)
		random.shuffle(key_assignment_arr)
		random.shuffle(iv_assignment_arr)
		
		for encrypted_string, key, iv in zip(encstr_assignment_arr, key_assignment_arr, iv_assignment_arr):
			new_tree.body.insert(0, encrypted_string)
			new_tree.body.insert(0, key)
			new_tree.body.insert(0, iv)
		
		ast.fix_missing_locations(new_tree)
		
		new_code = ast.unparse(new_tree)
		new_code = f"{RuntimeCode.set_to_string}\n{RuntimeCode.dec_code}\n{new_code}"
		return new_code

class StringTransformer(ast.NodeTransformer):
	def __init__(self, encrypt_string, encrypted_strings, obf_var_id):
		self.obfstr_var_id = obf_var_id
		self.encrypt_string = encrypt_string
		self.encrypted_strings = encrypted_strings
		self.decrypt_func_name = "__bb01"
		self.set_unpacker_func_name = "__rfs"
		self.str_len_cap = 1024
		self.in_del_method = False

	def visit_FunctionDef(self, node):
		if node.name == "__del__":
			self.in_del_method = True
			self.generic_visit(node)
			self.in_del_method = False
		else:
			self.generic_visit(node)
		return node

	def visit_Constant(self, node):
		if isinstance(node.value, str) and not self.in_del_method:
			original_string = node.value
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

class ImportTransformer(ast.NodeTransformer):
	def __init__(self):
		self.imports = {}
		self.star_imports = {}
		super().__init__()
  
	def visit_Import(self, node):
		for alias in node.names:
			self.imports[alias.asname or alias.name] = alias.name
		return None

	def visit_ImportFrom(self, node):
		if node.names[0].name == '*':
			return node
		else:
			module = node.module
			for alias in node.names:
				name = alias.name
				asname = alias.asname or name
				self.imports[asname] = f'{module}.{name}'
		return None

	def visit_Name(self, node):
		if node.id in self.imports:
			full_import_path = self.imports[node.id]
			module, _, attr = full_import_path.rpartition('.')
			if module:
				new_node = ast.Attribute(
					value=ast.Call(
						func=ast.Name(id='__import__', ctx=ast.Load()),
						args=[ast.Constant(value=module)],
						keywords=[ast.keyword(arg='fromlist', value=ast.List(elts=[ast.Constant(value=attr)], ctx=ast.Load()))]
					),
					attr=attr,
					ctx=node.ctx
				)
			else:
				new_node = ast.Call(
					func=ast.Name(id='__import__', ctx=ast.Load()),
					args=[ast.Constant(value=full_import_path)],
					keywords=[]
				)
			return ast.copy_location(new_node, node)
		elif node.id in self.star_imports:
			module = self.star_imports[node.id]
			new_node = ast.Attribute(
				value=ast.Call(
					func=ast.Name(id='__import__', ctx=ast.Load()),
					args=[ast.Constant(value=module)],
					keywords=[ast.keyword(arg='fromlist', value=ast.List(elts=[ast.Constant(value=node.id)], ctx=ast.Load()))]
				),
				attr=node.id,
				ctx=node.ctx
			)
			return ast.copy_location(new_node, node)
		return self.generic_visit(node)

	def visit_Attribute(self, node):
		node.value = self.visit(node.value)
		return node
	
class ImportToInlineImport:
	@staticmethod
	def imports_to_inline_imports(code):
		tree = ast.parse(code)
		transformer = ImportTransformer()
		transformed_tree = transformer.visit(tree)
		ast.fix_missing_locations(transformed_tree)
		return ast.unparse(transformed_tree)

class AddAntiDebugger:
	@staticmethod
	def add_anti_debugger_code(code):  
		return f"{RuntimeCode.anti_debug}\n{code}"

class CodeCompressorAndEncryptor:
	def __init__(self):
		self.decompressor_func_name = "___"
		self.data_var_ids = ["___asteroid___", "___bomb___", "___fire___"]
  
	def encrypt_and_compress_code(self, code):
		zlib_compressed_code = zlib.compress(bytes(code, 'utf-8'))
		gzip_compressed_code = gzip.compress(zlib_compressed_code)
		
		aes_key = os.urandom(32)
		aes_iv = os.urandom(16)

		padder = padding.PKCS7(algorithms.AES.block_size).padder()
		gzip_compressed_code_padded = padder.update(gzip_compressed_code) + padder.finalize()

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
		encryptor = cipher.encryptor()
		encrypted_code = encryptor.update(gzip_compressed_code_padded) + encryptor.finalize()

		encrypted_code_b64 = base64.b64encode(encrypted_code).decode()
		aes_key_b64 = base64.b64encode(aes_key).decode()
		aes_iv_b64 = base64.b64encode(aes_iv).decode()
		
		dec_code = RuntimeCode.decompressor
		
		dec_code += f"\n{self.data_var_ids[1]} = '{aes_key_b64}'\n{self.data_var_ids[2]} = '{aes_iv_b64}'\n{self.data_var_ids[0]} = '{encrypted_code_b64}'"
		dec_code += f"\nexec({self.decompressor_func_name}({self.data_var_ids[0]}, {self.data_var_ids[1]}, {self.data_var_ids[2]}))"
		
		return dec_code

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