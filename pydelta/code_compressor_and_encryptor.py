import base64
import gzip
import zlib
import os

from .runtime_code import RuntimeCode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Cryptography was used because it seems to work faster with pyscript and left here
# pycryptodome seems to be faster and safer locally

class CodeCompressorAndEncryptor:
	def __init__(self):
		self.decompressor_func_name = "___"
		self.data_var_ids = ["___asteroid___", "___bomb___", "___fire___"]
  
	def encrypt_and_compress_code(self, code):
		# Compressing using gzip and zlib
		zlib_compressed_code = zlib.compress(bytes(code, 'utf-8'))
		gzip_compressed_code = gzip.compress(zlib_compressed_code)
		
		aes_key = os.urandom(32)
		aes_iv = os.urandom(16)

		# Padding and encryption using cryptography
		padder = padding.PKCS7(algorithms.AES.block_size).padder()
		gzip_compressed_code_padded = padder.update(gzip_compressed_code) + padder.finalize()

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
		encryptor = cipher.encryptor()
		encrypted_code = encryptor.update(gzip_compressed_code_padded) + encryptor.finalize()

		encrypted_code_b64 = base64.b64encode(encrypted_code).decode()
		aes_key_b64 = base64.b64encode(aes_key).decode()
		aes_iv_b64 = base64.b64encode(aes_iv).decode()
		
		# Adding decompressor code
		decompressor_code = RuntimeCode.decompressor
		decompressor_code += f"\n{self.data_var_ids[1]} = '{aes_key_b64}'\n{self.data_var_ids[2]} = '{aes_iv_b64}'\n{self.data_var_ids[0]} = '{encrypted_code_b64}'"
		decompressor_code += f"\nexec({self.decompressor_func_name}({self.data_var_ids[0]}, {self.data_var_ids[1]}, {self.data_var_ids[2]}))"
		
		return decompressor_code