class AddAntiDebugger:
	@staticmethod
	def add_anti_debugger_code(code):
		with open('runtime_code/AntiDebug.py', 'r') as anti_dbg_file:
			anti_dbg = anti_dbg_file.read()
	 
		return f"{anti_dbg}\n{code}"