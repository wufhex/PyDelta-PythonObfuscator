class AddAntiDebugger:
	@staticmethod
	def add_anti_debugger_code(code):
		with open('runtime_code/AntiDebug.py', 'r') as file1:
			anti_dbg = file1.read()
	 
		return f"{anti_dbg}\n{code}"