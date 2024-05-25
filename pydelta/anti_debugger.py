from .runtime_code import RuntimeCode

class AddAntiDebugger:
	@staticmethod
	def add_anti_debugger_code(code):
		return f"{RuntimeCode.anti_debug}\n{code}"