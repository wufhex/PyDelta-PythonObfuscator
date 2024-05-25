import ast
import importlib

class ImportTransformer(ast.NodeTransformer):
	def __init__(self):
		self.imports = {}
		self.star_imports = {}
		super().__init__()
  
	# Scanning for imports
	def visit_Import(self, node):
		for alias in node.names:
			self.imports[alias.asname or alias.name] = alias.name
		return None

	def visit_ImportFrom(self, node):
		# If import uses a wildcard use importlib to get every module class
		# min version skips these type of imports entirely
		# Example:
		# from module import *
		if node.names[0].name == '*':
			module = node.module
			try:
				imported_module = importlib.import_module(module)
				for attr in dir(imported_module):
					if not attr.startswith('_'):
						self.star_imports[attr] = module
			except ImportError:
				pass
		# Normal import
		else:
			module = node.module
			for alias in node.names:
				name = alias.name
				asname = alias.asname or name
				self.imports[asname] = f'{module}.{name}'
		return None # Removes original import

	# Adds an `__import__` reference to every function that
	# requires that module
	def visit_Name(self, node):
		if node.id in self.imports:
			full_import_path = self.imports[node.id]
			module, _, attr = full_import_path.rpartition('.')
			# If a sub module is imported alongside the module
			# import module.alex
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
			# Normal import
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