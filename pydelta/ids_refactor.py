import ast

from .delta_random import RandomUtil
from .reserved_names import Reserved

class NameVisitor(ast.NodeVisitor):
	def __init__(self):
		self.funcs = set()
		self.classes = set()
		self.args = set()
		self.local_vars = set()
		self.self_attrs = set()
		self.decorated_funcs = set()
		self.class_attrs = {}

	# Scanning for functions
	def visit_FunctionDef(self, node):
		if not node.decorator_list:
			if node.name not in Reserved.reserved_init_names:
				self.funcs.add(node.name)
		else:
			self.decorated_funcs.add(node.name)
		self._extract_args(node)
		self.generic_visit(node)

	# Scanning for async functions
	def visit_AsyncFunctionDef(self, node):
		if not node.decorator_list:
			# Check if the current class member is not a reserved id
			if node.name not in Reserved.reserved_init_names:
				self.funcs.add(node.name)
		else:
			self.decorated_funcs.add(node.name)
		self._extract_args(node)
		self.generic_visit(node)

	# Scanning for classes
	def visit_ClassDef(self, node):
		self.classes.add(node.name)
		self.class_attrs[node.name] = set()
		# Scanning for statements
		for stmt in node.body:
			if isinstance(stmt, ast.Assign):
				for target in stmt.targets:
					if isinstance(target, ast.Name):
						self.class_attrs[node.name].add(target.id)
			elif isinstance(stmt, ast.AnnAssign):
				if isinstance(stmt.target, ast.Name):
					self.class_attrs[node.name].add(stmt.target.id)
		self.generic_visit(node)

	# Scanning for variable names
	def visit_Name(self, node):
		if isinstance(node.ctx, (ast.Store, ast.Param)):
			self.local_vars.add(node.id)
		self.generic_visit(node)

	# Scanning for class attributes
	def visit_Attribute(self, node):
		if isinstance(node.value, ast.Name):
			if node.value.id == 'self':
				self.self_attrs.add(node.attr)
			elif node.value.id in self.classes and node.attr in self.class_attrs.get(node.value.id, set()):
				self.local_vars.add(node.attr)
		self.generic_visit(node)

	# Extracting attributes ids from functions
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

		# Refactoring every ids in the visitor arrays
		for name_set in [visitor.funcs, visitor.classes, visitor.args, visitor.local_vars, visitor.self_attrs]:
			for name in name_set:
				new_name = RandomUtil.generate_random_string()
				self.mapping[name] = new_name

		return self._replace_identifiers(parsed)

	# Replacing every id
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
			if node.annotation:
				self._replace_identifiers(node.annotation)
		elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
			if node.name in self.mapping and node.name not in self.decorated_funcs:
				node.name = self.mapping[node.name]
			for arg in node.args.args:
				if arg.arg in self.mapping:
					arg.arg = self.mapping[arg.arg]
			if node.returns:
				self._replace_identifiers(node.returns)
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
				elif isinstance(stmt, ast.AnnAssign):
					if isinstance(stmt.target, ast.Name) and stmt.target.id in self.mapping:
						stmt.target.id = self.mapping[stmt.target.id]
					if stmt.annotation:
						self._replace_identifiers(stmt.annotation)
		elif isinstance(node, ast.Call):
			for keyword in node.keywords:
				if keyword.arg in self.mapping:
					keyword.arg = self.mapping[keyword.arg]

		for child in ast.iter_child_nodes(node):
			self._replace_identifiers(child)
		return ast.unparse(node)
