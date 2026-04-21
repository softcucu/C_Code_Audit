"""
C++ Taint Analysis using Tree-sitter

This module performs taint analysis on C++ code to track how tainted data
propagates through variables, function calls, and expressions.

Given:
- Initial function name
- Tainted parameter index/name
- Maximum propagation depth

Output: All taint propagation paths
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
from enum import Enum, auto
from pathlib import Path
import json

try:
    import tree_sitter
    from tree_sitter import Language, Parser
    import tree_sitter_cpp
except ImportError as e:
    raise ImportError(
        "Please install required packages: pip install tree-sitter tree-sitter-cpp"
    ) from e

from cpp_analysis_datastructures import (
    SourceLocation,
    FunctionDefinition,
    Parameter,
    TypeReference,
)


class TaintKind(Enum):
    """Types of taint sources."""
    PARAMETER = auto()      # Function parameter
    GLOBAL = auto()         # Global variable
    RETURN = auto()         # Function return value
    EXTERNAL = auto()       # External input (e.g., scanf, cin)
    DERIVED = auto()        # Derived from tainted source


@dataclass(slots=True)
class TaintNode:
    """Represents a node in the taint propagation graph."""
    identifier: str           # Variable/function name
    kind: TaintKind          # Type of taint source
    location: SourceLocation  # Where this occurs
    function_name: str       # Which function contains this
    parent_node: Optional[str] = None  # Parent expression/statement
    
    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "kind": self.kind.name,
            "location": {
                "file": self.location.file_path,
                "start_line": self.location.start_line,
                "start_column": self.location.start_column,
                "end_line": self.location.end_line,
                "end_column": self.location.end_column,
            },
            "function_name": self.function_name,
            "parent_node": self.parent_node,
        }


@dataclass
class TaintPath:
    """Represents a complete taint propagation path."""
    source: TaintNode
    sink: TaintNode
    path: List[TaintNode]
    propagation_steps: List[str]
    
    def to_dict(self) -> dict:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "path": [node.to_dict() for node in self.path],
            "propagation_steps": self.propagation_steps,
            "path_length": len(self.path),
        }


@dataclass
class TaintState:
    """Tracks the current state of taint propagation."""
    tainted_vars: Dict[str, TaintNode]  # var_name -> TaintNode
    current_function: str
    depth: int
    visited: Set[Tuple[str, str]]  # (function_name, var_name) to avoid cycles


class CPPTaintAnalyzer:
    """
    Performs taint analysis on C++ code using tree-sitter.
    
    Tracks how tainted data flows through:
    - Variable assignments
    - Function calls (arguments and return values)
    - Member access
    - Array indexing
    - Binary/unary operations
    """
    
    # Functions that are considered taint sinks (dangerous operations)
    DANGEROUS_SINKS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'system', 'exec', 'execl', 'execle', 'execlp', 'execv', 'execve', 'execvp',
        'strcpy', 'strcat', 'sprintf', 'gets',
        'malloc', 'calloc', 'realloc', 'free',
        'open', 'read', 'write', 'close',
        'send', 'recv', 'socket', 'connect',
        'eval', 'execSQL', 'query',
    }
    
    # Functions that are considered taint sources
    TAINT_SOURCES = {
        'scanf', 'fscanf', 'sscanf', 'cin', 'gets', 'fgets', 'getline',
        'getenv', 'getcwd', 'read', 'recv',
        'malloc', 'calloc', 'realloc',
        'fopen', 'open', 'socket',
    }
    
    # Functions that propagate taint (return tainted value if any arg is tainted)
    TAINT_PROPAGATORS = {
        'strcpy', 'strncpy', 'strcat', 'strncat',
        'memcpy', 'memmove', 'memset',
        'sprintf', 'snprintf',
        'strtok', 'strchr', 'strstr', 'strcmp',
        'atoi', 'atol', 'atof', 'strtoul', 'strtol',
        'strlen', 'sizeof',
        'std::move', 'std::forward',
    }

    def __init__(self):
        """Initialize the taint analyzer."""
        language = tree_sitter.Language(tree_sitter_cpp.language())
        self.parser = tree_sitter.Parser(language)
        
        self.functions: Dict[str, FunctionDefinition] = {}
        self.global_vars: Set[str] = set()
        self.taint_paths: List[TaintPath] = []
        self._current_file: str = ""
        self._source_lines: List[str] = []
        
    def parse_file(self, file_path: str) -> None:
        """Parse a C++ source file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        self._current_file = str(path.absolute())
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
            
        self._source_lines = source_code.splitlines()
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        # Extract functions and global variables
        self._extract_functions(root_node)
        self._extract_global_variables(root_node)
        
    def parse_string(self, source_code: str, file_path: str = "<string>") -> None:
        """Parse C++ source code from a string."""
        self._current_file = file_path
        self._source_lines = source_code.splitlines()
        
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        self._extract_functions(root_node)
        self._extract_global_variables(root_node)
        
    def _create_source_location(self, node) -> SourceLocation:
        """Create a SourceLocation from a tree-sitter node."""
        start_point = node.start_point
        end_point = node.end_point
        
        return SourceLocation(
            file_path=self._current_file,
            start_line=start_point[0] + 1,
            start_column=start_point[1] + 1,
            end_line=end_point[0] + 1,
            end_column=end_point[1] + 1,
        )
    
    def _get_text(self, node) -> str:
        """Get the text content of a node."""
        return node.text.decode('utf-8') if isinstance(node.text, bytes) else node.text
    
    def _extract_functions(self, root_node) -> None:
        """Extract function definitions from the AST."""
        query = self.parser.language.query("""
            (function_definition) @func_def
        """)
        
        captures = query.captures(root_node)
        
        if isinstance(captures, dict):
            func_nodes = captures.get('func_def', [])
        else:
            func_nodes = [node for node, capture_name in captures if capture_name == 'func_def']
        
        for node in func_nodes:
            func_def = self._parse_function(node)
            if func_def:
                self.functions[func_def.name] = func_def
                
    def _parse_function(self, node) -> Optional[FunctionDefinition]:
        """Parse a function_definition node."""
        declarator_node = node.child_by_field_name('declarator')
        if not declarator_node:
            return None
            
        name_node = None
        for child in declarator_node.children:
            if child.type == 'identifier':
                name_node = child
                break
                
        if not name_node:
            return None
            
        func_name = self._get_text(name_node)
        location = self._create_source_location(node)
        
        # Extract parameters
        params: List[Parameter] = []
        param_list_node = node.child_by_field_name('parameters')
        if param_list_node:
            params = self._parse_parameters(param_list_node)
            
        return FunctionDefinition(
            name=func_name,
            qualified_name=func_name,  # For now, use simple name as qualified name
            location=location,
            parameters=params,
            return_type=TypeReference(name="void"),
        )
        
    def _parse_parameters(self, param_list_node) -> List[Parameter]:
        """Parse function parameters."""
        params = []
        for child in param_list_node.children:
            if child.type in ('parameter_declaration', 'optional_parameter_declaration'):
                param_info = self._parse_parameter(child)
                if param_info:
                    params.append(param_info)
        return params
        
    def _parse_parameter(self, node) -> Optional[Parameter]:
        """Parse a single parameter declaration."""
        type_node = node.child_by_field_name('type')
        
        # Find the declarator - it could be wrapped in pointer/reference declarator or be direct identifier
        declarator_node = node.child_by_field_name('declarator')
        
        if not declarator_node:
            # For simple parameters like "int x", the identifier is a direct child
            for child in node.children:
                if child.type == 'identifier':
                    declarator_node = child
                    break
        
        if not declarator_node:
            return None
            
        # Now find the identifier within the declarator
        name_node = self._find_identifier_in_declarator(declarator_node)
            
        if not name_node:
            return None
            
        param_name = self._get_text(name_node)
        type_name = self._get_text(type_node) if type_node else "unknown"
        
        return Parameter(
            name=param_name,
            type_ref=TypeReference(name=type_name),
        )
        
    def _find_identifier_in_declarator(self, node):
        """Recursively find identifier in a declarator (handles pointers, references, arrays)."""
        if node.type == 'identifier':
            return node
            
        # Check common declarator types that wrap identifiers
        for child in node.children:
            if child.type == 'identifier':
                return child
            elif child.type in ('pointer_declarator', 'reference_declarator', 
                               'array_declarator', 'balanced_expression'):
                result = self._find_identifier_in_declarator(child)
                if result:
                    return result
                    
        return None
        
    def _extract_global_variables(self, root_node) -> None:
        """Extract global variable declarations."""
        query = self.parser.language.query("""
            (declaration) @decl
            (init_declarator) @init_decl
        """)
        
        captures = query.captures(root_node)
        
        if isinstance(captures, dict):
            nodes = captures.get('decl', []) + captures.get('init_decl', [])
        else:
            nodes = [node for node, _ in captures]
            
        for node in nodes:
            # Check if this is at global scope (not inside a function)
            parent = node.parent
            while parent and parent.type != 'translation_unit':
                if parent.type == 'function_definition':
                    break
                parent = parent.parent
                
            if parent and parent.type == 'translation_unit':
                var_name = self._extract_identifier(node)
                if var_name:
                    self.global_vars.add(var_name)
                    
    def _extract_identifier(self, node) -> Optional[str]:
        """Extract identifier from a declaration node."""
        if node.type == 'init_declarator':
            declarator = node.child_by_field_name('declarator')
            if declarator and declarator.type == 'identifier':
                return self._get_text(declarator)
        elif node.type == 'declaration':
            for child in node.children:
                if child.type == 'init_declarator':
                    return self._extract_identifier(child)
        return None
        
    def analyze_taint(
        self,
        initial_function: str,
        tainted_param: Any,  # Can be parameter index (int) or name (str)
        max_propagation_depth: int = 10,
    ) -> List[TaintPath]:
        """
        Perform taint analysis starting from a specific function parameter.
        
        Args:
            initial_function: Name of the function where taint starts
            tainted_param: Parameter index (0-based) or parameter name
            max_propagation_depth: Maximum number of propagation steps
            
        Returns:
            List of all taint propagation paths found
        """
        self.taint_paths = []
        
        if initial_function not in self.functions:
            print(f"Function '{initial_function}' not found")
            return self.taint_paths
            
        func_def = self.functions[initial_function]
        
        # Resolve tainted parameter
        taint_param_name = None
        if isinstance(tainted_param, int):
            if 0 <= tainted_param < len(func_def.parameters):
                taint_param_name = func_def.parameters[tainted_param].name
            else:
                print(f"Parameter index {tainted_param} out of range")
                return self.taint_paths
        elif isinstance(tainted_param, str):
            for param in func_def.parameters:
                if param.name == tainted_param:
                    taint_param_name = param.name
                    break
            if not taint_param_name:
                print(f"Parameter '{tainted_param}' not found in function '{initial_function}'")
                return self.taint_paths
        else:
            print("tainted_param must be int (index) or str (name)")
            return self.taint_paths
            
        # Create initial taint node
        initial_node = TaintNode(
            identifier=taint_param_name,
            kind=TaintKind.PARAMETER,
            location=func_def.location,
            function_name=initial_function,
        )
        
        # Start taint propagation
        initial_state = TaintState(
            tainted_vars={taint_param_name: initial_node},
            current_function=initial_function,
            depth=0,
            visited=set(),
        )
        
        # Analyze the function body
        self._propagate_taint(initial_state, max_propagation_depth)
        
        return self.taint_paths
        
    def _propagate_taint(self, state: TaintState, max_depth: int) -> None:
        """Recursively propagate taint through the code."""
        if state.depth >= max_depth:
            return
            
        func_name = state.current_function
        if func_name not in self.functions:
            return
            
        func_def = self.functions[func_name]
        
        # Get function body
        func_node = self._find_function_node(func_name)
        if not func_node:
            return
            
        body_node = func_node.child_by_field_name('body')
        if not body_node:
            return
            
        # Traverse the function body
        self._analyze_block(body_node, state, max_depth)
        
    def _find_function_node(self, func_name: str):
        """Find the tree-sitter node for a function."""
        query = self.parser.language.query(f"""
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @name
                ))
                (#eq? @name "{func_name}")
        """)
        
        # We need to re-parse to get the tree
        source_code = '\n'.join(self._source_lines)
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        captures = query.captures(root_node)
        if isinstance(captures, dict):
            nodes = captures.get('name', [])
        else:
            nodes = [node for node, _ in captures]
            
        if nodes:
            # Return the function_definition node (parent of the name node)
            return nodes[0].parent.parent
        return None
        
    def _analyze_block(self, block_node, state: TaintState, max_depth: int) -> None:
        """Analyze a block of statements for taint propagation."""
        for stmt in block_node.children:
            if stmt.type in ('expression_statement', 'declaration', 'return_statement',
                           'if_statement', 'while_statement', 'for_statement',
                           'do_statement', 'switch_statement'):
                self._analyze_statement(stmt, state, max_depth)
                
    def _analyze_statement(self, stmt, state: TaintState, max_depth: int) -> None:
        """Analyze a single statement for taint propagation."""
        if stmt.type == 'expression_statement':
            expr = stmt.child(0) if stmt.child_count > 0 else None
            if expr:
                self._analyze_expression(expr, state, max_depth)
        elif stmt.type == 'declaration':
            self._analyze_declaration(stmt, state, max_depth)
        elif stmt.type == 'return_statement':
            self._analyze_return(stmt, state, max_depth)
        elif stmt.type == 'if_statement':
            self._analyze_control_flow(stmt, state, max_depth)
        elif stmt.type in ('while_statement', 'for_statement', 'do_statement'):
            self._analyze_loop(stmt, state, max_depth)
            
    def _analyze_expression(self, expr, state: TaintState, max_depth: int, 
                           lhs_vars: Optional[List[str]] = None) -> None:
        """
        Analyze an expression for taint propagation.
        
        Args:
            expr: The expression node
            state: Current taint state
            max_depth: Maximum propagation depth
            lhs_vars: Variables on the left-hand side of assignment (if any)
        """
        if not expr:
            return
            
        # Check if any operand is tainted
        tainted_operands = self._find_tainted_operands(expr, state)
        
        if expr.type == 'assignment_expression':
            # Handle assignment: lhs = rhs
            lhs = expr.child_by_field_name('left')
            rhs = expr.child_by_field_name('right')
            
            if lhs and rhs:
                # First analyze RHS to find tainted sources
                self._analyze_expression(rhs, state, max_depth)
                
                # Check if RHS is tainted
                rhs_tainted = self._is_expression_tainted(rhs, state)
                
                if rhs_tainted:
                    # Propagate taint to LHS
                    lhs_vars_list = self._extract_assignable_vars(lhs)
                    for var in lhs_vars_list:
                        self._mark_variable_tainted(var, state, expr, TaintKind.DERIVED)
                        
                # If LHS variables exist and RHS is tainted, record the path
                if lhs_vars_list and rhs_tainted:
                    self._record_taint_path(state, lhs_vars_list[0], expr)
                    
        elif expr.type == 'call_expression':
            # Handle function call
            self._analyze_function_call(expr, state, max_depth)
            
        elif expr.type in ('binary_expression', 'unary_expression'):
            # Check if result should be tainted
            if tainted_operands:
                # For certain operators, the result is tainted
                operator = expr.child_by_field_name('operator')
                if operator:
                    op_text = self._get_text(operator)
                    # Most binary ops propagate taint
                    if op_text not in ('&&', '||', '==', '!=', '<', '>', '<=', '>='):
                        # Comparison operators don't propagate taint to result
                        pass
                        
        elif expr.type == 'identifier':
            # Simple identifier - check if it's tainted
            var_name = self._get_text(expr)
            if var_name in state.tainted_vars:
                pass  # Already tracked
                
        elif expr.type == 'member_expression':
            # Check member access like obj.member
            obj = expr.child_by_field_name('object')
            if obj and self._is_expression_tainted(obj, state):
                member_name = self._get_text(expr)
                # Member access of tainted object is also tainted
                
    def _analyze_declaration(self, decl, state: TaintState, max_depth: int) -> None:
        """Analyze a variable declaration with optional initialization."""
        init_declarator = None
        for child in decl.children:
            if child.type == 'init_declarator':
                init_declarator = child
                break
                
        if init_declarator:
            declarator = init_declarator.child_by_field_name('declarator')
            value = init_declarator.child_by_field_name('value')
            
            if declarator and value:
                var_name = self._get_text(declarator)
                
                # Check if initializer is tainted
                if self._is_expression_tainted(value, state):
                    self._mark_variable_tainted(var_name, state, decl, TaintKind.DERIVED)
                    self._record_taint_path(state, var_name, decl)
                else:
                    # Check for taint source functions
                    if value.type == 'call_expression':
                        func_name = self._get_call_name(value)
                        if func_name in self.TAINT_SOURCES:
                            self._mark_variable_tainted(var_name, state, decl, TaintKind.EXTERNAL)
                            
    def _analyze_return(self, ret_stmt, state: TaintState, max_depth: int) -> None:
        """Analyze a return statement."""
        for child in ret_stmt.children:
            if child.type != 'return':
                # This is the return value expression
                if self._is_expression_tainted(child, state):
                    # Record path to return (sink)
                    sink_node = TaintNode(
                        identifier="return",
                        kind=TaintKind.RETURN,
                        location=self._create_source_location(ret_stmt),
                        function_name=state.current_function,
                    )
                    
                    # Find the source of this taint
                    for var_name, taint_node in state.tainted_vars.items():
                        path = TaintPath(
                            source=taint_node,
                            sink=sink_node,
                            path=[taint_node, sink_node],
                            propagation_steps=[f"Return tainted value from {var_name}"],
                        )
                        self.taint_paths.append(path)
                        
    def _analyze_function_call(self, call_expr, state: TaintState, max_depth: int) -> None:
        """Analyze a function call for taint propagation."""
        func_name = self._get_call_name(call_expr)
        
        if not func_name:
            return
            
        # Get arguments
        args = []
        args_node = call_expr.child_by_field_name('arguments')
        if args_node:
            for child in args_node.children:
                if child.type != '(' and child.type != ')':
                    args.append(child)
                    
        # Check if any argument is tainted
        tainted_args = []
        for i, arg in enumerate(args):
            if self._is_expression_tainted(arg, state):
                tainted_args.append((i, arg))
                
        # If calling a dangerous sink with tainted args, record the path
        if func_name in self.DANGEROUS_SINKS and tainted_args:
            for arg_idx, arg_node in tainted_args:
                for var_name, taint_node in state.tainted_vars.items():
                    sink_node = TaintNode(
                        identifier=func_name,
                        kind=TaintKind.DERIVED,
                        location=self._create_source_location(call_expr),
                        function_name=state.current_function,
                        parent_node=f"argument[{arg_idx}]",
                    )
                    
                    path = TaintPath(
                        source=taint_node,
                        sink=sink_node,
                        path=[taint_node, sink_node],
                        propagation_steps=[f"Tainted {var_name} passed to dangerous function {func_name}"],
                    )
                    self.taint_paths.append(path)
                    
        # If calling a taint propagator with tainted args, mark result as tainted
        if func_name in self.TAINT_PROPAGATORS and tainted_args:
            # The return value becomes tainted
            pass
            
        # If calling another function, propagate into it
        if func_name in self.functions and tainted_args:
            # Map tainted args to callee's parameters
            callee = self.functions[func_name]
            new_state = TaintState(
                tainted_vars=dict(state.tainted_vars),
                current_function=func_name,
                depth=state.depth + 1,
                visited=state.visited.copy(),
            )
            
            # Mark callee's parameters as tainted based on tainted arguments
            for arg_idx, arg_node in tainted_args:
                if arg_idx < len(callee.parameters):
                    param_name = callee.parameters[arg_idx].name
                    taint_node = TaintNode(
                        identifier=param_name,
                        kind=TaintKind.PARAMETER,
                        location=callee.location,
                        function_name=func_name,
                    )
                    new_state.tainted_vars[param_name] = taint_node
                    
                    # Check for cycles
                    key = (func_name, param_name)
                    if key not in state.visited:
                        new_state.visited.add(key)
                        self._propagate_taint(new_state, max_depth)
                        
    def _analyze_control_flow(self, stmt, state: TaintState, max_depth: int) -> None:
        """Analyze control flow statements (if, switch)."""
        if stmt.type == 'if_statement':
            condition = stmt.child_by_field_name('condition')
            consequence = stmt.child_by_field_name('consequence')
            alternative = stmt.child_by_field_name('alternative')
            
            if consequence:
                self._analyze_block(consequence, state, max_depth)
            if alternative:
                self._analyze_block(alternative, state, max_depth)
                
    def _analyze_loop(self, stmt, state: TaintState, max_depth: int) -> None:
        """Analyze loop statements (while, for, do)."""
        body = None
        if stmt.type == 'while_statement':
            body = stmt.child_by_field_name('body')
        elif stmt.type == 'for_statement':
            body = stmt.child_by_field_name('body')
        elif stmt.type == 'do_statement':
            body = stmt.child_by_field_name('body')
            
        if body:
            self._analyze_block(body, state, max_depth)
            
    def _find_tainted_operands(self, expr, state: TaintState) -> List[str]:
        """Find all tainted operands in an expression."""
        tainted = []
        
        if expr.type == 'identifier':
            var_name = self._get_text(expr)
            if var_name in state.tainted_vars:
                tainted.append(var_name)
        elif expr.type == 'member_expression':
            obj = expr.child_by_field_name('object')
            if obj:
                tainted.extend(self._find_tainted_operands(obj, state))
        elif expr.type == 'subscript_expression':
            arr = expr.child_by_field_name('array')
            if arr:
                tainted.extend(self._find_tainted_operands(arr, state))
        else:
            for child in expr.children:
                tainted.extend(self._find_tainted_operands(child, state))
                
        return tainted
        
    def _is_expression_tainted(self, expr, state: TaintState) -> bool:
        """Check if an expression is tainted."""
        if not expr:
            return False
            
        # Direct identifier check
        if expr.type == 'identifier':
            var_name = self._get_text(expr)
            return var_name in state.tainted_vars
            
        # Check if it's a call to a taint source
        if expr.type == 'call_expression':
            func_name = self._get_call_name(expr)
            if func_name in self.TAINT_SOURCES:
                return True
                
        # Recursively check children
        return len(self._find_tainted_operands(expr, state)) > 0
        
    def _extract_assignable_vars(self, expr) -> List[str]:
        """Extract all assignable variables from an LHS expression."""
        vars_list = []
        
        if expr.type == 'identifier':
            vars_list.append(self._get_text(expr))
        elif expr.type == 'member_expression':
            # For obj.member, we track the base object
            obj = expr.child_by_field_name('object')
            if obj:
                vars_list.extend(self._extract_assignable_vars(obj))
        elif expr.type == 'subscript_expression':
            arr = expr.child_by_field_name('array')
            if arr:
                vars_list.extend(self._extract_assignable_vars(arr))
        elif expr.type == 'parenthesized_expression':
            inner = expr.child(1) if expr.child_count > 1 else expr.child(0)
            if inner:
                vars_list.extend(self._extract_assignable_vars(inner))
                
        return vars_list
        
    def _mark_variable_tainted(self, var_name: str, state: TaintState, 
                               node, kind: TaintKind) -> None:
        """Mark a variable as tainted."""
        taint_node = TaintNode(
            identifier=var_name,
            kind=kind,
            location=self._create_source_location(node),
            function_name=state.current_function,
        )
        state.tainted_vars[var_name] = taint_node
        
    def _record_taint_path(self, state: TaintState, sink_var: str, 
                          node) -> None:
        """Record a taint propagation path."""
        for var_name, source_node in state.tainted_vars.items():
            if var_name != sink_var:
                sink_node = TaintNode(
                    identifier=sink_var,
                    kind=TaintKind.DERIVED,
                    location=self._create_source_location(node),
                    function_name=state.current_function,
                )
                
                step = f"{source_node.identifier} -> {sink_var}"
                path = TaintPath(
                    source=source_node,
                    sink=sink_node,
                    path=[source_node, sink_node],
                    propagation_steps=[step],
                )
                self.taint_paths.append(path)
                
    def _get_call_name(self, call_expr) -> Optional[str]:
        """Extract function name from a call_expression."""
        func_node = call_expr.child_by_field_name('function')
        if not func_node:
            return None
            
        if func_node.type == 'identifier':
            return self._get_text(func_node)
        elif func_node.type == 'member_expression':
            # Handle method calls like obj.method()
            member = func_node.child_by_field_name('property')
            if member:
                return self._get_text(member)
        elif func_node.type == 'qualified_type':
            # Handle qualified calls like std::cout
            return self._get_text(func_node)
            
        return None
        
    def get_results(self) -> List[dict]:
        """Get taint analysis results as a list of dictionaries."""
        return [path.to_dict() for path in self.taint_paths]
        
    def print_results(self) -> None:
        """Print taint analysis results in a human-readable format."""
        if not self.taint_paths:
            print("No taint paths found.")
            return
            
        print(f"\nFound {len(self.taint_paths)} taint propagation path(s):\n")
        print("=" * 80)
        
        for i, path in enumerate(self.taint_paths, 1):
            print(f"\nPath {i}:")
            print(f"  Source: {path.source.identifier} ({path.source.kind.name})")
            print(f"    Location: {path.source.location.file_path}:{path.source.location.start_line}")
            print(f"    Function: {path.source.function_name}")
            print(f"  Sink: {path.sink.identifier} ({path.sink.kind.name})")
            print(f"    Location: {path.sink.location.file_path}:{path.sink.location.start_line}")
            print(f"    Function: {path.sink.function_name}")
            print(f"  Steps:")
            for step in path.propagation_steps:
                print(f"    - {step}")
            print("-" * 80)


def main():
    """Example usage of the taint analyzer."""
    # Create analyzer
    analyzer = CPPTaintAnalyzer()
    
    # Parse a C++ file
    test_code = """
#include <stdio.h>
#include <string.h>

void processInput(char* data) {
    char buffer[256];
    strcpy(buffer, data);  // Taint propagates to buffer
    printf("%s\\n", buffer);  // Dangerous: printing tainted data
}

void vulnerableFunction(const char* userInput) {
    char localBuf[128];
    strcpy(localBuf, userInput);  // Taint propagates
    system(localBuf);  // Dangerous: executing tainted command
}

int main(int argc, char** argv) {
    if (argc > 1) {
        vulnerableFunction(argv[1]);  // argv[1] is tainted source
    }
    return 0;
}
"""
    
    analyzer.parse_string(test_code, "test.cpp")
    
    # Perform taint analysis
    print("Analyzing taint propagation from 'userInput' parameter in 'vulnerableFunction'...")
    paths = analyzer.analyze_taint(
        initial_function="vulnerableFunction",
        tainted_param="userInput",
        max_propagation_depth=5,
    )
    
    analyzer.print_results()
    
    # Also analyze processInput
    print("\n\nAnalyzing taint propagation from 'data' parameter in 'processInput'...")
    paths2 = analyzer.analyze_taint(
        initial_function="processInput",
        tainted_param="data",
        max_propagation_depth=5,
    )
    
    analyzer.print_results()
    
    # Output as JSON
    print("\n\nJSON Output:")
    results = analyzer.get_results()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
