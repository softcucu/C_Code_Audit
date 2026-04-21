"""
C++ Code Parser using Tree-sitter

This module parses C++ source code using tree-sitter and extracts:
- Struct declarations
- Macro definitions
- Global variables

It uses the data structures defined in cpp_analysis_datastructures.py.
"""

from pathlib import Path
from typing import List, Optional

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
    ClassDefinition,
    MacroDefinition,
    VariableDeclaration,
    TypeReference,
    StorageClass,
    VariableScope,
    AccessSpecifier,
    FunctionDefinition,
    Parameter,
    TemplateParameter,
    FunctionType,
    MemberVariable,
    BaseClass,
)


class CPPParser:
    """
    Parser for C++ source code using tree-sitter.
    Extracts struct declarations, macro definitions, and global variables.
    """

    def __init__(self):
        """Initialize the parser with tree-sitter C++ language."""
        # New tree-sitter API (0.24+): Language is created from the PyCapsule
        language = tree_sitter.Language(tree_sitter_cpp.language())
        self.parser = tree_sitter.Parser(language)
        
        # Store parsed results
        self.functions: List[FunctionDefinition] = []
        self.classes: List[ClassDefinition] = []
        self.structs: List[ClassDefinition] = []
        self.macros: List[MacroDefinition] = []
        self.global_variables: List[VariableDeclaration] = []
        
        # Current file being parsed
        self._current_file: str = ""
        self._source_lines: List[str] = []
        self._namespace_stack: List[str] = []

    def parse_file(self, file_path: str) -> None:
        """
        Parse a C++ source file.
        
        Args:
            file_path: Path to the C++ source file
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        self._current_file = str(path.absolute())
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        self._source_lines = source_code.splitlines()
        
        # Parse the source code
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        # Reset collections for new file
        self.functions = []
        self.classes = []
        self.structs = []
        self.macros = []
        self.global_variables = []
        
        # Traverse the AST and extract entities
        self._extract_functions(root_node)
        self._extract_classes(root_node)
        self._extract_structs(root_node)
        self._extract_macros(root_node)
        self._extract_global_variables(root_node)

    def parse_string(self, source_code: str, file_path: str = "<string>") -> None:
        """
        Parse C++ source code from a string.
        
        Args:
            source_code: C++ source code as string
            file_path: Optional file path for location tracking
        """
        self._current_file = file_path
        self._source_lines = source_code.splitlines()
        
        # Parse the source code
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        # Reset collections
        self.functions = []
        self.classes = []
        self.structs = []
        self.macros = []
        self.global_variables = []
        
        # Traverse the AST and extract entities
        self._extract_functions(root_node)
        self._extract_classes(root_node)
        self._extract_structs(root_node)
        self._extract_macros(root_node)
        self._extract_global_variables(root_node)

    def _create_source_location(self, node) -> SourceLocation:
        """Create a SourceLocation from a tree-sitter node."""
        start_point = node.start_point
        end_point = node.end_point
        
        return SourceLocation(
            file_path=self._current_file,
            start_line=start_point[0] + 1,  # Convert to 1-based
            start_column=start_point[1] + 1,
            end_line=end_point[0] + 1,
            end_column=end_point[1] + 1,
        )

    def _get_text(self, node) -> str:
        """Get the text content of a node."""
        return node.text.decode('utf-8') if isinstance(node.text, bytes) else node.text

    def _get_current_namespace(self) -> Optional[str]:
        """Get the current namespace from the stack."""
        if not self._namespace_stack:
            return None
        return '::'.join(self._namespace_stack)

    def _extract_functions(self, root_node) -> None:
        """
        Extract function definitions from the AST.
        
        Tree-sitter C++ grammar uses 'function_definition' for function definitions.
        """
        query = self.parser.language.query("""
            (function_definition) @func_def
        """)
        
        captures = query.captures(root_node)
        
        # New API returns a dict: {capture_name: [nodes]}
        if isinstance(captures, dict):
            func_nodes = captures.get('func_def', [])
        else:
            # Old API returns list of (node, capture_name) tuples
            func_nodes = [node for node, capture_name in captures if capture_name == 'func_def']
        
        for node in func_nodes:
            func_def = self._parse_function(node)
            if func_def:
                self.functions.append(func_def)

    def _parse_function(self, node) -> Optional[FunctionDefinition]:
        """
        Parse a function_definition node into a FunctionDefinition.
        """
        # Get function name from declarator
        declarator_node = node.child_by_field_name('declarator')
        if not declarator_node:
            return None
        
        # Find the name identifier
        name_node = None
        for child in declarator_node.children:
            if child.type == 'identifier':
                name_node = child
                break
            elif child.type == 'qualified_type':
                # Handle qualified names like MyClass::method
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        name_node = grandchild
        
        if not name_node:
            return None
        
        name = self._get_text(name_node)
        
        # Build qualified name
        current_ns = self._get_current_namespace()
        qualified_name = f"{current_ns}::{name}" if current_ns else name
        
        # Get return type
        return_type_node = node.child_by_field_name('type')
        return_type = self._parse_type(return_type_node) if return_type_node else TypeReference(name="void")
        
        # Get parameters
        parameters = []
        params_node = declarator_node.child_by_field_name('parameters')
        if params_node:
            parameters = self._parse_parameters(params_node)
        
        # Check for various function properties
        is_const = False
        is_volatile = False
        is_noexcept = False
        is_static = False
        is_virtual = False
        is_pure_virtual = False
        is_override = False
        is_final = False
        is_inline = False
        is_constexpr = False
        is_deleted = False
        is_defaulted = False
        is_explicit = False
        
        function_type = FunctionType.NORMAL
        
        # Check for qualifiers
        for child in node.children:
            if child.type == 'const':
                is_const = True
            elif child.type == 'volatile':
                is_volatile = True
            elif child.type == 'noexcept':
                is_noexcept = True
            elif child.type == 'override':
                is_override = True
                function_type = FunctionType.OVERRIDE
            elif child.type == 'final':
                is_final = True
            elif child.type == 'inline':
                is_inline = True
                function_type = FunctionType.INLINE
            elif child.type == 'virtual':
                is_virtual = True
                function_type = FunctionType.VIRTUAL
            elif child.type == 'static':
                is_static = True
                function_type = FunctionType.STATIC
            elif child.type == 'constexpr':
                is_constexpr = True
                function_type = FunctionType.CONSTEXPR
            elif child.type == 'explicit':
                is_explicit = True
            elif child.type == 'delete_expression':
                is_deleted = True
            elif child.type == 'default_expression':
                is_defaulted = True
        
        # Check for pure virtual (= 0)
        if declarator_node:
            for child in declarator_node.children:
                if child.type == 'number_literal' and self._get_text(child) == '0':
                    is_pure_virtual = True
                    function_type = FunctionType.PURE_VIRTUAL
                    break
        
        # Determine function type (constructor, destructor, etc.)
        parent_class = None
        # Check if this is a method by looking at qualified name or context
        if '::' in qualified_name:
            parts = qualified_name.rsplit('::', 1)
            if len(parts) == 2:
                parent_class = parts[0]
                # Check for constructor/destructor
                if name == parent_class.split('::')[-1]:
                    function_type = FunctionType.CONSTRUCTOR
                elif name.startswith('~') and name[1:] == parent_class.split('::')[-1]:
                    function_type = FunctionType.DESTRUCTOR
        
        # Get template parameters
        template_params = []
        template_node = node.child_by_field_name('template_parameters')
        if template_node:
            template_params = self._parse_template_parameters(template_node)
        
        location = self._create_source_location(node)
        
        func_def = FunctionDefinition(
            name=name,
            qualified_name=qualified_name,
            return_type=return_type,
            location=location,
            parameters=parameters,
            function_type=function_type,
            is_const=is_const,
            is_volatile=is_volatile,
            is_noexcept=is_noexcept,
            is_deleted=is_deleted,
            is_defaulted=is_defaulted,
            is_explicit=is_explicit,
            is_inline=is_inline,
            is_virtual=is_virtual,
            is_pure_virtual=is_pure_virtual,
            is_override=is_override,
            is_final=is_final,
            is_static=is_static,
            is_constexpr=is_constexpr,
            template_params=template_params,
            parent_class=parent_class,
            parent_namespace=current_ns,
        )
        
        return func_def

    def _parse_parameters(self, params_node) -> List[Parameter]:
        """Parse function parameters from a parameter_list node."""
        parameters = []
        
        for child in params_node.children:
            if child.type == 'parameter_declaration':
                param = self._parse_parameter(child)
                if param:
                    parameters.append(param)
            elif child.type == 'variadic_parameter':
                # Handle ... (variadic)
                parameters.append(Parameter(
                    name="args",
                    type_ref=TypeReference(name="..."),
                    is_variadic=True
                ))
        
        return parameters

    def _parse_parameter(self, node) -> Optional[Parameter]:
        """Parse a single parameter_declaration node."""
        # Get type
        type_node = None
        name_node = None
        default_value = None
        
        for child in node.children:
            if child.type in ('primitive_type', 'type_identifier', 'qualified_type', 
                             'pointer_type', 'reference_type', 'template_type'):
                type_node = child
            elif child.type == 'identifier':
                name_node = child
            elif child.type == 'parameter_declaration':
                # Nested - recurse
                return self._parse_parameter(child)
        
        # Try to find declarator for name
        declarator_node = node.child_by_field_name('declarator')
        if declarator_node and not name_node:
            for child in declarator_node.children:
                if child.type == 'identifier':
                    name_node = child
                    break
        
        # Check for default value
        for child in node.children:
            if child.type in ('initializer_list', 'call_expression', 'number_literal',
                             'string_literal', 'char_literal', 'true', 'false', 'nullptr'):
                default_value = self._get_text(child)
                break
        
        if not name_node:
            # Anonymous parameter - use empty name
            name = ""
        else:
            name = self._get_text(name_node)
        
        type_ref = self._parse_type(node) if type_node else TypeReference(name="unknown")
        
        return Parameter(
            name=name,
            type_ref=type_ref,
            default_value=default_value,
        )

    def _extract_classes(self, root_node) -> None:
        """
        Extract class declarations from the AST.
        
        Tree-sitter C++ grammar uses 'class_specifier' for class declarations.
        """
        query = self.parser.language.query("""
            (class_specifier) @class_def
        """)
        
        captures = query.captures(root_node)
        
        # New API returns a dict: {capture_name: [nodes]}
        if isinstance(captures, dict):
            class_nodes = captures.get('class_def', [])
        else:
            # Old API returns list of (node, capture_name) tuples
            class_nodes = [node for node, capture_name in captures if capture_name == 'class_def']
        
        for node in class_nodes:
            class_def = self._parse_class(node)
            if class_def:
                self.classes.append(class_def)

    def _parse_class(self, node) -> Optional[ClassDefinition]:
        """
        Parse a class_specifier node into a ClassDefinition.
        """
        # Get class name
        name_node = node.child_by_field_name('name')
        if not name_node:
            # Anonymous class
            name = f"<anonymous_class_{node.start_point[0]}>"
        else:
            name = self._get_text(name_node)
        
        # Build qualified name
        current_ns = self._get_current_namespace()
        qualified_name = f"{current_ns}::{name}" if current_ns else name
        
        # Check for template parameters
        template_params = []
        template_node = node.child_by_field_name('template_parameters')
        if template_node:
            template_params = self._parse_template_parameters(template_node)
        
        # Extract base classes
        base_classes = []
        for child in node.children:
            if child.type == 'base_class_clause':
                base = self._parse_base_class(child)
                if base:
                    base_classes.append(base)
        
        # Extract member variables and functions
        member_variables = []
        member_functions = []
        
        body_node = node.child_by_field_name('body')
        if body_node:
            member_variables = self._parse_class_members(body_node)
            # Note: member functions declared in class are stored as IDs
            # They will be linked when parsing function definitions
        
        # Check for properties
        is_abstract = any(f.is_pure_virtual for f in self.functions 
                         if f.parent_class and f.parent_class.endswith(name))
        is_polymorphic = any(f.is_virtual for f in self.functions 
                            if f.parent_class and f.parent_class.endswith(name))
        
        # Check for final specifier
        is_final = False
        for child in node.children:
            if child.type == 'final':
                is_final = True
                break
        
        location = self._create_source_location(node)
        
        class_def = ClassDefinition(
            name=name,
            qualified_name=qualified_name,
            kind='class',
            location=location,
            member_variables=member_variables,
            base_classes=base_classes,
            template_params=template_params,
            is_abstract=is_abstract,
            is_final=is_final,
            is_polymorphic=is_polymorphic,
            parent_namespace=current_ns,
        )
        
        return class_def

    def _parse_base_class(self, node) -> Optional[BaseClass]:
        """Parse a base_class_clause node."""
        type_node = None
        access = AccessSpecifier.PUBLIC  # Default for class
        is_virtual = False
        
        for child in node.children:
            if child.type in ('type_identifier', 'qualified_type'):
                type_node = child
            elif child.type == 'public':
                access = AccessSpecifier.PUBLIC
            elif child.type == 'protected':
                access = AccessSpecifier.PROTECTED
            elif child.type == 'private':
                access = AccessSpecifier.PRIVATE
            elif child.type == 'virtual':
                is_virtual = True
        
        if not type_node:
            return None
        
        class_name = self._get_text(type_node)
        
        return BaseClass(
            class_name=class_name,
            access=access,
            is_virtual=is_virtual,
        )

    def _parse_class_members(self, body_node) -> List[MemberVariable]:
        """Parse member variables from a class body."""
        members = []
        current_access = AccessSpecifier.PRIVATE  # Default for class
        
        for child in body_node.children:
            if child.type == 'access_specifier':
                # Update current access level
                spec_text = self._get_text(child).rstrip(':').strip()
                if spec_text == 'public':
                    current_access = AccessSpecifier.PUBLIC
                elif spec_text == 'protected':
                    current_access = AccessSpecifier.PROTECTED
                elif spec_text == 'private':
                    current_access = AccessSpecifier.PRIVATE
            elif child.type in ('declaration', 'field_declaration'):
                member = self._parse_member_declaration(child, current_access)
                if member:
                    members.append(member)
        
        return members

    def _parse_member_declaration(self, node, default_access: AccessSpecifier = AccessSpecifier.PRIVATE) -> Optional:
        """Parse a member field declaration."""
        # Helper to get all descendants
        def get_descendants(n):
            result = []
            for child in n.children:
                result.append(child)
                result.extend(get_descendants(child))
            return result
        
        # Get the declarator (contains name and type info)
        declarator_node = None
        type_node = None
        
        for child in node.children:
            if child.type == 'field_identifier':
                declarator_node = child
            elif child.type in ('primitive_type', 'type_identifier', 'qualified_type', 
                               'pointer_type', 'reference_type', 'template_type'):
                type_node = child
        
        # Try to get name from different possible locations
        name = ""
        if declarator_node:
            name = self._get_text(declarator_node)
        else:
            # Try to find field_identifier in nested structure
            for child in get_descendants(node):
                if child.type == 'field_identifier':
                    name = self._get_text(child)
                    break
        
        if not name:
            return None
        
        # Get type
        type_ref = self._parse_type(node)
        
        # Determine access specifier based on context
        access = default_access
        
        # Check for static, const, mutable keywords
        is_static = False
        is_const = False
        is_mutable = False
        
        for child in node.children:
            keyword = self._get_text(child) if hasattr(child, 'type') and child.type in ('static', 'const', 'mutable') else ""
            if keyword == 'static':
                is_static = True
            elif keyword == 'const':
                is_const = True
            elif keyword == 'mutable':
                is_mutable = True
        
        location = self._create_source_location(node)
        
        return MemberVariable(
            name=name,
            type_ref=type_ref,
            access=access,
            is_static=is_static,
            is_const=is_const,
            is_mutable=is_mutable,
            location=location,
        )

    def _extract_structs(self, root_node) -> None:
        """
        Extract struct declarations from the AST.
        
        Tree-sitter C++ grammar uses 'struct_specifier' for struct declarations.
        """
        # Query for struct specifiers
        # struct_specifier can be: struct name { body }; or struct name;
        query = self.parser.language.query("""
            (struct_specifier) @struct_def
        """)
        
        captures = query.captures(root_node)
        
        # New API returns a dict: {capture_name: [nodes]}
        if isinstance(captures, dict):
            struct_nodes = captures.get('struct_def', [])
        else:
            # Old API returns list of (node, capture_name) tuples
            struct_nodes = [node for node, capture_name in captures if capture_name == 'struct_def']
        
        for node in struct_nodes:
            struct_def = self._parse_struct(node)
            if struct_def:
                self.structs.append(struct_def)

    def _parse_struct(self, node) -> Optional[ClassDefinition]:
        """
        Parse a struct_specifier node into a ClassDefinition.
        """
        # Get struct name
        name_node = node.child_by_field_name('name')
        if not name_node:
            # Anonymous struct
            name = f"<anonymous_struct_{node.start_point[0]}>"
        else:
            name = self._get_text(name_node)
        
        # Build qualified name (simplified - would need namespace tracking for full qualification)
        qualified_name = name
        
        # Check for template parameters
        template_params = []
        template_node = node.child_by_field_name('template_parameters')
        if template_node:
            template_params = self._parse_template_parameters(template_node)
        
        # Extract member variables
        member_variables = []
        body_node = node.child_by_field_name('body')
        if body_node:
            member_variables = self._parse_struct_members(body_node)
        
        # Create the ClassDefinition
        location = self._create_source_location(node)
        
        struct_def = ClassDefinition(
            name=name,
            qualified_name=qualified_name,
            kind='struct',
            location=location,
            member_variables=member_variables,
            template_params=template_params,
        )
        
        return struct_def

    def _parse_template_parameters(self, template_node) -> List:
        """Parse template parameters from a template_parameters node."""
        from cpp_analysis_datastructures import TemplateParameter
        
        params = []
        # Find type_parameter_declaration and parameter_declaration children
        for child in template_node.children:
            if child.type == 'type_parameter_declaration':
                # typename T or class T
                name_child = child.child_by_field_name('name')
                if name_child:
                    param_name = self._get_text(name_child)
                    params.append(TemplateParameter(name=param_name, is_type=True))
            elif child.type == 'parameter_declaration':
                # Non-type parameter like int N
                name_child = child.child_by_field_name('declarator')
                if name_child:
                    param_name = self._get_text(name_child)
                    params.append(TemplateParameter(name=param_name, is_type=False))
        
        return params

    def _parse_struct_members(self, body_node) -> List:
        """Parse member variables from a struct body."""
        from cpp_analysis_datastructures import MemberVariable
        
        members = []
        
        for child in body_node.children:
            if child.type in ('declaration', 'field_declaration'):
                member = self._parse_member_declaration(child, AccessSpecifier.PUBLIC)
                if member:
                    members.append(member)
        
        return members

    def _parse_member_declaration(self, node, default_access: AccessSpecifier = AccessSpecifier.PRIVATE) -> Optional[MemberVariable]:
        """Parse a member field declaration."""
        # Helper to get all descendants
        def get_descendants(n):
            result = []
            for child in n.children:
                result.append(child)
                result.extend(get_descendants(child))
            return result
        
        # Get the declarator (contains name and type info)
        declarator_node = None
        type_node = None
        
        for child in node.children:
            if child.type == 'field_identifier':
                declarator_node = child
            elif child.type in ('primitive_type', 'type_identifier', 'qualified_type', 
                               'pointer_type', 'reference_type', 'template_type'):
                type_node = child
        
        # Try to get name from different possible locations
        name = ""
        if declarator_node:
            name = self._get_text(declarator_node)
        else:
            # Try to find field_identifier in nested structure
            for child in get_descendants(node):
                if child.type == 'field_identifier':
                    name = self._get_text(child)
                    break
        
        if not name:
            return None
        
        # Get type
        type_ref = self._parse_type(node)
        
        # Determine access specifier based on context
        access = default_access
        
        # Check for static, const, mutable keywords
        is_static = False
        is_const = False
        is_mutable = False
        
        for child in node.children:
            keyword = self._get_text(child) if hasattr(child, 'type') and child.type in ('static', 'const', 'mutable') else ""
            if keyword == 'static':
                is_static = True
            elif keyword == 'const':
                is_const = True
            elif keyword == 'mutable':
                is_mutable = True
        
        location = self._create_source_location(node)
        
        return MemberVariable(
            name=name,
            type_ref=type_ref,
            access=access,
            is_static=is_static,
            is_const=is_const,
            is_mutable=is_mutable,
            location=location,
        )

    def _parse_type(self, node) -> TypeReference:
        """Parse a type from a node."""
        type_name = ""
        is_pointer = False
        is_reference = False
        is_const = False
        
        # Find type-related children
        for child in node.children:
            if child.type == 'primitive_type':
                type_name = self._get_text(child)
                if 'const' in type_name:
                    is_const = True
                    type_name = type_name.replace('const', '').strip()
            elif child.type == 'type_identifier':
                type_name = self._get_text(child)
            elif child.type == 'qualified_type':
                # Handle namespaced types like std::string
                type_name = self._get_text(child)
            elif child.type == 'pointer_type':
                is_pointer = True
                # Recursively get the base type
                inner_type = self._parse_type(child)
                type_name = inner_type.name
                is_const = is_const or inner_type.is_const
            elif child.type == 'reference_type':
                is_reference = True
                inner_type = self._parse_type(child)
                type_name = inner_type.name
            elif child.type == 'const':
                is_const = True
        
        if not type_name:
            type_name = "unknown"
        
        return TypeReference(
            name=type_name,
            is_pointer=is_pointer,
            is_reference=is_reference,
            is_const=is_const,
        )

    def _extract_macros(self, root_node) -> None:
        """
        Extract macro definitions from the AST.
        
        Tree-sitter C++ grammar uses 'preproc_def' for #define directives.
        """
        query = self.parser.language.query("""
            (preproc_def) @macro_def
            (preproc_function_def) @macro_func_def
        """)
        
        captures = query.captures(root_node)
        
        # New API returns a dict: {capture_name: [nodes]}
        if isinstance(captures, dict):
            macro_nodes = []
            for cap_name in ('macro_def', 'macro_func_def'):
                for node in captures.get(cap_name, []):
                    macro_nodes.append((node, cap_name))
        else:
            # Old API returns list of (node, capture_name) tuples
            macro_nodes = [(node, capture_name) for node, capture_name in captures 
                          if capture_name in ('macro_def', 'macro_func_def')]
        
        for node, capture_name in macro_nodes:
            is_func = capture_name == 'macro_func_def'
            macro_def = self._parse_macro(node, is_func)
            if macro_def:
                self.macros.append(macro_def)

    def _parse_macro(self, node, is_function: bool) -> Optional[MacroDefinition]:
        """Parse a preproc_def or preproc_function_def node."""
        # Get macro name
        name_node = node.child_by_field_name('name')
        if not name_node:
            return None
        
        name = self._get_text(name_node)
        
        # Get replacement text (value)
        value_node = node.child_by_field_name('value')
        replacement = ""
        if value_node:
            replacement = self._get_text(value_node)
        
        # For function-like macros, extract parameters
        parameters = []
        is_variadic = False
        
        if is_function:
            params_node = node.child_by_field_name('parameters')
            if params_node:
                for child in params_node.children:
                    if child.type == 'identifier':
                        parameters.append(self._get_text(child))
                    elif child.type == 'variadic_parameter':
                        is_variadic = True
        
        kind = 'function' if is_function else 'object'
        location = self._create_source_location(node)
        
        return MacroDefinition(
            name=name,
            kind=kind,
            replacement=replacement,
            location=location,
            parameters=parameters,
            is_variadic=is_variadic,
        )

    def _extract_global_variables(self, root_node) -> None:
        """
        Extract global variable declarations from the AST.
        
        Global variables are typically declaration nodes at translation_unit level
        or namespace level, not inside functions or classes.
        """
        # We look for declaration nodes that are direct children of translation_unit
        # or namespace_body, but not inside function bodies or class bodies
        
        self._extract_variables_recursive(root_node, is_global_context=True)

    def _extract_variables_recursive(self, node, is_global_context: bool, 
                                     current_namespace: Optional[str] = None) -> None:
        """Recursively extract variable declarations, tracking context."""
        
        node_type = node.type
        
        # Skip function bodies and class bodies - variables there are not global
        if node_type in ('function_definition', 'function_declarator', 
                         'class_specifier', 'struct_specifier', 'union_specifier'):
            return
        
        # Check for namespace
        if node_type == 'namespace_definition':
            name_node = node.child_by_field_name('name')
            ns_name = self._get_text(name_node) if name_node else "<anonymous>"
            new_ns = f"{current_namespace}::{ns_name}" if current_namespace else ns_name
            
            # Process namespace body
            for child in node.children:
                if child.type == 'namespace_body':
                    self._extract_variables_recursive(child, is_global_context=True, 
                                                       current_namespace=new_ns)
            return
        
        # Check for variable declarations in global context
        if is_global_context and node_type == 'declaration':
            var_decl = self._parse_variable_declaration(node, current_namespace)
            if var_decl:
                self.global_variables.append(var_decl)
        
        # Also check for linkagespec (extern "C" blocks)
        if node_type == 'linkage_specification':
            for child in node.children:
                if child.type in ('declaration', 'function_definition'):
                    if child.type == 'declaration':
                        var_decl = self._parse_variable_declaration(child, current_namespace)
                        if var_decl:
                            self.global_variables.append(var_decl)
        
        # Recurse into children
        for child in node.children:
            # Continue in global context for namespace_body and translation_unit
            new_global_context = is_global_context and (node_type in ('translation_unit', 'namespace_body'))
            self._extract_variables_recursive(child, new_global_context, current_namespace)

    def _parse_variable_declaration(self, node, namespace: Optional[str] = None) -> Optional[VariableDeclaration]:
        """Parse a declaration node into a VariableDeclaration."""
        # Get the declarator which contains the variable name
        declarator_node = None
        type_node = None
        
        for child in node.children:
            if child.type == 'declarator':
                declarator_node = child
                # Look for identifier inside declarator
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        break
            elif child.type in ('primitive_type', 'type_identifier', 'qualified_type',
                               'sized_type_specifier', 'type_specifier'):
                type_node = child
        
        # Extract variable name from declarator
        name = ""
        if declarator_node:
            for child in declarator_node.children:
                if child.type == 'identifier':
                    name = self._get_text(child)
                    break
        
        if not name:
            return None
        
        # Parse type
        type_ref = self._parse_type(node)
        
        # Check for storage class and other modifiers
        storage_class = StorageClass.NONE
        is_static = False
        is_extern = False
        is_const = False
        is_inline = False
        
        for child in node.children:
            if child.type == 'storage_class_specifier':
                spec = self._get_text(child)
                if spec == 'static':
                    storage_class = StorageClass.STATIC
                    is_static = True
                elif spec == 'extern':
                    storage_class = StorageClass.EXTERN
                    is_extern = True
                elif spec == 'register':
                    storage_class = StorageClass.REGISTER
                elif spec == 'mutable':
                    storage_class = StorageClass.MUTABLE
                elif spec == 'thread_local' or spec == 'constexpr':
                    storage_class = StorageClass.THREAD_LOCAL
            elif child.type == 'inline':
                is_inline = True
            elif child.type == 'const':
                is_const = True
            elif child.type == 'constexpr':
                is_const = True
        
        # Get initializer if present
        initializer = None
        is_initialized = False
        
        if declarator_node:
            for child in declarator_node.children:
                if child.type in ('initializer_list', 'call_expression', 
                                 'number_literal', 'string_literal', 'char_literal'):
                    initializer = self._get_text(child)
                    is_initialized = True
                    break
        
        location = self._create_source_location(node)
        
        return VariableDeclaration(
            name=name,
            type_ref=type_ref,
            scope=VariableScope.GLOBAL,
            location=location,
            storage_class=storage_class,
            is_const=is_const,
            is_extern=is_extern,
            is_static=is_static,
            is_inline=is_inline,
            initializer=initializer,
            is_initialized=is_initialized,
            parent_namespace=namespace,
        )

    def get_results(self) -> dict:
        """
        Get all parsed results.
        
        Returns:
            Dictionary containing functions, classes, structs, macros, and global_variables lists
        """
        return {
            'functions': self.functions,
            'classes': self.classes,
            'structs': self.structs,
            'macros': self.macros,
            'global_variables': self.global_variables,
        }


def parse_cpp_file(file_path: str) -> dict:
    """
    Convenience function to parse a C++ file and return results.
    
    Args:
        file_path: Path to the C++ source file
        
    Returns:
        Dictionary with 'functions', 'classes', 'structs', 'macros', and 'global_variables' keys
    """
    parser = CPPParser()
    parser.parse_file(file_path)
    return parser.get_results()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cpp_parser.py <file.cpp>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    results = parse_cpp_file(file_path)
    
    print(f"Parsed {file_path}:")
    print(f"  Functions: {len(results['functions'])}")
    for f in results['functions']:
        print(f"    - {f.name}({', '.join(p.name for p in f.parameters)}) -> {f.return_type.name} at line {f.location.start_line}")
    
    print(f"  Classes: {len(results['classes'])}")
    for c in results['classes']:
        print(f"    - {c.name} at line {c.location.start_line}")
    
    print(f"  Structs: {len(results['structs'])}")
    for s in results['structs']:
        print(f"    - {s.name} at line {s.location.start_line}")
    
    print(f"  Macros: {len(results['macros'])}")
    for m in results['macros']:
        print(f"    - {m.name} ({m.kind}) at line {m.location.start_line}")
    
    print(f"  Global Variables: {len(results['global_variables'])}")
    for v in results['global_variables']:
        print(f"    - {v.name} ({v.type_ref.name}) at line {v.location.start_line}")
