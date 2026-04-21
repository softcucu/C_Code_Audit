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
        self.structs: List[ClassDefinition] = []
        self.macros: List[MacroDefinition] = []
        self.global_variables: List[VariableDeclaration] = []
        
        # Current file being parsed
        self._current_file: str = ""
        self._source_lines: List[str] = []

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
        self.structs = []
        self.macros = []
        self.global_variables = []
        
        # Traverse the AST and extract entities
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
        self.structs = []
        self.macros = []
        self.global_variables = []
        
        # Traverse the AST and extract entities
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
                member = self._parse_member_declaration(child)
                if member:
                    members.append(member)
        
        return members

    def _parse_member_declaration(self, node) -> Optional:
        """Parse a member field declaration."""
        from cpp_analysis_datastructures import MemberVariable
        
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
        # In struct, default is public unless specified
        access = AccessSpecifier.PUBLIC
        
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
            Dictionary containing structs, macros, and global_variables lists
        """
        return {
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
        Dictionary with 'structs', 'macros', and 'global_variables' keys
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
    print(f"  Structs: {len(results['structs'])}")
    for s in results['structs']:
        print(f"    - {s.name} at line {s.location.start_line}")
    
    print(f"  Macros: {len(results['macros'])}")
    for m in results['macros']:
        print(f"    - {m.name} ({m.kind}) at line {m.location.start_line}")
    
    print(f"  Global Variables: {len(results['global_variables'])}")
    for v in results['global_variables']:
        print(f"    - {v.name} ({v.type_ref.name}) at line {v.location.start_line}")
