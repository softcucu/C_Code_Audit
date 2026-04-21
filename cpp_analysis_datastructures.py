"""
C++ Code Analysis Data Structures

This module defines the data structures for storing parsed C++ code information.
The design focuses on:
1. Completeness: Capturing all necessary information for control flow analysis,
   taint analysis, and vulnerability mining.
2. Memory efficiency: Using file paths + line numbers instead of storing full code.
3. Extensibility: Easy to add new fields or structures as needed.

Key entities captured:
- Functions (including methods, constructors, destructors, templates)
- Classes and Structs
- Unions and Enums
- Global/namespace variables
- Macro definitions
- Type definitions (typedef, using)
- Include directives
- Namespace declarations
- Template declarations
- Variable declarations (global, local, member)
- Control flow statements
- Expressions and operators
- Comments (for potential sensitive information)
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Set
from enum import Enum, auto
from pathlib import Path


class NodeType(Enum):
    """Types of AST nodes for categorization."""
    FUNCTION = auto()
    CLASS = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()
    VARIABLE = auto()
    MACRO = auto()
    TYPEDEF = auto()
    NAMESPACE = auto()
    TEMPLATE = auto()
    INCLUDE = auto()
    CONTROL_FLOW = auto()
    EXPRESSION = auto()
    STATEMENT = auto()
    COMMENT = auto()
    UNKNOWN = auto()


class StorageClass(Enum):
    """Storage class specifiers."""
    NONE = auto()
    STATIC = auto()
    EXTERN = auto()
    REGISTER = auto()
    MUTABLE = auto()
    THREAD_LOCAL = auto()


class AccessSpecifier(Enum):
    """Access specifiers for class members."""
    PUBLIC = auto()
    PROTECTED = auto()
    PRIVATE = auto()
    DEFAULT = auto()  # For struct (default public) or unspecified


class FunctionType(Enum):
    """Function type classification."""
    NORMAL = auto()
    CONSTRUCTOR = auto()
    DESTRUCTOR = auto()
    COPY_CONSTRUCTOR = auto()
    MOVE_CONSTRUCTOR = auto()
    COPY_ASSIGNMENT = auto()
    MOVE_ASSIGNMENT = auto()
    CONVERSION_OPERATOR = auto()
    VIRTUAL = auto()
    PURE_VIRTUAL = auto()
    OVERRIDE = auto()
    FINAL = auto()
    INLINE = auto()
    FRIEND = auto()
    STATIC = auto()
    CONSTEXPR = auto()
    CONSTEVAL = auto()
    CONSTINIT = auto()


class VariableScope(Enum):
    """Variable scope classification."""
    GLOBAL = auto()
    NAMESPACE = auto()
    CLASS_MEMBER = auto()
    FUNCTION_LOCAL = auto()
    BLOCK = auto()
    PARAMETER = auto()
    CAPTURED = auto()  # Lambda capture


@dataclass(slots=True)
class SourceLocation:
    """
    Represents a location in source code.
    Uses file path + line/column numbers for memory efficiency.
    """
    file_path: str  # Relative or absolute path to the source file
    start_line: int  # 1-based line number
    start_column: int  # 1-based column number
    end_line: int = 0  # 0 means same as start_line
    end_column: int = 0  # 0 means same as start_column
    
    def __post_init__(self):
        if self.end_line == 0:
            self.end_line = self.start_line
        if self.end_column == 0:
            self.end_column = self.start_column


@dataclass(slots=True)
class TypeReference:
    """
    Represents a type reference without storing full type definition.
    References can be resolved later using the type name and context.
    """
    name: str  # Type name (e.g., "int", "std::vector<T>", "MyClass*")
    is_pointer: bool = False
    is_reference: bool = False
    is_const: bool = False
    is_volatile: bool = False
    array_dimensions: List[int] = field(default_factory=list)  # Empty if not array
    template_args: List['TypeReference'] = field(default_factory=list)
    
    def get_base_type(self) -> str:
        """Get the base type name without pointers/references."""
        return self.name.rstrip('*&').strip()


@dataclass(slots=True)
class Parameter:
    """Function/method parameter."""
    name: str
    type_ref: TypeReference
    default_value: Optional[str] = None  # Store as string for memory efficiency
    is_variadic: bool = False  # For ... parameters
    storage_class: StorageClass = StorageClass.NONE


@dataclass(slots=True)
class TemplateParameter:
    """Template parameter (type or non-type)."""
    name: str
    is_type: bool = True  # True for typename T, False for non-type (e.g., int N)
    type_ref: Optional[TypeReference] = None  # For non-type parameters
    default_value: Optional[str] = None


@dataclass(slots=True)
class FunctionDefinition:
    """
    Represents a function or method definition.
    Stores minimal information with references to source location.
    """
    name: str
    qualified_name: str  # Full qualified name including namespace/class
    return_type: TypeReference
    location: SourceLocation
    parameters: List[Parameter] = field(default_factory=list)
    
    # Function properties
    function_type: FunctionType = FunctionType.NORMAL
    is_const: bool = False  # For const member functions
    is_volatile: bool = False
    is_noexcept: bool = False
    is_deleted: bool = False
    is_defaulted: bool = False
    is_explicit: bool = False  # For constructors
    is_inline: bool = False
    is_virtual: bool = False
    is_pure_virtual: bool = False
    is_override: bool = False
    is_final: bool = False
    is_static: bool = False
    is_friend: bool = False
    is_extern: bool = False
    is_constexpr: bool = False
    
    # Access specifier (for class methods)
    access: AccessSpecifier = AccessSpecifier.PUBLIC
    
    # Template info
    template_params: List[TemplateParameter] = field(default_factory=list)
    
    # Parent context
    parent_class: Optional[str] = None  # Class name if method
    parent_namespace: Optional[str] = None  # Namespace if applicable
    
    # Additional metadata
    calling_convention: Optional[str] = None  # e.g., __stdcall, __cdecl
    attributes: List[str] = field(default_factory=list)  # Custom attributes
    comments: List[str] = field(default_factory=list)  # Associated comments
    
    # For control flow analysis
    basic_blocks: List['BasicBlock'] = field(default_factory=list)
    cfg_edges: List[Tuple[int, int]] = field(default_factory=list)  # (from_block, to_block)
    
    # Unique identifier for cross-referencing
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = f"{self.qualified_name}@{self.location.file_path}:{self.location.start_line}"


@dataclass(slots=True)
class MemberVariable:
    """Class/struct/union member variable."""
    name: str
    type_ref: TypeReference
    access: AccessSpecifier = AccessSpecifier.PUBLIC
    is_static: bool = False
    is_const: bool = False
    is_volatile: bool = False
    is_mutable: bool = False
    default_initializer: Optional[str] = None  # Store as string
    bitfield_width: Optional[int] = None  # For bitfields
    location: Optional[SourceLocation] = None


@dataclass(slots=True)
class BaseClass:
    """Base class specification."""
    class_name: str
    access: AccessSpecifier = AccessSpecifier.PUBLIC
    is_virtual: bool = False


@dataclass(slots=True)
class ClassDefinition:
    """
    Represents a class, struct, or union definition.
    """
    name: str
    qualified_name: str
    kind: str  # 'class', 'struct', or 'union'
    
    # Location info
    location: SourceLocation
    
    # Members
    member_variables: List[MemberVariable] = field(default_factory=list)
    member_functions: List[str] = field(default_factory=list)  # Function IDs
    
    # Inheritance
    base_classes: List[BaseClass] = field(default_factory=list)
    
    # Template info
    template_params: List[TemplateParameter] = field(default_factory=list)
    
    # Properties
    is_abstract: bool = False
    is_final: bool = False
    is_polymorphic: bool = False  # Has virtual functions
    
    # Parent context
    parent_namespace: Optional[str] = None
    parent_class: Optional[str] = None  # For nested classes
    
    # Additional metadata
    attributes: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = f"{self.kind}:{self.qualified_name}@{self.location.file_path}:{self.location.start_line}"


@dataclass(slots=True)
class EnumDefinition:
    """Enum definition."""
    name: str
    qualified_name: str
    underlying_type: Optional[str] = None  # e.g., "int", "unsigned"
    is_scoped: bool = False  # enum class vs enum
    location: Optional[SourceLocation] = None
    
    # Enumerators
    enumerators: List[Tuple[str, Optional[str]]] = field(default_factory=list)  # (name, value)
    
    # Parent context
    parent_namespace: Optional[str] = None
    parent_class: Optional[str] = None
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            self.id = f"enum:{self.qualified_name}@{self.location.file_path if self.location else ''}"


@dataclass(slots=True)
class VariableDeclaration:
    """
    Global, namespace, or local variable declaration.
    """
    name: str
    type_ref: TypeReference
    scope: VariableScope = VariableScope.GLOBAL
    
    # Location info
    location: Optional[SourceLocation] = None
    
    # Properties
    storage_class: StorageClass = StorageClass.NONE
    is_const: bool = False
    is_volatile: bool = False
    is_extern: bool = False
    is_static: bool = False
    is_thread_local: bool = False
    is_inline: bool = False  # C++17 inline variables
    
    # Initialization
    initializer: Optional[str] = None  # Store as string
    is_initialized: bool = False
    
    # Parent context
    parent_function: Optional[str] = None  # Function ID if local
    parent_class: Optional[str] = None  # Class name if member
    parent_namespace: Optional[str] = None
    
    # Additional metadata
    attributes: List[str] = field(default_factory=list)
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            loc_str = f"{self.location.file_path}:{self.location.start_line}" if self.location else "unknown"
            self.id = f"var:{self.name}@{loc_str}"


@dataclass(slots=True)
class MacroDefinition:
    """Macro definition (#define)."""
    name: str
    kind: str  # 'object' or 'function'
    replacement: str  # Macro replacement text
    
    # Location info
    location: Optional[SourceLocation] = None
    
    # For function-like macros
    parameters: List[str] = field(default_factory=list)
    is_variadic: bool = False
    
    # Properties
    is_undef: bool = False  # True if this represents an #undef
    
    # Additional metadata
    condition: Optional[str] = None  # Conditional compilation condition if any
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            loc_str = f"{self.location.file_path}:{self.location.start_line}" if self.location else "unknown"
            self.id = f"macro:{self.name}@{loc_str}"


@dataclass(slots=True)
class TypeDefinition:
    """Type definition (typedef or using alias)."""
    name: str
    aliased_type: str  # The type being aliased
    kind: str  # 'typedef' or 'using'
    
    # Location info
    location: Optional[SourceLocation] = None
    
    # For using aliases with templates
    template_params: List[TemplateParameter] = field(default_factory=list)
    
    # Parent context
    parent_namespace: Optional[str] = None
    parent_class: Optional[str] = None
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            loc_str = f"{self.location.file_path}:{self.location.start_line}" if self.location else "unknown"
            self.id = f"type:{self.name}@{loc_str}"


@dataclass(slots=True)
class IncludeDirective:
    """#include directive."""
    path: str  # Included file path
    is_system: bool = False  # True for <>, false for ""
    location: Optional[SourceLocation] = None
    
    # Resolved path (if available)
    resolved_path: Optional[str] = None
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            loc_str = f"{self.location.file_path}:{self.location.start_line}" if self.location else "unknown"
            self.id = f"include:{self.path}@{loc_str}"


@dataclass(slots=True)
class NamespaceDefinition:
    """Namespace definition."""
    name: str
    qualified_name: str
    
    # Location info
    location: Optional[SourceLocation] = None
    
    # Child namespaces
    child_namespaces: List[str] = field(default_factory=list)  # Namespace IDs
    
    # Is anonymous namespace
    is_anonymous: bool = False
    is_inline: bool = False  # C++17 inline namespace
    
    # Parent context
    parent_namespace: Optional[str] = None
    
    # Unique identifier
    id: str = ""
    
    def __post_init__(self):
        if not self.id:
            loc_str = f"{self.location.file_path}:{self.location.start_line}" if self.location else "unknown"
            self.id = f"ns:{self.qualified_name}@{loc_str}"


@dataclass(slots=True)
class BasicBlock:
    """
    Basic block for control flow graph.
    Used in function definitions for CFG analysis.
    """
    id: int
    start_location: SourceLocation
    end_location: SourceLocation
    
    # Statements in this block (stored as strings for memory efficiency)
    statements: List[str] = field(default_factory=list)
    
    # Predecessors and successors
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    
    # Block type
    is_entry: bool = False
    is_exit: bool = False
    is_loop_header: bool = False
    loop_id: Optional[int] = None
    
    # Dominator info (for advanced analysis)
    dominator: Optional[int] = None
    dominated_blocks: List[int] = field(default_factory=list)


@dataclass(slots=True)
class ControlFlowStatement:
    """Control flow statement (if, for, while, switch, etc.)."""
    kind: str  # 'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break', 'continue', 'return', 'goto', 'try', 'catch', 'throw'
    location: SourceLocation
    
    # Condition expression (as string)
    condition: Optional[str] = None
    
    # Related blocks
    then_block: Optional[int] = None
    else_block: Optional[int] = None
    init_block: Optional[int] = None  # For for-loops
    update_block: Optional[int] = None  # For for-loops
    body_block: Optional[int] = None
    
    # For switch
    case_value: Optional[str] = None
    
    # For goto
    label: Optional[str] = None
    
    # For try-catch
    exception_type: Optional[str] = None
    exception_var: Optional[str] = None
    
    # Parent function
    parent_function: Optional[str] = None


@dataclass(slots=True)
class Comment:
    """Source code comment."""
    kind: str  # 'line', 'block', 'doc'
    content: str
    location: SourceLocation
    
    # Associated entity (if parseable)
    associated_entity: Optional[str] = None  # ID of associated function/class/etc.


@dataclass(slots=True)
class Literal:
    """Literal value (number, string, character, etc.)."""
    kind: str  # 'integer', 'float', 'string', 'character', 'boolean', 'nullptr', 'array', 'struct'
    value: str  # Store as string
    type_ref: Optional[TypeReference] = None
    location: Optional[SourceLocation] = None


@dataclass(slots=True)
class Expression:
    """Expression node."""
    kind: str  # 'binary', 'unary', 'call', 'member_access', 'array_access', 'cast', 'new', 'delete', 'lambda', etc.
    operator: Optional[str] = None
    operands: List[str] = field(default_factory=list)  # IDs of operand expressions
    type_ref: Optional[TypeReference] = None
    location: Optional[SourceLocation] = None
    
    # For function calls
    callee: Optional[str] = None  # Function name or ID
    
    # For member access
    object_expr: Optional[str] = None
    member_name: Optional[str] = None
    
    # For lambda
    captures: List[str] = field(default_factory=list)


@dataclass(slots=True)
class Label:
    """Goto label."""
    name: str
    location: SourceLocation
    parent_function: Optional[str] = None


@dataclass(slots=True)
class ExceptionSpecification:
    """Exception specification for functions."""
    kind: str  # 'throw', 'noexcept', 'none'
    types: List[str] = field(default_factory=list)  # Exception types for throw()
    is_noexcept_true: bool = False  # For noexcept(true)
    is_noexcept_false: bool = False  # For noexcept(false)


@dataclass(slots=True)
class Attribute:
    """C++11+ attribute."""
    name: str
    arguments: List[str] = field(default_factory=list)
    location: Optional[SourceLocation] = None


@dataclass(slots=True)
class TranslationUnit:
    """
    Represents a complete translation unit (source file).
    Top-level container for all parsed information.
    """
    file_path: str
    file_hash: Optional[str] = None  # For change detection
    
    # Top-level declarations
    functions: List[FunctionDefinition] = field(default_factory=list)
    classes: List[ClassDefinition] = field(default_factory=list)
    enums: List[EnumDefinition] = field(default_factory=list)
    variables: List[VariableDeclaration] = field(default_factory=list)
    macros: List[MacroDefinition] = field(default_factory=list)
    type_defs: List[TypeDefinition] = field(default_factory=list)
    includes: List[IncludeDirective] = field(default_factory=list)
    namespaces: List[NamespaceDefinition] = field(default_factory=list)
    
    # Indexes for fast lookup
    function_index: Dict[str, FunctionDefinition] = field(default_factory=dict)
    class_index: Dict[str, ClassDefinition] = field(default_factory=dict)
    variable_index: Dict[str, VariableDeclaration] = field(default_factory=dict)
    macro_index: Dict[str, MacroDefinition] = field(default_factory=dict)
    
    # Metadata
    language: str = "C++"
    standard: Optional[str] = None  # e.g., "C++17", "C++20"
    compiler: Optional[str] = None
    compile_flags: List[str] = field(default_factory=list)
    
    # Statistics
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    
    def build_indexes(self):
        """Build indexes for fast lookup."""
        self.function_index = {f.id: f for f in self.functions}
        self.class_index = {c.id: c for c in self.classes}
        self.variable_index = {v.id: v for v in self.variables}
        self.macro_index = {m.id: m for m in self.macros}


@dataclass(slots=True)
class AnalysisResult:
    """
    Container for analysis results (control flow, taint, vulnerabilities).
    This will be populated in subsequent analysis phases.
    """
    translation_unit: TranslationUnit
    
    # Control flow analysis results
    call_graph: Dict[str, List[str]] = field(default_factory=dict)  # caller -> [callees]
    cfg_by_function: Dict[str, List[BasicBlock]] = field(default_factory=dict)
    
    # Data flow analysis results
    reaching_definitions: Dict[str, Set[str]] = field(default_factory=dict)
    live_variables: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Taint analysis results
    tainted_sources: Set[str] = field(default_factory=set)
    tainted_sinks: Set[str] = field(default_factory=set)
    taint_paths: List[List[str]] = field(default_factory=list)
    
    # Vulnerability findings
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metrics
    cyclomatic_complexity: Dict[str, int] = field(default_factory=dict)
    lines_of_code: Dict[str, int] = field(default_factory=dict)


# Convenience type aliases
FunctionId = str
ClassId = str
VariableId = str
MacroId = str
NamespaceId = str
BlockId = int


def create_source_location(file_path: str, start_line: int, start_column: int = 1,
                          end_line: int = 0, end_column: int = 0) -> SourceLocation:
    """Helper function to create SourceLocation."""
    return SourceLocation(
        file_path=file_path,
        start_line=start_line,
        start_column=start_column,
        end_line=end_line,
        end_column=end_column
    )


def create_type_reference(name: str, is_pointer: bool = False, 
                         is_reference: bool = False,
                         is_const: bool = False) -> TypeReference:
    """Helper function to create TypeReference."""
    return TypeReference(
        name=name,
        is_pointer=is_pointer,
        is_reference=is_reference,
        is_const=is_const
    )
