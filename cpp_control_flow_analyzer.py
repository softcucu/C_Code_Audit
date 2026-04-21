#!/usr/bin/env python3
"""
C++ Control Flow Analyzer using Tree-sitter

This module analyzes the control flow structure of C++ functions using tree-sitter.
It extracts:
- Basic blocks
- Control flow statements (if, for, while, switch, etc.)
- Branches and jumps
- Loop structures
- Function call relationships
"""

from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
import json

try:
    import tree_sitter
    from tree_sitter import Language, Parser
    import tree_sitter_cpp
except ImportError as e:
    raise ImportError(
        "Please install required packages: pip install tree-sitter tree-sitter-cpp"
    ) from e


class CFGNodeType(Enum):
    """Types of nodes in the control flow graph."""
    ENTRY = auto()
    EXIT = auto()
    STATEMENT = auto()
    CONDITION = auto()
    LOOP_HEADER = auto()
    LOOP_BODY = auto()
    BRANCH = auto()
    SWITCH = auto()
    CASE = auto()
    RETURN = auto()
    BREAK = auto()
    CONTINUE = auto()
    GOTO = auto()
    LABEL = auto()
    CALL = auto()
    THROW = auto()
    CATCH = auto()


@dataclass
class CFGNode:
    """Represents a node in the control flow graph."""
    id: int
    node_type: CFGNodeType
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    code: str = ""
    label: Optional[str] = None  # For goto labels
    condition: Optional[str] = None  # For conditional statements
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.node_type.name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "code": self.code,
            "label": self.label,
            "condition": self.condition,
            "successors": self.successors,
            "predecessors": self.predecessors,
        }


@dataclass
class LoopInfo:
    """Information about a loop structure."""
    loop_type: str  # 'for', 'while', 'do_while'
    header_node_id: int
    body_node_ids: List[int] = field(default_factory=list)
    exit_node_id: Optional[int] = None
    continue_targets: List[int] = field(default_factory=list)
    break_targets: List[int] = field(default_factory=list)
    nesting_level: int = 0


@dataclass
class FunctionCFG:
    """Control Flow Graph for a function."""
    function_name: str
    qualified_name: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    return_type: str = "void"
    
    nodes: List[CFGNode] = field(default_factory=list)
    edges: List[Tuple[int, int]] = field(default_factory=list)
    entry_node_id: Optional[int] = None
    exit_node_id: Optional[int] = None
    
    loops: List[LoopInfo] = field(default_factory=list)
    branch_count: int = 0
    loop_count: int = 0
    cyclomatic_complexity: int = 1
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "function_name": self.function_name,
            "qualified_name": self.qualified_name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "parameters": self.parameters,
            "return_type": self.return_type,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [{"from": e[0], "to": e[1]} for e in self.edges],
            "entry_node_id": self.entry_node_id,
            "exit_node_id": self.exit_node_id,
            "loops": [
                {
                    "type": l.loop_type,
                    "header": l.header_node_id,
                    "body": l.body_node_ids,
                    "exit": l.exit_node_id,
                    "nesting_level": l.nesting_level,
                }
                for l in self.loops
            ],
            "branch_count": self.branch_count,
            "loop_count": self.loop_count,
            "cyclomatic_complexity": self.cyclomatic_complexity,
        }


class CPPControlFlowAnalyzer:
    """
    Analyzes control flow structure of C++ functions using tree-sitter.
    """
    
    def __init__(self):
        """Initialize the analyzer with tree-sitter C++ language."""
        language = tree_sitter.Language(tree_sitter_cpp.language())
        self.parser = tree_sitter.Parser(language)
        self._current_file: str = ""
        self._source_code: str = ""
        self._source_lines: List[str] = []
        
    def parse_file(self, file_path: str) -> List[FunctionCFG]:
        """
        Parse a C++ source file and extract control flow graphs for all functions.
        
        Args:
            file_path: Path to the C++ source file
            
        Returns:
            List of FunctionCFG objects for each function found
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        self._current_file = str(path.absolute())
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            self._source_code = f.read()
        
        self._source_lines = self._source_code.splitlines()
        
        tree = self.parser.parse(bytes(self._source_code, 'utf8'))
        root_node = tree.root_node
        
        return self._extract_function_cfgs(root_node)
    
    def parse_string(self, source_code: str, file_path: str = "<string>") -> List[FunctionCFG]:
        """
        Parse C++ source code from a string.
        
        Args:
            source_code: C++ source code as string
            file_path: Optional file path for location tracking
            
        Returns:
            List of FunctionCFG objects for each function found
        """
        self._current_file = file_path
        self._source_code = source_code
        self._source_lines = source_code.splitlines()
        
        tree = self.parser.parse(bytes(source_code, 'utf8'))
        root_node = tree.root_node
        
        return self._extract_function_cfgs(root_node)
    
    def _get_text(self, node) -> str:
        """Get the text content of a node."""
        return node.text.decode('utf-8') if isinstance(node.text, bytes) else node.text
    
    def _get_node_range(self, node) -> Tuple[int, int, int, int]:
        """Get start and end line/column for a node (1-based)."""
        start_point = node.start_point
        end_point = node.end_point
        return (
            start_point[0] + 1,  # start_line (1-based)
            start_point[1] + 1,  # start_column (1-based)
            end_point[0] + 1,    # end_line (1-based)
            end_point[1] + 1,    # end_column (1-based)
        )
    
    def _extract_function_cfgs(self, root_node) -> List[FunctionCFG]:
        """Extract control flow graphs for all functions in the AST."""
        query = self.parser.language.query("""
            (function_definition) @func_def
        """)
        
        captures = query.captures(root_node)
        
        if isinstance(captures, dict):
            func_nodes = captures.get('func_def', [])
        else:
            func_nodes = [node for node, capture_name in captures if capture_name == 'func_def']
        
        cfgs = []
        for node in func_nodes:
            cfg = self._build_function_cfg(node)
            if cfg:
                cfgs.append(cfg)
        
        return cfgs
    
    def _get_function_name(self, node) -> Tuple[str, str]:
        """Extract function name and qualified name."""
        declarator_node = node.child_by_field_name('declarator')
        if not declarator_node:
            return ("unknown", "unknown")
        
        name_node = None
        for child in declarator_node.children:
            if child.type == 'identifier':
                name_node = child
                break
            elif child.type == 'qualified_type':
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        name_node = grandchild
        
        if not name_node:
            return ("unknown", "unknown")
        
        name = self._get_text(name_node)
        qualified_name = name  # Could be extended to include namespace/class
        
        return (name, qualified_name)
    
    def _get_function_params(self, node) -> List[str]:
        """Extract parameter names."""
        params = []
        declarator_node = node.child_by_field_name('declarator')
        if not declarator_node:
            return params
        
        params_node = declarator_node.child_by_field_name('parameters')
        if not params_node:
            return params
        
        for child in params_node.children:
            if child.type == 'parameter_declaration':
                for grandchild in child.children:
                    if grandchild.type == 'identifier':
                        params.append(self._get_text(grandchild))
        
        return params
    
    def _get_return_type(self, node) -> str:
        """Extract return type."""
        type_node = node.child_by_field_name('type')
        if type_node:
            return self._get_text(type_node)
        return "void"
    
    def _build_function_cfg(self, node) -> Optional[FunctionCFG]:
        """Build control flow graph for a function."""
        name, qualified_name = self._get_function_name(node)
        start_line, start_col, end_line, end_col = self._get_node_range(node)
        params = self._get_function_params(node)
        return_type = self._get_return_type(node)
        
        cfg = FunctionCFG(
            function_name=name,
            qualified_name=qualified_name,
            start_line=start_line,
            end_line=end_line,
            parameters=params,
            return_type=return_type,
        )
        
        # Find function body
        body_node = node.child_by_field_name('body')
        if not body_node:
            # Function without body (declaration only)
            return cfg
        
        # Build CFG from function body
        node_counter = [0]  # Use list for mutable counter in nested function
        
        # Create entry node
        entry_node = CFGNode(
            id=node_counter[0],
            node_type=CFGNodeType.ENTRY,
            start_line=start_line,
            end_line=start_line,
            start_column=start_col,
            end_column=start_col,
            code=f"Entry: {name}",
        )
        cfg.nodes.append(entry_node)
        cfg.entry_node_id = entry_node.id
        node_counter[0] += 1
        
        # Create exit node (will be connected later)
        exit_node = CFGNode(
            id=node_counter[0],
            node_type=CFGNodeType.EXIT,
            start_line=end_line,
            end_line=end_line,
            start_column=start_col,
            end_column=end_col,
            code=f"Exit: {name}",
        )
        cfg.nodes.append(exit_node)
        cfg.exit_node_id = exit_node.id
        node_counter[0] += 1
        
        # Track loops and control flow
        loop_stack: List[LoopInfo] = []
        label_map: Dict[str, int] = {}  # label -> node_id mapping
        break_targets: List[int] = []  # Stack of break target node IDs
        continue_targets: List[int] = []  # Stack of continue target node IDs
        
        # Process function body recursively
        current_successors = [entry_node.id]
        
        def process_statement(stmt_node, successors: List[int]) -> List[int]:
            """Process a statement and return its exit successors."""
            nonlocal node_counter, cfg, loop_stack, break_targets, continue_targets
            
            if not stmt_node:
                return successors
            
            stmt_type = stmt_node.type
            
            # Skip certain node types
            if stmt_type in ('{', '}', ';'):
                return successors
            
            # Get statement code
            stmt_code = self._get_text(stmt_node)
            start_l, start_c, end_l, end_c = self._get_node_range(stmt_node)
            
            # Handle different statement types - check compound statement first
            if stmt_type == 'compound_statement':
                # Block statement - process children
                return self._process_compound_statement(
                    stmt_node, successors, node_counter, cfg, break_targets, continue_targets
                )
            
            elif stmt_type == 'if_statement':
                return self._process_if_statement(stmt_node, successors, node_counter, cfg)
            
            elif stmt_type == 'for_statement':
                loop_info, exit_node_id = self._process_for_statement(
                    stmt_node, successors, node_counter, cfg, len(loop_stack)
                )
                loop_stack.append(loop_info)
                cfg.loops.append(loop_info)
                cfg.loop_count += 1
                break_targets.append(loop_info.exit_node_id or exit_node_id)
                continue_targets.append(loop_info.header_node_id)
                result = [exit_node_id]
                return result
            
            elif stmt_type == 'while_statement':
                loop_info, exit_node_id = self._process_while_statement(
                    stmt_node, successors, node_counter, cfg, len(loop_stack)
                )
                loop_stack.append(loop_info)
                cfg.loops.append(loop_info)
                cfg.loop_count += 1
                break_targets.append(loop_info.exit_node_id or exit_node_id)
                continue_targets.append(loop_info.header_node_id)
                return [exit_node_id]
            
            elif stmt_type == 'do_statement':
                loop_info, exit_node_id = self._process_do_statement(
                    stmt_node, successors, node_counter, cfg, len(loop_stack)
                )
                loop_stack.append(loop_info)
                cfg.loops.append(loop_info)
                cfg.loop_count += 1
                break_targets.append(loop_info.exit_node_id or exit_node_id)
                continue_targets.append(loop_info.header_node_id)
                return [exit_node_id]
            
            elif stmt_type == 'switch_statement':
                return self._process_switch_statement(
                    stmt_node, successors, node_counter, cfg
                )
            
            elif stmt_type == 'return_statement':
                return self._process_return_statement(
                    stmt_node, successors, node_counter, cfg
                )
            
            elif stmt_type == 'break_statement':
                return self._process_break_statement(
                    stmt_node, successors, node_counter, cfg, break_targets
                )
            
            elif stmt_type == 'continue_statement':
                return self._process_continue_statement(
                    stmt_node, successors, node_counter, cfg, continue_targets
                )
            
            elif stmt_type == 'goto_statement':
                return self._process_goto_statement(
                    stmt_node, successors, node_counter, cfg, label_map
                )
            
            elif stmt_type == 'labeled_statement':
                return self._process_labeled_statement(
                    stmt_node, successors, node_counter, cfg, label_map
                )
            
            elif stmt_type == 'expression_statement':
                # Check if it contains a function call
                has_call = False
                for child in stmt_node.children:
                    if child.type == 'call_expression':
                        has_call = True
                        break
                
                if has_call:
                    node_id = node_counter[0]
                    cfg_node = CFGNode(
                        id=node_id,
                        node_type=CFGNodeType.CALL,
                        start_line=start_l,
                        end_line=end_l,
                        start_column=start_c,
                        end_column=end_c,
                        code=stmt_code,
                    )
                    cfg.nodes.append(cfg_node)
                    node_counter[0] += 1
                    
                    for pred in successors:
                        cfg.nodes[pred].successors.append(node_id)
                        cfg_node.predecessors.append(pred)
                        cfg.edges.append((pred, node_id))
                    
                    return [node_id]
                else:
                    # Regular statement
                    node_id = node_counter[0]
                    cfg_node = CFGNode(
                        id=node_id,
                        node_type=CFGNodeType.STATEMENT,
                        start_line=start_l,
                        end_line=end_l,
                        start_column=start_c,
                        end_column=end_c,
                        code=stmt_code,
                    )
                    cfg.nodes.append(cfg_node)
                    node_counter[0] += 1
                    
                    for pred in successors:
                        if pred < len(cfg.nodes):
                            cfg.nodes[pred].successors.append(node_id)
                            cfg_node.predecessors.append(pred)
                            cfg.edges.append((pred, node_id))
                    
                    return [node_id]
            
            else:
                # Default: treat as statement
                node_id = node_counter[0]
                cfg_node = CFGNode(
                    id=node_id,
                    node_type=CFGNodeType.STATEMENT,
                    start_line=start_l,
                    end_line=end_l,
                    start_column=start_c,
                    end_column=end_c,
                    code=stmt_code,
                )
                cfg.nodes.append(cfg_node)
                node_counter[0] += 1
                
                for pred in successors:
                    if pred < len(cfg.nodes):
                        cfg.nodes[pred].successors.append(node_id)
                        cfg_node.predecessors.append(pred)
                        cfg.edges.append((pred, node_id))
                
                return [node_id]
        
        # Process the function body
        body_successors = process_statement(body_node, [entry_node.id])
        
        # Connect final statements to exit node
        for node_id in body_successors:
            if node_id < len(cfg.nodes):
                cfg.nodes[node_id].successors.append(exit_node.id)
                exit_node.predecessors.append(node_id)
                cfg.edges.append((node_id, exit_node.id))
        
        # Calculate cyclomatic complexity
        # M = E - N + 2P where E=edges, N=nodes, P=connected components (usually 1)
        # Or simpler: M = number of decision points + 1
        decision_points = cfg.branch_count + cfg.loop_count
        cfg.cyclomatic_complexity = decision_points + 1
        
        return cfg
    
    def _process_if_statement(self, node, successors: List[int], 
                              node_counter: List[int], cfg: FunctionCFG) -> List[int]:
        """Process an if statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        # Get condition
        condition_node = node.child_by_field_name('condition')
        condition = self._get_text(condition_node) if condition_node else ""
        
        # Create condition node
        cond_node_id = node_counter[0]
        cond_node = CFGNode(
            id=cond_node_id,
            node_type=CFGNodeType.CONDITION,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=f"if ({condition})",
            condition=condition,
        )
        cfg.nodes.append(cond_node)
        node_counter[0] += 1
        
        # Connect predecessors to condition
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(cond_node_id)
                cond_node.predecessors.append(pred)
                cfg.edges.append((pred, cond_node_id))
        
        cfg.branch_count += 1
        
        # Get then and else branches
        then_node = node.child_by_field_name('consequence')
        else_node = node.child_by_field_name('alternative')
        
        # Process then branch
        then_exit = []
        if then_node:
            then_exit = self._process_statement_recursive(then_node, [cond_node_id], 
                                                          node_counter, cfg)
        
        # Process else branch
        else_exit = []
        if else_node:
            else_exit = self._process_statement_recursive(else_node, [cond_node_id],
                                                          node_counter, cfg)
        else:
            # No else branch - condition false goes directly to successors
            else_exit = [cond_node_id]
        
        # Merge exits
        result = []
        if then_exit:
            result.extend(then_exit)
        if else_exit:
            result.extend(else_exit)
        
        if not result:
            result = [cond_node_id]
        
        return result
    
    def _process_for_statement(self, node, successors: List[int],
                               node_counter: List[int], cfg: FunctionCFG,
                               nesting_level: int) -> Tuple[LoopInfo, int]:
        """Process a for loop."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        # Get initializer, condition, update
        init_node = node.child_by_field_name('initializer')
        condition_node = node.child_by_field_name('condition')
        update_node = node.child_by_field_name('update')
        body_node = node.child_by_field_name('body')
        
        condition = self._get_text(condition_node) if condition_node else "true"
        
        # Create loop header node
        header_id = node_counter[0]
        header_code = f"for ({self._get_text(init_node) if init_node else ''}; {condition}; {self._get_text(update_node) if update_node else ''})"
        header_node = CFGNode(
            id=header_id,
            node_type=CFGNodeType.LOOP_HEADER,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=header_code.strip(),
            condition=condition,
        )
        cfg.nodes.append(header_node)
        node_counter[0] += 1
        
        # Connect predecessors to header
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(header_id)
                header_node.predecessors.append(pred)
                cfg.edges.append((pred, header_id))
        
        # Create exit node for loop
        exit_id = node_counter[0]
        exit_node = CFGNode(
            id=exit_id,
            node_type=CFGNodeType.STATEMENT,
            start_line=end_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code="/* loop exit */",
        )
        cfg.nodes.append(exit_node)
        node_counter[0] += 1
        
        # Process loop body
        body_exit = []
        body_node_ids = []
        if body_node:
            body_exit = self._process_statement_recursive(body_node, [header_id],
                                                          node_counter, cfg)
            # Collect body node IDs
            for nid in body_exit:
                body_node_ids.append(nid)
        
        # Connect body exit back to header (for continue/normal flow)
        for nid in body_exit:
            if nid < len(cfg.nodes):
                cfg.nodes[nid].successors.append(header_id)
                header_node.predecessors.append(nid)
                cfg.edges.append((nid, header_id))
        
        # Connect condition false to exit
        cfg.edges.append((header_id, exit_id))
        exit_node.predecessors.append(header_id)
        header_node.successors.append(exit_id)
        
        loop_info = LoopInfo(
            loop_type='for',
            header_node_id=header_id,
            body_node_ids=body_node_ids,
            exit_node_id=exit_id,
            nesting_level=nesting_level,
        )
        
        return (loop_info, exit_id)
    
    def _process_while_statement(self, node, successors: List[int],
                                  node_counter: List[int], cfg: FunctionCFG,
                                  nesting_level: int) -> Tuple[LoopInfo, int]:
        """Process a while loop."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        condition_node = node.child_by_field_name('condition')
        body_node = node.child_by_field_name('body')
        condition = self._get_text(condition_node) if condition_node else "true"
        
        # Create loop header node
        header_id = node_counter[0]
        header_node = CFGNode(
            id=header_id,
            node_type=CFGNodeType.LOOP_HEADER,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=f"while ({condition})",
            condition=condition,
        )
        cfg.nodes.append(header_node)
        node_counter[0] += 1
        
        # Connect predecessors to header
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(header_id)
                header_node.predecessors.append(pred)
                cfg.edges.append((pred, header_id))
        
        # Create exit node
        exit_id = node_counter[0]
        exit_node = CFGNode(
            id=exit_id,
            node_type=CFGNodeType.STATEMENT,
            start_line=end_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code="/* loop exit */",
        )
        cfg.nodes.append(exit_node)
        node_counter[0] += 1
        
        # Process body
        body_exit = []
        body_node_ids = []
        if body_node:
            body_exit = self._process_statement_recursive(body_node, [header_id],
                                                          node_counter, cfg)
            for nid in body_exit:
                body_node_ids.append(nid)
        
        # Connect body exit back to header
        for nid in body_exit:
            if nid < len(cfg.nodes):
                cfg.nodes[nid].successors.append(header_id)
                header_node.predecessors.append(nid)
                cfg.edges.append((nid, header_id))
        
        # Connect condition false to exit
        cfg.edges.append((header_id, exit_id))
        exit_node.predecessors.append(header_id)
        header_node.successors.append(exit_id)
        
        loop_info = LoopInfo(
            loop_type='while',
            header_node_id=header_id,
            body_node_ids=body_node_ids,
            exit_node_id=exit_id,
            nesting_level=nesting_level,
        )
        
        return (loop_info, exit_id)
    
    def _process_do_statement(self, node, successors: List[int],
                               node_counter: List[int], cfg: FunctionCFG,
                               nesting_level: int) -> Tuple[LoopInfo, int]:
        """Process a do-while loop."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        condition_node = node.child_by_field_name('condition')
        body_node = node.child_by_field_name('body')
        condition = self._get_text(condition_node) if condition_node else "true"
        
        # Create loop header node (at the condition for do-while)
        header_id = node_counter[0]
        header_node = CFGNode(
            id=header_id,
            node_type=CFGNodeType.LOOP_HEADER,
            start_line=end_l,  # Condition is at the end
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=f"while ({condition})",
            condition=condition,
        )
        cfg.nodes.append(header_node)
        node_counter[0] += 1
        
        # Create exit node
        exit_id = node_counter[0]
        exit_node = CFGNode(
            id=exit_id,
            node_type=CFGNodeType.STATEMENT,
            start_line=end_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code="/* loop exit */",
        )
        cfg.nodes.append(exit_node)
        node_counter[0] += 1
        
        # Process body first (do-while executes body before condition)
        body_exit = []
        body_node_ids = []
        if body_node:
            body_exit = self._process_statement_recursive(body_node, successors,
                                                          node_counter, cfg)
            for nid in body_exit:
                body_node_ids.append(nid)
        
        # Connect body to header (condition check)
        for nid in body_exit:
            if nid < len(cfg.nodes):
                cfg.nodes[nid].successors.append(header_id)
                header_node.predecessors.append(nid)
                cfg.edges.append((nid, header_id))
        
        # Connect predecessors to body entry
        for pred in successors:
            if pred < len(cfg.nodes):
                # Find first body node and connect
                if body_node_ids:
                    first_body = body_node_ids[0]
                    cfg.nodes[pred].successors.append(first_body)
                    cfg.nodes[first_body].predecessors.append(pred)
                    cfg.edges.append((pred, first_body))
        
        # Connect condition to body (true) and exit (false)
        cfg.edges.append((header_id, body_node_ids[0] if body_node_ids else exit_id))
        cfg.edges.append((header_id, exit_id))
        if body_node_ids:
            cfg.nodes[body_node_ids[0]].predecessors.append(header_id)
        exit_node.predecessors.append(header_id)
        header_node.successors.extend([body_node_ids[0] if body_node_ids else exit_id, exit_id])
        
        loop_info = LoopInfo(
            loop_type='do_while',
            header_node_id=header_id,
            body_node_ids=body_node_ids,
            exit_node_id=exit_id,
            nesting_level=nesting_level,
        )
        
        return (loop_info, exit_id)
    
    def _process_switch_statement(self, node, successors: List[int],
                                   node_counter: List[int], cfg: FunctionCFG) -> List[int]:
        """Process a switch statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        condition_node = node.child_by_field_name('condition')
        condition = self._get_text(condition_node) if condition_node else ""
        
        # Create switch node
        switch_id = node_counter[0]
        switch_node = CFGNode(
            id=switch_id,
            node_type=CFGNodeType.SWITCH,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=f"switch ({condition})",
            condition=condition,
        )
        cfg.nodes.append(switch_node)
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(switch_id)
                switch_node.predecessors.append(pred)
                cfg.edges.append((pred, switch_id))
        
        cfg.branch_count += 1  # Switch counts as one decision point
        
        # Process body (which contains case labels)
        body_node = node.child_by_field_name('body')
        case_exits = []
        
        if body_node:
            case_exits = self._process_statement_recursive(body_node, [switch_id],
                                                           node_counter, cfg)
        
        # Create merge node after switch
        merge_id = node_counter[0]
        merge_node = CFGNode(
            id=merge_id,
            node_type=CFGNodeType.STATEMENT,
            start_line=end_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code="/* switch end */",
        )
        cfg.nodes.append(merge_node)
        node_counter[0] += 1
        
        # Connect all case exits to merge
        for eid in case_exits:
            if eid < len(cfg.nodes):
                cfg.edges.append((eid, merge_id))
                merge_node.predecessors.append(eid)
                cfg.nodes[eid].successors.append(merge_id)
        
        return [merge_id]
    
    def _process_return_statement(self, node, successors: List[int],
                                   node_counter: List[int], cfg: FunctionCFG) -> List[int]:
        """Process a return statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        code = self._get_text(node)
        
        return_id = node_counter[0]
        return_node = CFGNode(
            id=return_id,
            node_type=CFGNodeType.RETURN,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=code,
        )
        cfg.nodes.append(return_node)
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(return_id)
                return_node.predecessors.append(pred)
                cfg.edges.append((pred, return_id))
        
        # Return doesn't continue to normal successors
        return []
    
    def _process_break_statement(self, node, successors: List[int],
                                  node_counter: List[int], cfg: FunctionCFG,
                                  break_targets: List[int]) -> List[int]:
        """Process a break statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        code = self._get_text(node)
        
        break_id = node_counter[0]
        break_node = CFGNode(
            id=break_id,
            node_type=CFGNodeType.BREAK,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=code,
        )
        cfg.nodes.append(break_node)
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(break_id)
                break_node.predecessors.append(pred)
                cfg.edges.append((pred, break_id))
        
        # Break jumps to innermost loop/switch exit
        if break_targets:
            target = break_targets[-1]
            cfg.edges.append((break_id, target))
            if target < len(cfg.nodes):
                cfg.nodes[target].predecessors.append(break_id)
        
        return []
    
    def _process_continue_statement(self, node, successors: List[int],
                                     node_counter: List[int], cfg: FunctionCFG,
                                     continue_targets: List[int]) -> List[int]:
        """Process a continue statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        code = self._get_text(node)
        
        cont_id = node_counter[0]
        cont_node = CFGNode(
            id=cont_id,
            node_type=CFGNodeType.CONTINUE,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=code,
        )
        cfg.nodes.append(cont_node)
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(cont_id)
                cont_node.predecessors.append(pred)
                cfg.edges.append((pred, cont_id))
        
        # Continue jumps to innermost loop continue target
        if continue_targets:
            target = continue_targets[-1]
            cfg.edges.append((cont_id, target))
            if target < len(cfg.nodes):
                cfg.nodes[target].predecessors.append(cont_id)
        
        return []
    
    def _process_goto_statement(self, node, successors: List[int],
                                 node_counter: List[int], cfg: FunctionCFG,
                                 label_map: Dict[str, int]) -> List[int]:
        """Process a goto statement."""
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        code = self._get_text(node)
        
        # Extract label name
        label_name = ""
        for child in node.children:
            if child.type == 'identifier':
                label_name = self._get_text(child)
                break
        
        goto_id = node_counter[0]
        goto_node = CFGNode(
            id=goto_id,
            node_type=CFGNodeType.GOTO,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=code,
            label=label_name,
        )
        cfg.nodes.append(goto_node)
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(goto_id)
                goto_node.predecessors.append(pred)
                cfg.edges.append((pred, goto_id))
        
        # Goto jumps to labeled statement (may not be processed yet)
        # Store for later resolution if needed
        return []
    
    def _process_labeled_statement(self, node, successors: List[int],
                                    node_counter: List[int], cfg: FunctionCFG,
                                    label_map: Dict[str, int]) -> List[int]:
        """Process a labeled statement."""
        # Get label name
        label_name = ""
        for child in node.children:
            if child.type == 'statement_identifier':
                label_name = self._get_text(child)
                break
        
        start_l, start_c, end_l, end_c = self._get_node_range(node)
        
        # Create label node
        label_id = node_counter[0]
        label_node = CFGNode(
            id=label_id,
            node_type=CFGNodeType.LABEL,
            start_line=start_l,
            end_line=end_l,
            start_column=start_c,
            end_column=end_c,
            code=f"{label_name}:",
            label=label_name,
        )
        cfg.nodes.append(label_node)
        label_map[label_name] = label_id
        node_counter[0] += 1
        
        # Connect predecessors
        for pred in successors:
            if pred < len(cfg.nodes):
                cfg.nodes[pred].successors.append(label_id)
                label_node.predecessors.append(pred)
                cfg.edges.append((pred, label_id))
        
        # Process the labeled statement
        stmt_node = node.child_by_field_name('value')
        if stmt_node:
            return self._process_statement_recursive(stmt_node, [label_id],
                                                     node_counter, cfg)
        
        return [label_id]
    
    def _process_compound_statement(self, node, successors: List[int],
                                     node_counter: List[int], cfg: FunctionCFG,
                                     break_targets: List[int],
                                     continue_targets: List[int]) -> List[int]:
        """Process a compound statement (block)."""
        current_succ = successors
        
        for child in node.children:
            if child.type not in ('{', '}'):
                current_succ = self._process_statement_recursive(
                    child, current_succ, node_counter, cfg
                )
        
        return current_succ
    
    def _process_statement_recursive(self, node, successors: List[int],
                                      node_counter: List[int], cfg: FunctionCFG) -> List[int]:
        """Recursively process a statement node."""
        if not node:
            return successors
        
        stmt_type = node.type
        
        # Handle different statement types
        if stmt_type == 'if_statement':
            return self._process_if_statement(node, successors, node_counter, cfg)
        
        elif stmt_type == 'for_statement':
            # Simplified - just process as block for now
            body_node = node.child_by_field_name('body')
            if body_node:
                return self._process_statement_recursive(body_node, successors,
                                                         node_counter, cfg)
            return successors
        
        elif stmt_type == 'while_statement':
            body_node = node.child_by_field_name('body')
            if body_node:
                return self._process_statement_recursive(body_node, successors,
                                                         node_counter, cfg)
            return successors
        
        elif stmt_type == 'do_statement':
            body_node = node.child_by_field_name('body')
            if body_node:
                return self._process_statement_recursive(body_node, successors,
                                                         node_counter, cfg)
            return successors
        
        elif stmt_type == 'switch_statement':
            return self._process_switch_statement(node, successors, node_counter, cfg)
        
        elif stmt_type == 'return_statement':
            return self._process_return_statement(node, successors, node_counter, cfg)
        
        elif stmt_type == 'break_statement':
            return self._process_break_statement(node, successors, node_counter, cfg, [])
        
        elif stmt_type == 'continue_statement':
            return self._process_continue_statement(node, successors, node_counter, cfg, [])
        
        elif stmt_type == 'compound_statement':
            return self._process_compound_statement(node, successors, node_counter, cfg, [], [])
        
        elif stmt_type == 'expression_statement':
            start_l, start_c, end_l, end_c = self._get_node_range(node)
            code = self._get_text(node)
            
            node_id = node_counter[0]
            cfg_node = CFGNode(
                id=node_id,
                node_type=CFGNodeType.STATEMENT,
                start_line=start_l,
                end_line=end_l,
                start_column=start_c,
                end_column=end_c,
                code=code,
            )
            cfg.nodes.append(cfg_node)
            node_counter[0] += 1
            
            for pred in successors:
                if pred < len(cfg.nodes):
                    cfg.nodes[pred].successors.append(node_id)
                    cfg_node.predecessors.append(pred)
                    cfg.edges.append((pred, node_id))
            
            return [node_id]
        
        else:
            # Default handling
            start_l, start_c, end_l, end_c = self._get_node_range(node)
            code = self._get_text(node)
            
            node_id = node_counter[0]
            cfg_node = CFGNode(
                id=node_id,
                node_type=CFGNodeType.STATEMENT,
                start_line=start_l,
                end_line=end_l,
                start_column=start_c,
                end_column=end_c,
                code=code,
            )
            cfg.nodes.append(cfg_node)
            node_counter[0] += 1
            
            for pred in successors:
                if pred < len(cfg.nodes):
                    cfg.nodes[pred].successors.append(node_id)
                    cfg_node.predecessors.append(pred)
                    cfg.edges.append((pred, node_id))
            
            return [node_id]
    
    def print_cfg_summary(self, cfg: FunctionCFG) -> None:
        """Print a summary of the control flow graph."""
        print(f"\n{'='*60}")
        print(f"Function: {cfg.qualified_name}")
        print(f"Location: lines {cfg.start_line}-{cfg.end_line}")
        print(f"Parameters: {', '.join(cfg.parameters) if cfg.parameters else 'None'}")
        print(f"Return Type: {cfg.return_type}")
        print(f"{'='*60}")
        print(f"Nodes: {len(cfg.nodes)}")
        print(f"Edges: {len(cfg.edges)}")
        print(f"Branch Count: {cfg.branch_count}")
        print(f"Loop Count: {cfg.loop_count}")
        print(f"Cyclomatic Complexity: {cfg.cyclomatic_complexity}")
        
        if cfg.loops:
            print(f"\nLoops:")
            for i, loop in enumerate(cfg.loops):
                print(f"  Loop {i+1}: {loop.loop_type} (header: node {loop.header_node_id}, nesting: {loop.nesting_level})")
        
        print(f"\nControl Flow Nodes:")
        for node in cfg.nodes:
            node_type_str = node.node_type.name
            if node.condition:
                print(f"  [{node.id}] {node_type_str}: {node.code[:50]}... (cond: {node.condition})")
            else:
                print(f"  [{node.id}] {node_type_str}: {node.code[:60]}")
    
    def export_to_json(self, cfgs: List[FunctionCFG], output_path: str) -> None:
        """Export control flow graphs to JSON file."""
        data = {
            "functions": [cfg.to_dict() for cfg in cfgs],
            "file": self._current_file,
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        print(f"\nControl flow graphs exported to: {output_path}")


def main():
    """Main function to demonstrate the control flow analyzer."""
    import sys
    
    # Sample C++ code with various control flow structures
    sample_code = """
#include <iostream>

int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

int findMax(int arr[], int size) {
    int max = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

void processNumber(int num) {
    switch (num % 3) {
        case 0:
            std::cout << "Divisible by 3" << std::endl;
            break;
        case 1:
            std::cout << "Remainder 1" << std::endl;
            break;
        default:
            std::cout << "Remainder 2" << std::endl;
    }
}

int whileExample(int n) {
    int sum = 0;
    while (n > 0) {
        if (n % 2 == 0) {
            sum += n;
        }
        n--;
    }
    return sum;
}

int doWhileExample(int n) {
    int count = 0;
    do {
        count++;
        n /= 10;
    } while (n > 0);
    return count;
}

void gotoExample(int n) {
    if (n < 0) {
        goto negative;
    }
    std::cout << "Positive" << std::endl;
    return;
    
negative:
    std::cout << "Negative" << std::endl;
}

int nestedLoops(int rows, int cols) {
    int total = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (i == j) {
                continue;
            }
            if (i + j > 10) {
                break;
            }
            total++;
        }
    }
    return total;
}
"""
    
    analyzer = CPPControlFlowAnalyzer()
    
    # Parse the sample code
    print("Parsing C++ code and extracting control flow graphs...")
    cfgs = analyzer.parse_string(sample_code, "sample.cpp")
    
    # Print summaries for each function
    for cfg in cfgs:
        analyzer.print_cfg_summary(cfg)
    
    # Export to JSON
    analyzer.export_to_json(cfgs, "control_flow_analysis.json")
    
    # Also analyze test_sample.cpp if it exists
    test_file = Path("test_sample.cpp")
    if test_file.exists():
        print(f"\n\nAnalyzing {test_file}...")
        cfgs2 = analyzer.parse_file(str(test_file))
        for cfg in cfgs2:
            analyzer.print_cfg_summary(cfg)
        analyzer.export_to_json(cfgs2, "test_sample_cfg.json")
    
    print("\n\nAnalysis complete!")


if __name__ == "__main__":
    main()
