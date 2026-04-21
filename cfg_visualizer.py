#!/usr/bin/env python3
"""
C++ Control Flow Graph Visualizer

This module provides visualization capabilities for C++ control flow graphs,
showing the execution relationships between basic blocks.

Features:
- Text-based CFG visualization with arrows showing execution flow
- DOT format export for Graphviz rendering
- Detailed basic block relationship display
- Loop and branch highlighting
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass

# Import from the main analyzer
try:
    from cpp_control_flow_analyzer import (
        CPPControlFlowAnalyzer, 
        FunctionCFG, 
        CFGNode,
        CFGNodeType
    )
except ImportError as e:
    raise ImportError(
        "Please ensure cpp_control_flow_analyzer.py is in the same directory"
    ) from e


@dataclass
class BasicBlock:
    """Represents a basic block in the CFG."""
    block_id: int
    node_ids: List[int]
    entry_node: CFGNode
    exit_node: CFGNode
    successors: List[int]  # Block IDs
    predecessors: List[int]  # Block IDs
    block_type: str = "NORMAL"
    
    def __str__(self):
        return f"Block_{self.block_id}"


class CFGVisualizer:
    """
    Visualizes control flow graphs showing basic block relationships.
    """
    
    def __init__(self, analyzer: CPPControlFlowAnalyzer):
        self.analyzer = analyzer
        
    def print_cfg_text(self, cfg: FunctionCFG, show_code: bool = True, max_code_len: int = 40):
        """
        Print a text-based visualization of the CFG.
        
        Args:
            cfg: FunctionCFG to visualize
            show_code: Whether to show code snippets
            max_code_len: Maximum length of code to display
        """
        print("\n" + "=" * 80)
        print(f"CONTROL FLOW GRAPH: {cfg.function_name}")
        print("=" * 80)
        print(f"Location: lines {cfg.start_line}-{cfg.end_line}")
        print(f"Parameters: {', '.join(cfg.parameters)}")
        print(f"Return Type: {cfg.return_type}")
        print(f"Cyclomatic Complexity: {cfg.cyclomatic_complexity}")
        print(f"Nodes: {len(cfg.nodes)}, Edges: {len(cfg.edges)}")
        print("=" * 80)
        
        # Build node lookup
        node_map = {node.id: node for node in cfg.nodes}
        
        # Print all nodes with their connections
        print("\n📊 BASIC BLOCKS AND EXECUTION FLOW:\n")
        print("-" * 80)
        
        for node in cfg.nodes:
            # Format node type with emoji
            type_emoji = self._get_type_emoji(node.node_type)
            type_str = f"{type_emoji} {node.node_type.name}"
            
            # Format code snippet
            code_display = ""
            if show_code and node.code:
                code = node.code.replace('\n', ' ').strip()
                if len(code) > max_code_len:
                    code = code[:max_code_len-3] + "..."
                code_display = f"\n       Code: {code}"
            
            # Format condition if present
            cond_display = ""
            if node.condition:
                cond = node.condition.replace('\n', ' ').strip()
                if len(cond) > 50:
                    cond = cond[:47] + "..."
                cond_display = f"\n       Condition: {cond}"
            
            # Format successors
            succ_str = ", ".join([f"N{s}" for s in node.successors]) if node.successors else "None"
            
            # Format predecessors
            pred_str = ", ".join([f"N{p}" for p in node.predecessors]) if node.predecessors else "None"
            
            # Print node info
            print(f"\n🔷 Node N{node.id} [{type_str}]")
            print(f"   Lines: {node.start_line}-{node.end_line}")
            if code_display:
                print(code_display)
            if cond_display:
                print(cond_display)
            print(f"   ⬅️  Predecessors: {pred_str}")
            print(f"   ➡️  Successors: {succ_str}")
            
            # Draw edges visually
            if node.successors:
                edge_str = "   " + " → ".join([f"N{node.id}" for _ in range(len(node.successors)+1)])
                print(f"\n   Execution Flow: N{node.id}", end="")
                for succ_id in node.successors:
                    print(f" → N{succ_id}", end="")
                print()
        
        # Print summary of edges
        print("\n" + "-" * 80)
        print("📈 EDGE SUMMARY:")
        print("-" * 80)
        for i, (src, dst) in enumerate(cfg.edges):
            src_node = node_map.get(src)
            dst_node = node_map.get(dst)
            edge_type = self._get_edge_type(src_node, dst_node)
            print(f"  Edge {i+1:2d}: N{src} ({src_node.node_type.name if src_node else '?'}) "
                  f"{'─' * 3}{edge_type}{'─' * 3}> N{dst} ({dst_node.node_type.name if dst_node else '?'})")
        
        # Print loop information
        if cfg.loops:
            print("\n" + "-" * 80)
            print("🔄 LOOP STRUCTURES:")
            print("-" * 80)
            for i, loop in enumerate(cfg.loops):
                print(f"\n  Loop {i+1}: {loop.loop_type.upper()}")
                print(f"    Header Node: N{loop.header_node_id}")
                print(f"    Body Nodes: {[f'N{n}' for n in loop.body_node_ids]}")
                if loop.exit_node_id:
                    print(f"    Exit Node: N{loop.exit_node_id}")
                print(f"    Nesting Level: {loop.nesting_level}")
        
        print("\n" + "=" * 80)
    
    def _get_type_emoji(self, node_type: CFGNodeType) -> str:
        """Get emoji for node type."""
        emoji_map = {
            CFGNodeType.ENTRY: "🟢",
            CFGNodeType.EXIT: "🔴",
            CFGNodeType.STATEMENT: "📝",
            CFGNodeType.CONDITION: "❓",
            CFGNodeType.LOOP_HEADER: "🔁",
            CFGNodeType.LOOP_BODY: "🔂",
            CFGNodeType.BRANCH: "🔀",
            CFGNodeType.SWITCH: "🔣",
            CFGNodeType.CASE: "📍",
            CFGNodeType.RETURN: "⏹️",
            CFGNodeType.BREAK: "🛑",
            CFGNodeType.CONTINUE: "⏭️",
            CFGNodeType.GOTO: "➡️",
            CFGNodeType.LABEL: "🏷️",
            CFGNodeType.CALL: "📞",
            CFGNodeType.THROW: "💥",
            CFGNodeType.CATCH: "🧤",
        }
        return emoji_map.get(node_type, "⬜")
    
    def _get_edge_type(self, src: Optional[CFGNode], dst: Optional[CFGNode]) -> str:
        """Determine edge type based on node types."""
        if not src or not dst:
            return "──"
        
        # Back edge (loop)
        if dst.node_type == CFGNodeType.LOOP_HEADER and src.node_type in [
            CFGNodeType.LOOP_BODY, CFGNodeType.CONTINUE
        ]:
            return "⟲"  # Loop back edge
        
        # Break edge
        if src.node_type == CFGNodeType.BREAK:
            return "⇥"  # Break out
        
        # Continue edge
        if src.node_type == CFGNodeType.CONTINUE:
            return "⇄"  # Continue
        
        # Return edge
        if src.node_type == CFGNodeType.RETURN:
            return "⏹"  # Return
        
        # Conditional branches
        if src.node_type == CFGNodeType.CONDITION:
            return "⇆"  # Branch
        
        # Switch
        if src.node_type == CFGNodeType.SWITCH:
            return "⇿"  # Multi-way branch
        
        # Normal flow
        return "──>"
    
    def export_to_dot(self, cfg: FunctionCFG, output_path: str):
        """
        Export CFG to DOT format for Graphviz visualization.
        
        Args:
            cfg: FunctionCFG to export
            output_path: Path to save the .dot file
        """
        dot_lines = [
            f'digraph CFG_{cfg.function_name} {{',
            '  rankdir=TB;',
            '  node [shape=box, style=filled];',
            ''
        ]
        
        # Define node colors by type
        color_map = {
            CFGNodeType.ENTRY: "#90EE90",  # Light green
            CFGNodeType.EXIT: "#FFB6C1",   # Light red
            CFGNodeType.CONDITION: "#FFD700",  # Gold
            CFGNodeType.LOOP_HEADER: "#87CEEB",  # Light blue
            CFGNodeType.LOOP_BODY: "#DDA0DD",  # Plum
            CFGNodeType.RETURN: "#FFA07A",  # Light salmon
            CFGNodeType.BREAK: "#FF6347",  # Tomato
            CFGNodeType.CONTINUE: "#20B2AA",  # Light sea green
            CFGNodeType.SWITCH: "#DA70D6",  # Orchid
            CFGNodeType.CASE: "#E6E6FA",  # Lavender
            CFGNodeType.GOTO: "#F0E68C",  # Khaki
            CFGNodeType.LABEL: "#FFE4B5",  # Moccasin
            CFGNodeType.CALL: "#98FB98",  # Pale green
            CFGNodeType.THROW: "#FF4500",  # Orange red
            CFGNodeType.CATCH: "#FF7F50",  # Coral
        }
        
        # Add nodes
        for node in cfg.nodes:
            color = color_map.get(node.node_type, "#FFFFFF")
            label = f"N{node.id}: {node.node_type.name}"
            
            if node.code:
                code = node.code.replace('\n', '\\n').replace('"', '\\"')
                if len(code) > 50:
                    code = code[:47] + "..."
                label += f"\\n{code}"
            
            if node.condition:
                cond = node.condition.replace('\n', '\\n').replace('"', '\\"')
                if len(cond) > 30:
                    cond = cond[:27] + "..."
                label += f"\\n[{cond}]"
            
            dot_lines.append(f'  N{node.id} [label="{label}", fillcolor="{color}"];')
        
        dot_lines.append('')
        
        # Add edges
        for src, dst in cfg.edges:
            src_node = next((n for n in cfg.nodes if n.id == src), None)
            dst_node = next((n for n in cfg.nodes if n.id == dst), None)
            
            # Determine edge style
            style = ""
            if src_node and dst_node:
                if dst_node.node_type == CFGNodeType.LOOP_HEADER and src_node.node_type in [
                    CFGNodeType.LOOP_BODY, CFGNodeType.CONTINUE
                ]:
                    style = ' [style=dashed, color="blue", label="back"]'
                elif src_node.node_type == CFGNodeType.BREAK:
                    style = ' [style=dashed, color="red", label="break"]'
                elif src_node.node_type == CFGNodeType.CONTINUE:
                    style = ' [style=dotted, color="green", label="continue"]'
                elif src_node.node_type == CFGNodeType.RETURN:
                    style = ' [style=bold, color="orange", label="return"]'
                elif src_node.node_type == CFGNodeType.CONDITION:
                    style = ' [color="purple"]'
            
            dot_lines.append(f'  N{src} -> N{dst}{style};')
        
        dot_lines.append('}')
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write('\n'.join(dot_lines))
        
        print(f"✓ DOT file exported to: {output_path}")
        print(f"  To render: dot -Tpng {output_path} -o {output_path}.png")
    
    def print_execution_paths(self, cfg: FunctionCFG, max_paths: int = 10):
        """
        Print possible execution paths through the function.
        
        Args:
            cfg: FunctionCFG to analyze
            max_paths: Maximum number of paths to display
        """
        print("\n" + "=" * 80)
        print(f"POSSIBLE EXECUTION PATHS: {cfg.function_name}")
        print("=" * 80)
        
        # Find all paths from entry to exit using DFS
        node_map = {node.id: node for node in cfg.nodes}
        entry_id = cfg.entry_node_id
        exit_id = cfg.exit_node_id
        
        if entry_id is None or exit_id is None:
            print("Cannot determine paths: missing entry or exit node")
            return
        
        paths = []
        
        def dfs(current_id: int, path: List[int], visited: Set[int]):
            if len(paths) >= max_paths:
                return
            
            if current_id == exit_id:
                paths.append(path.copy())
                return
            
            # Prevent infinite loops
            if current_id in visited:
                return
            
            visited.add(current_id)
            path.append(current_id)
            
            node = node_map.get(current_id)
            if node and node.successors:
                for succ_id in node.successors:
                    dfs(succ_id, path, visited.copy())
            
            # If no successors but not at exit, path ends here
            if not node or not node.successors:
                if current_id != exit_id:
                    paths.append(path.copy())
        
        dfs(entry_id, [], set())
        
        print(f"\nFound {len(paths)} execution path(s) (showing up to {max_paths}):\n")
        
        for i, path in enumerate(paths, 1):
            path_str = " → ".join([f"N{n}" for n in path])
            
            # Annotate path with node types
            annotations = []
            for node_id in path:
                node = node_map.get(node_id)
                if node:
                    if node.node_type == CFGNodeType.CONDITION:
                        annotations.append(f"N{node_id}(if)")
                    elif node.node_type == CFGNodeType.LOOP_HEADER:
                        annotations.append(f"N{node_id}(loop)")
                    elif node.node_type == CFGNodeType.RETURN:
                        annotations.append(f"N{node_id}(ret)")
            
            print(f"Path {i}: {path_str}")
            if annotations:
                print(f"       Key points: {', '.join(annotations)}")
            print()
    
    def analyze_basic_blocks(self, cfg: FunctionCFG) -> List[BasicBlock]:
        """
        Analyze CFG to identify basic blocks.
        
        A basic block is a maximal sequence of consecutive statements
        with a single entry point and single exit point.
        
        Args:
            cfg: FunctionCFG to analyze
            
        Returns:
            List of BasicBlock objects
        """
        # Identify block leaders (entry points of basic blocks)
        leaders = set()
        leaders.add(cfg.entry_node_id)  # Entry is always a leader
        
        # Targets of jumps are leaders
        for node in cfg.nodes:
            for succ_id in node.successors:
                leaders.add(succ_id)
        
        # Nodes following control flow statements are leaders
        for node in cfg.nodes:
            if node.node_type in [
                CFGNodeType.CONDITION, CFGNodeType.BRANCH,
                CFGNodeType.RETURN, CFGNodeType.BREAK,
                CFGNodeType.CONTINUE, CFGNodeType.GOTO,
                CFGNodeType.LOOP_HEADER, CFGNodeType.SWITCH
            ]:
                for succ_id in node.successors:
                    leaders.add(succ_id)
        
        # Build basic blocks
        blocks = []
        node_map = {node.id: node for node in cfg.nodes}
        assigned = set()
        
        for leader_id in sorted(leaders):
            if leader_id is None or leader_id in assigned:
                continue
            
            block_nodes = []
            current_id = leader_id
            
            while current_id is not None and current_id not in assigned:
                node = node_map.get(current_id)
                if not node:
                    break
                
                block_nodes.append(node)
                assigned.add(current_id)
                
                # Stop at control flow statements
                if node.node_type in [
                    CFGNodeType.CONDITION, CFGNodeType.BRANCH,
                    CFGNodeType.RETURN, CFGNodeType.BREAK,
                    CFGNodeType.CONTINUE, CFGNodeType.GOTO,
                    CFGNodeType.LOOP_HEADER, CFGNodeType.SWITCH,
                    CFGNodeType.EXIT
                ]:
                    break
                
                # Continue to successor if only one
                if len(node.successors) == 1:
                    current_id = node.successors[0]
                else:
                    break
            
            if block_nodes:
                # Calculate block successors (to other blocks)
                block_succs = set()
                block_preds = set()
                
                for node in block_nodes:
                    for succ_id in node.successors:
                        if succ_id not in assigned or succ_id in leaders:
                            block_succs.add(succ_id)
                    for pred_id in node.predecessors:
                        if pred_id in assigned:
                            block_preds.add(pred_id)
                
                # Determine block type
                entry_node = block_nodes[0]
                if entry_node.node_type == CFGNodeType.ENTRY:
                    block_type = "ENTRY"
                elif entry_node.node_type == CFGNodeType.EXIT:
                    block_type = "EXIT"
                elif entry_node.node_type == CFGNodeType.CONDITION:
                    block_type = "CONDITIONAL"
                elif entry_node.node_type == CFGNodeType.LOOP_HEADER:
                    block_type = "LOOP_HEADER"
                else:
                    block_type = "NORMAL"
                
                block = BasicBlock(
                    block_id=len(blocks),
                    node_ids=[n.id for n in block_nodes],
                    entry_node=entry_node,
                    exit_node=block_nodes[-1],
                    successors=list(block_succs),
                    predecessors=list(block_preds),
                    block_type=block_type
                )
                blocks.append(block)
        
        return blocks
    
    def print_basic_block_relationships(self, cfg: FunctionCFG):
        """
        Print detailed relationships between basic blocks.
        
        Args:
            cfg: FunctionCFG to analyze
        """
        blocks = self.analyze_basic_blocks(cfg)
        node_map = {node.id: node for node in cfg.nodes}
        
        print("\n" + "=" * 80)
        print(f"BASIC BLOCK RELATIONSHIPS: {cfg.function_name}")
        print("=" * 80)
        print(f"Total Basic Blocks: {len(blocks)}\n")
        
        for block in blocks:
            print(f"{'=' * 60}")
            print(f"📦 Block B{block.block_id} [{block.block_type}]")
            print(f"{'=' * 60}")
            print(f"   Contains Nodes: {[f'N{n}' for n in block.node_ids]}")
            
            # Show code in block
            print(f"\n   Statements:")
            for node_id in block.node_ids:
                node = node_map.get(node_id)
                if node:
                    code = node.code.replace('\n', ' ').strip()
                    if len(code) > 60:
                        code = code[:57] + "..."
                    print(f"      N{node_id}: {code}")
            
            # Show relationships
            print(f"\n   🔗 Relationships:")
            print(f"      Predecessor Blocks: {[f'B{p}' for p in self._get_block_ids_for_nodes(block.predecessors, blocks)]}")
            print(f"      Successor Blocks: {[f'B{s}' for s in self._get_block_ids_for_nodes(block.successors, blocks)]}")
            
            # Show execution flow within block
            if len(block.node_ids) > 1:
                print(f"\n   ➡️  Internal Flow: {' → '.join([f'N{n}' for n in block.node_ids])}")
            
            print()
        
        # Print block-level CFG
        print(f"\n{'=' * 60}")
        print("🗺️  BLOCK-LEVEL CONTROL FLOW GRAPH:")
        print(f"{'=' * 60}")
        
        for block in blocks:
            succ_blocks = self._get_block_ids_for_nodes(block.successors, blocks)
            if succ_blocks:
                flow_str = " → ".join([f"B{block.block_id}"] + [f"B{s}" for s in succ_blocks])
                print(f"   {flow_str}")
            else:
                print(f"   B{block.block_id} → [END]")
        
        print()
    
    def _get_block_ids_for_nodes(self, node_ids: List[int], blocks: List[BasicBlock]) -> List[int]:
        """Get block IDs that contain the given node IDs."""
        result = []
        for node_id in node_ids:
            for block in blocks:
                if node_id in block.node_ids:
                    if block.block_id not in result:
                        result.append(block.block_id)
        return result


def main():
    """Main function demonstrating CFG visualization."""
    # Sample C++ code with various control flow structures
    sample_cpp = """
#include <iostream>
#include <vector>

// Recursive function with condition
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Function with loop and condition
int findMax(int arr[], int size) {
    int max = arr[0];
    for (int i = 1; i < size; i++) {
        if (arr[i] > max) {
            max = arr[i];
        }
    }
    return max;
}

// Switch statement
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

// While loop with continue
int countOddDigits(int n) {
    int count = 0;
    while (n > 0) {
        int digit = n % 10;
        if (digit % 2 == 0) {
            n /= 10;
            continue;
        }
        count++;
        n /= 10;
    }
    return count;
}

// Nested loops
void nestedLoops(int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (i == j) {
                continue;
            }
            std::cout << i << "," << j << std::endl;
        }
    }
}

// Goto example (rare but valid)
void gotoExample(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        if (i == 5) {
            goto end;
        }
        sum += i;
    }
end:
    std::cout << "Sum: " << sum << std::endl;
}

// Multiple returns
int classify(int x) {
    if (x < 0) {
        return -1;
    }
    if (x == 0) {
        return 0;
    }
    return 1;
}

// Do-while loop
int countDigits(int n) {
    int count = 0;
    do {
        count++;
        n /= 10;
    } while (n > 0);
    return count;
}

int main() {
    int arr[] = {3, 7, 2, 9, 1};
    int max = findMax(arr, 5);
    std::cout << "Max: " << max << std::endl;
    
    std::cout << "5! = " << factorial(5) << std::endl;
    
    processNumber(7);
    
    return 0;
}
"""
    
    print("=" * 80)
    print("C++ CONTROL FLOW ANALYZER - BASIC BLOCK RELATIONSHIPS")
    print("=" * 80)
    
    # Initialize analyzer and visualizer
    analyzer = CPPControlFlowAnalyzer()
    visualizer = CFGVisualizer(analyzer)
    
    # Parse the sample code
    print("\nParsing C++ code...")
    cfgs = analyzer.parse_string(sample_cpp, "sample.cpp")
    print(f"Found {len(cfgs)} functions\n")
    
    # Analyze each function
    for cfg in cfgs:
        # Print basic block relationships
        visualizer.print_basic_block_relationships(cfg)
        
        # Print text-based CFG
        visualizer.print_cfg_text(cfg, show_code=True)
        
        # Print execution paths
        visualizer.print_execution_paths(cfg, max_paths=5)
        
        # Export to DOT format
        dot_file = f"cfg_{cfg.function_name}.dot"
        visualizer.export_to_dot(cfg, dot_file)
        
        print("\n")
    
    # Also export complete JSON with enhanced block information
    print("=" * 80)
    print("EXPORTING ENHANCED ANALYSIS")
    print("=" * 80)
    
    output_data = {
        "functions": []
    }
    
    for cfg in cfgs:
        blocks = visualizer.analyze_basic_blocks(cfg)
        
        func_data = cfg.to_dict()
        func_data["basic_blocks"] = [
            {
                "block_id": b.block_id,
                "block_type": b.block_type,
                "node_ids": b.node_ids,
                "successors": b.successors,
                "predecessors": b.predecessors,
            }
            for b in blocks
        ]
        output_data["functions"].append(func_data)
    
    output_file = "enhanced_control_flow_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n✓ Enhanced analysis exported to: {output_file}")
    print(f"✓ DOT files generated for Graphviz visualization")
    print("\nTo visualize with Graphviz:")
    print("  dot -Tpng cfg_factorial.dot -o cfg_factorial.png")
    print("  dot -Tpng cfg_findMax.dot -o cfg_findMax.png")
    print("  etc.\n")


if __name__ == "__main__":
    main()
