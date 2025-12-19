// packages/core/src/types/ConfigNode.ts

/**
 * Defines the type of a configuration node in the Abstract Syntax Tree (AST).
 * - 'section': Represents a configuration block (e.g., interface, router bgp).
 * - 'command': Represents a single configuration command within a section or globally.
 * - 'comment': Represents a comment line in the configuration.
 * - 'virtual_root': A synthetic node used to wrap orphan commands for rule validation.
 */
export type NodeType = 'section' | 'command' | 'comment' | 'virtual_root';

/**
 * Represents a node in the Abstract Syntax Tree (AST) of a configuration file.
 * This structure normalizes flattened text into a hierarchical tree.
 */
export interface ConfigNode {
    /**
     * A unique identifier for the node, typically derived from its raw text or path.
     * Example: "interface GigabitEthernet1"
     */
    id: string;

    /**
     * The type of the configuration node.
     */
    type: NodeType;

    /**
     * The original raw text line(s) that this node represents.
     */
    rawText: string;

    /**
     * Parameters extracted from the rawText, typically the command and its arguments.
     * Example: for "interface Gi0/1", params might be ["interface", "Gi0/1"].
     */
    params: string[];

    /**
     * Child configuration nodes, forming the hierarchical structure.
     */
    children: ConfigNode[];

    /**
     * Critical for "Snippet Resilience": Indicates if the node originated from
     * the base configuration or a partial snippet.
     */
    source: 'base' | 'snippet';

    /**
     * Location in the original source file for error reporting and context.
     */
    loc: {
        startLine: number;
        endLine: number;
    };

    /**
     * The indentation level of the rawText (number of leading whitespace characters).
     * This is crucial for indentation-based parsing.
     */
    indent: number;

    /**
     * For section nodes, the block depth from BlockStarterDefs.
     * - 0: Top-level blocks (interface, router, vlan)
     * - 1: Nested blocks (address-family inside router)
     * - 2: Deeply nested (vrf inside address-family)
     * - undefined: For non-section nodes (commands, comments)
     */
    blockDepth?: number;
}
