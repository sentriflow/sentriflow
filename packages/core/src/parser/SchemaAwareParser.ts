// packages/core/src/parser/SchemaAwareParser.ts

import type { ConfigNode, NodeType } from '../types/ConfigNode';
import type { VendorSchema, BlockStarterDef } from './VendorSchema';
import { defaultVendor } from './vendors';
import { sanitizeText, parseParameters } from './Sanitizer';
import {
  MAX_LINE_LENGTH,
  MAX_CONFIG_SIZE,
  MAX_NESTING_DEPTH,
  MAX_LINE_COUNT,
} from '../constants';
import { SentriflowParseError, SentriflowSizeLimitError } from '../errors';

/**
 * Options for the SchemaAwareParser.
 */
export interface ParserOptions {
  /**
   * The starting line number for the input text, useful for snippets.
   * @default 0
   */
  startLine?: number;
  /**
   * Whether the input is a full configuration ('base') or a partial snippet ('snippet').
   * @default 'base'
   */
  source?: 'base' | 'snippet';
  /**
   * Vendor schema to use for parsing. If not specified, defaults to Cisco IOS.
   * Use detectVendor() to auto-detect the vendor from config content.
   */
  vendor?: VendorSchema;
}

/**
 * Represents a line processed during parsing, including its content and indentation level.
 */
interface ParsedLine {
  original: string;
  sanitized: string;
  lineNumber: number;
  indent: number;
  isBlockStarter: boolean;
  blockStarterDepth: number;
  isBlockEnder: boolean;
  hasBraceOpen: boolean;
  hasBraceClose: boolean;
}

/**
 * Implements a permissive parser that can interpret hierarchical configuration
 * structures even from flattened text or snippets, using both indentation
 * and schema-aware block starters.
 *
 * Supports both indentation-based hierarchy (Cisco IOS) and brace-based
 * hierarchy (Juniper JunOS) through the VendorSchema system.
 */
export class SchemaAwareParser {
  private readonly options: Required<Omit<ParserOptions, 'vendor'>>;
  private readonly vendor: VendorSchema;

  constructor(options?: ParserOptions) {
    this.options = {
      startLine: options?.startLine ?? 0,
      source: options?.source ?? 'base',
    };
    this.vendor = options?.vendor ?? defaultVendor;
  }

  /**
   * Get the vendor schema being used by this parser instance.
   */
  public getVendor(): VendorSchema {
    return this.vendor;
  }

  /**
   * Parses the input configuration text into an Abstract Syntax Tree (AST) of ConfigNodes.
   * It attempts to infer hierarchy using indentation and predefined block-starting keywords.
   *
   * For brace-based vendors (Juniper), tracks brace depth to determine hierarchy.
   * For indentation-based vendors (Cisco), uses schema-defined block starters and depth.
   *
   * Security: Validates input size and line lengths to prevent DoS attacks.
   *
   * @param configText The raw configuration text to parse.
   * @returns An array of top-level ConfigNodes representing the parsed configuration.
   * @throws SentriflowSizeLimitError if input exceeds size limits
   */
  public parse(configText: string): ConfigNode[] {
    if (configText.length > MAX_CONFIG_SIZE) {
      throw new SentriflowSizeLimitError(
        `Configuration exceeds maximum size of ${
          MAX_CONFIG_SIZE / 1024 / 1024
        }MB`
      );
    }

    const lines = configText.split('\n');

    if (lines.length > MAX_LINE_COUNT) {
      throw new SentriflowSizeLimitError(
        `Configuration exceeds maximum line count of ${MAX_LINE_COUNT}`
      );
    }

    // Use brace-based parsing for Juniper-style configs
    if (this.vendor.useBraceHierarchy) {
      return this.parseBraceHierarchy(lines);
    }

    // Use indentation-based parsing for Cisco-style configs
    return this.parseIndentationHierarchy(lines);
  }

  /**
   * Parses configuration using brace-based hierarchy (Juniper JunOS style).
   * Tracks opening and closing braces to determine block depth.
   */
  private parseBraceHierarchy(lines: string[]): ConfigNode[] {
    const rootNodes: ConfigNode[] = [];
    const parentStack: ConfigNode[] = [];
    let braceDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const originalLine = lines[i];
      if (!originalLine) continue;

      if (originalLine.length > MAX_LINE_LENGTH) {
        continue;
      }

      const sanitizedLine = sanitizeText(originalLine);

      // Skip empty lines and comments
      if (sanitizedLine.length === 0 || this.isComment(sanitizedLine)) {
        continue;
      }

      // Check for braces in the line
      const hasBraceOpen = sanitizedLine.includes('{');
      const hasBraceClose = sanitizedLine.includes('}');

      // Handle closing brace - pop from stack
      if (hasBraceClose) {
        const closeCount = (sanitizedLine.match(/\}/g) || []).length;
        for (let j = 0; j < closeCount; j++) {
          if (parentStack.length > 0) {
            parentStack.pop();
          }
          braceDepth = Math.max(0, braceDepth - 1);
        }

        // If line is just a closing brace, continue to next line
        if (sanitizedLine.trim() === '}') {
          continue;
        }
      }

      // Process content (before opening brace if present)
      let contentLine = sanitizedLine;
      if (hasBraceOpen) {
        // Extract content before the brace
        contentLine = sanitizedLine.replace(/\s*\{.*$/, '').trim();
      }

      // Skip if no meaningful content
      if (!contentLine || contentLine === '}') {
        // Handle opening brace on its own line or after content
        if (hasBraceOpen) {
          const openCount = (sanitizedLine.match(/\{/g) || []).length;
          braceDepth += openCount;
        }
        continue;
      }

      // Remove trailing semicolon for cleaner node ID
      const nodeId = contentLine.replace(/;$/, '').trim();

      // Determine node type - if followed by brace or matches block starter, it's a section
      const blockStarterDepth = this.getBlockStarterDepth(contentLine);
      const isSection = hasBraceOpen || blockStarterDepth >= 0;
      const nodeType: NodeType = isSection ? 'section' : 'command';

      // Prevent excessive nesting
      if (parentStack.length >= MAX_NESTING_DEPTH) {
        while (parentStack.length >= MAX_NESTING_DEPTH) {
          parentStack.pop();
        }
      }

      const newNode = this.createConfigNode(
        {
          original: originalLine,
          sanitized: nodeId,
          lineNumber: this.options.startLine + i,
          indent: originalLine.search(/\S|$/),
          isBlockStarter: isSection,
          blockStarterDepth:
            blockStarterDepth >= 0 ? blockStarterDepth : braceDepth,
          isBlockEnder: false,
          hasBraceOpen,
          hasBraceClose,
        },
        nodeType
      );

      // Add to parent or root
      const currentParent = parentStack.at(-1);
      if (currentParent) {
        currentParent.children.push(newNode);
      } else {
        rootNodes.push(newNode);
      }

      // If this starts a new block (has opening brace), push to stack
      if (hasBraceOpen && isSection) {
        parentStack.push(newNode);
        const openCount = (sanitizedLine.match(/\{/g) || []).length;
        braceDepth += openCount;
      }
    }

    return this.applyVirtualContext(rootNodes);
  }

  /**
   * Parses configuration using indentation-based hierarchy (Cisco IOS style).
   * Uses schema-defined block starters and depth for nesting.
   */
  private parseIndentationHierarchy(lines: string[]): ConfigNode[] {
    const lineContexts: ParsedLine[] = [];

    for (let i = 0; i < lines.length; i++) {
      const originalLine = lines[i];
      if (!originalLine) continue;

      if (originalLine.length > MAX_LINE_LENGTH) {
        continue;
      }

      const sanitizedLine = sanitizeText(originalLine);

      // Skip empty lines and comments
      if (sanitizedLine.length === 0 || this.isComment(sanitizedLine)) {
        continue;
      }

      const blockStarterDepth = this.getBlockStarterDepth(sanitizedLine);
      lineContexts.push({
        original: originalLine,
        sanitized: sanitizedLine,
        lineNumber: this.options.startLine + i,
        indent: originalLine.search(/\S|$/),
        isBlockStarter: blockStarterDepth >= 0,
        blockStarterDepth,
        isBlockEnder: this.isSchemaBlockEnder(sanitizedLine),
        hasBraceOpen: false,
        hasBraceClose: false,
      });
    }

    const rootNodes: ConfigNode[] = [];
    const parentStack: ConfigNode[] = [];

    for (const currentLine of lineContexts) {
      // SEC-FIX: Context-aware block starter override (CUMULUS_FIX.md)
      // If a depth-0 pattern matches but the line is indented AND we're inside
      // an iface/auto block, treat it as a child command, not a new block.
      // This fixes the issue where "vrf mgmt" inside "iface eth0" was incorrectly
      // parsed as a new top-level section instead of a child command.
      let isBlockStarter = currentLine.isBlockStarter;
      let blockStarterDepth = currentLine.blockStarterDepth;

      if (isBlockStarter && currentLine.indent > 0) {
        let sectionParent: ConfigNode | undefined;
        for (let i = parentStack.length - 1; i >= 0; i--) {
          const candidate = parentStack[i];
          if (candidate?.blockDepth !== undefined) {
            sectionParent = candidate;
            break;
          }
        }

        if (sectionParent) {
          const parentType = sectionParent.id.split(/\s+/)[0];

          // For iface/auto blocks specifically, depth-0 patterns should be commands
          // This must be checked FIRST before multi-depth logic
          if (
            (parentType === 'iface' || parentType === 'auto') &&
            blockStarterDepth === 0
          ) {
            // Override: treat as child command, not new block
            isBlockStarter = false;
            blockStarterDepth = -1;
          } else {
            if (currentLine.indent > sectionParent.indent) {
              const uniqueDepths = [
                ...new Set(
                  this.getAllBlockStarterDepths(currentLine.sanitized)
                ),
              ];
              const parentDepth = sectionParent.blockDepth ?? 0;
              const expectedChildDepth = parentDepth + 1;

              if (uniqueDepths.length > 1) {
                if (uniqueDepths.includes(expectedChildDepth)) {
                  blockStarterDepth = expectedChildDepth;
                } else {
                  const deeperDepth = Math.min(
                    ...uniqueDepths.filter((depth) => depth > parentDepth)
                  );
                  if (Number.isFinite(deeperDepth)) {
                    blockStarterDepth = deeperDepth;
                  }
                }
              } else if (
                sectionParent.blockDepth !== undefined &&
                blockStarterDepth <= parentDepth
              ) {
                // Support nested Fortinet config/edit tables by forcing child depth
                blockStarterDepth = expectedChildDepth;
              }
            }
          }
        }
      }

      // FLAT-CONFIG-FIX: For flat configs (indent=0) with intentional multi-depth patterns,
      // search up the parent stack to find the best valid ancestor.
      // This enables correct nesting without relying on indentation.
      // Only applies when the SAME pattern (identical regex) is defined at multiple depths.
      if (isBlockStarter && currentLine.indent === 0) {
        const multiDepthsForSamePattern =
          this.getMultiDepthsForSamePattern(currentLine.sanitized);

        if (multiDepthsForSamePattern.length > 1) {
          // Cache block type extraction (first word) for sibling detection
          // This avoids repeated regex splits on the same string
          const currentBlockType = currentLine.sanitized.split(/\s+/)[0];

          // Search stack from most recent to oldest for a valid parent
          // Limited to MAX_NESTING_DEPTH to bound worst-case iteration
          const maxSearch = Math.min(parentStack.length, MAX_NESTING_DEPTH);
          for (let i = parentStack.length - 1; i >= parentStack.length - maxSearch; i--) {
            const ancestor = parentStack[i];
            if (
              ancestor?.type === 'section' &&
              ancestor.blockDepth !== undefined
            ) {
              // Sibling detection: Skip same block types - they should be siblings, not parent/child
              // Example: address-family X and address-family Y should be siblings
              // NOTE: Uses first word only, which works for most cases but may not handle
              // commands like "router bgp" vs "router ospf" where both have "router" as first word.
              // This is acceptable as those blocks typically don't nest.
              const ancestorBlockType = ancestor.id.split(/\s+/)[0];
              if (ancestorBlockType === currentBlockType) {
                continue;
              }

              const ancestorDepth = ancestor.blockDepth;
              // Find depths that would make us a valid child of this ancestor
              const validChildDepths = multiDepthsForSamePattern.filter(
                (d) => d > ancestorDepth
              );
              if (validChildDepths.length > 0) {
                // Use the smallest valid depth (closest nesting level)
                blockStarterDepth = Math.min(...validChildDepths);
                break;
              }
            }
          }
        }
      }

      const newNodeType: NodeType = isBlockStarter ? 'section' : 'command';
      const modifiedLine: ParsedLine = {
        ...currentLine,
        isBlockStarter,
        blockStarterDepth,
      };
      const newNode = this.createConfigNode(modifiedLine, newNodeType);

      if (parentStack.length >= MAX_NESTING_DEPTH) {
        while (parentStack.length >= MAX_NESTING_DEPTH) {
          parentStack.pop();
        }
      }

      while (parentStack.length > 0) {
        const topOfStack = parentStack.at(-1)!;

        if (isBlockStarter) {
          if (topOfStack.type !== 'section') {
            parentStack.pop();
          } else {
            const parentDepth = topOfStack.blockDepth ?? 0;
            const currentDepth = blockStarterDepth;

            if (currentDepth > parentDepth) {
              break;
            } else {
              parentStack.pop();
            }
          }
        } else if (currentLine.isBlockEnder) {
          if (topOfStack.type === 'section') {
            parentStack.pop();
            break;
          } else {
            parentStack.pop();
          }
        } else {
          if (topOfStack.type === 'section') {
            break;
          } else if (currentLine.indent <= topOfStack.indent) {
            parentStack.pop();
          } else {
            break;
          }
        }
      }

      const currentParent = parentStack.at(-1);

      if (currentParent) {
        currentParent.children.push(newNode);
      } else {
        rootNodes.push(newNode);
      }

      parentStack.push(newNode);
    }

    return this.applyVirtualContext(rootNodes);
  }

  /**
   * Checks if a line is a comment according to the vendor's comment patterns.
   */
  private isComment(sanitizedLine: string): boolean {
    return this.vendor.commentPatterns.some((pattern) =>
      pattern.test(sanitizedLine)
    );
  }

  /**
   * Returns the block starter depth for a line, or -1 if not a block starter.
   *
   * Returns the FIRST (shallowest) matching pattern. For context-aware decisions
   * (e.g., preferring depth-1 over depth-0 based on parent), see the override logic
   * in parseIndentationHierarchy().
   */
  private getBlockStarterDepth(sanitizedLine: string): number {
    for (const def of this.vendor.blockStarters) {
      if (def.pattern.test(sanitizedLine)) {
        return def.depth;
      }
    }
    return -1;
  }

  /**
   * Returns ALL matching block starter depths for a line.
   * Used for context-aware parsing where multiple depths may match.
   */
  private getAllBlockStarterDepths(sanitizedLine: string): number[] {
    const depths: number[] = [];
    for (const def of this.vendor.blockStarters) {
      if (def.pattern.test(sanitizedLine)) {
        depths.push(def.depth);
      }
    }
    return depths;
  }

  /**
   * Returns depths only for patterns where the SAME regex pattern is defined
   * at multiple depth levels. This is used for flat config parsing where we need
   * to detect intentional multi-depth patterns (like address-family at depth 1 AND 2)
   * vs accidental overlaps (like vrf definition matching both vrf\s+definition and vrf\s+\S+).
   *
   * Example: address-family\s+\S+ at depth 1 AND depth 2 → returns [1, 2]
   * Example: vrf definition X matching vrf\s+definition (depth 0) AND vrf\s+\S+ (depth 2) → returns []
   */
  private getMultiDepthsForSamePattern(sanitizedLine: string): number[] {
    const patternToDepths = new Map<string, number[]>();

    for (const def of this.vendor.blockStarters) {
      if (def.pattern.test(sanitizedLine)) {
        // Include regex flags in key to properly distinguish patterns
        // e.g., /pattern/i and /pattern/ are different patterns
        const key = `${def.pattern.source}|${def.pattern.flags}`;
        if (!patternToDepths.has(key)) {
          patternToDepths.set(key, []);
        }
        patternToDepths.get(key)!.push(def.depth);
      }
    }

    // Return depths for the FIRST pattern that appears at multiple depths.
    // This enables multi-depth nesting (e.g., address-family at depth 1 AND 2).
    // Note: If multiple different patterns have multi-depth definitions, only
    // the first one found is returned. This is sufficient for current use cases
    // where we just need to know IF multi-depth nesting applies.
    for (const depths of patternToDepths.values()) {
      if (depths.length > 1) {
        return depths;
      }
    }
    return [];
  }

  /**
   * Checks if a sanitized line matches any of the defined BlockEnders regexes.
   */
  private isSchemaBlockEnder(sanitizedLine: string): boolean {
    return this.vendor.blockEnders.some((regex) => regex.test(sanitizedLine));
  }

  /**
   * Creates a ConfigNode object from a ParsedLine.
   */
  private createConfigNode(parsedLine: ParsedLine, type: NodeType): ConfigNode {
    const params = parseParameters(parsedLine.sanitized);
    const id = parsedLine.sanitized;

    const node: ConfigNode = {
      id,
      type,
      rawText: parsedLine.original,
      params,
      children: [],
      source: this.options.source,
      loc: {
        startLine: parsedLine.lineNumber,
        endLine: parsedLine.lineNumber,
      },
      indent: parsedLine.indent,
    };

    if (type === 'section' && parsedLine.blockStarterDepth >= 0) {
      node.blockDepth = parsedLine.blockStarterDepth;
    }

    return node;
  }

  /**
   * Logic to detect "Orphan" commands and wrap them in a `virtual_root`.
   */
  private applyVirtualContext(nodes: ConfigNode[]): ConfigNode[] {
    const processedNodes: ConfigNode[] = [];
    let currentVirtualRoot: ConfigNode | null = null;

    for (const node of nodes) {
      if (node.type === 'command') {
        if (!currentVirtualRoot) {
          currentVirtualRoot = {
            id: `virtual_root_line_${node.loc.startLine}`,
            type: 'virtual_root',
            rawText: 'virtual_root',
            params: ['virtual_root'],
            children: [],
            source: this.options.source,
            loc: {
              startLine: node.loc.startLine,
              endLine: node.loc.endLine,
            },
            indent: 0,
          };
          processedNodes.push(currentVirtualRoot);
        }
        currentVirtualRoot!.children.push(node);
        currentVirtualRoot!.loc.endLine = Math.max(
          currentVirtualRoot!.loc.endLine,
          node.loc.endLine
        );
      } else {
        currentVirtualRoot = null;
        processedNodes.push(node);
      }
    }
    return processedNodes;
  }
}
