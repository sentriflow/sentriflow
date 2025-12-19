// packages/core/src/parser/IncrementalParser.ts

import type { ConfigNode } from '../types/ConfigNode';
import { SchemaAwareParser } from './SchemaAwareParser';
import type { ParserOptions } from './SchemaAwareParser';
import type { VendorSchema } from './VendorSchema';
import { defaultVendor, detectVendor } from './vendors';
import { INCREMENTAL_PARSE_THRESHOLD } from '../constants';

/**
 * Options for the IncrementalParser.
 */
export interface IncrementalParserOptions {
  /**
   * Vendor schema to use for parsing.
   * - If not specified, defaults to auto-detection.
   * - Use 'auto' to auto-detect vendor from config content.
   * - Use a specific VendorSchema for explicit vendor selection.
   */
  vendor?: VendorSchema | 'auto';
}

/**
 * Cached document state for incremental parsing.
 */
interface DocumentCache {
  /** The parsed AST */
  ast: ConfigNode[];
  /** Hash of each line for change detection */
  lineHashes: string[];
  /** Document version (increments on each edit) */
  version: number;
  /** Original line count */
  lineCount: number;
  /** Vendor used for parsing this document */
  vendor: VendorSchema;
}

/**
 * Represents a range of changed lines.
 */
interface ChangeRange {
  startLine: number;
  endLine: number;
}

/**
 * Statistics about the last parse operation.
 */
export interface ParseStats {
  /** Whether a full parse was performed */
  fullParse: boolean;
  /** Number of changed line ranges detected */
  changedRanges: number;
  /** Number of sections re-parsed (if incremental) */
  sectionsReparsed: number;
  /** Parse time in milliseconds */
  parseTimeMs: number;
  /** Reason for full parse (if applicable) */
  fullParseReason?: string;
  /** Vendor used for parsing */
  vendorId?: string;
}

/**
 * Incremental parser that caches ASTs and only re-parses changed sections.
 * Supports multiple vendors through the VendorSchema system.
 *
 * Performance characteristics:
 * - Single line edit: Only affected section re-parsed (~5-20x faster)
 * - Multi-line paste: Affected sections re-parsed (~2-10x faster)
 * - Large changes (>30%): Falls back to full re-parse
 *
 * Vendor support:
 * - Auto-detection: Analyzes config content to determine vendor
 * - Explicit vendor: Pass VendorSchema in options
 * - Cached vendor: Re-uses detected vendor for subsequent parses
 *
 * Usage:
 * ```typescript
 * const parser = new IncrementalParser();
 *
 * // First parse - auto-detects vendor, full parse, cached
 * const ast1 = parser.parse('doc1', content1, 1);
 *
 * // Edit - incremental parse if possible, same vendor
 * const ast2 = parser.parse('doc1', content2, 2);
 *
 * // Explicit vendor
 * const parser2 = new IncrementalParser({ vendor: JuniperJunOSSchema });
 * const ast3 = parser2.parse('junos-config', junosContent, 1);
 *
 * // Clear cache when document closes
 * parser.invalidate('doc1');
 * ```
 */
export class IncrementalParser {
  private cache = new Map<string, DocumentCache>();
  private lastStats: ParseStats | null = null;
  private readonly defaultVendorOption: VendorSchema | 'auto';

  constructor(options?: IncrementalParserOptions) {
    this.defaultVendorOption = options?.vendor ?? 'auto';
  }

  /**
   * Parse document content, using cached AST when possible.
   *
   * @param uri Unique identifier for the document (e.g., file URI)
   * @param content The document content to parse
   * @param version Document version number (should increment on each edit)
   * @param vendor Optional vendor override for this specific parse
   * @returns Parsed AST
   */
  public parse(
    uri: string,
    content: string,
    version: number,
    vendor?: VendorSchema | 'auto'
  ): ConfigNode[] {
    const startTime = performance.now();
    const cached = this.cache.get(uri);
    const lines = content.split('\n');
    const lineHashes = lines.map((line) => this.hashLine(line));

    // Determine vendor to use
    const vendorOption = vendor ?? this.defaultVendorOption;
    const resolvedVendor = this.resolveVendor(vendorOption, content, cached);

    // Full parse if no cache
    if (!cached) {
      const ast = this.fullParse(content, resolvedVendor);
      this.cache.set(uri, { ast, lineHashes, version, lineCount: lines.length, vendor: resolvedVendor });
      this.lastStats = {
        fullParse: true,
        changedRanges: 0,
        sectionsReparsed: 0,
        parseTimeMs: performance.now() - startTime,
        fullParseReason: 'no_cache',
        vendorId: resolvedVendor.id,
      };
      return ast;
    }

    // Full parse if vendor changed
    if (cached.vendor.id !== resolvedVendor.id) {
      const ast = this.fullParse(content, resolvedVendor);
      this.cache.set(uri, { ast, lineHashes, version, lineCount: lines.length, vendor: resolvedVendor });
      this.lastStats = {
        fullParse: true,
        changedRanges: 0,
        sectionsReparsed: 0,
        parseTimeMs: performance.now() - startTime,
        fullParseReason: 'vendor_changed',
        vendorId: resolvedVendor.id,
      };
      return ast;
    }

    // Full parse if version hasn't increased (stale request)
    if (version <= cached.version) {
      this.lastStats = {
        fullParse: false,
        changedRanges: 0,
        sectionsReparsed: 0,
        parseTimeMs: performance.now() - startTime,
        vendorId: resolvedVendor.id,
      };
      return cached.ast;
    }

    // Find changed line ranges
    const changedRanges = this.findChangedRanges(cached.lineHashes, lineHashes);

    // Calculate percentage of lines changed
    const totalChangedLines = changedRanges.reduce(
      (sum, range) => sum + (range.endLine - range.startLine + 1),
      0
    );
    const changeRatio = totalChangedLines / Math.max(lines.length, cached.lineCount);

    // Full parse if too many changes or structural changes detected
    if (changeRatio > INCREMENTAL_PARSE_THRESHOLD || this.hasStructuralChanges(changedRanges, cached, lines)) {
      const ast = this.fullParse(content, resolvedVendor);
      this.cache.set(uri, { ast, lineHashes, version, lineCount: lines.length, vendor: resolvedVendor });
      this.lastStats = {
        fullParse: true,
        changedRanges: changedRanges.length,
        sectionsReparsed: 0,
        parseTimeMs: performance.now() - startTime,
        fullParseReason: changeRatio > INCREMENTAL_PARSE_THRESHOLD ? 'too_many_changes' : 'structural_changes',
        vendorId: resolvedVendor.id,
      };
      return ast;
    }

    // No changes detected
    if (changedRanges.length === 0) {
      cached.version = version;
      this.lastStats = {
        fullParse: false,
        changedRanges: 0,
        sectionsReparsed: 0,
        parseTimeMs: performance.now() - startTime,
        vendorId: resolvedVendor.id,
      };
      return cached.ast;
    }

    // Incremental update
    const { ast: updatedAst, sectionsReparsed } = this.incrementalUpdate(
      cached.ast,
      lines,
      changedRanges,
      resolvedVendor
    );

    this.cache.set(uri, { ast: updatedAst, lineHashes, version, lineCount: lines.length, vendor: resolvedVendor });
    this.lastStats = {
      fullParse: false,
      changedRanges: changedRanges.length,
      sectionsReparsed,
      parseTimeMs: performance.now() - startTime,
      vendorId: resolvedVendor.id,
    };

    return updatedAst;
  }

  /**
   * Resolve the vendor to use for parsing.
   * @param vendorOption The vendor option (VendorSchema or 'auto')
   * @param content The config content for auto-detection
   * @param cached Optional cached document for reusing vendor
   */
  private resolveVendor(
    vendorOption: VendorSchema | 'auto',
    content: string,
    cached?: DocumentCache
  ): VendorSchema {
    if (vendorOption !== 'auto') {
      return vendorOption;
    }

    // If cached and auto, reuse the detected vendor for consistency
    if (cached) {
      return cached.vendor;
    }

    // Auto-detect from content
    return detectVendor(content);
  }

  /**
   * Perform a full parse using SchemaAwareParser.
   */
  private fullParse(content: string, vendor: VendorSchema): ConfigNode[] {
    const parser = new SchemaAwareParser({ vendor });
    return parser.parse(content);
  }

  /**
   * Simple string hash for fast line comparison.
   * Uses djb2 algorithm for good distribution.
   */
  private hashLine(line: string): string {
    let hash = 5381;
    for (let i = 0; i < line.length; i++) {
      hash = ((hash << 5) + hash) ^ line.charCodeAt(i);
    }
    return (hash >>> 0).toString(36);
  }

  /**
   * Find ranges of consecutive changed lines.
   */
  private findChangedRanges(oldHashes: string[], newHashes: string[]): ChangeRange[] {
    const ranges: ChangeRange[] = [];
    let inChange = false;
    let changeStart = 0;

    const maxLen = Math.max(oldHashes.length, newHashes.length);

    for (let i = 0; i < maxLen; i++) {
      const changed = oldHashes[i] !== newHashes[i];

      if (changed && !inChange) {
        inChange = true;
        changeStart = i;
      } else if (!changed && inChange) {
        inChange = false;
        ranges.push({
          startLine: changeStart,
          endLine: i - 1,
        });
      }
    }

    // Handle change that extends to end of file
    if (inChange) {
      ranges.push({
        startLine: changeStart,
        endLine: maxLen - 1,
      });
    }

    return ranges;
  }

  /**
   * Detect structural changes that require full re-parse.
   * Examples: Line count changed significantly, changes span multiple sections.
   */
  private hasStructuralChanges(
    changedRanges: ChangeRange[],
    cached: DocumentCache,
    newLines: string[]
  ): boolean {
    // Significant line count change (insertions/deletions)
    const lineDelta = Math.abs(newLines.length - cached.lineCount);
    if (lineDelta > 10) {
      return true;
    }

    // Changes affect multiple top-level sections
    let affectedSections = 0;
    for (const range of changedRanges) {
      for (const node of cached.ast) {
        if (this.rangeOverlapsNode(range, node)) {
          affectedSections++;
        }
      }
    }

    // If changes affect more than half of top-level sections, do full parse
    if (affectedSections > cached.ast.length / 2) {
      return true;
    }

    return false;
  }

  /**
   * Check if a change range overlaps with a node's location.
   */
  private rangeOverlapsNode(range: ChangeRange, node: ConfigNode): boolean {
    return range.startLine <= node.loc.endLine && range.endLine >= node.loc.startLine;
  }

  /**
   * Incrementally update AST by re-parsing only affected sections.
   */
  private incrementalUpdate(
    oldAst: ConfigNode[],
    lines: string[],
    changedRanges: ChangeRange[],
    vendor: VendorSchema
  ): { ast: ConfigNode[]; sectionsReparsed: number } {
    // Find which top-level sections are affected by changes
    const affectedSectionIndices = new Set<number>();

    for (const range of changedRanges) {
      for (let i = 0; i < oldAst.length; i++) {
        const node = oldAst[i];
        if (node && this.rangeOverlapsNode(range, node)) {
          affectedSectionIndices.add(i);
        }
      }
    }

    // If no sections affected but we have changes, changes are in gaps between sections
    // or at the end of file - do full re-parse to be safe
    if (affectedSectionIndices.size === 0 && changedRanges.length > 0) {
      const parser = new SchemaAwareParser({ vendor });
      return { ast: parser.parse(lines.join('\n')), sectionsReparsed: oldAst.length };
    }

    // Calculate line offset caused by insertions/deletions
    // For simplicity, we'll re-parse affected sections with adjusted line numbers
    const newAst: ConfigNode[] = [];
    let lineOffset = 0;

    for (let i = 0; i < oldAst.length; i++) {
      const node = oldAst[i];
      if (!node) continue;

      if (affectedSectionIndices.has(i)) {
        // Find the section boundaries in the new content
        const sectionStart = node.loc.startLine + lineOffset;
        const nextNode = i < oldAst.length - 1 ? oldAst[i + 1] : null;
        const sectionEnd = this.findSectionEnd(lines, sectionStart, nextNode ?? null, lineOffset);

        if (sectionStart < lines.length) {
          // Extract and re-parse this section
          const sectionLines = lines.slice(sectionStart, sectionEnd + 1);
          const sectionContent = sectionLines.join('\n');

          const sectionParser = new SchemaAwareParser({
            startLine: sectionStart,
            vendor,
          });

          const reparsedNodes = sectionParser.parse(sectionContent);

          // Add re-parsed nodes
          newAst.push(...reparsedNodes);

          // Update line offset based on size change
          const oldSectionSize = node.loc.endLine - node.loc.startLine + 1;
          const newSectionSize = sectionEnd - sectionStart + 1;
          lineOffset += newSectionSize - oldSectionSize;
        }
      } else {
        // Keep existing node but adjust line numbers
        const adjustedNode = this.adjustNodeLineNumbers(node, lineOffset);
        newAst.push(adjustedNode);
      }
    }

    return { ast: newAst, sectionsReparsed: affectedSectionIndices.size };
  }

  /**
   * Find the end line of a section in the new content.
   */
  private findSectionEnd(
    lines: string[],
    sectionStart: number,
    nextSection: ConfigNode | null,
    lineOffset: number
  ): number {
    // If there's a next section, the current section ends just before it
    if (nextSection) {
      const nextStart = nextSection.loc.startLine + lineOffset;
      // Find the last non-empty line before the next section
      let end = nextStart - 1;
      while (end > sectionStart && lines[end]?.trim() === '') {
        end--;
      }
      return Math.max(sectionStart, end);
    }

    // Last section - extends to end of file
    let end = lines.length - 1;
    while (end > sectionStart && lines[end]?.trim() === '') {
      end--;
    }
    return Math.max(sectionStart, end);
  }

  /**
   * Recursively adjust line numbers in a node and its children.
   */
  private adjustNodeLineNumbers(node: ConfigNode, offset: number): ConfigNode {
    if (offset === 0) {
      return node;
    }

    return {
      ...node,
      loc: {
        startLine: node.loc.startLine + offset,
        endLine: node.loc.endLine + offset,
      },
      children: node.children.map((child) => this.adjustNodeLineNumbers(child, offset)),
    };
  }

  /**
   * Get statistics about the last parse operation.
   */
  public getLastStats(): ParseStats | null {
    return this.lastStats;
  }

  /**
   * Get the vendor used for a cached document.
   *
   * @param uri The document URI
   * @returns The VendorSchema or undefined if not cached
   */
  public getCachedVendor(uri: string): VendorSchema | undefined {
    return this.cache.get(uri)?.vendor;
  }

  /**
   * Clear cache for a specific document.
   *
   * @param uri The document URI to invalidate
   */
  public invalidate(uri: string): void {
    this.cache.delete(uri);
  }

  /**
   * Clear all cached documents.
   */
  public clearAll(): void {
    this.cache.clear();
  }

  /**
   * Get the number of cached documents.
   */
  public getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Check if a document is cached.
   *
   * @param uri The document URI to check
   */
  public isCached(uri: string): boolean {
    return this.cache.has(uri);
  }

  /**
   * Get cached document version.
   *
   * @param uri The document URI
   * @returns The cached version or -1 if not cached
   */
  public getCachedVersion(uri: string): number {
    return this.cache.get(uri)?.version ?? -1;
  }
}
