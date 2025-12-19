// packages/core/src/parser/VendorSchema.ts

/**
 * Represents a block-starting pattern with its nesting depth.
 * Depth determines where a block can appear in the hierarchy:
 * - depth 0: Top-level blocks (interface, router, vlan, system, interfaces)
 * - depth 1: Must be inside a depth-0 block (address-family inside router, ge-0/0/0 inside interfaces)
 * - depth 2: Must be inside a depth-1 block (vrf inside address-family, unit inside interface)
 * - depth 3: Deeply nested (family inet inside unit)
 */
export interface BlockStarterDef {
  pattern: RegExp;
  depth: number;
}

/**
 * Defines a vendor's configuration syntax schema.
 * Each vendor (Cisco IOS, Juniper JunOS, etc.) has different
 * block structures, comment styles, and hierarchy rules.
 *
 * This abstraction allows the parser to handle multiple vendor
 * configuration formats using the same parsing engine.
 */
export interface VendorSchema {
  /**
   * Unique vendor identifier.
   * Used for programmatic lookup and configuration.
   * @example 'cisco-ios', 'cisco-nxos', 'juniper-junos', 'arista-eos'
   */
  id: string;

  /**
   * Human-readable display name.
   * @example 'Cisco IOS/IOS-XE', 'Juniper JunOS'
   */
  name: string;

  /**
   * Block starters with depth information for this vendor.
   * Order matters: more specific patterns should come before generic ones.
   */
  blockStarters: BlockStarterDef[];

  /**
   * Block enders (exit commands or closing braces).
   * These patterns indicate the end of a configuration block.
   * @example Cisco: /^exit$/i, /^exit-address-family$/i
   * @example Junos: /^\}$/
   */
  blockEnders: RegExp[];

  /**
   * Comment patterns for this vendor.
   * Lines matching these patterns are treated as comments and skipped.
   * @example Cisco: /^!/, Junos: /^#/, /^\/\*.*\*\/$/
   */
  commentPatterns: RegExp[];

  /**
   * Optional section delimiter character.
   * Used to separate logical sections in the configuration.
   * @example Cisco: '!', Junos: '}'
   */
  sectionDelimiter?: string;

  /**
   * Whether this vendor uses braces for hierarchy.
   * - true: Juniper JunOS style with { } blocks
   * - false: Cisco style with indentation-based blocks
   */
  useBraceHierarchy: boolean;
}
