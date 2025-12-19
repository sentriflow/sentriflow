// packages/core/src/types/IRule.ts

import type { ConfigNode } from "./ConfigNode";
import { getAvailableVendors } from '../parser/vendors';

/**
 * Represents the outcome of a rule check.
 */
export interface RuleResult {
    /**
     * True if the rule passed, false if it failed.
     */
    passed: boolean;
    /**
     * A message explaining the rule's outcome, especially on failure.
     */
    message: string;
    /**
     * The ID of the rule that was checked.
     */
    ruleId: string;
    /**
     * The ID of the node that was checked.
     */
    nodeId: string;
    /**
     * The level of the result (error, warning, info).
     */
    level: 'error' | 'warning' | 'info';
    /**
     * Optional: Remediation steps if the rule failed.
     */
    remediation?: string;
    /**
     * Optional: The specific lines in the configuration where the issue was found.
     */
    loc?: {
        startLine: number;
        endLine: number;
    };
}

/**
 * Contextual information passed to a rule's check function.
 * This might include global settings, other AST nodes, or environmental data.
 */
export interface Context {
    /**
     * Lazy getter for the full configuration AST. Only call this if your rule
     * needs cross-reference validation (e.g., checking if an IP referenced in
     * OSPF exists on an interface). Simple single-node rules should not use this.
     */
    getAst?: () => ConfigNode[];
}

/**
 * Vendor identifiers that a rule can target.
 * Use 'common' for vendor-agnostic rules that apply to all vendors.
 */
export type RuleVendor =
    | 'common'
    | 'cisco-ios'
    | 'cisco-nxos'
    | 'juniper-junos'
    | 'aruba-aoscx'
    | 'aruba-aosswitch'
    | 'aruba-wlc'
    | 'paloalto-panos'
    | 'arista-eos'
    | 'vyos'
    | 'fortinet-fortigate'
    | 'extreme-exos'
    | 'extreme-voss'
    | 'huawei-vrp'
    | 'mikrotik-routeros'
    | 'nokia-sros'
    | 'cumulus-linux';

/**
 * Canonical list of valid vendor identifiers.
 * Dynamically derived from vendorSchemas - single source of truth.
 * SEC-004: Centralized vendor list to prevent synchronization issues.
 */
export const VALID_VENDOR_IDS: readonly RuleVendor[] = [
    'common',
    ...getAvailableVendors(),
] as readonly RuleVendor[];

/**
 * Type guard to check if a string is a valid vendor identifier.
 * SEC-004: Provides consistent validation across CLI and VSCode.
 *
 * @param id The string to check
 * @returns true if the id is a valid RuleVendor
 */
export function isValidVendorId(id: string): id is RuleVendor {
    return VALID_VENDOR_IDS.includes(id as RuleVendor);
}

/**
 * Specifies what to disable from the default rule pack.
 */
export interface PackDisableConfig {
    /**
     * Disable the entire default pack (all rules).
     * When true, no default rules will run unless explicitly re-enabled.
     */
    all?: boolean;

    /**
     * Disable all default rules for specific vendors.
     * Example: ['cisco-ios', 'cisco-nxos'] disables all Cisco rules.
     */
    vendors?: RuleVendor[];

    /**
     * Disable specific rules by ID.
     * Example: ['NET-IP-001', 'NET-DOC-001']
     */
    rules?: string[];
}

/**
 * Metadata for a rule pack.
 */
export interface RulePackMetadata {
    /**
     * Unique identifier for the pack (e.g., 'acme-secpack').
     * Used for registration, unregistration, and conflict resolution.
     */
    name: string;

    /**
     * Semantic version of the pack (e.g., '1.0.0').
     */
    version: string;

    /**
     * Publisher/vendor name (e.g., 'ACME Corp').
     */
    publisher: string;

    /**
     * Brief description of the pack's purpose.
     */
    description?: string;

    /**
     * License type (e.g., 'Commercial', 'MIT', 'Proprietary').
     */
    license?: string;

    /**
     * Homepage or documentation URL.
     */
    homepage?: string;
}

/**
 * A rule pack containing multiple rules with shared metadata.
 */
export interface RulePack extends RulePackMetadata {
    /**
     * Priority for conflict resolution (higher wins).
     * Default pack has priority 0.
     * Recommended: 100+ for proprietary packs.
     */
    priority: number;

    /**
     * Rules included in this pack.
     */
    rules: IRule[];

    /**
     * Configuration for disabling default pack rules.
     * Allows disabling by: all, vendors, or specific rule IDs.
     */
    disables?: PackDisableConfig;
}

/**
 * SEC-007: Security metadata for SARIF integration.
 * Provides CWE mappings and CVSS scores for security-related rules.
 */
export interface SecurityMetadata {
    /**
     * CWE (Common Weakness Enumeration) identifiers.
     * Example: ['CWE-798', 'CWE-259'] for hardcoded credentials.
     */
    cwe?: string[];

    /**
     * CVSS v3.1 base score (0.0 - 10.0).
     * Used by security scanners to prioritize findings.
     */
    cvssScore?: number;

    /**
     * CVSS v3.1 vector string.
     * Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
     */
    cvssVector?: string;

    /**
     * Security-related tags for categorization.
     * Example: ['authentication', 'hardcoded-credentials', 'encryption']
     */
    tags?: string[];
}

/**
 * Extended rule metadata including optional security fields.
 * SEC-007: Supports CWE/CVSS metadata for SARIF output.
 */
export interface RuleMetadata {
    /** Severity level of the rule */
    level: 'error' | 'warning' | 'info';
    /** Organizational Business Unit responsible for this rule */
    obu: string;
    /** Owner of the rule logic */
    owner: string;
    /** Brief description of what the rule checks */
    description?: string;
    /** Suggested steps to fix the violation */
    remediation?: string;
    /** SEC-007: Optional security metadata for SARIF integration */
    security?: SecurityMetadata;
}

/**
 * Defines the structure of a configuration validation rule.
 */
export interface IRule {
    /**
     * A unique identifier for the rule (e.g., "NET-SEC-001").
     */
    id: string;

    /**
     * An optional selector string (e.g., "interface", "router bgp")
     * that determines which `ConfigNode` types this rule should be applied to.
     * This is used for optimization to avoid running rules on irrelevant nodes.
     */
    selector?: string;

    /**
     * Optional vendor(s) this rule applies to.
     * - Single vendor: 'cisco-ios'
     * - Multiple vendors: ['cisco-ios', 'cisco-nxos']
     * - All vendors: 'common' or omit this property
     *
     * When omitted, the rule is treated as vendor-agnostic and runs for all vendors.
     * This is useful for proprietary rule packs that want to override or extend
     * default rules for specific vendors only.
     */
    vendor?: RuleVendor | RuleVendor[];

    /**
     * The function that contains the core logic of the rule.
     * It takes a `ConfigNode` and a `Context` object, and returns a `RuleResult`.
     */
    check: (node: ConfigNode, context: Context) => RuleResult;

    /**
     * Metadata associated with the rule, used for reporting and categorization.
     * SEC-007: Extended to support security metadata for SARIF integration.
     */
    metadata: RuleMetadata;
}
