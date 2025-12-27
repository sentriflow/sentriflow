// packages/core/src/constants.ts

/**
 * Security and performance constants for SentriFlow.
 * Centralized configuration for limits and thresholds.
 */

/** Maximum length of a single line before skipping regex evaluation (ReDoS protection) */
export const MAX_LINE_LENGTH = 2048;

/** Maximum size of configuration content in bytes */
export const MAX_CONFIG_SIZE = 10 * 1024 * 1024; // 10MB

/** Maximum nesting depth for parsed configuration blocks */
export const MAX_NESTING_DEPTH = 50;

/** Maximum number of lines to parse */
export const MAX_LINE_COUNT = 100_000;

/** Maximum traversal depth when searching for config files */
export const MAX_TRAVERSAL_DEPTH = 20;

/** Allowed extensions for config/rules files */
export const ALLOWED_CONFIG_EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs'];

/** SEC-012: Allowed extensions for encrypted rule packs (.grpx legacy format) */
export const ALLOWED_ENCRYPTED_PACK_EXTENSIONS = ['.grpx'];

/** Allowed extensions for GRX2 extended encrypted rule packs */
export const ALLOWED_GRX2_PACK_EXTENSIONS = ['.grx2'];

/** Allowed extensions for JSON rule files */
export const ALLOWED_JSON_RULES_EXTENSIONS = ['.json'];

/** Maximum file size for config/rules files (1MB) */
export const MAX_CONFIG_FILE_SIZE = 1024 * 1024;

/** SEC-012: Maximum file size for encrypted rule packs (5MB) */
export const MAX_ENCRYPTED_PACK_SIZE = 5 * 1024 * 1024;

/** Maximum number of external rules that can be registered */
export const MAX_EXTERNAL_RULES = 2000;

/** Rule execution timeout in milliseconds */
export const RULE_TIMEOUT_MS = 5000;

// ============================================================================
// Performance Optimization Constants
// ============================================================================

/** Use simple (non-indexed) engine below this rule count */
export const MAX_RULES_WITHOUT_INDEX = 50;

/** Percentage of lines changed to trigger full reparse (0.3 = 30%) */
export const INCREMENTAL_PARSE_THRESHOLD = 0.3;

/** Maximum time per rule per node in milliseconds */
export const RULE_PER_NODE_TIMEOUT_MS = 100;

/** Maximum total scan time in milliseconds */
export const SCAN_TIMEOUT_MS = 5000;

/** Pattern for valid rule IDs */
export const RULE_ID_PATTERN = /^[A-Z][A-Z0-9_-]{2,49}$/;

// ============================================================================
// JSON Rules Security Constants
// ============================================================================

/** Maximum length for regex patterns in JSON rules (ReDoS protection) */
export const MAX_PATTERN_LENGTH = 500;

/** Maximum length for metadata string fields in JSON rules */
export const MAX_METADATA_LENGTH = 10_000;

/**
 * ReDoS detection pattern - matches nested quantifiers that cause exponential backtracking.
 * Detects patterns like (a+)+, (a*)+, (a+)*, (a|b+)+, etc.
 */
export const REDOS_PATTERN = /\([^)]*[+*][^)]*\)[+*]|\(\?:[^)]*[+*][^)]*\)[+*]/;
