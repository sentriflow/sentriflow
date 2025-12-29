/**
 * Configuration file loader for SentriFlow CLI
 * Supports: sentriflow.config.js, sentriflow.config.ts, .sentriflowrc.js, .sentriflowrc.ts
 */
import {
  SentriflowConfigError,
  MAX_TRAVERSAL_DEPTH,
  RULE_ID_PATTERN,
  VALID_VENDOR_IDS,
  isValidVendorId,
  loadEncryptedPack,
  validatePackFormat,
  PackLoadError,
  // JSON rules support
  validateJsonRuleFile,
  compileJsonRules,
  type JsonRuleFile,
  // GRX2 Extended Pack Support
  loadExtendedPack,
  getMachineId,
  EncryptedPackError,
  // Shared validation utilities (DRY)
  isValidRule,
  isValidRulePack,
  ruleAppliesToVendor,
} from '@sentriflow/core';
import type {
  IRule,
  RulePack,
  RuleVendor,
  PackDisableConfig,
} from '@sentriflow/core';
import {
  allRules as defaultRules,
  getRulesByVendor,
} from '@sentriflow/rules-default';
import { existsSync } from 'fs';
import { readFile as readFileAsync } from 'fs/promises';
import { resolve, dirname } from 'path';
import {
  validateConfigPath,
  validatePackPath,
  validateJsonRulesPath,
} from './security/pathValidator';
import {
  loadAndValidate,
  validatePathOrThrow,
  wrapLoadError,
  createPackDescriptors,
  FORMAT_PRIORITIES,
} from './loaders';
import type { PackDescriptor } from './loaders';

/**
 * Directory scanning options from config file (FR-005)
 */
export interface DirectoryConfig {
  /** Regex patterns to exclude files (FR-006) */
  excludePatterns?: string[];
  /** File extensions to include (without dots) (FR-007) */
  extensions?: string[];
  /** Enable recursive directory scanning (FR-008) */
  recursive?: boolean;
  /** Maximum recursion depth (FR-009) */
  maxDepth?: number;
  /** Glob patterns to exclude (FR-010) */
  exclude?: string[];
}

/** Configuration file structure */
export interface SentriflowConfig {
  /** Additional rules to include (legacy, use rulePacks instead) */
  rules?: IRule[];

  /** Rule IDs to disable (legacy, use rulePacks instead) */
  disable?: string[];

  /** Whether to include default rules (default: true) */
  includeDefaults?: boolean;

  /** Rule packs to load (recommended) */
  rulePacks?: RulePack[];

  /** JSON rule file paths (relative to config file or absolute) */
  jsonRules?: string[];

  /** Directory scanning options (FR-005) */
  directory?: DirectoryConfig;

  /**
   * Filter out special IP ranges from IP summaries.
   * When enabled, filters out loopback, multicast, reserved, broadcast,
   * and documentation addresses. Keeps only public, private, and CGNAT addresses.
   * @default false
   */
  filterSpecialIps?: boolean;
}

/** Resolved configuration with final rule set */
export interface ResolvedConfig {
  rules: IRule[];
  disabledIds: Set<string>;
}

/** Config file names to search for (in order of priority) */
const CONFIG_FILES = [
  'sentriflow.config.ts',
  'sentriflow.config.js',
  '.sentriflowrc.ts',
  '.sentriflowrc.js',
];

/**
 * Find config file starting from given directory, walking up to root.
 * Limited traversal depth to prevent unbounded directory walking.
 */
export function findConfigFile(startDir: string): string | null {
  let currentDir = resolve(startDir);
  let depth = 0;

  while (depth < MAX_TRAVERSAL_DEPTH) {
    for (const configFile of CONFIG_FILES) {
      const configPath = resolve(currentDir, configFile);
      if (existsSync(configPath)) {
        // Validate the found config path
        const validation = validateConfigPath(configPath);
        if (validation.valid) {
          return validation.canonicalPath!;
        }
        // If validation fails, continue searching
      }
    }
    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
    depth++;
  }

  return null;
}

/**
 * Validates that an object conforms to the SentriflowConfig interface.
 */
function isValidSentriflowConfig(config: unknown): config is SentriflowConfig {
  if (typeof config !== 'object' || config === null) {
    return false;
  }

  const obj = config as Record<string, unknown>;

  // Validate optional 'rules' array
  if (obj.rules !== undefined) {
    if (!Array.isArray(obj.rules)) {
      return false;
    }
    // Basic validation of each rule
    for (const rule of obj.rules) {
      if (!isValidRule(rule)) {
        return false;
      }
    }
  }

  // Validate optional 'disable' array
  if (obj.disable !== undefined) {
    if (!Array.isArray(obj.disable)) {
      return false;
    }
    for (const id of obj.disable) {
      if (typeof id !== 'string') {
        return false;
      }
    }
  }

  // Validate optional 'includeDefaults' boolean
  if (
    obj.includeDefaults !== undefined &&
    typeof obj.includeDefaults !== 'boolean'
  ) {
    return false;
  }

  // Validate optional 'rulePacks' array
  if (obj.rulePacks !== undefined) {
    if (!Array.isArray(obj.rulePacks)) {
      return false;
    }
    for (const pack of obj.rulePacks) {
      if (!isValidRulePack(pack)) {
        return false;
      }
    }
  }

  // Validate optional 'jsonRules' array
  if (obj.jsonRules !== undefined) {
    if (!Array.isArray(obj.jsonRules)) {
      return false;
    }
    for (const path of obj.jsonRules) {
      if (typeof path !== 'string') {
        return false;
      }
    }
  }

  // Validate optional 'directory' config
  if (obj.directory !== undefined) {
    if (!isValidDirectoryConfig(obj.directory)) {
      return false;
    }
  }

  // Validate optional 'filterSpecialIps' boolean
  if (
    obj.filterSpecialIps !== undefined &&
    typeof obj.filterSpecialIps !== 'boolean'
  ) {
    return false;
  }

  return true;
}

/**
 * Validates that an object conforms to the DirectoryConfig interface.
 * TR-004: Validates structure, regex patterns, and type constraints.
 */
export function isValidDirectoryConfig(config: unknown): config is DirectoryConfig {
  if (config === null || config === undefined) {
    return false;
  }

  if (typeof config !== 'object') {
    return false;
  }

  const obj = config as Record<string, unknown>;

  // Validate excludePatterns: must be array of valid regex strings
  if (obj.excludePatterns !== undefined) {
    if (!Array.isArray(obj.excludePatterns)) {
      return false;
    }
    for (const pattern of obj.excludePatterns) {
      if (typeof pattern !== 'string') {
        return false;
      }
      // Validate regex syntax
      try {
        new RegExp(pattern);
      } catch {
        return false;
      }
    }
  }

  // Validate extensions: must be array of strings
  if (obj.extensions !== undefined) {
    if (!Array.isArray(obj.extensions)) {
      return false;
    }
    for (const ext of obj.extensions) {
      if (typeof ext !== 'string') {
        return false;
      }
    }
  }

  // Validate recursive: must be boolean
  if (obj.recursive !== undefined && typeof obj.recursive !== 'boolean') {
    return false;
  }

  // Validate maxDepth: must be number between 0 and 1000
  if (obj.maxDepth !== undefined) {
    if (typeof obj.maxDepth !== 'number') {
      return false;
    }
    if (obj.maxDepth < 0 || obj.maxDepth > 1000) {
      return false;
    }
  }

  // Validate exclude: must be array of strings
  if (obj.exclude !== undefined) {
    if (!Array.isArray(obj.exclude)) {
      return false;
    }
    for (const pattern of obj.exclude) {
      if (typeof pattern !== 'string') {
        return false;
      }
    }
  }

  return true;
}

import type { DirectoryScanOptions } from './scanner/DirectoryScanner';

/**
 * Merge CLI options with config file directory options.
 * TR-005: Arrays are merged (union), scalars use CLI precedence.
 */
export function mergeDirectoryOptions(
  cliOptions: Partial<DirectoryScanOptions>,
  configOptions: DirectoryConfig | undefined
): Partial<DirectoryScanOptions> {
  const result: Partial<DirectoryScanOptions> = {};

  // Start with CLI options
  if (cliOptions.excludePatterns) {
    result.excludePatterns = [...cliOptions.excludePatterns];
  } else {
    result.excludePatterns = [];
  }

  // Add config excludePatterns (compile strings to RegExp)
  if (configOptions?.excludePatterns) {
    for (const pattern of configOptions.excludePatterns) {
      try {
        const regex = new RegExp(pattern);
        result.excludePatterns.push(regex);
      } catch {
        // Skip invalid patterns (already validated by isValidDirectoryConfig)
      }
    }
  }

  // Merge exclude patterns (union)
  const excludeSet = new Set<string>();
  if (cliOptions.exclude) {
    for (const p of cliOptions.exclude) excludeSet.add(p);
  }
  if (configOptions?.exclude) {
    for (const p of configOptions.exclude) excludeSet.add(p);
  }
  result.exclude = [...excludeSet];

  // Scalar options: CLI wins if defined
  if (cliOptions.recursive !== undefined) {
    result.recursive = cliOptions.recursive;
  } else if (configOptions?.recursive !== undefined) {
    result.recursive = configOptions.recursive;
  }

  if (cliOptions.maxDepth !== undefined) {
    result.maxDepth = cliOptions.maxDepth;
  } else if (configOptions?.maxDepth !== undefined) {
    result.maxDepth = configOptions.maxDepth;
  }

  if (cliOptions.extensions !== undefined) {
    result.extensions = cliOptions.extensions;
  } else if (configOptions?.extensions !== undefined) {
    result.extensions = configOptions.extensions;
  }

  return result;
}

// Note: isValidRule is now imported from @sentriflow/core

// Note: isValidRulePack is now imported from @sentriflow/core

/**
 * Load configuration from a file.
 * Uses generic loader with path validation and structure checking.
 *
 * @param configPath - Path to the configuration file
 * @param baseDirs - SEC-011: Optional allowed base directories
 */
export async function loadConfigFile(
  configPath: string,
  baseDirs?: string[]
): Promise<SentriflowConfig> {
  return loadAndValidate<SentriflowConfig>({
    path: configPath,
    baseDirs,
    pathValidator: validateConfigPath,
    loader: async (p) => {
      const m = await import(p);
      return m.default ?? m;
    },
    validator: isValidSentriflowConfig,
    errorContext: 'config',
  });
}

/**
 * Load rules from an external file (for --rules flag).
 * Uses helpers for path validation and error handling.
 *
 * @param rulesPath - Path to the rules file
 * @param baseDirs - SEC-011: Optional allowed base directories
 */
export async function loadExternalRules(
  rulesPath: string,
  baseDirs?: string[]
): Promise<IRule[]> {
  const canonicalPath = validatePathOrThrow(
    rulesPath,
    validateConfigPath,
    'rules',
    baseDirs
  );

  return wrapLoadError(async () => {
    const module = await import(canonicalPath);
    const rules = module.default ?? module.rules ?? module;

    if (!Array.isArray(rules)) {
      throw new SentriflowConfigError('Rules file must export an array of rules');
    }

    // Validate each rule, warn on invalid ones
    const validRules: IRule[] = [];
    for (const rule of rules) {
      if (isValidRule(rule)) {
        validRules.push(rule);
      } else {
        // SEC-005: Sanitize error message
        const safeRuleId =
          typeof rule === 'object' && rule !== null && 'id' in rule
            ? String((rule as Record<string, unknown>).id).slice(0, 50)
            : 'unknown';
        console.warn(`Skipping invalid rule: ${safeRuleId} (validation failed)`);
      }
    }

    if (validRules.length === 0 && rules.length > 0) {
      throw new SentriflowConfigError('No valid rules found in rules file');
    }

    return validRules;
  }, 'rules');
}

/**
 * Load rules from a JSON rules file.
 * Uses helpers for path validation and error handling.
 *
 * @param jsonPath - Path to the JSON rules file
 * @param baseDirs - SEC-011: Optional allowed base directories
 */
export async function loadJsonRules(
  jsonPath: string,
  baseDirs?: string[]
): Promise<IRule[]> {
  const canonicalPath = validatePathOrThrow(
    jsonPath,
    validateJsonRulesPath,
    'JSON rules',
    baseDirs
  );

  return wrapLoadError(async () => {
    const content = await readFileAsync(canonicalPath, 'utf-8');
    let jsonData: unknown;

    try {
      jsonData = JSON.parse(content);
    } catch {
      throw new SentriflowConfigError('Invalid JSON syntax in rules file');
    }

    const validationResult = validateJsonRuleFile(jsonData);
    if (!validationResult.valid) {
      const errors = validationResult.errors.map((e) => `  ${e.path}: ${e.message}`).join('\n');
      throw new SentriflowConfigError(`Invalid JSON rules file:\n${errors}`);
    }

    for (const warning of validationResult.warnings) {
      console.warn(`[JSON Rules] Warning: ${warning.path}: ${warning.message}`);
    }

    const ruleFile = jsonData as JsonRuleFile;
    const compiledRules = compileJsonRules(ruleFile.rules);

    if (compiledRules.length === 0 && ruleFile.rules.length > 0) {
      throw new SentriflowConfigError('No valid rules compiled from JSON file');
    }

    return compiledRules;
  }, 'JSON rules');
}

export interface ResolveOptions {
  /** Path to config file (overrides auto-detection) */
  configPath?: string;

  /** Skip config file loading */
  noConfig?: boolean;

  /** Additional rules file path (legacy) */
  rulesPath?: string;

  /** Path(s) to rule pack(s) - auto-detects format (GRX2, GRPX, or unencrypted) */
  packPaths?: string | string[];

  /** License key for encrypted packs (shared across all packs) */
  licenseKey?: string;

  /** Fail immediately if any pack cannot be loaded (default: false, warn and continue) */
  strictPacks?: boolean;

  /** Path(s) to JSON rules file(s) */
  jsonRulesPaths?: string | string[];

  /** Rule IDs to disable (CLI override) */
  disableIds?: string[];

  /** Vendor ID for filtering rules */
  vendorId?: string;

  /** Working directory for config file search */
  cwd?: string;

  /** SEC-011: Allowed base directories for file path validation */
  allowedBaseDirs?: string[];
}

// Re-export from core for backward compatibility
export { ruleAppliesToVendor };

/**
 * Check if a default rule should be disabled based on pack disable configs.
 */
function isDefaultRuleDisabled(
  ruleId: string,
  vendorId: string | undefined,
  packs: RulePack[],
  legacyDisableIds: Set<string>
): boolean {
  if (legacyDisableIds.has(ruleId)) return true;

  for (const pack of packs) {
    if (!pack.disables) continue;
    if (pack.disables.all) return true;
    if (pack.disables.rules?.includes(ruleId)) return true;
    if (vendorId && pack.disables.vendors?.includes(vendorId as RuleVendor))
      return true;
  }

  return false;
}

/**
 * Load a rule pack from a file.
 * Uses generic loader with path validation and structure checking.
 *
 * @param packPath - Path to the rule pack file
 * @param baseDirs - SEC-011: Optional allowed base directories
 */
export async function loadRulePackFile(
  packPath: string,
  baseDirs?: string[]
): Promise<RulePack> {
  return loadAndValidate<RulePack>({
    path: packPath,
    baseDirs,
    pathValidator: validateConfigPath,
    loader: async (p) => {
      const m = await import(p);
      return m.default ?? m;
    },
    validator: isValidRulePack,
    errorContext: 'rule pack',
  });
}

/** Map PackLoadError codes to user-friendly messages */
function mapPackLoadError(error: PackLoadError): never {
  const messages: Record<string, string> = {
    DECRYPTION_FAILED: 'Invalid license key for encrypted pack',
    EXPIRED: 'Encrypted pack has expired',
    MACHINE_MISMATCH: 'License is not valid for this machine',
    ACTIVATION_LIMIT: 'Maximum activations exceeded for this license',
  };
  throw new SentriflowConfigError(
    messages[error.code] ?? `Failed to load encrypted pack: ${error.message}`
  );
}

/**
 * SEC-012: Load an encrypted rule pack (.grpx) file.
 * Uses helper for path validation with specialized error mapping.
 *
 * @param packPath - Path to the encrypted pack file
 * @param licenseKey - License key for decryption
 * @param baseDirs - Optional allowed base directories
 */
export async function loadEncryptedRulePack(
  packPath: string,
  licenseKey: string,
  baseDirs?: string[]
): Promise<RulePack> {
  const canonicalPath = validatePathOrThrow(
    packPath,
    validatePackPath,
    'encrypted pack',
    baseDirs
  );

  try {
    const packData = await readFileAsync(canonicalPath);

    if (!validatePackFormat(packData)) {
      throw new SentriflowConfigError('Invalid encrypted pack format');
    }

    const loadedPack = await loadEncryptedPack(packData, {
      licenseKey,
      timeout: 10000,
    });

    return {
      ...loadedPack.metadata,
      priority: 200,
      rules: loadedPack.rules,
    };
  } catch (error) {
    if (error instanceof PackLoadError) mapPackLoadError(error);
    if (error instanceof SentriflowConfigError) throw error;
    throw new SentriflowConfigError('Failed to load encrypted rule pack');
  }
}

/**
 * Resolve final rule set from config file + CLI options + rule packs.
 *
 * Priority order (higher number wins):
 * 1. Default rules (priority 0)
 * 2. Config file legacy rules (priority 50)
 * 3. Config file rule packs (their own priority)
 * 4. CLI --rules file (priority 50)
 * 5. Config file JSON rules (priority 75)
 * 6. CLI --json-rules file(s) (priority 100+)
 * 7. CLI --pack file(s) with format-based priority:
 *    - Unencrypted packs (priority 100 + index)
 *    - GRPX packs (priority 200 + index)
 *    - GRX2 packs (priority 300 + index)
 *
 * Disables are collected from all packs and applied to default rules.
 */
export async function resolveRules(
  options: ResolveOptions = {}
): Promise<IRule[]> {
  const {
    configPath,
    noConfig = false,
    rulesPath,
    packPaths,
    licenseKey,
    strictPacks = false, // Default to graceful handling
    jsonRulesPaths,
    disableIds = [],
    vendorId,
    cwd = process.cwd(),
    allowedBaseDirs, // SEC-011: Allowed base directories for file path validation
  } = options;

  // Normalize pack paths to array
  const packPathsArray = packPaths
    ? Array.isArray(packPaths)
      ? packPaths
      : [packPaths]
    : [];

  // Normalize JSON rules paths to array
  const jsonPathsArray = jsonRulesPaths
    ? Array.isArray(jsonRulesPaths)
      ? jsonRulesPaths
      : [jsonRulesPaths]
    : [];

  let config: SentriflowConfig = { includeDefaults: true };

  // Load config file (unless --no-config)
  if (!noConfig) {
    const foundConfigPath = configPath ?? findConfigFile(cwd);
    if (foundConfigPath) {
      config = await loadConfigFile(foundConfigPath, allowedBaseDirs);
    }
  }

  // Collect all rule packs
  const allPacks: RulePack[] = [];

  // Add config file rule packs
  if (config.rulePacks) {
    allPacks.push(...config.rulePacks);
  }

  // Add legacy config rules as a pack (priority 50)
  if (config.rules && config.rules.length > 0) {
    allPacks.push({
      name: '_config_legacy',
      version: '1.0.0',
      publisher: 'Config File',
      priority: 50,
      rules: config.rules,
    });
  }

  // Add CLI --rules file as a pack (priority 50)
  if (rulesPath) {
    const externalRules = await loadExternalRules(rulesPath, allowedBaseDirs);
    if (externalRules.length > 0) {
      allPacks.push({
        name: '_cli_rules',
        version: '1.0.0',
        publisher: 'CLI',
        priority: 50,
        rules: externalRules,
      });
    }
  }

  // Add JSON rules from config file (priority 75)
  if (config.jsonRules && config.jsonRules.length > 0) {
    for (const jsonPath of config.jsonRules) {
      try {
        const jsonRules = await loadJsonRules(jsonPath, allowedBaseDirs);
        if (jsonRules.length > 0) {
          allPacks.push({
            name: `_config_json_${jsonPath}`,
            version: '1.0.0',
            publisher: 'Config File (JSON)',
            priority: 75,
            rules: jsonRules,
          });
        }
      } catch (error) {
        const errorMsg =
          error instanceof Error ? error.message : 'Unknown error';
        console.error(`Warning: Failed to load JSON rules: ${errorMsg}`);
        console.error(`Warning: Skipping JSON rules file: ${jsonPath}`);
      }
    }
  }

  // Add CLI --json-rules file(s) (priority 100)
  if (jsonPathsArray.length > 0) {
    for (let i = 0; i < jsonPathsArray.length; i++) {
      const jsonPath = jsonPathsArray[i];
      if (!jsonPath) continue;

      try {
        const jsonRules = await loadJsonRules(jsonPath, allowedBaseDirs);
        if (jsonRules.length > 0) {
          allPacks.push({
            name: `_cli_json_${i}`,
            version: '1.0.0',
            publisher: 'CLI (JSON)',
            priority: 100 + i, // CLI JSON rules have higher priority than config JSON rules
            rules: jsonRules,
          });
        }
      } catch (error) {
        const errorMsg =
          error instanceof Error ? error.message : 'Unknown error';
        console.error(`Warning: Failed to load JSON rules: ${errorMsg}`);
        console.error(`Warning: Skipping JSON rules file: ${jsonPath}`);
      }
    }
  }

  // Unified pack loading with auto-format detection
  // Priority assignment: unencrypted=100+i, grpx=200+i, grx2=300+i
  if (packPathsArray.length > 0) {
    // Detect format for each pack
    let packDescriptors: PackDescriptor[];
    try {
      packDescriptors = await createPackDescriptors(packPathsArray);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      if (strictPacks) {
        throw new SentriflowConfigError(`Pack detection failed: ${errorMsg}`);
      }
      console.error(`Warning: Pack detection failed: ${errorMsg}`);
      packDescriptors = [];
    }

    // Check if any encrypted packs need a license key
    const hasEncryptedPacks = packDescriptors.some(
      (d) => d.format === 'grx2' || d.format === 'grpx'
    );
    if (hasEncryptedPacks && !licenseKey) {
      const errorMsg =
        'License key required for encrypted packs (use --license-key or set SENTRIFLOW_LICENSE_KEY)';
      if (strictPacks) {
        throw new SentriflowConfigError(errorMsg);
      }
      console.error(`Warning: ${errorMsg}`);
    }

    // Get machine ID for GRX2 packs (only if needed)
    let machineId: string | undefined;
    const hasGrx2Packs = packDescriptors.some((d) => d.format === 'grx2');
    if (hasGrx2Packs && licenseKey) {
      try {
        machineId = await getMachineId();
      } catch (error) {
        const errorMsg = 'Failed to retrieve machine ID for license validation';
        if (strictPacks) {
          throw new SentriflowConfigError(errorMsg);
        }
        console.error(`Warning: ${errorMsg}`);
      }
    }

    // Track loading statistics
    let loadedCount = 0;
    let totalRules = 0;
    const failedPacks: string[] = [];

    // Load each pack based on detected format
    for (const desc of packDescriptors) {
      try {
        // Validate path is within allowed directories
        const validation = validatePackPath(desc.path, allowedBaseDirs);
        if (!validation.valid) {
          throw new SentriflowConfigError(validation.error ?? 'Invalid pack path');
        }

        let loadedPack: RulePack;

        switch (desc.format) {
          case 'grx2': {
            if (!licenseKey) {
              console.error(`Warning: Skipping GRX2 pack (no license key): ${desc.path}`);
              continue;
            }
            if (!machineId) {
              console.error(`Warning: Skipping GRX2 pack (no machine ID): ${desc.path}`);
              continue;
            }
            loadedPack = await loadExtendedPack(
              validation.canonicalPath!,
              licenseKey,
              machineId
            );
            loadedPack.priority = desc.priority;
            break;
          }

          case 'grpx': {
            if (!licenseKey) {
              console.error(`Warning: Skipping GRPX pack (no license key): ${desc.path}`);
              continue;
            }
            loadedPack = await loadEncryptedRulePack(
              validation.canonicalPath!,
              licenseKey,
              allowedBaseDirs
            );
            loadedPack.priority = desc.priority;
            break;
          }

          case 'unencrypted': {
            loadedPack = await loadRulePackFile(
              validation.canonicalPath!,
              allowedBaseDirs
            );
            loadedPack.priority = desc.priority;
            break;
          }

          default:
            console.error(`Warning: Unknown pack format, skipping: ${desc.path}`);
            continue;
        }

        allPacks.push(loadedPack);
        loadedCount++;
        totalRules += loadedPack.rules.length;
      } catch (error) {
        // Map error codes to user-friendly messages
        let errorMsg: string;
        if (error instanceof EncryptedPackError) {
          const messages: Record<string, string> = {
            LICENSE_MISSING: 'Invalid or missing license key',
            LICENSE_EXPIRED: 'License has expired',
            LICENSE_INVALID: 'License key is invalid for this pack',
            DECRYPTION_FAILED: 'Failed to decrypt pack (invalid key or corrupted data)',
            MACHINE_MISMATCH: 'License is not valid for this machine',
            PACK_CORRUPTED: 'Pack file is corrupted or invalid',
            NOT_EXTENDED_FORMAT: 'Pack is not in extended GRX2 format',
          };
          errorMsg = messages[error.code] ?? `Pack load error: ${error.message}`;
        } else {
          errorMsg = error instanceof Error ? error.message : 'Unknown error';
        }

        if (strictPacks) {
          throw new SentriflowConfigError(
            `Failed to load pack '${desc.path}': ${errorMsg}`
          );
        }
        console.error(`Warning: Failed to load pack: ${errorMsg}`);
        console.error(`Warning: Skipping pack: ${desc.path}`);
        failedPacks.push(desc.path);
      }
    }

    // Display summary of loaded packs
    if (packPathsArray.length > 0) {
      const successMsg = `Packs: ${loadedCount} of ${packPathsArray.length} loaded (${totalRules} rules)`;
      if (failedPacks.length > 0) {
        console.error(`${successMsg}, ${failedPacks.length} failed`);
      } else if (loadedCount > 0) {
        console.error(successMsg);
      }
    }
  }

  // Collect legacy disabled IDs
  const legacyDisabledIds = new Set<string>([
    ...(config.disable ?? []),
    ...disableIds,
  ]);

  // Build rule map with priority tracking
  const ruleMap = new Map<string, { rule: IRule; priority: number }>();

  // 1. Add default rules (priority 0) - filtered by vendor and disables
  if (config.includeDefaults !== false) {
    const defaults = vendorId ? getRulesByVendor(vendorId) : defaultRules;
    for (const rule of defaults) {
      if (
        !isDefaultRuleDisabled(rule.id, vendorId, allPacks, legacyDisabledIds)
      ) {
        ruleMap.set(rule.id, { rule, priority: 0 });
      }
    }
  }

  // 2. Process rule packs sorted by priority (ascending, so higher priority wins)
  const sortedPacks = allPacks.sort((a, b) => a.priority - b.priority);

  for (const pack of sortedPacks) {
    for (const rule of pack.rules) {
      // Filter by vendor if specified
      if (vendorId && !ruleAppliesToVendor(rule, vendorId)) {
        continue;
      }

      const existing = ruleMap.get(rule.id);
      if (!existing || pack.priority >= existing.priority) {
        ruleMap.set(rule.id, { rule, priority: pack.priority });
      }
    }
  }

  return Array.from(ruleMap.values()).map((entry) => entry.rule);
}
