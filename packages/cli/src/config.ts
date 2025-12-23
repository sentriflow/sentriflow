/**
 * Configuration file loader for SentriFlow CLI
 * Supports: sentriflow.config.js, sentriflow.config.ts, .sentriflowrc.js, .sentriflowrc.ts
 */
import {
  SentriflowConfigError,
  MAX_TRAVERSAL_DEPTH,
  RULE_ID_PATTERN,
  VALID_VENDOR_IDS,
  isValidVendorId, // SEC-012: Encrypted pack support
  loadEncryptedPack,
  validatePackFormat,
  PackLoadError,
  // JSON rules support
  validateJsonRuleFile,
  compileJsonRules,
  type JsonRuleFile,
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
  validateEncryptedPackPath,
  validateJsonRulesPath,
} from './security/pathValidator';
import {
  loadAndValidate,
  validatePathOrThrow,
  wrapLoadError,
} from './loaders';

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

  return true;
}

/**
 * Validates that an object has the basic structure of an IRule.
 */
function isValidRule(rule: unknown): rule is IRule {
  if (typeof rule !== 'object' || rule === null) {
    return false;
  }

  const obj = rule as Record<string, unknown>;

  // Required: id (string matching pattern)
  if (typeof obj.id !== 'string' || !RULE_ID_PATTERN.test(obj.id)) {
    return false;
  }

  // Required: check (function)
  if (typeof obj.check !== 'function') {
    return false;
  }

  // Optional: vendor (string or array of valid vendors)
  // SEC-004: Use centralized isValidVendorId from @sentriflow/core
  if (obj.vendor !== undefined) {
    if (Array.isArray(obj.vendor)) {
      for (const v of obj.vendor) {
        if (typeof v !== 'string' || !isValidVendorId(v)) {
          return false;
        }
      }
    } else if (typeof obj.vendor !== 'string' || !isValidVendorId(obj.vendor)) {
      return false;
    }
  }

  // Required: metadata (object with level)
  if (typeof obj.metadata !== 'object' || obj.metadata === null) {
    return false;
  }

  const metadata = obj.metadata as Record<string, unknown>;
  if (!['error', 'warning', 'info'].includes(metadata.level as string)) {
    return false;
  }

  return true;
}

/**
 * Validates that an object has the basic structure of a RulePack.
 */
function isValidRulePack(pack: unknown): pack is RulePack {
  if (typeof pack !== 'object' || pack === null) {
    return false;
  }

  const obj = pack as Record<string, unknown>;

  // Required: name (non-empty string)
  if (typeof obj.name !== 'string' || obj.name.length === 0) {
    return false;
  }

  // Required: version (string)
  if (typeof obj.version !== 'string' || obj.version.length === 0) {
    return false;
  }

  // Required: publisher (string)
  if (typeof obj.publisher !== 'string' || obj.publisher.length === 0) {
    return false;
  }

  // Required: priority (number >= 0)
  if (typeof obj.priority !== 'number' || obj.priority < 0) {
    return false;
  }

  // Required: rules (array)
  if (!Array.isArray(obj.rules)) {
    return false;
  }

  // Validate each rule in the pack
  for (const rule of obj.rules) {
    if (!isValidRule(rule)) {
      return false;
    }
  }

  // Optional: disables (object with specific structure)
  if (obj.disables !== undefined) {
    if (typeof obj.disables !== 'object' || obj.disables === null) {
      return false;
    }

    const disables = obj.disables as Record<string, unknown>;

    if (disables.all !== undefined && typeof disables.all !== 'boolean') {
      return false;
    }

    // SEC-004: Use centralized isValidVendorId from @sentriflow/core
    if (disables.vendors !== undefined) {
      if (!Array.isArray(disables.vendors)) {
        return false;
      }
      for (const v of disables.vendors) {
        if (typeof v !== 'string' || !isValidVendorId(v)) {
          return false;
        }
      }
    }

    if (disables.rules !== undefined) {
      if (!Array.isArray(disables.rules)) {
        return false;
      }
      for (const r of disables.rules) {
        if (typeof r !== 'string') {
          return false;
        }
      }
    }
  }

  return true;
}

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

  /** Path to rule pack file */
  rulePackPath?: string;

  /** SEC-012: Path(s) to encrypted rule pack(s) (.grpx) */
  encryptedPackPaths?: string | string[];

  /** SEC-012: License key for encrypted packs (shared across all packs) */
  licenseKey?: string;

  /** SEC-012: Fail if encrypted pack cannot be loaded (default: false, warn and continue) */
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

/**
 * Check if a rule applies to the given vendor.
 * Exported for use in per-file filtering when vendor detection happens after rule resolution.
 */
export function ruleAppliesToVendor(rule: IRule, vendorId: string): boolean {
  if (!rule.vendor) return true;
  if (Array.isArray(rule.vendor)) {
    return (
      rule.vendor.includes('common') ||
      rule.vendor.includes(vendorId as RuleVendor)
    );
  }
  return rule.vendor === 'common' || rule.vendor === vendorId;
}

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
    validateEncryptedPackPath,
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
 * 5. CLI --rule-pack file (its own priority)
 * 6. Config file JSON rules (priority 75)
 * 7. CLI --json-rules file(s) (priority 100+)
 * 8. SEC-012: CLI --encrypted-pack file (priority 200+)
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
    rulePackPath,
    encryptedPackPaths,
    licenseKey,
    strictPacks = false, // SEC-012: Default to graceful handling
    jsonRulesPaths,
    disableIds = [],
    vendorId,
    cwd = process.cwd(),
    allowedBaseDirs, // SEC-011: Allowed base directories for file path validation
  } = options;

  // Normalize encrypted pack paths to array
  const packPathsArray = encryptedPackPaths
    ? Array.isArray(encryptedPackPaths)
      ? encryptedPackPaths
      : [encryptedPackPaths]
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

  // Add CLI --rule-pack file
  if (rulePackPath) {
    const cliPack = await loadRulePackFile(rulePackPath, allowedBaseDirs);
    allPacks.push(cliPack);
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

  // SEC-012: Add CLI --encrypted-pack file(s) (priority 200+)
  if (packPathsArray.length > 0) {
    if (!licenseKey) {
      const errorMsg =
        'License key required for encrypted packs (use --license-key or set SENTRIFLOW_LICENSE_KEY)';
      if (strictPacks) {
        throw new SentriflowConfigError(errorMsg);
      }
      console.error(`Warning: ${errorMsg}`);
      console.error(
        `Warning: Skipping ${packPathsArray.length} encrypted pack(s)`
      );
    } else {
      // Load each pack with incrementing priority (200, 201, 202, ...)
      for (let i = 0; i < packPathsArray.length; i++) {
        const packPath = packPathsArray[i];
        if (!packPath) continue;

        try {
          const encryptedPack = await loadEncryptedRulePack(
            packPath,
            licenseKey,
            allowedBaseDirs
          );
          // Increment priority for each pack so later packs override earlier ones
          encryptedPack.priority = 200 + i;
          allPacks.push(encryptedPack);
        } catch (error) {
          const errorMsg =
            error instanceof Error ? error.message : 'Unknown error';
          if (strictPacks) {
            throw error;
          }
          console.error(`Warning: Failed to load encrypted pack: ${errorMsg}`);
          console.error(`Warning: Skipping encrypted pack: ${packPath}`);
        }
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
