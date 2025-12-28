declare const __VERSION__: string;

import * as vscode from 'vscode';
import {
  IncrementalParser,
  SchemaAwareParser,
  RuleEngine,
  MAX_EXTERNAL_RULES,
  RULE_ID_PATTERN,
  detectVendor,
  getVendor,
  isValidVendor,
  getAvailableVendors,
  getAvailableVendorInfo,
  VALID_VENDOR_IDS,
  isValidVendorId,
} from '@sentriflow/core';
import type {
  IRule,
  RuleVendor,
  RulePack,
  RulePackMetadata,
  PackDisableConfig,
  VendorSchema,
  IncrementalParserOptions,
} from '@sentriflow/core';
import { allRules, getRulesByVendor } from '@sentriflow/rules-default';
import { RulesTreeProvider, RuleTreeItem } from './providers/RulesTreeProvider';
import { SettingsWebviewProvider } from './providers/SettingsWebviewProvider';
import { SentriFlowHoverProvider } from './providers/HoverProvider';
import {
  IPAddressesTreeProvider,
  IPTreeItem,
} from './providers/IPAddressesTreeProvider';
import { LicenseTreeProvider } from './providers/LicenseTreeProvider';
import {
  LicenseManager,
  CloudClient,
  loadAllPacks,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
  type UpdateCheckResult,
  type EncryptedPackInfo,
  DEFAULT_PACKS_DIRECTORY,
  CACHE_DIRECTORY,
} from './encryption';

// ============================================================================
// Rule Pack Management
// ============================================================================

// SEC-004: Use centralized VALID_VENDOR_IDS from @sentriflow/core instead of local duplicate

/**
 * SEC-003: Rate limiter for public API methods.
 * Prevents DoS via rapid registration calls from malicious extensions.
 */
const apiRateLimiter = {
  lastCall: 0,
  callCount: 0,
  WINDOW_MS: 1000,
  MAX_CALLS_PER_WINDOW: 10,

  /**
   * Check if the current call is within rate limits.
   * @returns true if call is allowed, false if rate limited
   */
  check(): boolean {
    const now = Date.now();
    if (now - this.lastCall > this.WINDOW_MS) {
      this.callCount = 0;
      this.lastCall = now;
    }
    this.callCount++;
    return this.callCount <= this.MAX_CALLS_PER_WINDOW;
  },

  /**
   * Reset rate limiter state (for testing).
   */
  reset(): void {
    this.lastCall = 0;
    this.callCount = 0;
  },
};

/** Default pack name */
const DEFAULT_PACK_NAME = 'sf-default';

/** Default pack containing built-in rules */
const defaultPack: RulePack = {
  name: DEFAULT_PACK_NAME,
  version: __VERSION__,
  publisher: 'SentriFlow',
  description: 'Default rules for network configuration validation',
  license: 'MIT',
  priority: 0,
  rules: [], // Populated dynamically via getRulesByVendor
};

/** Registered rule packs (excluding default) */
const registeredPacks = new Map<string, RulePack>();

/** Legacy: individually disabled rule IDs (for backward compatibility) */
const disabledRuleIds = new Set<string>();

// ============================================================================
// Encrypted Pack Management
// ============================================================================

/** License manager instance (initialized on activation) */
let licenseManager: LicenseManager | null = null;

/** Cloud client instance (initialized when license is available) */
let cloudClient: CloudClient | null = null;

/** Currently loaded encrypted packs info */
let encryptedPacksInfo: EncryptedPackInfo[] = [];

/** Last update check result */
let lastUpdateCheck: UpdateCheckResult | null = null;

/**
 * Internal representation of a registered pack with computed state.
 */
interface RegisteredPackState {
  pack: RulePack;
  /** Rules indexed by ID for quick lookup */
  rulesById: Map<string, IRule>;
}

/**
 * Check if a rule applies to the given vendor.
 * Rules without a vendor property are considered vendor-agnostic (apply to all).
 * Rules with vendor: 'common' also apply to all vendors.
 */
function ruleAppliesToVendor(rule: IRule, vendorId: string): boolean {
  // No vendor specified = vendor-agnostic, applies to all
  if (!rule.vendor) {
    return true;
  }

  // Handle array of vendors
  if (Array.isArray(rule.vendor)) {
    return (
      rule.vendor.includes('common') ||
      rule.vendor.includes(vendorId as RuleVendor)
    );
  }

  // Single vendor
  return rule.vendor === 'common' || rule.vendor === vendorId;
}

/**
 * Check if a rule should be disabled based on settings and pack disable configs.
 * @param ruleId The rule ID to check
 * @param vendorId Optional vendor ID for vendor-specific disable checks
 * @param checkPackDisables Whether to check pack disable configs (for default rules only)
 */
/**
 * Parse disabledRules setting, handling comma-separated values.
 * Users might enter "NET-001,NET-002" as a single item instead of separate items.
 */
function getDisabledRulesSet(): Set<string> {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const disabledRules = config.get<string[]>('disabledRules', []);
  const ruleSet = new Set<string>();

  for (const item of disabledRules) {
    // Handle comma-separated values in a single item
    const parts = item
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    for (const part of parts) {
      ruleSet.add(part);
    }
  }

  return ruleSet;
}

function isRuleDisabled(
  ruleId: string,
  vendorId: string | undefined,
  checkPackDisables: boolean = true
): boolean {
  // Check user's disabledRules setting (applies to ALL rules)
  const disabledRulesSet = getDisabledRulesSet();
  if (disabledRulesSet.has(ruleId)) {
    log(`Rule ${ruleId} disabled via settings`);
    return true;
  }

  // Check legacy disabled set (programmatic API)
  if (disabledRuleIds.has(ruleId)) {
    return true;
  }

  // Check pack disable configs (only for default rules)
  if (checkPackDisables) {
    for (const pack of registeredPacks.values()) {
      if (!pack.disables) continue;

      // Check if all defaults are disabled
      if (pack.disables.all) {
        return true;
      }

      // Check if this specific rule is disabled
      if (pack.disables.rules?.includes(ruleId)) {
        return true;
      }

      // Check if vendor is disabled (only if we know the vendor)
      if (vendorId && pack.disables.vendors?.includes(vendorId as RuleVendor)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Validates that an object has the basic structure of an IRule.
 * Security: Prevents malicious extensions from registering invalid rules (M-4 fix).
 * Returns error message if invalid, null if valid.
 */
function validateRule(rule: unknown): string | null {
  if (typeof rule !== 'object' || rule === null) {
    return 'Rule is not an object';
  }

  const obj = rule as Record<string, unknown>;

  // Required: id (string matching pattern)
  if (typeof obj.id !== 'string') {
    return 'Rule id is not a string';
  }
  if (!RULE_ID_PATTERN.test(obj.id)) {
    return `Rule id "${obj.id}" does not match pattern ${RULE_ID_PATTERN}`;
  }

  // Required: check (function)
  if (typeof obj.check !== 'function') {
    return `Rule ${obj.id}: check is not a function (got ${typeof obj.check})`;
  }

  // Optional but recommended: selector (string)
  if (obj.selector !== undefined && typeof obj.selector !== 'string') {
    return `Rule ${obj.id}: selector is not a string`;
  }

  // Optional: vendor (string or array of strings)
  // SEC-004: Use centralized isValidVendorId from @sentriflow/core
  if (obj.vendor !== undefined) {
    if (Array.isArray(obj.vendor)) {
      // Validate each vendor in the array
      for (const v of obj.vendor) {
        if (typeof v !== 'string') {
          return `Rule ${obj.id}: vendor array contains non-string`;
        }
        if (!isValidVendorId(v)) {
          return `Rule ${obj.id}: invalid vendor "${v}"`;
        }
      }
    } else if (typeof obj.vendor !== 'string') {
      return `Rule ${obj.id}: vendor is not a string`;
    } else if (!isValidVendorId(obj.vendor)) {
      return `Rule ${obj.id}: invalid vendor "${obj.vendor}"`;
    }
  }

  // Required: metadata (object with level)
  if (typeof obj.metadata !== 'object' || obj.metadata === null) {
    return `Rule ${obj.id}: metadata is not an object`;
  }

  const metadata = obj.metadata as Record<string, unknown>;
  if (!['error', 'warning', 'info'].includes(metadata.level as string)) {
    return `Rule ${obj.id}: invalid metadata.level "${metadata.level}"`;
  }

  return null;
}

function isValidRule(rule: unknown): rule is IRule {
  return validateRule(rule) === null;
}

/**
 * Validates that an object has the basic structure of a RulePack.
 * Returns error message if invalid, null if valid.
 */
function validateRulePack(pack: unknown): string | null {
  if (typeof pack !== 'object' || pack === null) {
    return 'Pack is not an object';
  }

  const obj = pack as Record<string, unknown>;

  // Required: name (non-empty string)
  if (typeof obj.name !== 'string' || obj.name.length === 0) {
    return 'Pack name is missing or empty';
  }

  // Cannot use reserved default pack name
  if (obj.name === DEFAULT_PACK_NAME) {
    return `Pack name "${obj.name}" is reserved`;
  }

  // Required: version (string)
  if (typeof obj.version !== 'string' || obj.version.length === 0) {
    return 'Pack version is missing or empty';
  }

  // Required: publisher (string)
  if (typeof obj.publisher !== 'string' || obj.publisher.length === 0) {
    return 'Pack publisher is missing or empty';
  }

  // Required: priority (number)
  if (typeof obj.priority !== 'number' || obj.priority < 0) {
    return `Pack priority is invalid (got ${obj.priority})`;
  }

  // Required: rules (array)
  if (!Array.isArray(obj.rules)) {
    return 'Pack rules is not an array';
  }

  // Validate each rule in the pack
  for (let i = 0; i < obj.rules.length; i++) {
    const ruleError = validateRule(obj.rules[i]);
    if (ruleError) {
      return `Rule[${i}]: ${ruleError}`;
    }
  }

  // Optional: disables (object with specific structure)
  if (obj.disables !== undefined) {
    if (typeof obj.disables !== 'object' || obj.disables === null) {
      return 'Pack disables is not an object';
    }

    const disables = obj.disables as Record<string, unknown>;

    // Optional: all (boolean)
    if (disables.all !== undefined && typeof disables.all !== 'boolean') {
      return 'Pack disables.all is not a boolean';
    }

    // Optional: vendors (array of valid vendor strings)
    // SEC-004: Use centralized isValidVendorId from @sentriflow/core
    if (disables.vendors !== undefined) {
      if (!Array.isArray(disables.vendors)) {
        return 'Pack disables.vendors is not an array';
      }
      for (const v of disables.vendors) {
        if (typeof v !== 'string' || !isValidVendorId(v)) {
          return `Pack disables.vendors contains invalid vendor "${v}"`;
        }
      }
    }

    // Optional: rules (array of strings)
    if (disables.rules !== undefined) {
      if (!Array.isArray(disables.rules)) {
        return 'Pack disables.rules is not an array';
      }
      for (const r of disables.rules) {
        if (typeof r !== 'string') {
          return 'Pack disables.rules contains non-string';
        }
      }
    }
  }

  return null;
}

function isValidRulePack(pack: unknown): pack is RulePack {
  return validateRulePack(pack) === null;
}

/**
 * Get all rules from all packs, filtered by vendor and respecting priorities.
 *
 * Rule resolution order:
 * 1. Default pack rules (priority 0) - filtered by vendor, can be disabled
 * 2. Registered packs sorted by priority (higher wins)
 * 3. Same rule ID: higher priority pack wins
 *
 * @param vendorId Optional vendor ID to filter rules. If not provided, returns all rules.
 */
function getAllRules(vendorId?: string): IRule[] {
  // Track rules by ID with their source priority
  const ruleMap = new Map<string, { rule: IRule; priority: number }>();

  // Check if default rules are enabled
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);

  // 1. Add default pack rules (priority 0) - only if enabled
  if (enableDefaultRules) {
    const defaultRules = vendorId ? getRulesByVendor(vendorId) : allRules;
    for (const rule of defaultRules) {
      // Check if this default rule is disabled (check pack disables for default rules)
      if (isRuleDisabled(rule.id, vendorId, true)) {
        continue;
      }
      ruleMap.set(rule.id, { rule, priority: 0 });
    }
  }

  // 2. Get all registered packs sorted by priority (ascending, so higher priority processes last and wins)
  const sortedPacks = Array.from(registeredPacks.values()).sort(
    (a, b) => a.priority - b.priority
  );

  // Get per-pack vendor overrides
  const packVendorOverrides = config.get<
    Record<string, { disabledVendors?: string[] }>
  >('packVendorOverrides', {});

  // 3. Process each pack's rules
  for (const pack of sortedPacks) {
    // Get disabled vendors for this pack
    const packOverride = packVendorOverrides[pack.name];
    const disabledVendors = new Set(packOverride?.disabledVendors ?? []);

    for (const rule of pack.rules) {
      // Check if rule is globally disabled via settings (don't check pack disables for non-default packs)
      if (isRuleDisabled(rule.id, vendorId, false)) {
        continue;
      }

      // Filter by vendor if specified
      if (vendorId && !ruleAppliesToVendor(rule, vendorId)) {
        continue;
      }

      // Check if rule's vendor is disabled for this pack
      if (disabledVendors.size > 0) {
        // Rules without vendor or with vendor='common' are treated as 'common'
        const ruleVendors = rule.vendor
          ? Array.isArray(rule.vendor)
            ? rule.vendor
            : [rule.vendor]
          : ['common'];
        // Check if all of the rule's vendors are disabled
        const allVendorsDisabled = ruleVendors.every((v) =>
          disabledVendors.has(v)
        );
        if (allVendorsDisabled) {
          continue;
        }
      }

      // Check if this rule ID already exists
      const existing = ruleMap.get(rule.id);
      if (existing) {
        // Only override if this pack has higher or equal priority
        if (pack.priority >= existing.priority) {
          ruleMap.set(rule.id, { rule, priority: pack.priority });
        }
      } else {
        ruleMap.set(rule.id, { rule, priority: pack.priority });
      }
    }
  }

  const rules = Array.from(ruleMap.values()).map((entry) => entry.rule);

  // Update module-level rule map for O(1) lookup in diagnostics
  currentRuleMap = new Map(rules.map((r) => [r.id, r]));

  return rules;
}

/** Re-scan active editor after rule changes */
function rescanActiveEditor(): void {
  // Increment rules version to trigger index rebuild
  rulesVersion++;
  if (vscode.window.activeTextEditor) {
    scheduleScan(vscode.window.activeTextEditor.document, 0);
  }
}

/**
 * Handle pack disables configuration.
 * Prompts user once per pack if it has disables config.
 * Stores "prompted" state in workspace state to avoid repeated prompts.
 */
async function handlePackDisables(pack: RulePack): Promise<void> {
  if (!pack.disables) return;

  // Check if we've already prompted for this pack
  const promptedKey = `sentriflow.disablesPrompted.${pack.name}`;
  const alreadyPrompted = extensionContext.workspaceState.get<boolean>(
    promptedKey,
    false
  );

  if (alreadyPrompted) {
    return;
  }

  // Build description of what will be disabled
  const disableActions: string[] = [];
  if (pack.disables.all) {
    disableActions.push('disable ALL default rules');
  }
  if (pack.disables.vendors?.length) {
    disableActions.push(
      `disable default rules for vendors: ${pack.disables.vendors.join(', ')}`
    );
  }
  if (pack.disables.rules?.length) {
    const ruleCount = pack.disables.rules.length;
    disableActions.push(`disable ${ruleCount} specific default rule(s)`);
  }

  if (disableActions.length === 0) {
    return;
  }

  // Show prompt
  const message = `Pack '${pack.name}' requests to ${disableActions.join(
    ' and '
  )}. Apply these settings?`;

  const result = await vscode.window.showInformationMessage(
    message,
    { modal: false },
    'Yes, Apply',
    'No, Keep Defaults'
  );

  // Mark as prompted regardless of choice
  await extensionContext.workspaceState.update(promptedKey, true);

  if (result === 'Yes, Apply') {
    const config = vscode.workspace.getConfiguration('sentriflow');

    // Apply disables.all - disable default rules entirely
    if (pack.disables.all) {
      await config.update(
        'enableDefaultRules',
        false,
        vscode.ConfigurationTarget.Workspace
      );
      log(`Pack '${pack.name}': Disabled all default rules per pack request`);
    }

    // Apply disables.vendors - we don't have a direct setting for this,
    // but packs with disables.vendors will automatically override those rules
    // since they have higher priority. Just log it.
    if (pack.disables.vendors?.length) {
      log(
        `Pack '${
          pack.name
        }': Will override default rules for vendors: ${pack.disables.vendors.join(
          ', '
        )}`
      );
    }

    // Apply disables.rules - add to legacy disabled rules set
    if (pack.disables.rules?.length) {
      for (const ruleId of pack.disables.rules) {
        disabledRuleIds.add(ruleId);
      }
      log(
        `Pack '${pack.name}': Disabled ${pack.disables.rules.length} specific default rules`
      );
    }

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Applied disable settings from '${pack.name}'`
    );
    rulesTreeProvider.refresh();
    rescanActiveEditor();
  } else {
    log(`Pack '${pack.name}': User declined disable settings`);
  }
}

/**
 * Prompt user about default rules preference on first activation.
 * Uses globalState to persist the "already asked" flag across VS Code restarts.
 */
async function promptDefaultRulesOnce(): Promise<void> {
  const PROMPT_KEY = 'sentriflow.defaultRulesPrompted';

  // Check if we've already prompted the user
  const alreadyPrompted = extensionContext.globalState.get<boolean>(
    PROMPT_KEY,
    false
  );
  if (alreadyPrompted) {
    return;
  }

  // Show the prompt
  const result = await vscode.window.showInformationMessage(
    'SENTRIFLOW: Would you like to enable the built-in default rules for configuration validation?',
    { modal: false },
    'Yes, Enable',
    'No, Disable'
  );

  // Mark as prompted regardless of choice (even if dismissed)
  await extensionContext.globalState.update(PROMPT_KEY, true);

  if (result === 'No, Disable') {
    const config = vscode.workspace.getConfiguration('sentriflow');
    await config.update(
      'enableDefaultRules',
      false,
      vscode.ConfigurationTarget.Global
    );
    log('Default rules disabled by user choice during first activation');
    vscode.window.showInformationMessage(
      'SENTRIFLOW: Default rules disabled. You can re-enable them in settings.'
    );
    rulesTreeProvider.refresh();
    rescanActiveEditor();
  } else if (result === 'Yes, Enable') {
    log('Default rules confirmed enabled by user during first activation');
  } else {
    // User dismissed the prompt - keep default (enabled)
    log('Default rules prompt dismissed, keeping default (enabled)');
  }
}

// ============================================================================
// Vendor Configuration
// ============================================================================

/**
 * Get the configured vendor option from VS Code settings.
 * Returns 'auto' or a specific vendor ID.
 */
function getConfiguredVendor(): VendorSchema | 'auto' {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const vendorSetting = config.get<string>('defaultVendor', 'auto');

  if (vendorSetting === 'auto') {
    return 'auto';
  }

  if (isValidVendor(vendorSetting)) {
    return getVendor(vendorSetting);
  }

  // Invalid vendor setting - fallback to auto
  log(`Invalid vendor setting: ${vendorSetting}, falling back to auto`);
  return 'auto';
}

/**
 * Check if vendor should be shown in status bar.
 */
function shouldShowVendorInStatusBar(): boolean {
  const config = vscode.workspace.getConfiguration('sentriflow');
  return config.get<boolean>('showVendorInStatusBar', true);
}

// ============================================================================
// Singleton Instances - Reused across all scans to avoid GC pressure
// ============================================================================

// Create incremental parser with auto-detection by default
// Vendor will be resolved per-document based on settings
let incrementalParser = new IncrementalParser({ vendor: 'auto' });

const engine = new RuleEngine({
  enableTimeoutProtection: true,
  executionOptions: {
    timeoutMs: 100, // 100ms per rule per node
    maxTimeouts: 3, // Auto-disable after 3 timeouts
    onTimeout: (ruleId: string, nodeId: string, elapsedMs: number) => {
      log(
        `Rule ${ruleId} exceeded timeout (${elapsedMs.toFixed(
          1
        )}ms) on node: ${nodeId}`
      );
    },
    onRuleDisabled: (ruleId: string, reason: string) => {
      log(`Rule ${ruleId} auto-disabled: ${reason}`);
      vscode.window.showWarningMessage(
        `SENTRIFLOW: Rule ${ruleId} was auto-disabled due to slow performance`
      );
    },
    onError: (ruleId: string, nodeId: string, error: unknown) => {
      log(
        `[ERROR] Rule ${ruleId} failed on ${nodeId}: ${
          error instanceof Error ? error.stack ?? error.message : String(error)
        }`
      );
    },
  },
});

// Track when rules change to rebuild index only when needed
let rulesVersion = 0;
let lastIndexedVersion = -1;
let lastIndexedVendorId: string | null = null;

// Module-level rule map for O(1) lookup by rule ID (used for diagnostics with category)
let currentRuleMap = new Map<string, IRule>();

/**
 * Get a rule by its ID from the current rule map.
 * Used to enrich diagnostics with category information.
 */
function getRuleById(ruleId: string): IRule | undefined {
  return currentRuleMap.get(ruleId);
}

/**
 * Format category for display in diagnostic messages.
 */
function formatCategory(rule: IRule | undefined): string {
  if (!rule?.category) return 'general';
  return Array.isArray(rule.category)
    ? rule.category.join(', ')
    : rule.category;
}

// Track current vendor for status bar display
let currentVendor: VendorSchema | null = null;

// Category filter for diagnostics (undefined = show all)
let categoryFilter: string | undefined = undefined;

/**
 * Get unique categories from current rules.
 */
function getUniqueCategories(): string[] {
  const categories = new Set<string>();
  for (const rule of currentRuleMap.values()) {
    if (rule.category) {
      const cats = Array.isArray(rule.category)
        ? rule.category
        : [rule.category];
      cats.forEach((c) => categories.add(c));
    }
  }
  return [...categories].sort();
}

// ============================================================================
// Extension State
// ============================================================================
let extensionContext: vscode.ExtensionContext;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let vendorStatusBarItem: vscode.StatusBarItem;
let diagnosticCollection: vscode.DiagnosticCollection;
let rulesTreeProvider: RulesTreeProvider;
let settingsWebviewProvider: SettingsWebviewProvider;
let ipAddressesTreeProvider: IPAddressesTreeProvider;
let licenseTreeProvider: LicenseTreeProvider;

// Debounce timers per document URI
const debounceTimers = new Map<string, NodeJS.Timeout>();

// Track scan version to cancel stale results
const scanVersions = new Map<string, number>();

// Configuration
const SUPPORTED_LANGUAGES = ['network-config', 'plaintext'];
const DEBOUNCE_MS = 300;
const MAX_FILE_SIZE = 500_000; // 500KB - be conservative for real-time

// Debug mode - only log when explicitly enabled
let debugMode = false;

// ============================================================================
// Encrypted Pack Functions
// ============================================================================

/**
 * Initialize encrypted pack support.
 * Called during extension activation.
 */
async function initializeEncryptedPacks(
  context: vscode.ExtensionContext
): Promise<void> {
  log('[EncryptedPacks] Initializing encrypted packs support...');

  // Always initialize license manager (for license info display)
  licenseManager = new LicenseManager(context);
  log('[EncryptedPacks] License manager initialized');

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enabled = config.get<boolean>('encryptedPacks.enabled', true);
  log(`[EncryptedPacks] encryptedPacks.enabled = ${enabled}`);

  // Check if we have a license key
  const hasLicense = await licenseManager.hasLicenseKey();
  log(`[EncryptedPacks] Has license key: ${hasLicense}`);
  if (!hasLicense) {
    log(
      '[EncryptedPacks] No license key configured - encrypted packs not available'
    );
    return;
  }

  // Get license info (for display even if packs disabled)
  const licenseInfo = await licenseManager.getLicenseInfo();
  if (!licenseInfo) {
    logInfo('[EncryptedPacks] Failed to parse license info');
    return;
  }
  log(
    `[EncryptedPacks] License info: tier=${licenseInfo.payload.tier}, expires=${
      licenseInfo.expiryDate
    }, feeds=${licenseInfo.payload.feeds.join(',')}`
  );

  // Stop here if encrypted packs are disabled (but license info is still available)
  if (!enabled) {
    log(
      '[EncryptedPacks] Encrypted packs disabled by configuration - license info still available'
    );
    return;
  }

  if (licenseInfo.isExpired) {
    logInfo(`[EncryptedPacks] License expired on ${licenseInfo.expiryDate}`);
    vscode.window.showWarningMessage(
      `SentriFlow license expired on ${licenseInfo.expiryDate}. Encrypted packs will not be loaded.`
    );
    return;
  }

  // Warn if expiring soon
  if (licenseInfo.daysUntilExpiry <= 14) {
    vscode.window.showWarningMessage(
      `SentriFlow license expires in ${licenseInfo.daysUntilExpiry} days (${licenseInfo.expiryDate}).`
    );
  }

  // Initialize cloud client
  log(`[EncryptedPacks] API URL for updates: ${licenseInfo.payload.api}`);
  cloudClient = new CloudClient({
    apiUrl: licenseInfo.payload.api,
    licenseKey: licenseInfo.jwt,
  });

  // Check auto-update setting
  const autoUpdate = config.get<string>(
    'encryptedPacks.autoUpdate',
    'on-activation'
  );
  const shouldCheckUpdates = await licenseManager.isUpdateCheckDue(
    autoUpdate as 'disabled' | 'on-activation' | 'daily' | 'manual'
  );

  if (shouldCheckUpdates && cloudClient) {
    // Check for updates in background
    checkAndDownloadUpdates().catch((err) => {
      log(`Update check failed: ${err.message}`);
    });
  }

  // Load encrypted packs
  log('[EncryptedPacks] About to call loadEncryptedPacks()...');
  await loadEncryptedPacks();
  log('[EncryptedPacks] loadEncryptedPacks() returned');

  // Update license tree view
  updateLicenseTree();
  log('[EncryptedPacks] initializeEncryptedPacks() COMPLETED');
}

/**
 * Check for and download pack updates from cloud.
 */
async function checkAndDownloadUpdates(): Promise<void> {
  if (!cloudClient || !licenseManager) {
    return;
  }

  // Build local version map
  const localVersions = new Map<string, string>();
  for (const pack of encryptedPacksInfo) {
    if (pack.loaded) {
      localVersions.set(pack.feedId, pack.version);
    }
  }

  // Check for updates (errors logged silently, continues with cached packs)
  lastUpdateCheck = await checkForUpdatesWithProgress(
    cloudClient,
    localVersions,
    log
  );

  if (lastUpdateCheck?.hasUpdates) {
    const updateCount = lastUpdateCheck.updatesAvailable.length;
    const action = await vscode.window.showInformationMessage(
      `SentriFlow: ${updateCount} pack update(s) available`,
      'Download Now',
      'Later'
    );

    if (action === 'Download Now') {
      await downloadUpdatesWithProgress(
        cloudClient,
        lastUpdateCheck.updatesAvailable
      );
      // Reload packs after download
      await loadEncryptedPacks();
    }
  }

  // Record last check time
  await licenseManager.setLastUpdateCheck(new Date().toISOString());
}

/**
 * Load encrypted packs from configured directory and cache.
 */
async function loadEncryptedPacks(): Promise<void> {
  log('[EncryptedPacks] Starting loadEncryptedPacks...');

  if (!licenseManager) {
    log('[EncryptedPacks] Cannot load - no license manager initialized');
    return;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enabled = config.get<boolean>('encryptedPacks.enabled', true);
  log(`[EncryptedPacks] Enabled setting: ${enabled}`);

  if (!enabled) {
    log('[EncryptedPacks] Encrypted packs disabled in settings');
    return;
  }

  const licenseInfo = await licenseManager.getLicenseInfo();
  if (!licenseInfo) {
    log('[EncryptedPacks] No license key configured');
    return;
  }
  if (licenseInfo.isExpired) {
    log(`[EncryptedPacks] License expired on ${licenseInfo.expiryDate}`);
    return;
  }
  log(
    `[EncryptedPacks] License valid - tier: ${
      licenseInfo.payload.tier
    }, feeds: ${licenseInfo.payload.feeds.join(', ')}`
  );

  const configDirectory = config.get<string>('encryptedPacks.directory', '');
  const directory = configDirectory || DEFAULT_PACKS_DIRECTORY;
  log(`[EncryptedPacks] Scanning directory: ${directory}`);

  // Use machine ID only if license is bound to a specific machine
  // Portable licenses (no 'mid' in JWT) use 'portable-pack' convention
  let machineId: string;
  const actualMachineId = await licenseManager.getMachineId();
  log(`[EncryptedPacks] This machine's ID: ${actualMachineId}`);

  if (licenseInfo.payload.mid) {
    if (licenseInfo.payload.mid !== actualMachineId) {
      logInfo(`[EncryptedPacks] ERROR: License bound to different machine`);
      log(
        `[EncryptedPacks] Machine ID mismatch! License: ${licenseInfo.payload.mid}, this machine: ${actualMachineId}`
      );
      vscode.window.showErrorMessage(
        'SentriFlow: This license is bound to a different machine. Encrypted packs will not load.'
      );
      return;
    }
    machineId = actualMachineId;
    log(
      `[EncryptedPacks] Machine ID verified: ${machineId.substring(0, 8)}...`
    );
  } else {
    machineId = 'portable-pack';
    log('[EncryptedPacks] Machine ID binding: portable (portable-pack)');
  }

  // Clear existing encrypted packs
  for (const packInfo of encryptedPacksInfo) {
    if (packInfo.loaded && registeredPacks.has(packInfo.feedId)) {
      registeredPacks.delete(packInfo.feedId);
    }
  }
  encryptedPacksInfo = [];

  // Load from main directory
  log(`[EncryptedPacks] Loading from main directory: ${directory}`);
  const mainResult = await loadAllPacks(
    directory,
    licenseInfo.jwt,
    machineId,
    licenseInfo.payload.feeds,
    log
  );
  log(
    `[EncryptedPacks] Main directory result: ${mainResult.packs.length} packs found, ${mainResult.errors.length} errors`
  );
  if (mainResult.errors.length > 0) {
    logInfo(
      `[EncryptedPacks] Errors loading packs: ${mainResult.errors.join('; ')}`
    );
  }
  for (const pack of mainResult.packs) {
    log(
      `[EncryptedPacks]   - ${pack.feedId}: ${
        pack.loaded ? 'loaded' : 'failed'
      } (${pack.error || 'ok'})`
    );
  }

  // Load from cache directory
  log(`[EncryptedPacks] Loading from cache directory: ${CACHE_DIRECTORY}`);
  const cacheResult = await loadAllPacks(
    CACHE_DIRECTORY,
    licenseInfo.jwt,
    machineId,
    licenseInfo.payload.feeds,
    log
  );
  log(
    `[EncryptedPacks] Cache directory result: ${cacheResult.packs.length} packs found, ${cacheResult.errors.length} errors`
  );
  if (cacheResult.errors.length > 0) {
    log(
      `[EncryptedPacks] Cache directory errors: ${cacheResult.errors.join(
        '; '
      )}`
    );
  }

  // Merge results (prefer cache for newer versions)
  const allPacks = new Map<string, EncryptedPackInfo>();

  for (const pack of mainResult.packs) {
    allPacks.set(pack.feedId, pack);
  }

  for (const pack of cacheResult.packs) {
    const existing = allPacks.get(pack.feedId);
    if (!existing || (pack.loaded && !existing.loaded)) {
      allPacks.set(pack.feedId, { ...pack, source: 'cache' });
    }
  }

  encryptedPacksInfo = Array.from(allPacks.values());
  log(`[EncryptedPacks] Total merged packs: ${encryptedPacksInfo.length}`);

  // Register loaded packs with the extension
  let loadedCount = 0;
  let totalRules = 0;

  for (const packInfo of encryptedPacksInfo) {
    if (packInfo.loaded) {
      // Load the actual pack data again (we need the rules)
      try {
        const packResult = await loadAllPacks(
          packInfo.source === 'cache' ? CACHE_DIRECTORY : directory,
          licenseInfo.jwt,
          machineId,
          [packInfo.feedId],
          log
        );

        // Find matching pack with rules
        // The loadAllPacks returns pack info but not the actual rules
        // We need to use loadExtendedPack directly
        const { loadExtendedPack } = await import(
          './encryption/GRX2ExtendedLoader'
        );
        const pack = await loadExtendedPack(
          packInfo.filePath,
          licenseInfo.jwt,
          machineId,
          log
        );

        // Register the pack
        registeredPacks.set(packInfo.feedId, {
          ...pack,
          name: packInfo.feedId,
        });

        loadedCount++;
        totalRules += pack.rules.length;
        logInfo(
          `Loaded encrypted pack: ${packInfo.feedId} v${packInfo.version} (${pack.rules.length} rules)`
        );
      } catch (err) {
        logInfo(
          `Failed to load encrypted pack ${packInfo.feedId}: ${
            (err as Error).message
          }`
        );
      }
    }
  }

  if (loadedCount > 0) {
    logInfo(`Loaded ${loadedCount} encrypted pack(s) with ${totalRules} rules`);
    rulesTreeProvider?.refresh();
    rescanActiveEditor();
  }

  // Log errors
  const allErrors = [...mainResult.errors, ...cacheResult.errors];
  for (const error of allErrors) {
    log(`Encrypted pack error: ${error}`);
  }

  // Update license tree with loaded packs
  updateLicenseTree();
}

/**
 * Update the license tree view with current license and pack info.
 */
async function updateLicenseTree(): Promise<void> {
  if (!licenseTreeProvider) {
    return;
  }

  const hasKey = licenseManager ? await licenseManager.hasLicenseKey() : false;
  const licenseInfo = licenseManager
    ? await licenseManager.getLicenseInfo()
    : null;

  licenseTreeProvider.setLicenseInfo(licenseInfo, hasKey);
  licenseTreeProvider.setEncryptedPacks(encryptedPacksInfo);
}

/**
 * Command: Enter license key
 */
async function cmdEnterLicenseKey(): Promise<void> {
  if (!licenseManager) {
    licenseManager = new LicenseManager(extensionContext);
  }

  const success = await licenseManager.promptForLicenseKey();
  if (success) {
    // Initialize cloud client for update checks
    const licenseInfo = await licenseManager.getLicenseInfo();
    if (licenseInfo && !licenseInfo.isExpired && licenseInfo.payload.api) {
      log(`[EncryptedPacks] API URL for updates: ${licenseInfo.payload.api}`);
      cloudClient = new CloudClient({
        apiUrl: licenseInfo.payload.api,
        licenseKey: licenseInfo.jwt,
      });
    }

    // Reload encrypted packs with new license
    await loadEncryptedPacks();
    updateLicenseTree();
  }
}

/**
 * Command: Clear license key
 */
async function cmdClearLicenseKey(): Promise<void> {
  if (!licenseManager) {
    vscode.window.showInformationMessage('No license key configured');
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    'Are you sure you want to clear your SentriFlow license key?',
    'Yes',
    'No'
  );

  if (confirm === 'Yes') {
    await licenseManager.clearLicenseKey();

    // Unregister encrypted packs
    for (const packInfo of encryptedPacksInfo) {
      if (registeredPacks.has(packInfo.feedId)) {
        registeredPacks.delete(packInfo.feedId);
      }
    }
    encryptedPacksInfo = [];

    cloudClient = null;
    vscode.window.showInformationMessage('License key cleared');
    rulesTreeProvider?.refresh();
    rescanActiveEditor();
    updateLicenseTree();
  }
}

/**
 * Command: Show license status
 */
async function cmdShowLicenseStatus(): Promise<void> {
  if (!licenseManager) {
    licenseManager = new LicenseManager(extensionContext);
  }
  await licenseManager.showLicenseStatus();
}

/**
 * Command: Check for pack updates
 */
async function cmdCheckForUpdates(): Promise<void> {
  if (!cloudClient || !licenseManager) {
    const action = await vscode.window.showWarningMessage(
      'No license key configured. Enter a license key to check for updates.',
      'Enter License Key'
    );
    if (action === 'Enter License Key') {
      await cmdEnterLicenseKey();
    }
    return;
  }

  // Build local version map
  const localVersions = new Map<string, string>();
  for (const pack of encryptedPacksInfo) {
    if (pack.loaded) {
      localVersions.set(pack.feedId, pack.version);
    }
  }

  lastUpdateCheck = await checkForUpdatesWithProgress(
    cloudClient,
    localVersions,
    log
  );

  if (lastUpdateCheck) {
    await licenseManager.setLastUpdateCheck(new Date().toISOString());

    if (lastUpdateCheck.hasUpdates) {
      const updateCount = lastUpdateCheck.updatesAvailable.length;
      vscode.window.showInformationMessage(
        `SentriFlow: ${updateCount} pack update(s) available. Use "Download Pack Updates" to download.`
      );
    } else {
      vscode.window.showInformationMessage(
        'SentriFlow: All packs are up to date'
      );
    }
  }
}

/**
 * Command: Download pack updates
 */
async function cmdDownloadUpdates(): Promise<void> {
  if (!cloudClient) {
    vscode.window.showWarningMessage('No license key configured');
    return;
  }

  if (!lastUpdateCheck?.hasUpdates) {
    // Check first
    await cmdCheckForUpdates();
    if (!lastUpdateCheck?.hasUpdates) {
      return;
    }
  }

  const downloaded = await downloadUpdatesWithProgress(
    cloudClient,
    lastUpdateCheck.updatesAvailable
  );

  if (downloaded.length > 0) {
    vscode.window.showInformationMessage(
      `Downloaded ${downloaded.length} pack update(s). Reloading...`
    );
    await loadEncryptedPacks();
  }
}

/**
 * Command: Reload encrypted packs
 */
async function cmdReloadEncryptedPacks(): Promise<void> {
  await loadEncryptedPacks();
  vscode.window.showInformationMessage('Encrypted packs reloaded');
}

/**
 * Command: Show encrypted pack status
 */
async function cmdShowEncryptedPackStatus(): Promise<void> {
  if (encryptedPacksInfo.length === 0) {
    vscode.window.showInformationMessage('No encrypted packs loaded');
    return;
  }

  const items: vscode.QuickPickItem[] = encryptedPacksInfo.map((pack) => ({
    label: `${pack.loaded ? '$(check)' : '$(x)'} ${pack.name || pack.feedId}`,
    description: `v${pack.version} - ${pack.ruleCount} rules`,
    detail: pack.loaded
      ? `Source: ${pack.source} | Publisher: ${pack.publisher}`
      : `Error: ${pack.error}`,
  }));

  await vscode.window.showQuickPick(items, {
    title: 'Encrypted Pack Status',
    placeHolder: `${encryptedPacksInfo.filter((p) => p.loaded).length} of ${
      encryptedPacksInfo.length
    } packs loaded`,
  });
}

// ============================================================================
// Activation
// ============================================================================
export function activate(context: vscode.ExtensionContext) {
  try {
    // Store context for use in API functions
    extensionContext = context;

    // Create output channel (lazy - don't show unless needed)
    outputChannel = vscode.window.createOutputChannel('SentriFlow Linter');

    // Create status bar item for scan results
    statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );
    statusBarItem.command = 'sentriflow.scan';
    statusBarItem.tooltip = 'Click to scan current file';
    statusBarItem.show();

    // Create status bar item for vendor selection
    vendorStatusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      99
    );
    vendorStatusBarItem.command = 'sentriflow.selectVendor';
    vendorStatusBarItem.tooltip = 'Click to change vendor';
    vendorStatusBarItem.show();

    // Initialize status bar displays
    updateStatusBar('ready');

    // Create diagnostic collection
    diagnosticCollection =
      vscode.languages.createDiagnosticCollection('sentriflow');

    // Create and register Rules TreeView
    rulesTreeProvider = new RulesTreeProvider();
    rulesTreeProvider.initialize(
      () => defaultPack,
      () => registeredPacks,
      () => allRules,
      getDisabledRulesSet,
      (packName: string) =>
        encryptedPacksInfo.some((p) => p.feedId === packName && p.loaded)
    );
    const rulesTreeView = vscode.window.createTreeView('sentriflowRules', {
      treeDataProvider: rulesTreeProvider,
      showCollapseAll: true,
    });
    context.subscriptions.push(rulesTreeView);

    // Create and register Settings Webview
    settingsWebviewProvider = new SettingsWebviewProvider(context.extensionUri);
    settingsWebviewProvider.initialize(
      () => defaultPack,
      () => registeredPacks,
      () => allRules,
      getDisabledRulesSet
    );
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(
        SettingsWebviewProvider.viewType,
        settingsWebviewProvider
      )
    );

    // Create and register IP Addresses TreeView
    ipAddressesTreeProvider = new IPAddressesTreeProvider();
    const ipAddressesTreeView = vscode.window.createTreeView(
      'sentriflowIPAddresses',
      {
        treeDataProvider: ipAddressesTreeProvider,
        showCollapseAll: true,
      }
    );
    context.subscriptions.push(ipAddressesTreeView);

    // Initialize IP view with current document
    if (vscode.window.activeTextEditor) {
      ipAddressesTreeProvider.updateFromDocument(
        vscode.window.activeTextEditor.document
      );
    }

    // Create and register License TreeView
    licenseTreeProvider = new LicenseTreeProvider();
    const licenseTreeView = vscode.window.createTreeView('sentriflowLicense', {
      treeDataProvider: licenseTreeProvider,
      showCollapseAll: false,
    });
    context.subscriptions.push(licenseTreeView);

    // Register hover provider for diagnostic tooltips with category and tags
    const hoverProvider = new SentriFlowHoverProvider(
      diagnosticCollection,
      getRuleById
    );
    context.subscriptions.push(
      vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider)
    );

    // Register commands
    context.subscriptions.push(
      vscode.commands.registerCommand('sentriflow.scan', cmdScanFile),
      vscode.commands.registerCommand(
        'sentriflow.scanSelection',
        cmdScanSelection
      ),
      vscode.commands.registerCommand('sentriflow.setLanguage', cmdSetLanguage),
      vscode.commands.registerCommand('sentriflow.toggleDebug', cmdToggleDebug),
      vscode.commands.registerCommand(
        'sentriflow.selectVendor',
        cmdSelectVendor
      ),
      vscode.commands.registerCommand(
        'sentriflow.showRulePacks',
        cmdShowRulePacks
      ),
      // TreeView commands
      vscode.commands.registerCommand(
        'sentriflow.disableTreeItem',
        cmdDisableTreeItem
      ),
      vscode.commands.registerCommand(
        'sentriflow.enableTreeItem',
        cmdEnableTreeItem
      ),
      vscode.commands.registerCommand('sentriflow.copyRuleId', cmdCopyRuleId),
      vscode.commands.registerCommand(
        'sentriflow.viewRuleDetails',
        cmdViewRuleDetails
      ),
      vscode.commands.registerCommand('sentriflow.refreshRulesTree', () =>
        rulesTreeProvider.refresh()
      ),
      // Direct commands
      vscode.commands.registerCommand('sentriflow.togglePack', cmdTogglePack),
      vscode.commands.registerCommand(
        'sentriflow.toggleVendor',
        cmdToggleVendor
      ),
      vscode.commands.registerCommand(
        'sentriflow.disableRuleById',
        cmdDisableRuleById
      ),
      vscode.commands.registerCommand(
        'sentriflow.enableRuleById',
        cmdEnableRuleById
      ),
      vscode.commands.registerCommand(
        'sentriflow.showDisabled',
        cmdShowDisabled
      ),
      vscode.commands.registerCommand(
        'sentriflow.filterTagType',
        cmdFilterTagType
      ),
      vscode.commands.registerCommand(
        'sentriflow.filterByCategory',
        cmdFilterByCategory
      ),
      vscode.commands.registerCommand('sentriflow.focusRulesView', () =>
        vscode.commands.executeCommand('sentriflowRules.focus')
      )
    );

    // Register encrypted pack commands
    context.subscriptions.push(
      vscode.commands.registerCommand(
        'sentriflow.enterLicenseKey',
        cmdEnterLicenseKey
      ),
      vscode.commands.registerCommand(
        'sentriflow.clearLicenseKey',
        cmdClearLicenseKey
      ),
      vscode.commands.registerCommand(
        'sentriflow.showLicenseStatus',
        cmdShowLicenseStatus
      ),
      vscode.commands.registerCommand(
        'sentriflow.checkForUpdates',
        cmdCheckForUpdates
      ),
      vscode.commands.registerCommand(
        'sentriflow.downloadUpdates',
        cmdDownloadUpdates
      ),
      vscode.commands.registerCommand(
        'sentriflow.reloadEncryptedPacks',
        cmdReloadEncryptedPacks
      ),
      vscode.commands.registerCommand(
        'sentriflow.showEncryptedPackStatus',
        cmdShowEncryptedPackStatus
      )
    );

    // Register IP TreeView commands
    context.subscriptions.push(
      vscode.commands.registerCommand('sentriflow.refreshIPTree', () => {
        if (vscode.window.activeTextEditor) {
          ipAddressesTreeProvider.updateFromDocument(
            vscode.window.activeTextEditor.document
          );
        }
      }),
      vscode.commands.registerCommand('sentriflow.copyAllIPs', async () => {
        const allIPs = ipAddressesTreeProvider.getAllIPsForClipboard();
        if (allIPs) {
          await vscode.env.clipboard.writeText(allIPs);
          const counts = ipAddressesTreeProvider.getCounts();
          vscode.window.showInformationMessage(
            `Copied ${counts.total} IP addresses/subnets to clipboard.`
          );
        } else {
          vscode.window.showInformationMessage('No IP addresses to copy.');
        }
      }),
      vscode.commands.registerCommand(
        'sentriflow.copyIPValue',
        async (ipValue: string) => {
          if (ipValue) {
            await vscode.env.clipboard.writeText(ipValue);
            vscode.window.showInformationMessage(`Copied: ${ipValue}`);
          }
        }
      ),
      vscode.commands.registerCommand(
        'sentriflow.copyIPCategory',
        async (item: IPTreeItem) => {
          if (item?.categoryId) {
            const categoryIPs =
              ipAddressesTreeProvider.getCategoryIPsForClipboard(
                item.categoryId
              );
            if (categoryIPs) {
              await vscode.env.clipboard.writeText(categoryIPs);
              const count = ipAddressesTreeProvider.getCategoryCount(
                item.categoryId
              );
              const categoryLabel = item.categoryId
                .replace(/-/g, ' ')
                .replace(/ipv(\d)/g, 'IPv$1');
              vscode.window.showInformationMessage(
                `Copied ${count} ${categoryLabel} to clipboard.`
              );
            }
          }
        }
      )
    );

    // Register event handlers with debouncing
    context.subscriptions.push(
      vscode.workspace.onDidChangeTextDocument(onDocumentChange),
      vscode.workspace.onDidSaveTextDocument((doc) => scheduleScan(doc, 0)), // Immediate on save
      vscode.workspace.onDidOpenTextDocument((doc) => scheduleScan(doc, 100)), // Quick on open
      vscode.workspace.onDidCloseTextDocument(onDocumentClose),
      vscode.window.onDidChangeActiveTextEditor(onActiveEditorChange),
      vscode.workspace.onDidChangeConfiguration(onConfigurationChange)
    );

    // Register disposables
    context.subscriptions.push(
      outputChannel,
      statusBarItem,
      vendorStatusBarItem,
      diagnosticCollection
    );

    // Initial scan of active editor
    if (vscode.window.activeTextEditor) {
      scheduleScan(vscode.window.activeTextEditor.document, 0);
    }

    // Prompt user about default rules (once per installation)
    promptDefaultRulesOnce();

    // Initialize encrypted pack support (async, don't block activation)
    initializeEncryptedPacks(context)
      .catch((err) => {
        log(`Failed to initialize encrypted packs: ${(err as Error).message}`);
      })
      .finally(() => {
        // Always update license tree after initialization attempt
        updateLicenseTree();
      });

    logInfo('SENTRIFLOW extension activated');
    logInfo(`Available vendors: ${getAvailableVendors().join(', ')}`);

    // Return API for other extensions to register rules and packs
    return {
      // ========================================================================
      // Rule Pack API (Recommended)
      // ========================================================================

      /**
       * Register a rule pack with full metadata and priority.
       *
       * Rule packs can:
       * - Override default rules by using the same rule ID
       * - Disable default rules by vendor, by rule ID, or entirely
       * - Be prioritized (higher priority packs win on rule ID conflicts)
       *
       * @param pack The rule pack to register
       * @returns true if registration succeeded, false otherwise
       *
       * @example
       * ```typescript
       * sentriflow.registerRulePack({
       *   name: 'acme-secpack',
       *   version: '1.0.0',
       *   publisher: 'ACME Corp',
       *   description: 'Enterprise security rules',
       *   license: 'Commercial',
       *   homepage: 'https://acme.com/secpack',
       *   priority: 100,
       *   rules: [
       *     { id: 'ACME-001', vendor: 'cisco-ios', selector: 'interface', ... },
       *   ],
       *   disables: {
       *     vendors: ['cisco-ios', 'cisco-nxos'], // Disable all Cisco default rules
       *     rules: ['NET-IP-001'],                // Disable specific rules
       *   },
       * });
       * ```
       */
      registerRulePack: (pack: unknown): boolean => {
        try {
          // SEC-003: Rate limit API calls to prevent DoS
          if (!apiRateLimiter.check()) {
            const msg = 'Too many registration attempts. Please try again.';
            console.error(`SENTRIFLOW: ${msg}`);
            vscode.window.showErrorMessage(`SENTRIFLOW: ${msg}`);
            return false;
          }

          const validationError = validateRulePack(pack);
          if (validationError) {
            console.error(`SENTRIFLOW: Invalid rule pack - ${validationError}`);
            vscode.window.showErrorMessage(
              `SENTRIFLOW: Invalid rule pack - ${validationError}`
            );
            return false;
          }

          // After validation, we know pack is a valid RulePack
          const validPack = pack as RulePack;

          // Check if pack is blocked by configuration
          const config = vscode.workspace.getConfiguration('sentriflow');
          const blockedPacks = config.get<string[]>('blockedPacks', []);
          if (blockedPacks.includes(validPack.name)) {
            const msg = `Pack '${validPack.name}' is blocked by configuration`;
            console.error(`SENTRIFLOW: ${msg}`);
            vscode.window.showWarningMessage(`SENTRIFLOW: ${msg}`);
            return false;
          }

          // Check if pack already exists
          if (registeredPacks.has(validPack.name)) {
            log(`Warning: Replacing existing pack '${validPack.name}'`);
          }

          // Check total rule count limit
          const currentRuleCount = Array.from(registeredPacks.values()).reduce(
            (sum, p) => sum + p.rules.length,
            0
          );
          if (currentRuleCount + validPack.rules.length > MAX_EXTERNAL_RULES) {
            const msg = `Pack '${validPack.name}' has too many rules (${
              validPack.rules.length
            }). Maximum allowed: ${MAX_EXTERNAL_RULES - currentRuleCount}`;
            console.error(`SENTRIFLOW: ${msg}`);
            vscode.window.showErrorMessage(`SENTRIFLOW: ${msg}`);
            return false;
          }

          registeredPacks.set(validPack.name, validPack);
          logInfo(
            `Registered rule pack '${validPack.name}' v${validPack.version} (${validPack.rules.length} rules, priority ${validPack.priority})`
          );

          rulesTreeProvider.refresh();
          rescanActiveEditor();

          // Handle disables config (async, don't block registration)
          if (validPack.disables) {
            handlePackDisables(validPack);
          }

          return true;
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Unknown error';
          console.error(`SENTRIFLOW: Failed to register rule pack - ${msg}`);
          vscode.window.showErrorMessage(
            `SENTRIFLOW: Failed to register rule pack - ${msg}`
          );
          return false;
        }
      },

      /**
       * Unregister a rule pack by name.
       *
       * @param packName The name of the pack to unregister
       * @returns true if the pack was found and removed, false otherwise
       */
      unregisterRulePack: (packName: string): boolean => {
        if (typeof packName !== 'string' || packName === DEFAULT_PACK_NAME) {
          return false;
        }

        if (registeredPacks.has(packName)) {
          registeredPacks.delete(packName);
          log(`Unregistered rule pack '${packName}'`);
          rulesTreeProvider.refresh();
          rescanActiveEditor();
          return true;
        }

        return false;
      },

      /**
       * Get metadata for all registered packs (including default).
       */
      getRegisteredPacks: (): RulePackMetadata[] => {
        const packs: RulePackMetadata[] = [
          {
            name: defaultPack.name,
            version: defaultPack.version,
            publisher: defaultPack.publisher,
            description: defaultPack.description,
            license: defaultPack.license,
          },
        ];

        for (const pack of registeredPacks.values()) {
          packs.push({
            name: pack.name,
            version: pack.version,
            publisher: pack.publisher,
            description: pack.description,
            license: pack.license,
            homepage: pack.homepage,
          });
        }

        return packs;
      },

      /**
       * Get detailed info about a specific pack.
       */
      getPackInfo: (
        packName: string
      ): {
        metadata: RulePackMetadata;
        ruleCount: number;
        priority: number;
      } | null => {
        if (packName === DEFAULT_PACK_NAME) {
          return {
            metadata: {
              name: defaultPack.name,
              version: defaultPack.version,
              publisher: defaultPack.publisher,
              description: defaultPack.description,
              license: defaultPack.license,
            },
            ruleCount: allRules.length,
            priority: 0,
          };
        }

        const pack = registeredPacks.get(packName);
        if (!pack) return null;

        return {
          metadata: {
            name: pack.name,
            version: pack.version,
            publisher: pack.publisher,
            description: pack.description,
            license: pack.license,
            homepage: pack.homepage,
          },
          ruleCount: pack.rules.length,
          priority: pack.priority,
        };
      },

      // ========================================================================
      // Legacy API (Backward Compatible)
      // ========================================================================

      /**
       * @deprecated Use registerRulePack() instead.
       * Register individual rules (creates an anonymous pack with priority 50).
       */
      registerRules: (rules: unknown[]): number => {
        // SEC-003: Rate limit API calls to prevent DoS
        if (!apiRateLimiter.check()) {
          log('Rate limit exceeded for registerRules');
          return 0;
        }

        if (!Array.isArray(rules)) {
          log('Error: registerRules requires an array');
          return 0;
        }

        const validRules: IRule[] = [];
        for (const rule of rules) {
          if (isValidRule(rule)) {
            validRules.push(rule);
          } else {
            // SEC-005: Sanitize log message to prevent information disclosure
            const safeRuleId =
              typeof rule === 'object' && rule !== null && 'id' in rule
                ? String((rule as Record<string, unknown>).id).slice(0, 50)
                : 'unknown';
            log(`Rejected invalid rule: ${safeRuleId} (validation failed)`);
          }
        }

        if (validRules.length === 0) {
          return 0;
        }

        // Create or update anonymous legacy pack
        const legacyPackName = '_legacy_rules';
        const existingPack = registeredPacks.get(legacyPackName);
        const existingRules = existingPack?.rules ?? [];

        const totalRuleCount = Array.from(registeredPacks.values()).reduce(
          (sum, p) => sum + p.rules.length,
          0
        );
        if (totalRuleCount + validRules.length > MAX_EXTERNAL_RULES) {
          log(
            `Error: Cannot register rules. Would exceed maximum limit (${MAX_EXTERNAL_RULES})`
          );
          return 0;
        }

        registeredPacks.set(legacyPackName, {
          name: legacyPackName,
          version: '1.0.0',
          publisher: 'Legacy',
          description: 'Rules registered via legacy registerRules() API',
          priority: 50,
          rules: [...existingRules, ...validRules],
        });

        log(`Registered ${validRules.length} rule(s) via legacy API`);
        rescanActiveEditor();
        return validRules.length;
      },

      /**
       * @deprecated Use registerRulePack() with disables config instead.
       * Disable rules by ID.
       */
      disableRules: (ruleIds: unknown[]): number => {
        // SEC-003: Rate limit API calls to prevent DoS
        if (!apiRateLimiter.check()) {
          log('Rate limit exceeded for disableRules');
          return 0;
        }

        if (!Array.isArray(ruleIds)) {
          log('Error: disableRules requires an array');
          return 0;
        }

        let count = 0;
        for (const id of ruleIds) {
          if (typeof id === 'string' && id.length > 0) {
            disabledRuleIds.add(id);
            count++;
          }
        }

        if (count > 0) {
          log(`Disabled ${count} rule(s) via legacy API`);
          rescanActiveEditor();
        }

        return count;
      },

      /**
       * @deprecated
       * Re-enable previously disabled rules.
       */
      enableRules: (ruleIds: unknown[]): number => {
        // SEC-003: Rate limit API calls to prevent DoS
        if (!apiRateLimiter.check()) {
          log('Rate limit exceeded for enableRules');
          return 0;
        }

        if (!Array.isArray(ruleIds)) {
          log('Error: enableRules requires an array');
          return 0;
        }

        let count = 0;
        for (const id of ruleIds) {
          if (typeof id === 'string' && disabledRuleIds.has(id)) {
            disabledRuleIds.delete(id);
            count++;
          }
        }

        if (count > 0) {
          log(`Enabled ${count} rule(s)`);
          rescanActiveEditor();
        }

        return count;
      },

      // ========================================================================
      // Query API
      // ========================================================================

      /**
       * Get list of individually disabled rule IDs (legacy).
       */
      getDisabledRules: () => Array.from(disabledRuleIds),

      /**
       * Get count of total active rules for current vendor.
       */
      getActiveRuleCount: () => getAllRules(currentVendor?.id).length,

      /**
       * Get maximum allowed external rules.
       */
      getMaxExternalRules: () => MAX_EXTERNAL_RULES,

      /**
       * Get the currently detected/configured vendor for the active document.
       */
      getCurrentVendor: () => currentVendor?.id ?? null,

      /**
       * Get list of available vendor IDs.
       */
      getAvailableVendors: () => getAvailableVendors(),

      /**
       * Get list of available vendors with display names.
       */
      getAvailableVendorInfo: () => getAvailableVendorInfo(),
    };
  } catch (error) {
    console.error('SENTRIFLOW Activation Error:', error);
    vscode.window.showErrorMessage('SENTRIFLOW Extension failed to activate.');
    return undefined;
  }
}

// ============================================================================
// Commands
// ============================================================================
function cmdScanFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('SENTRIFLOW: No active editor');
    return;
  }
  // Force scan regardless of language
  runScan(editor.document, true);
}

function cmdScanSelection() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('SENTRIFLOW: No active editor');
    return;
  }

  const selection = editor.selection;
  if (selection.isEmpty) {
    vscode.window.showWarningMessage('SENTRIFLOW: No text selected');
    return;
  }

  const text = editor.document.getText(selection);
  const startLine = selection.start.line;

  // Parse and scan selection
  updateStatusBar('scanning');

  try {
    // Determine vendor for selection parsing
    const vendorOption = getConfiguredVendor();
    const vendor = vendorOption === 'auto' ? detectVendor(text) : vendorOption;

    // Use SchemaAwareParser for selections (snippets don't benefit from incremental caching)
    const snippetParser = new SchemaAwareParser({
      startLine: startLine,
      source: 'snippet',
      vendor,
    });
    const nodes = snippetParser.parse(text);

    // Ensure rule index is up to date (with vendor filtering)
    const vendorId = vendor.id;
    if (
      rulesVersion !== lastIndexedVersion ||
      vendorId !== lastIndexedVendorId
    ) {
      const rules = getAllRules(vendorId);
      engine.buildIndex(rules);
      lastIndexedVersion = rulesVersion;
      lastIndexedVendorId = vendorId;
    }

    const results = engine.run(nodes);

    const diagnostics: vscode.Diagnostic[] = [];
    let errorCount = 0;
    let warningCount = 0;

    for (const result of results) {
      if (!result.passed && result.loc) {
        // Adjust line numbers relative to selection start
        const absoluteLine = startLine + result.loc.startLine;

        if (absoluteLine < editor.document.lineCount) {
          const line = editor.document.lineAt(absoluteLine);
          const severity = mapSeverity(result.level);
          const rule = getRuleById(result.ruleId);
          const category = formatCategory(rule);

          // Apply category filter if set
          if (categoryFilter) {
            const ruleCats = rule?.category
              ? Array.isArray(rule.category)
                ? rule.category
                : [rule.category]
              : [];
            if (!ruleCats.includes(categoryFilter)) {
              continue; // Skip diagnostics not matching the filter
            }
          }

          const diagnostic = new vscode.Diagnostic(
            line.range,
            `[${result.ruleId}] (${category}) ${result.message}`,
            severity
          );
          diagnostic.source = 'SentriFlow';
          diagnostic.code = result.ruleId;
          diagnostics.push(diagnostic);

          if (result.level === 'error') errorCount++;
          if (result.level === 'warning') warningCount++;
        }
      }
    }

    // Merge with existing diagnostics (only update selection range)
    const existingDiagnostics =
      diagnosticCollection.get(editor.document.uri) ?? [];
    const outsideSelection = [...existingDiagnostics].filter(
      (d) =>
        d.range.end.line < selection.start.line ||
        d.range.start.line > selection.end.line
    );

    diagnosticCollection.set(editor.document.uri, [
      ...outsideSelection,
      ...diagnostics,
    ]);

    currentVendor = vendor;
    updateStatusBar('ready', errorCount, warningCount);
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Selection scanned (${vendor.name}) - ${errorCount} errors, ${warningCount} warnings`
    );
  } catch (e) {
    updateStatusBar('error');
    log(`Selection scan error: ${e instanceof Error ? e.message : e}`);
  }
}

async function cmdSetLanguage() {
  const editor = vscode.window.activeTextEditor;
  if (editor) {
    await vscode.languages.setTextDocumentLanguage(
      editor.document,
      'network-config'
    );
    vscode.window.showInformationMessage(
      'SENTRIFLOW: Language set to Network Config'
    );
    scheduleScan(editor.document, 0);
  }
}

function cmdToggleDebug() {
  debugMode = !debugMode;
  vscode.window.showInformationMessage(
    `SENTRIFLOW: Debug logging ${debugMode ? 'enabled' : 'disabled'}`
  );
  if (debugMode) {
    outputChannel.show();
  }
}

async function cmdSelectVendor() {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const currentSetting = config.get<string>('defaultVendor', 'auto');

  // Build QuickPick items
  interface VendorPickItem extends vscode.QuickPickItem {
    vendorId: string;
  }

  const items: VendorPickItem[] = [
    {
      label: '$(search) Auto-detect',
      description: 'Automatically detect vendor from configuration content',
      vendorId: 'auto',
      picked: currentSetting === 'auto',
    },
  ];

  // Add all available vendors
  const vendors = getAvailableVendorInfo();
  for (const vendor of vendors) {
    items.push({
      label: vendor.name,
      description: vendor.id,
      vendorId: vendor.id,
      picked: currentSetting === vendor.id,
    });
  }

  // Show QuickPick
  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select vendor for configuration parsing',
    title: 'SENTRIFLOW: Select Vendor',
  });

  if (selected) {
    // Update configuration
    await config.update(
      'defaultVendor',
      selected.vendorId,
      vscode.ConfigurationTarget.Workspace
    );
    log(`Vendor changed to: ${selected.vendorId}`);
  }
}

/**
 * Get vendor coverage for a rule pack.
 * Returns array of vendor IDs that the pack's rules apply to.
 */
function getPackVendorCoverage(pack: RulePack): string[] {
  const vendors = new Set<string>();

  for (const rule of pack.rules) {
    if (!rule.vendor) {
      // Vendor-agnostic rule - applies to all
      return ['all'];
    }

    if (Array.isArray(rule.vendor)) {
      for (const v of rule.vendor) {
        if (v === 'common') {
          return ['all'];
        }
        vendors.add(v);
      }
    } else {
      if (rule.vendor === 'common') {
        return ['all'];
      }
      vendors.add(rule.vendor);
    }
  }

  return Array.from(vendors).sort();
}

/**
 * Format rules as an ASCII table.
 */
function formatRulesTable(rules: IRule[]): string {
  if (rules.length === 0) {
    return '  (no rules)';
  }

  // Define column widths
  const colId = 20;
  const colLevel = 8;
  const colVendor = 18;
  const colDescription = 60;

  const lines: string[] = [];

  // Header
  const header = `| ${'Rule ID'.padEnd(colId)} | ${'Level'.padEnd(
    colLevel
  )} | ${'Vendor'.padEnd(colVendor)} | ${'Description'.padEnd(
    colDescription
  )} |`;
  const separator = `|${'-'.repeat(colId + 2)}|${'-'.repeat(
    colLevel + 2
  )}|${'-'.repeat(colVendor + 2)}|${'-'.repeat(colDescription + 2)}|`;

  lines.push(separator);
  lines.push(header);
  lines.push(separator);

  // Sort rules by ID
  const sortedRules = [...rules].sort((a, b) => a.id.localeCompare(b.id));

  for (const rule of sortedRules) {
    const id = rule.id.slice(0, colId).padEnd(colId);
    const level = rule.metadata.level.slice(0, colLevel).padEnd(colLevel);

    // Format vendor
    let vendor = 'common';
    if (rule.vendor) {
      vendor = Array.isArray(rule.vendor)
        ? rule.vendor.join(', ')
        : rule.vendor;
    }
    vendor = vendor.slice(0, colVendor).padEnd(colVendor);

    // Format description (use remediation or description, truncate if needed)
    let desc = rule.metadata.remediation ?? rule.metadata.description ?? '';
    // Remove newlines and extra spaces
    desc = desc.replace(/\s+/g, ' ').trim();
    if (desc.length > colDescription) {
      desc = desc.slice(0, colDescription - 3) + '...';
    }
    desc = desc.padEnd(colDescription);

    lines.push(`| ${id} | ${level} | ${vendor} | ${desc} |`);
  }

  lines.push(separator);

  return lines.join('\n');
}

/**
 * Format pack details for output channel.
 */
function formatPackDetails(pack: RulePack, isDefault: boolean): string {
  const lines: string[] = [];
  const rules = isDefault ? allRules : pack.rules;
  const ruleCount = rules.length;

  lines.push(`\n${'='.repeat(120)}`);
  lines.push(`Pack: ${pack.name}`);
  lines.push(`${'='.repeat(120)}`);
  lines.push(`Version:     ${pack.version}`);
  lines.push(`Publisher:   ${pack.publisher}`);
  lines.push(`Priority:    ${pack.priority}`);
  lines.push(`License:     ${pack.license ?? 'Not specified'}`);
  lines.push(`Description: ${pack.description ?? 'No description'}`);
  if (pack.homepage) {
    lines.push(`Homepage:    ${pack.homepage}`);
  }
  lines.push(`Rule Count:  ${ruleCount}`);

  // Vendor coverage
  const vendors = isDefault ? ['all'] : getPackVendorCoverage(pack);
  lines.push(`Vendors:     ${vendors.join(', ')}`);

  // Disable configuration
  if (pack.disables) {
    lines.push(`\nDisable Config:`);
    if (pack.disables.all) {
      lines.push(`  - Disables ALL default rules`);
    }
    if (pack.disables.vendors?.length) {
      lines.push(`  - Disables vendors: ${pack.disables.vendors.join(', ')}`);
    }
    if (pack.disables.rules?.length) {
      lines.push(`  - Disables rules: ${pack.disables.rules.join(', ')}`);
    }
  }

  // Rule breakdown by vendor
  const vendorCounts = new Map<string, number>();
  for (const rule of rules) {
    const v = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(',')
        : rule.vendor
      : 'common';
    vendorCounts.set(v, (vendorCounts.get(v) ?? 0) + 1);
  }
  lines.push(`\nRules by Vendor:`);
  for (const [vendor, count] of Array.from(vendorCounts.entries()).sort()) {
    lines.push(`  ${vendor}: ${count} rules`);
  }

  // Rules table
  lines.push(`\nAll Rules:`);
  lines.push(formatRulesTable(rules));

  return lines.join('\n');
}

async function cmdShowRulePacks() {
  // Build QuickPick items for pack list
  interface PackPickItem extends vscode.QuickPickItem {
    packName: string;
    action: 'showAll' | 'selectPack';
  }

  const items: PackPickItem[] = [];

  // Add "Show All Details" option first
  items.push({
    label: '$(info) Show All Details',
    description: 'Dump all pack information to output channel',
    packName: '',
    action: 'showAll',
  });

  // Add separator
  items.push({
    label: '',
    kind: vscode.QuickPickItemKind.Separator,
    packName: '',
    action: 'selectPack',
  });

  // Add default pack
  items.push({
    label: `$(package) ${DEFAULT_PACK_NAME}`,
    description: `${allRules.length} rules | Priority: 0`,
    detail: `Built-in rules | Vendors: all`,
    packName: DEFAULT_PACK_NAME,
    action: 'selectPack',
  });

  // Add registered packs
  for (const [name, pack] of registeredPacks) {
    const vendors = getPackVendorCoverage(pack);
    const vendorSummary =
      vendors.length > 3
        ? `${vendors.slice(0, 3).join(', ')}... (+${vendors.length - 3})`
        : vendors.join(', ');

    items.push({
      label: `$(package) ${name}`,
      description: `${pack.rules.length} rules | Priority: ${pack.priority}`,
      detail: `${pack.publisher} | v${
        pack.version
      } | Vendors: ${vendorSummary}${
        pack.disables?.all ? ' | Disables defaults' : ''
      }`,
      packName: name,
      action: 'selectPack',
    });
  }

  // Show message if no external packs registered
  if (registeredPacks.size === 0) {
    items.push({
      label: '$(warning) No external packs registered',
      description: 'Install rule pack extensions to add more rules',
      packName: '',
      action: 'selectPack',
    });
  }

  // Show QuickPick
  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a pack to manage',
    title: 'SENTRIFLOW: Rule Packs',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  if (selected.action === 'showAll') {
    outputChannel.show(true);
    outputChannel.appendLine(`\n${'#'.repeat(60)}`);
    outputChannel.appendLine(
      `SENTRIFLOW Rule Packs - ${new Date().toISOString()}`
    );
    outputChannel.appendLine(`${'#'.repeat(60)}`);
    outputChannel.appendLine(
      `\nTotal Packs: ${registeredPacks.size + 1} (1 default + ${
        registeredPacks.size
      } external)`
    );
    outputChannel.appendLine(formatPackDetails(defaultPack, true));
    for (const pack of registeredPacks.values()) {
      outputChannel.appendLine(formatPackDetails(pack, false));
    }
    outputChannel.appendLine(`\n${'='.repeat(60)}\n`);
    return;
  }

  if (!selected.packName) return;

  // Show pack action menu
  await showPackActions(selected.packName);
}

/**
 * Show action menu for a specific pack
 */
async function showPackActions(packName: string) {
  const isDefault = packName === DEFAULT_PACK_NAME;
  const pack = isDefault ? defaultPack : registeredPacks.get(packName);
  if (!pack) return;

  // Check current disabled state
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const packVendorOverrides = config.get<
    Record<string, { disabledVendors?: string[] }>
  >('packVendorOverrides', {});

  // For non-default packs, check if all vendors are disabled
  let isPackDisabled = false;
  if (!isDefault) {
    const packOverride = packVendorOverrides[packName];
    const disabledVendors = new Set(packOverride?.disabledVendors ?? []);
    if (disabledVendors.size > 0) {
      // Get all vendors in this pack
      const vendorSet = new Set<string>();
      for (const rule of pack.rules) {
        if (rule.vendor) {
          const vendors = Array.isArray(rule.vendor)
            ? rule.vendor
            : [rule.vendor];
          vendors.forEach((v) => vendorSet.add(v));
        } else {
          vendorSet.add('common');
        }
      }
      // Check if all non-common vendors are disabled
      isPackDisabled = Array.from(vendorSet).every(
        (v) => v === 'common' || disabledVendors.has(v)
      );
    }
  }

  interface ActionItem extends vscode.QuickPickItem {
    action: 'details' | 'vendors' | 'rules' | 'disable' | 'enable' | 'back';
  }

  const actions: ActionItem[] = [
    {
      label: '$(info) View Details',
      description: 'Show pack metadata in output channel',
      action: 'details',
    },
    {
      label: '$(list-unordered) View All Rules',
      description: `Browse ${
        isDefault ? allRules.length : pack.rules.length
      } rules with descriptions`,
      action: 'rules',
    },
  ];

  // Add disable/enable option
  if (isDefault) {
    // For default pack, toggle sentriflow.enableDefaultRules
    if (enableDefaultRules) {
      actions.splice(1, 0, {
        label: '$(circle-slash) Disable Pack',
        description: 'Disable all default rules',
        action: 'disable',
      });
    } else {
      actions.splice(1, 0, {
        label: '$(check) Enable Pack',
        description: 'Enable default rules',
        action: 'enable',
      });
    }
  } else {
    // For external packs, toggle all vendors
    actions.splice(1, 0, {
      label: '$(settings-gear) Manage Vendors',
      description: 'Enable/disable vendors for this pack',
      action: 'vendors',
    });

    if (isPackDisabled) {
      actions.splice(2, 0, {
        label: '$(check) Enable Pack',
        description: 'Enable all vendors for this pack',
        action: 'enable',
      });
    } else {
      actions.splice(2, 0, {
        label: '$(circle-slash) Disable Pack',
        description: 'Disable all vendors for this pack',
        action: 'disable',
      });
    }
  }

  actions.push({
    label: '$(arrow-left) Back',
    description: 'Return to pack list',
    action: 'back',
  });

  const action = await vscode.window.showQuickPick(actions, {
    placeHolder: `${packName} - Select action`,
    title: `SENTRIFLOW: ${packName}`,
  });

  if (!action) return;

  switch (action.action) {
    case 'details':
      outputChannel.show(true);
      outputChannel.appendLine(formatPackDetails(pack, isDefault));
      break;
    case 'vendors':
      await managePackVendors(packName, pack);
      break;
    case 'rules':
      await showPackRules(packName, pack, isDefault);
      break;
    case 'disable':
      await disablePack(packName, pack, isDefault);
      break;
    case 'enable':
      await enablePack(packName, pack, isDefault);
      break;
    case 'back':
      await cmdShowRulePacks();
      break;
  }
}

/**
 * Disable a pack entirely
 */
async function disablePack(
  packName: string,
  pack: RulePack,
  isDefault: boolean
) {
  const config = vscode.workspace.getConfiguration('sentriflow');

  if (isDefault) {
    // Disable default rules via configuration
    await config.update(
      'enableDefaultRules',
      false,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage('SENTRIFLOW: Default rules disabled');
  } else {
    // Disable all vendors for this pack
    const vendorSet = new Set<string>();
    for (const rule of pack.rules) {
      if (rule.vendor) {
        const vendors = Array.isArray(rule.vendor)
          ? rule.vendor
          : [rule.vendor];
        vendors.forEach((v) => vendorSet.add(v));
      }
    }
    const allVendors = Array.from(vendorSet).filter((v) => v !== 'common');

    if (allVendors.length > 0) {
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const newOverrides = { ...overrides };
      newOverrides[packName] = { disabledVendors: allVendors };
      await config.update(
        'packVendorOverrides',
        newOverrides,
        vscode.ConfigurationTarget.Workspace
      );
    }

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Pack '${packName}' disabled`
    );
  }

  rescanActiveEditor();
}

/**
 * Enable a pack (re-enable all vendors or default rules)
 */
async function enablePack(
  packName: string,
  pack: RulePack,
  isDefault: boolean
) {
  const config = vscode.workspace.getConfiguration('sentriflow');

  if (isDefault) {
    // Enable default rules via configuration
    await config.update(
      'enableDefaultRules',
      true,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage('SENTRIFLOW: Default rules enabled');
  } else {
    // Remove all vendor overrides for this pack
    const overrides = config.get<
      Record<string, { disabledVendors?: string[] }>
    >('packVendorOverrides', {});
    const newOverrides = { ...overrides };
    delete newOverrides[packName];
    await config.update(
      'packVendorOverrides',
      newOverrides,
      vscode.ConfigurationTarget.Workspace
    );

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Pack '${packName}' enabled`
    );
  }

  rescanActiveEditor();
}

/**
 * Manage vendor settings for a pack
 */
async function managePackVendors(packName: string, pack: RulePack) {
  // Get unique vendors in this pack
  const vendorSet = new Set<string>();
  for (const rule of pack.rules) {
    if (rule.vendor) {
      const vendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
      vendors.forEach((v) => vendorSet.add(v));
    } else {
      vendorSet.add('common');
    }
  }
  const vendors = Array.from(vendorSet).sort();

  if (vendors.length === 0) {
    vscode.window.showInformationMessage(
      'This pack has no vendor-specific rules.'
    );
    return;
  }

  // Get current disabled vendors
  const config = vscode.workspace.getConfiguration('sentriflow');
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );
  const currentDisabled = new Set(overrides[packName]?.disabledVendors ?? []);

  // Count rules per vendor
  const vendorCounts = new Map<string, number>();
  for (const rule of pack.rules) {
    const v = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(',')
        : rule.vendor
      : 'common';
    vendorCounts.set(v, (vendorCounts.get(v) ?? 0) + 1);
  }

  // Build multi-select items
  interface VendorItem extends vscode.QuickPickItem {
    vendorId: string;
  }

  const items: VendorItem[] = vendors.map((v) => ({
    label: v,
    description: `${vendorCounts.get(v) ?? 0} rules`,
    picked: !currentDisabled.has(v),
    vendorId: v,
  }));

  const selected = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    placeHolder: 'Check vendors to enable, uncheck to disable',
    title: `SENTRIFLOW: ${packName} - Vendor Settings`,
  });

  if (selected === undefined) return; // User cancelled

  // Calculate newly disabled vendors
  const enabledVendors = new Set(selected.map((s) => s.vendorId));
  const disabledVendors = vendors.filter((v) => !enabledVendors.has(v));

  // Update configuration
  const newOverrides = { ...overrides };
  if (disabledVendors.length > 0) {
    newOverrides[packName] = { disabledVendors };
  } else {
    delete newOverrides[packName];
  }

  await config.update(
    'packVendorOverrides',
    newOverrides,
    vscode.ConfigurationTarget.Workspace
  );

  const msg =
    disabledVendors.length > 0
      ? `Disabled ${disabledVendors.length} vendor(s) for ${packName}`
      : `All vendors enabled for ${packName}`;
  vscode.window.showInformationMessage(`SENTRIFLOW: ${msg}`);

  // Rescan to apply changes
  rescanActiveEditor();
}

/**
 * Show all rules in a pack with their details
 */
async function showPackRules(
  packName: string,
  pack: RulePack,
  isDefault: boolean
) {
  const rules = isDefault ? allRules : pack.rules;

  // Get currently disabled rules from settings (handles comma-separated values)
  const disabledRules = getDisabledRulesSet();

  interface RuleItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RuleItem[] = rules.map((rule) => {
    const isDisabled = disabledRules.has(rule.id);
    const levelIcon =
      rule.metadata.level === 'error'
        ? '$(error)'
        : rule.metadata.level === 'warning'
        ? '$(warning)'
        : '$(info)';
    const statusIcon = isDisabled ? '$(circle-slash)' : '$(check)';
    const vendor = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(', ')
        : rule.vendor
      : 'common';

    return {
      label: `${statusIcon} ${levelIcon} ${rule.id}`,
      description: `${vendor}${isDisabled ? ' (disabled)' : ''}`,
      detail:
        rule.metadata.remediation ??
        rule.metadata.description ??
        'No description',
      ruleId: rule.id,
    };
  });

  // Add back option at the top
  items.unshift({
    label: '$(arrow-left) Back to pack actions',
    description: '',
    ruleId: '',
  });

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: `${rules.length} rules - Select to view/toggle`,
    title: `SENTRIFLOW: ${packName} - Rules`,
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  if (!selected.ruleId) {
    await showPackActions(packName);
    return;
  }

  // Show rule action menu
  await showRuleActions(selected.ruleId, packName, pack, isDefault);
}

/**
 * Show action menu for a specific rule
 */
async function showRuleActions(
  ruleId: string,
  packName: string,
  pack: RulePack,
  isDefault: boolean
) {
  const rules = isDefault ? allRules : pack.rules;
  const rule = rules.find((r) => r.id === ruleId);
  if (!rule) return;

  // Check if rule is disabled (handles comma-separated values)
  const disabledRulesSet = getDisabledRulesSet();
  const isDisabled = disabledRulesSet.has(ruleId);

  interface ActionItem extends vscode.QuickPickItem {
    action: 'details' | 'toggle' | 'back';
  }

  const actions: ActionItem[] = [
    {
      label: '$(info) View Details',
      description: 'Show rule metadata in output channel',
      action: 'details',
    },
    {
      label: isDisabled
        ? '$(check) Enable Rule'
        : '$(circle-slash) Disable Rule',
      description: isDisabled
        ? 'Remove from disabled rules list'
        : 'Add to disabled rules list',
      action: 'toggle',
    },
    {
      label: '$(arrow-left) Back to rules list',
      description: '',
      action: 'back',
    },
  ];

  const action = await vscode.window.showQuickPick(actions, {
    placeHolder: `${ruleId} - Select action`,
    title: `SENTRIFLOW: ${ruleId}`,
  });

  if (!action) return;

  switch (action.action) {
    case 'details':
      outputChannel.show(true);
      outputChannel.appendLine(`\n${'='.repeat(60)}`);
      outputChannel.appendLine(`Rule: ${rule.id}`);
      outputChannel.appendLine(`${'='.repeat(60)}`);
      outputChannel.appendLine(
        `Status:      ${isDisabled ? 'DISABLED' : 'Enabled'}`
      );
      outputChannel.appendLine(`Level:       ${rule.metadata.level}`);
      outputChannel.appendLine(`Vendor:      ${rule.vendor ?? 'common'}`);
      outputChannel.appendLine(`Selector:    ${rule.selector ?? '(none)'}`);
      if (rule.metadata.description) {
        outputChannel.appendLine(`Description: ${rule.metadata.description}`);
      }
      if (rule.metadata.remediation) {
        outputChannel.appendLine(`Remediation: ${rule.metadata.remediation}`);
      }
      if (rule.metadata.obu) {
        outputChannel.appendLine(`OBU:         ${rule.metadata.obu}`);
      }
      if (rule.metadata.owner) {
        outputChannel.appendLine(`Owner:       ${rule.metadata.owner}`);
      }
      if (rule.metadata.security) {
        const sec = rule.metadata.security;
        if (sec.cwe?.length) {
          outputChannel.appendLine(`CWE:         ${sec.cwe.join(', ')}`);
        }
        if (sec.cvssScore !== undefined) {
          outputChannel.appendLine(`CVSS Score:  ${sec.cvssScore}`);
        }
      }
      if (rule.metadata.tags?.length) {
        outputChannel.appendLine(
          `Tags:        ${rule.metadata.tags.map((t) => t.label).join(', ')}`
        );
      }
      outputChannel.appendLine('');
      // Stay in rule actions
      await showRuleActions(ruleId, packName, pack, isDefault);
      break;

    case 'toggle':
      await toggleRule(ruleId, isDisabled);
      // Return to rules list to see updated state
      await showPackRules(packName, pack, isDefault);
      break;

    case 'back':
      await showPackRules(packName, pack, isDefault);
      break;
  }
}

/**
 * Toggle a rule's disabled state in settings
 */
async function toggleRule(ruleId: string, currentlyDisabled: boolean) {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const disabledRules = config.get<string[]>('disabledRules', []);

  let newDisabledRules: string[];
  if (currentlyDisabled) {
    // Enable: remove from list
    newDisabledRules = disabledRules.filter((id) => id !== ruleId);
    vscode.window.showInformationMessage(`SENTRIFLOW: Rule ${ruleId} enabled`);
  } else {
    // Disable: add to list
    newDisabledRules = [...disabledRules, ruleId];
    vscode.window.showInformationMessage(`SENTRIFLOW: Rule ${ruleId} disabled`);
  }

  await config.update(
    'disabledRules',
    newDisabledRules,
    vscode.ConfigurationTarget.Workspace
  );

  // Refresh tree view
  rulesTreeProvider.refresh();
}

// ============================================================================
// TreeView Command Handlers
// ============================================================================

/**
 * Disable a tree item (pack, vendor, or rule)
 */
async function cmdDisableTreeItem(item: RuleTreeItem) {
  if (!item) return;

  const config = vscode.workspace.getConfiguration('sentriflow');

  switch (item.itemType) {
    case 'pack': {
      const packName = item.packName!;
      if (packName === DEFAULT_PACK_NAME) {
        await config.update(
          'enableDefaultRules',
          false,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Default rules disabled`
        );
      } else {
        const blockedPacks = config.get<string[]>('blockedPacks', []);
        if (!blockedPacks.includes(packName)) {
          await config.update(
            'blockedPacks',
            [...blockedPacks, packName],
            vscode.ConfigurationTarget.Workspace
          );
        }
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Pack '${packName}' disabled`
        );
      }
      break;
    }

    case 'vendor': {
      const packName = item.packName!;
      const vendorId = item.vendorId!;
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      if (!disabledVendors.includes(vendorId)) {
        const newOverrides = {
          ...overrides,
          [packName]: { disabledVendors: [...disabledVendors, vendorId] },
        };
        await config.update(
          'packVendorOverrides',
          newOverrides,
          vscode.ConfigurationTarget.Workspace
        );
      }
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Vendor '${vendorId}' in pack '${packName}' disabled`
      );
      break;
    }

    case 'rule': {
      const ruleId = item.rule!.id;
      await toggleRule(ruleId, false); // false = enable is false, so disable
      break;
    }
  }

  rulesTreeProvider.refresh();
  rescanActiveEditor();
}

/**
 * Enable a tree item (pack, vendor, or rule)
 */
async function cmdEnableTreeItem(item: RuleTreeItem) {
  if (!item) return;

  const config = vscode.workspace.getConfiguration('sentriflow');

  switch (item.itemType) {
    case 'pack': {
      const packName = item.packName!;
      if (packName === DEFAULT_PACK_NAME) {
        await config.update(
          'enableDefaultRules',
          true,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Default rules enabled`
        );
      } else {
        const blockedPacks = config.get<string[]>('blockedPacks', []);
        const newBlockedPacks = blockedPacks.filter((p) => p !== packName);
        await config.update(
          'blockedPacks',
          newBlockedPacks.length > 0 ? newBlockedPacks : undefined,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Pack '${packName}' enabled`
        );
      }
      break;
    }

    case 'vendor': {
      const packName = item.packName!;
      const vendorId = item.vendorId!;
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      const newDisabledVendors = disabledVendors.filter((v) => v !== vendorId);
      const newOverrides = { ...overrides };

      if (newDisabledVendors.length === 0) {
        delete newOverrides[packName];
      } else {
        newOverrides[packName] = { disabledVendors: newDisabledVendors };
      }

      await config.update(
        'packVendorOverrides',
        Object.keys(newOverrides).length > 0 ? newOverrides : undefined,
        vscode.ConfigurationTarget.Workspace
      );
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Vendor '${vendorId}' in pack '${packName}' enabled`
      );
      break;
    }

    case 'rule': {
      const ruleId = item.rule!.id;
      const packName = item.packName!;
      const vendorId = item.vendorId!;

      // Check if parent vendor is disabled
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      if (disabledVendors.includes(vendorId)) {
        // Vendor is disabled - need to enable vendor but disable all other rules
        // 1. Get all rules for this vendor in this pack
        const isDefault = packName === DEFAULT_PACK_NAME;
        const packRules = isDefault
          ? allRules
          : registeredPacks.get(packName)?.rules ?? [];
        const vendorRules = packRules.filter((r) => {
          if (!r.vendor) return vendorId === 'common';
          if (Array.isArray(r.vendor))
            return r.vendor.includes(vendorId as RuleVendor);
          return r.vendor === vendorId;
        });

        // 2. Enable the vendor (remove from disabledVendors)
        const newDisabledVendors = disabledVendors.filter(
          (v) => v !== vendorId
        );
        const newOverrides = { ...overrides };
        if (newDisabledVendors.length === 0) {
          delete newOverrides[packName];
        } else {
          newOverrides[packName] = { disabledVendors: newDisabledVendors };
        }
        await config.update(
          'packVendorOverrides',
          Object.keys(newOverrides).length > 0 ? newOverrides : undefined,
          vscode.ConfigurationTarget.Workspace
        );

        // 3. Disable all OTHER rules in this vendor (except the one we're enabling)
        const currentDisabled = config.get<string[]>('disabledRules', []);
        const disabledSet = new Set(currentDisabled);
        for (const rule of vendorRules) {
          if (rule.id !== ruleId) {
            disabledSet.add(rule.id);
          }
        }
        // Make sure the enabled rule is NOT in disabled set
        disabledSet.delete(ruleId);
        await config.update(
          'disabledRules',
          disabledSet.size > 0 ? Array.from(disabledSet) : undefined,
          vscode.ConfigurationTarget.Workspace
        );

        vscode.window.showInformationMessage(
          `SENTRIFLOW: Enabled rule '${ruleId}' - vendor '${vendorId}' enabled, ${
            vendorRules.length - 1
          } other rules disabled`
        );
      } else {
        // Vendor is enabled, just toggle the rule
        await toggleRule(ruleId, true); // true = enable
      }
      break;
    }
  }

  rulesTreeProvider.refresh();
  rescanActiveEditor();
}

/**
 * Copy rule ID to clipboard
 */
async function cmdCopyRuleId(item: RuleTreeItem) {
  if (!item || !item.rule) return;
  await vscode.env.clipboard.writeText(item.rule.id);
  vscode.window.showInformationMessage(
    `SENTRIFLOW: Copied '${item.rule.id}' to clipboard`
  );
}

/**
 * View details for a tree item in the output channel
 */
async function cmdViewRuleDetails(item: RuleTreeItem) {
  if (!item) return;

  outputChannel.show(true);
  outputChannel.appendLine(`\n${'='.repeat(60)}`);

  switch (item.itemType) {
    case 'pack': {
      const pack =
        item.packName === DEFAULT_PACK_NAME
          ? defaultPack
          : registeredPacks.get(item.packName!);
      if (pack) {
        outputChannel.appendLine(`Pack: ${pack.name}`);
        outputChannel.appendLine(`${'='.repeat(60)}`);
        outputChannel.appendLine(`Publisher:   ${pack.publisher}`);
        outputChannel.appendLine(`Version:     ${pack.version}`);
        outputChannel.appendLine(`Description: ${pack.description}`);
        outputChannel.appendLine(`Priority:    ${pack.priority}`);
        outputChannel.appendLine(
          `Rules:       ${
            item.packName === DEFAULT_PACK_NAME
              ? allRules.length
              : pack.rules.length
          }`
        );
        outputChannel.appendLine(
          `Status:      ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
        );
      }
      break;
    }

    case 'vendor': {
      outputChannel.appendLine(`Vendor: ${item.vendorId}`);
      outputChannel.appendLine(`${'='.repeat(60)}`);
      outputChannel.appendLine(`Pack:   ${item.packName}`);
      outputChannel.appendLine(
        `Status: ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
      );
      break;
    }

    case 'rule': {
      const rule = item.rule!;
      outputChannel.appendLine(`Rule: ${rule.id}`);
      outputChannel.appendLine(`${'='.repeat(60)}`);
      outputChannel.appendLine(`Level:       ${rule.metadata.level}`);
      outputChannel.appendLine(`Vendor:      ${rule.vendor ?? 'common'}`);
      outputChannel.appendLine(`Selector:    ${rule.selector ?? '(none)'}`);
      outputChannel.appendLine(
        `Status:      ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
      );
      if (rule.metadata.description) {
        outputChannel.appendLine(`Description: ${rule.metadata.description}`);
      }
      if (rule.metadata.remediation) {
        outputChannel.appendLine(`Remediation: ${rule.metadata.remediation}`);
      }
      if (rule.metadata.obu) {
        outputChannel.appendLine(`OBU:         ${rule.metadata.obu}`);
      }
      if (rule.metadata.owner) {
        outputChannel.appendLine(`Owner:       ${rule.metadata.owner}`);
      }
      if (rule.metadata.security) {
        const sec = rule.metadata.security;
        if (sec.cwe?.length) {
          outputChannel.appendLine(`CWE:         ${sec.cwe.join(', ')}`);
        }
        if (sec.cvssScore !== undefined) {
          outputChannel.appendLine(`CVSS Score:  ${sec.cvssScore}`);
        }
      }
      if (rule.metadata.tags?.length) {
        outputChannel.appendLine(
          `Tags:        ${rule.metadata.tags.map((t) => t.label).join(', ')}`
        );
      }
      break;
    }
  }

  outputChannel.appendLine('');
}

// ============================================================================
// Direct Command Handlers (Command Palette)
// ============================================================================

/**
 * Toggle a pack via command palette
 */
async function cmdTogglePack() {
  interface PackPickItem extends vscode.QuickPickItem {
    packName: string;
    isEnabled: boolean;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const blockedPacks = new Set(config.get<string[]>('blockedPacks', []));

  const items: PackPickItem[] = [];

  // Default pack
  items.push({
    label: `${
      enableDefaultRules ? '$(check)' : '$(circle-slash)'
    } ${DEFAULT_PACK_NAME}`,
    description: enableDefaultRules ? 'Enabled' : 'Disabled',
    detail: `${allRules.length} rules`,
    packName: DEFAULT_PACK_NAME,
    isEnabled: enableDefaultRules,
  });

  // External packs
  for (const [name, pack] of registeredPacks) {
    const isEnabled = !blockedPacks.has(name);
    items.push({
      label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${name}`,
      description: isEnabled ? 'Enabled' : 'Disabled',
      detail: `${pack.rules.length} rules | ${pack.publisher}`,
      packName: name,
      isEnabled,
    });
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a pack to toggle',
    title: 'SENTRIFLOW: Toggle Pack',
  });

  if (!selected) return;

  // Create a synthetic tree item to reuse toggle logic
  const item = new RuleTreeItem(
    selected.packName,
    vscode.TreeItemCollapsibleState.None,
    'pack',
    selected.packName,
    undefined,
    undefined,
    undefined,
    selected.isEnabled
  );

  // Toggle: if enabled, disable it; if disabled, enable it
  if (selected.isEnabled) {
    await cmdDisableTreeItem(item);
  } else {
    await cmdEnableTreeItem(item);
  }
}

/**
 * Toggle a vendor via command palette
 */
async function cmdToggleVendor() {
  interface VendorPickItem extends vscode.QuickPickItem {
    packName: string;
    vendorId: string;
    isEnabled: boolean;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );

  const items: VendorPickItem[] = [];

  // Collect vendors from default pack
  const defaultVendors = new Set<string>();
  for (const rule of allRules) {
    if (rule.vendor) {
      const vendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
      vendors.forEach((v) => defaultVendors.add(v));
    } else {
      defaultVendors.add('common');
    }
  }

  const defaultDisabled = new Set(
    overrides[DEFAULT_PACK_NAME]?.disabledVendors ?? []
  );
  for (const vendor of Array.from(defaultVendors).sort()) {
    const isEnabled = !defaultDisabled.has(vendor);
    items.push({
      label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${vendor}`,
      description: `${DEFAULT_PACK_NAME}`,
      packName: DEFAULT_PACK_NAME,
      vendorId: vendor,
      isEnabled,
    });
  }

  // Collect vendors from external packs
  for (const [packName, pack] of registeredPacks) {
    const packVendors = new Set<string>();
    for (const rule of pack.rules) {
      if (rule.vendor) {
        const vendors = Array.isArray(rule.vendor)
          ? rule.vendor
          : [rule.vendor];
        vendors.forEach((v) => packVendors.add(v));
      } else {
        packVendors.add('common');
      }
    }

    const packDisabled = new Set(overrides[packName]?.disabledVendors ?? []);
    for (const vendor of Array.from(packVendors).sort()) {
      const isEnabled = !packDisabled.has(vendor);
      items.push({
        label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${vendor}`,
        description: packName,
        packName,
        vendorId: vendor,
        isEnabled,
      });
    }
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a vendor to toggle',
    title: 'SENTRIFLOW: Toggle Vendor',
    matchOnDescription: true,
  });

  if (!selected) return;

  const item = new RuleTreeItem(
    selected.vendorId,
    vscode.TreeItemCollapsibleState.None,
    'vendor',
    selected.packName,
    selected.vendorId,
    undefined,
    undefined,
    selected.isEnabled
  );

  // Toggle: if enabled, disable it; if disabled, enable it
  if (selected.isEnabled) {
    await cmdDisableTreeItem(item);
  } else {
    await cmdEnableTreeItem(item);
  }
}

/**
 * Disable a rule via command palette with fuzzy search
 */
async function cmdDisableRuleById() {
  const disabledRules = getDisabledRulesSet();

  interface RulePickItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RulePickItem[] = allRules
    .filter((r) => !disabledRules.has(r.id))
    .map((r) => ({
      label: `$(${r.metadata.level}) ${r.id}`,
      description: r.vendor
        ? Array.isArray(r.vendor)
          ? r.vendor.join(', ')
          : r.vendor
        : 'common',
      detail: r.metadata.remediation ?? r.metadata.description,
      ruleId: r.id,
    }));

  if (items.length === 0) {
    vscode.window.showInformationMessage(
      'SENTRIFLOW: All rules are already disabled'
    );
    return;
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Type to search rules to disable...',
    title: 'SENTRIFLOW: Disable Rule',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  await toggleRule(selected.ruleId, false);
}

/**
 * Enable a disabled rule via command palette
 */
async function cmdEnableRuleById() {
  const disabledRules = Array.from(getDisabledRulesSet());

  if (disabledRules.length === 0) {
    vscode.window.showInformationMessage('SENTRIFLOW: No rules are disabled');
    return;
  }

  interface RulePickItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RulePickItem[] = disabledRules.map((id) => {
    const rule = allRules.find((r) => r.id === id);
    return {
      label: `$(circle-slash) ${id}`,
      description: rule?.vendor
        ? Array.isArray(rule.vendor)
          ? rule.vendor.join(', ')
          : rule.vendor
        : 'common',
      detail:
        rule?.metadata.remediation ??
        rule?.metadata.description ??
        'Currently disabled',
      ruleId: id,
    };
  });

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a rule to enable',
    title: 'SENTRIFLOW: Enable Disabled Rule',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  await toggleRule(selected.ruleId, true);
}

/**
 * Show all disabled items in the output channel
 */
async function cmdShowDisabled() {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const blockedPacks = config.get<string[]>('blockedPacks', []);
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );
  const disabledRules = Array.from(getDisabledRulesSet());

  outputChannel.show(true);
  outputChannel.appendLine(`\n${'='.repeat(60)}`);
  outputChannel.appendLine('SENTRIFLOW: Disabled Items Summary');
  outputChannel.appendLine(`${'='.repeat(60)}`);

  // Packs
  outputChannel.appendLine('\n--- Disabled Packs ---');
  if (!enableDefaultRules) {
    outputChannel.appendLine(
      `  - ${DEFAULT_PACK_NAME} (default rules disabled)`
    );
  }
  for (const pack of blockedPacks) {
    outputChannel.appendLine(`  - ${pack}`);
  }
  if (enableDefaultRules && blockedPacks.length === 0) {
    outputChannel.appendLine('  (none)');
  }

  // Vendors
  outputChannel.appendLine('\n--- Disabled Vendors ---');
  let hasDisabledVendors = false;
  for (const [packName, packOverride] of Object.entries(overrides)) {
    if (
      packOverride.disabledVendors &&
      packOverride.disabledVendors.length > 0
    ) {
      for (const vendor of packOverride.disabledVendors) {
        outputChannel.appendLine(`  - ${vendor} (in ${packName})`);
        hasDisabledVendors = true;
      }
    }
  }
  if (!hasDisabledVendors) {
    outputChannel.appendLine('  (none)');
  }

  // Rules
  outputChannel.appendLine('\n--- Disabled Rules ---');
  if (disabledRules.length > 0) {
    for (const ruleId of disabledRules.sort()) {
      outputChannel.appendLine(`  - ${ruleId}`);
    }
  } else {
    outputChannel.appendLine('  (none)');
  }

  const totalDisabled =
    (enableDefaultRules ? 0 : 1) +
    blockedPacks.length +
    Object.values(overrides).reduce(
      (sum, o) => sum + (o.disabledVendors?.length ?? 0),
      0
    ) +
    disabledRules.length;

  outputChannel.appendLine(`\nTotal disabled items: ${totalDisabled}`);
  outputChannel.appendLine('');
}

/**
 * Filter tags by type via quick pick
 */
async function cmdFilterTagType() {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const current = config.get<string>('tagTypeFilter', 'all');

  interface TypePickItem extends vscode.QuickPickItem {
    value: string;
  }

  const items: TypePickItem[] = [
    {
      label: 'All Types',
      description: 'Show all tags regardless of type',
      value: 'all',
    },
    {
      label: 'Security',
      description: 'Show only security-related tags',
      value: 'security',
    },
    {
      label: 'Operational',
      description: 'Show only operational tags',
      value: 'operational',
    },
    {
      label: 'Compliance',
      description: 'Show only compliance-related tags',
      value: 'compliance',
    },
    {
      label: 'General',
      description: 'Show only general tags',
      value: 'general',
    },
  ];

  // Mark current selection
  for (const item of items) {
    if (item.value === current) {
      item.label = `$(check) ${item.label}`;
    }
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select tag type to filter',
    title: 'Filter Tags by Type',
  });

  if (selected) {
    await config.update(
      'tagTypeFilter',
      selected.value,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Tag filter set to "${selected.value}"`
    );
  }
}

/**
 * Filter diagnostics by category via quick pick
 */
async function cmdFilterByCategory() {
  const categories = getUniqueCategories();

  interface CategoryPickItem extends vscode.QuickPickItem {
    value: string | undefined;
  }

  const items: CategoryPickItem[] = [
    {
      label:
        categoryFilter === undefined
          ? '$(check) All Categories'
          : 'All Categories',
      description: 'Show diagnostics from all categories',
      value: undefined,
    },
    ...categories.map((cat) => ({
      label: categoryFilter === cat ? `$(check) ${cat}` : cat,
      description: `Filter to "${cat}" category only`,
      value: cat,
    })),
  ];

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select category to filter diagnostics',
    title: 'Filter Diagnostics by Category',
  });

  if (selected !== undefined) {
    categoryFilter = selected.value;

    // Re-scan active editor to apply filter
    if (vscode.window.activeTextEditor) {
      scheduleScan(vscode.window.activeTextEditor.document, 0);
    }

    const filterMsg = categoryFilter ? `"${categoryFilter}"` : 'all categories';
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Showing diagnostics from ${filterMsg}`
    );
  }
}

// ============================================================================
// Event Handlers
// ============================================================================
function onDocumentChange(event: vscode.TextDocumentChangeEvent) {
  // Skip if no actual changes
  if (event.contentChanges.length === 0) return;

  scheduleScan(event.document, DEBOUNCE_MS);
}

function onDocumentClose(document: vscode.TextDocument) {
  const uri = document.uri.toString();

  // Clear pending timer
  const timer = debounceTimers.get(uri);
  if (timer) {
    clearTimeout(timer);
    debounceTimers.delete(uri);
  }

  // Clear scan version
  scanVersions.delete(uri);

  // Clear incremental parser cache for this document
  incrementalParser.invalidate(uri);

  // Clear diagnostics
  diagnosticCollection.delete(document.uri);
}

function onActiveEditorChange(editor: vscode.TextEditor | undefined) {
  // Update IP Addresses TreeView
  ipAddressesTreeProvider?.updateFromDocument(editor?.document);

  if (editor) {
    // Update current vendor from cached document
    const uri = editor.document.uri.toString();
    const cachedVendor = incrementalParser.getCachedVendor(uri);
    if (cachedVendor) {
      currentVendor = cachedVendor;
    }

    // Update status bar for current document
    const diagnostics = diagnosticCollection.get(editor.document.uri);
    if (diagnostics) {
      const errors = diagnostics.filter(
        (d) => d.severity === vscode.DiagnosticSeverity.Error
      ).length;
      const warnings = diagnostics.filter(
        (d) => d.severity === vscode.DiagnosticSeverity.Warning
      ).length;
      updateStatusBar('ready', errors, warnings);
    } else {
      updateStatusBar('ready');
    }
  }
}

function onConfigurationChange(event: vscode.ConfigurationChangeEvent) {
  if (event.affectsConfiguration('sentriflow.defaultVendor')) {
    log(`Vendor configuration changed`);
    // Clear all caches to force re-detection with new settings
    incrementalParser.clearAll();
    // Re-scan active editor
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.showVendorInStatusBar')) {
    // Update status bar display
    if (vscode.window.activeTextEditor) {
      const diagnostics = diagnosticCollection.get(
        vscode.window.activeTextEditor.document.uri
      );
      if (diagnostics) {
        const errors = diagnostics.filter(
          (d) => d.severity === vscode.DiagnosticSeverity.Error
        ).length;
        const warnings = diagnostics.filter(
          (d) => d.severity === vscode.DiagnosticSeverity.Warning
        ).length;
        updateStatusBar('ready', errors, warnings);
      }
    }
  }

  if (event.affectsConfiguration('sentriflow.enableDefaultRules')) {
    log(`Default rules setting changed`);
    // Update tree view, settings webview, and re-scan
    rulesTreeProvider.refresh();
    settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.blockedPacks')) {
    log(`Blocked packs setting changed`);
    // Note: This only affects future registrations
    // Already registered packs remain active until extension reload
    rulesTreeProvider.refresh();
    settingsWebviewProvider.refresh();
  }

  if (event.affectsConfiguration('sentriflow.packVendorOverrides')) {
    log(`Pack vendor overrides changed`);
    // Update tree view, settings webview, and re-scan
    rulesTreeProvider.refresh();
    settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.disabledRules')) {
    const config = vscode.workspace.getConfiguration('sentriflow');
    const disabledRules = config.get<string[]>('disabledRules', []);
    log(`Disabled rules setting changed: ${JSON.stringify(disabledRules)}`);
    // Increment rules version to force index rebuild
    rulesVersion++;
    rulesTreeProvider.refresh();
    settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }
}

// ============================================================================
// Scanning Logic
// ============================================================================
function scheduleScan(document: vscode.TextDocument, delay: number) {
  // Skip non-file schemes (git, gitlens, untitled, etc.)
  if (document.uri.scheme !== 'file') {
    return;
  }

  // Skip unsupported languages
  if (!SUPPORTED_LANGUAGES.includes(document.languageId)) {
    return;
  }

  // Skip large files
  if (document.getText().length > MAX_FILE_SIZE) {
    log(`Skipping large file: ${document.fileName}`);
    return;
  }

  const uri = document.uri.toString();

  // Clear existing timer for this document
  const existingTimer = debounceTimers.get(uri);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }

  // Schedule new scan
  const timer = setTimeout(() => {
    debounceTimers.delete(uri);
    runScan(document, false);
  }, delay);

  debounceTimers.set(uri, timer);
}

function runScan(document: vscode.TextDocument, force: boolean) {
  // Skip non-file schemes (git, gitlens, untitled, etc.)
  if (document.uri.scheme !== 'file') {
    return;
  }

  const uri = document.uri.toString();

  // Skip unsupported languages unless forced
  if (!force && !SUPPORTED_LANGUAGES.includes(document.languageId)) {
    return;
  }

  // Increment scan version to invalidate in-flight scans
  const currentVersion = (scanVersions.get(uri) ?? 0) + 1;
  scanVersions.set(uri, currentVersion);

  updateStatusBar('scanning');

  try {
    const text = document.getText();

    // Quick exit for empty documents
    if (text.trim().length === 0) {
      diagnosticCollection.set(document.uri, []);
      updateStatusBar('ready');
      return;
    }

    // Get configured vendor option
    const vendorOption = getConfiguredVendor();

    // Use incremental parser with document URI and version for caching
    // The parser will use configured vendor or auto-detect
    const nodes = incrementalParser.parse(
      uri,
      text,
      document.version,
      vendorOption
    );

    // Get the vendor that was actually used
    const usedVendor = incrementalParser.getCachedVendor(uri);
    if (usedVendor) {
      currentVendor = usedVendor;
    }

    // Log incremental parsing stats in debug mode
    const parseStats = incrementalParser.getLastStats();
    if (parseStats) {
      if (!parseStats.fullParse) {
        log(
          `Incremental parse: ${
            parseStats.sectionsReparsed
          } sections reparsed in ${parseStats.parseTimeMs.toFixed(2)}ms (${
            parseStats.vendorId
          })`
        );
      } else {
        log(
          `Full parse in ${parseStats.parseTimeMs.toFixed(2)}ms (${
            parseStats.vendorId
          })`
        );
      }
    }

    // Rebuild rule index when rules or vendor have changed
    const currentVendorId = currentVendor?.id ?? null;
    if (
      rulesVersion !== lastIndexedVersion ||
      currentVendorId !== lastIndexedVendorId
    ) {
      const rules = getAllRules(currentVendorId ?? undefined);
      engine.buildIndex(rules);
      lastIndexedVersion = rulesVersion;
      lastIndexedVendorId = currentVendorId;
      log(
        `Rule index rebuilt (version ${rulesVersion}, vendor: ${
          currentVendorId ?? 'all'
        }, ${rules.length} rules)`
      );
    }

    // Run with pre-indexed rules (no rules param = use existing index)
    const results = engine.run(nodes);

    // Check if this scan is still current (not superseded by newer scan)
    if (scanVersions.get(uri) !== currentVersion) {
      log(`Scan cancelled (superseded): ${document.fileName}`);
      return;
    }

    const diagnostics: vscode.Diagnostic[] = [];
    let errorCount = 0;
    let warningCount = 0;

    for (const result of results) {
      if (!result.passed && result.loc) {
        const startLine = result.loc.startLine;

        if (startLine >= 0 && startLine < document.lineCount) {
          const line = document.lineAt(startLine);
          const severity = mapSeverity(result.level);
          const rule = getRuleById(result.ruleId);
          const category = formatCategory(rule);

          // Apply category filter if set
          if (categoryFilter) {
            const ruleCats = rule?.category
              ? Array.isArray(rule.category)
                ? rule.category
                : [rule.category]
              : [];
            if (!ruleCats.includes(categoryFilter)) {
              continue; // Skip diagnostics not matching the filter
            }
          }

          const diagnostic = new vscode.Diagnostic(
            line.range,
            `[${result.ruleId}] (${category}) ${result.message}`,
            severity
          );
          diagnostic.source = 'SentriFlow';
          diagnostic.code = result.ruleId;
          diagnostics.push(diagnostic);

          if (result.level === 'error') errorCount++;
          if (result.level === 'warning') warningCount++;
        }
      }
    }

    // Final check before setting diagnostics
    if (scanVersions.get(uri) !== currentVersion) {
      return;
    }

    diagnosticCollection.set(document.uri, diagnostics);
    updateStatusBar('ready', errorCount, warningCount);

    log(
      `Scanned ${document.fileName}: ${errorCount} errors, ${warningCount} warnings`
    );
  } catch (e) {
    updateStatusBar('error');
    log(`Scan error: ${e instanceof Error ? e.message : e}`);
  }
}

// ============================================================================
// Utilities
// ============================================================================
function mapSeverity(level: string): vscode.DiagnosticSeverity {
  switch (level) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function updateStatusBar(
  state: 'ready' | 'scanning' | 'error',
  errors = 0,
  warnings = 0
) {
  // Count disabled items for tooltip
  const disabledRulesCount = getDisabledRulesSet().size;

  switch (state) {
    case 'scanning':
      statusBarItem.text = '$(sync~spin) SENTRIFLOW';
      statusBarItem.backgroundColor = undefined;
      statusBarItem.tooltip = 'Scanning configuration...';
      break;
    case 'error':
      statusBarItem.text = '$(error) SENTRIFLOW';
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        'statusBarItem.errorBackground'
      );
      statusBarItem.tooltip = 'Scan error - click to retry';
      break;
    case 'ready': {
      // Build rich markdown tooltip
      const tooltip = new vscode.MarkdownString();
      tooltip.isTrusted = true;
      tooltip.supportThemeIcons = true;
      tooltip.appendMarkdown('**SentriFlow Compliance Validator**\n\n');

      if (errors > 0) {
        statusBarItem.text = `$(error) SENTRIFLOW: ${errors}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.errorBackground'
        );
        tooltip.appendMarkdown(`$(error) **Errors:** ${errors}\n\n`);
        tooltip.appendMarkdown(`$(warning) **Warnings:** ${warnings}\n\n`);
      } else if (warnings > 0) {
        statusBarItem.text = `$(warning) SENTRIFLOW: ${warnings}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.warningBackground'
        );
        tooltip.appendMarkdown(`$(warning) **Warnings:** ${warnings}\n\n`);
      } else {
        statusBarItem.text = '$(check) SENTRIFLOW';
        statusBarItem.backgroundColor = undefined;
        tooltip.appendMarkdown('$(check) **No issues found**\n\n');
      }

      // Add disabled rules info if any
      if (disabledRulesCount > 0) {
        tooltip.appendMarkdown(
          `$(circle-slash) **Disabled Rules:** ${disabledRulesCount}\n\n`
        );
      }

      // Add vendor info
      if (currentVendor) {
        tooltip.appendMarkdown(
          `$(server) **Vendor:** ${currentVendor.name}\n\n`
        );
      }

      tooltip.appendMarkdown('---\n\n');
      tooltip.appendMarkdown('[$(search) Scan](command:sentriflow.scan) · ');
      tooltip.appendMarkdown(
        '[$(list-tree) Rules](command:sentriflow.focusRulesView) · '
      );
      tooltip.appendMarkdown(
        '[$(circle-slash) Disabled](command:sentriflow.showDisabled)'
      );

      statusBarItem.tooltip = tooltip;
      break;
    }
  }

  // Update vendor status bar whenever main status changes
  updateVendorStatusBar();
}

function updateVendorStatusBar() {
  if (!shouldShowVendorInStatusBar()) {
    vendorStatusBarItem.hide();
    return;
  }

  vendorStatusBarItem.show();

  const config = vscode.workspace.getConfiguration('sentriflow');
  const vendorSetting = config.get<string>('defaultVendor', 'auto');

  // Build rich markdown tooltip
  const tooltip = new vscode.MarkdownString();
  tooltip.isTrusted = true;
  tooltip.supportThemeIcons = true;

  if (vendorSetting === 'auto') {
    if (currentVendor) {
      // Auto mode with detected vendor
      vendorStatusBarItem.text = `$(server) ${currentVendor.name}`;
      tooltip.appendMarkdown(`**Vendor:** ${currentVendor.name}\n\n`);
      tooltip.appendMarkdown('$(info) *Auto-detected from configuration*\n\n');
    } else {
      // Auto mode, no detection yet
      vendorStatusBarItem.text = '$(server) Auto';
      tooltip.appendMarkdown('**Vendor:** Auto-detect\n\n');
      tooltip.appendMarkdown(
        '$(info) *Open a config file to detect vendor*\n\n'
      );
    }
  } else {
    // Manual vendor selection
    const vendorName = currentVendor?.name ?? vendorSetting;
    vendorStatusBarItem.text = `$(server) ${vendorName}`;
    tooltip.appendMarkdown(`**Vendor:** ${vendorName}\n\n`);
    tooltip.appendMarkdown('$(gear) *Manually configured*\n\n');
  }

  tooltip.appendMarkdown('---\n\n');
  tooltip.appendMarkdown(
    '[$(server) Change Vendor](command:sentriflow.selectVendor)'
  );

  vendorStatusBarItem.tooltip = tooltip;
}

/**
 * Log important operational messages (always visible)
 */
function logInfo(message: string) {
  outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
}

/**
 * Log debug messages (only when debug mode is enabled)
 */
function log(message: string) {
  if (debugMode) {
    logInfo(`[DEBUG] ${message}`);
  }
}

// ============================================================================
// Deactivation
// ============================================================================
export function deactivate() {
  // Clear all pending timers
  for (const timer of debounceTimers.values()) {
    clearTimeout(timer);
  }
  debounceTimers.clear();
  scanVersions.clear();

  // Clear parser and engine caches
  incrementalParser.clearAll();
  engine.clearIndex();
}
