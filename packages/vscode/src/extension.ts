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
 * Check if a default rule should be disabled based on pack disable configs.
 */
function isDefaultRuleDisabled(
  ruleId: string,
  vendorId: string | undefined
): boolean {
  // Check legacy disabled set
  if (disabledRuleIds.has(ruleId)) {
    return true;
  }

  // Check all registered packs for disable configs
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
      // Check if this default rule is disabled
      if (isDefaultRuleDisabled(rule.id, vendorId)) {
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

  return Array.from(ruleMap.values()).map((entry) => entry.rule);
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
    updateRulePacksStatusBar();
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
    updateRulePacksStatusBar();
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
  },
});

// Track when rules change to rebuild index only when needed
let rulesVersion = 0;
let lastIndexedVersion = -1;
let lastIndexedVendorId: string | null = null;

// Track current vendor for status bar display
let currentVendor: VendorSchema | null = null;

// ============================================================================
// Extension State
// ============================================================================
let extensionContext: vscode.ExtensionContext;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let vendorStatusBarItem: vscode.StatusBarItem;
let rulePacksStatusBarItem: vscode.StatusBarItem;
let diagnosticCollection: vscode.DiagnosticCollection;

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

    // Create status bar item for rule packs
    rulePacksStatusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      98
    );
    rulePacksStatusBarItem.command = 'sentriflow.showRulePacks';
    rulePacksStatusBarItem.show();

    // Initialize status bar displays (must be after all items are created)
    updateStatusBar('ready');
    updateRulePacksStatusBar();

    // Create diagnostic collection
    diagnosticCollection =
      vscode.languages.createDiagnosticCollection('sentriflow');

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
      rulePacksStatusBarItem,
      diagnosticCollection
    );

    // Initial scan of active editor
    if (vscode.window.activeTextEditor) {
      scheduleScan(vscode.window.activeTextEditor.document, 0);
    }

    // Prompt user about default rules (once per installation)
    promptDefaultRulesOnce();

    log('SENTRIFLOW extension activated');
    log(`Available vendors: ${getAvailableVendors().join(', ')}`);

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
          log(
            `Registered rule pack '${validPack.name}' v${validPack.version} (${validPack.rules.length} rules, priority ${validPack.priority})`
          );

          updateRulePacksStatusBar();
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
          updateRulePacksStatusBar();
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

          const diagnostic = new vscode.Diagnostic(
            line.range,
            result.message,
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

  interface RuleItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RuleItem[] = rules.map((rule) => {
    const levelIcon =
      rule.metadata.level === 'error'
        ? '$(error)'
        : rule.metadata.level === 'warning'
        ? '$(warning)'
        : '$(info)';
    const vendor = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(', ')
        : rule.vendor
      : 'common';

    return {
      label: `${levelIcon} ${rule.id}`,
      description: vendor,
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
    placeHolder: `${rules.length} rules - Select to view details`,
    title: `SENTRIFLOW: ${packName} - Rules`,
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  if (!selected.ruleId) {
    await showPackActions(packName);
    return;
  }

  // Show detailed rule info in output channel
  const rule = rules.find((r) => r.id === selected.ruleId);
  if (rule) {
    outputChannel.show(true);
    outputChannel.appendLine(`\n${'='.repeat(60)}`);
    outputChannel.appendLine(`Rule: ${rule.id}`);
    outputChannel.appendLine(`${'='.repeat(60)}`);
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
      if (sec.tags?.length) {
        outputChannel.appendLine(`Tags:        ${sec.tags.join(', ')}`);
      }
    }
    outputChannel.appendLine('');
  }

  // Stay in rules view
  await showPackRules(packName, pack, isDefault);
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
    // Update status bar and re-scan
    updateRulePacksStatusBar();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.blockedPacks')) {
    log(`Blocked packs setting changed`);
    // Note: This only affects future registrations
    // Already registered packs remain active until extension reload
  }

  if (event.affectsConfiguration('sentriflow.packVendorOverrides')) {
    log(`Pack vendor overrides changed`);
    // Update status bar and re-scan
    updateRulePacksStatusBar();
    rescanActiveEditor();
  }
}

// ============================================================================
// Scanning Logic
// ============================================================================
function scheduleScan(document: vscode.TextDocument, delay: number) {
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

          const diagnostic = new vscode.Diagnostic(
            line.range,
            result.message,
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
    case 'ready':
      if (errors > 0) {
        statusBarItem.text = `$(error) SENTRIFLOW: ${errors}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.errorBackground'
        );
        statusBarItem.tooltip = `${errors} error(s), ${warnings} warning(s) - Click to scan`;
      } else if (warnings > 0) {
        statusBarItem.text = `$(warning) SENTRIFLOW: ${warnings}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
          'statusBarItem.warningBackground'
        );
        statusBarItem.tooltip = `${warnings} warning(s) - Click to scan`;
      } else {
        statusBarItem.text = '$(check) SENTRIFLOW';
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = 'No issues - Click to scan';
      }
      break;
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

  if (vendorSetting === 'auto') {
    if (currentVendor) {
      // Auto mode with detected vendor
      vendorStatusBarItem.text = `$(server) ${currentVendor.name}`;
      vendorStatusBarItem.tooltip = `Vendor: ${currentVendor.name} (auto-detected)\nClick to change`;
    } else {
      // Auto mode, no detection yet
      vendorStatusBarItem.text = '$(server) Auto';
      vendorStatusBarItem.tooltip = 'Vendor: Auto-detect\nClick to change';
    }
  } else {
    // Manual vendor selection
    const vendorName = currentVendor?.name ?? vendorSetting;
    vendorStatusBarItem.text = `$(server) ${vendorName}`;
    vendorStatusBarItem.tooltip = `Vendor: ${vendorName} (manual)\nClick to change`;
  }
}

/**
 * Update rule packs status bar item with current pack/rule counts
 */
function updateRulePacksStatusBar() {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const packVendorOverrides = config.get<
    Record<string, { disabledVendors?: string[] }>
  >('packVendorOverrides', {});

  // Count active packs and rules
  let activePacks = 0;
  let totalRules = 0;
  const packSummaries: string[] = [];

  // Check default pack
  if (enableDefaultRules) {
    activePacks++;
    totalRules += allRules.length;
    packSummaries.push(`${DEFAULT_PACK_NAME}: ${allRules.length} rules`);
  } else {
    packSummaries.push(`${DEFAULT_PACK_NAME}: disabled`);
  }

  // Check registered packs
  for (const [name, pack] of registeredPacks) {
    const packOverride = packVendorOverrides[name];
    const disabledVendors = new Set(packOverride?.disabledVendors ?? []);

    // Count active rules (not disabled by vendor)
    let activeRules = 0;
    for (const rule of pack.rules) {
      if (disabledVendors.size > 0) {
        // Rules without vendor or with vendor='common' are treated as 'common'
        const ruleVendors = rule.vendor
          ? Array.isArray(rule.vendor)
            ? rule.vendor
            : [rule.vendor]
          : ['common'];
        const allVendorsDisabled = ruleVendors.every((v) =>
          disabledVendors.has(v)
        );
        if (allVendorsDisabled) continue;
      }
      activeRules++;
    }

    if (activeRules > 0) {
      activePacks++;
      totalRules += activeRules;
      if (activeRules < pack.rules.length) {
        packSummaries.push(
          `${name}: ${activeRules}/${pack.rules.length} rules`
        );
      } else {
        packSummaries.push(`${name}: ${activeRules} rules`);
      }
    } else {
      packSummaries.push(`${name}: disabled`);
    }
  }

  // Update status bar
  rulePacksStatusBarItem.text = `$(package) ${totalRules} rules`;
  rulePacksStatusBarItem.tooltip = `Rule Packs (${activePacks} active)\n${packSummaries.join(
    '\n'
  )}\n\nClick to manage`;
}

function log(message: string) {
  if (debugMode) {
    outputChannel.appendLine(`[${new Date().toISOString()}] ${message}`);
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
