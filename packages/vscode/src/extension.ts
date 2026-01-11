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
  // Shared validation utilities (DRY)
  validateRule,
  isValidRule,
  validateRulePack,
  isValidRulePack,
  ruleAppliesToVendor,
  // JSON Rules compilation
  compileJsonRules,
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
import { CustomRulesLoader } from './providers/CustomRulesLoader';
import { CustomRulesCompletionProvider } from './providers/CustomRulesCompletionProvider';
import {
  LicenseManager,
  CloudClient,
  loadAllPacksUnified,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
  EncryptedPackError,
  type UpdateCheckResult,
  type EncryptedPackInfo,
  type CloudPackContext,
  type EntitlementInfo,
  type CloudConnectionStatus,
  DEFAULT_PACKS_DIRECTORY,
  CACHE_DIRECTORY,
  DEFAULT_CLOUD_API_URL,
} from './encryption';

// Import utilities from extracted modules
import {
  parseCommaSeparated,
  formatCategory,
  getUniqueCategoriesFromRules,
  isConfigFile as isConfigFilePath,
  formatLogMessage,
  formatDebugMessage,
  SUPPORTED_LANGUAGES,
  DEBOUNCE_MS,
  MAX_FILE_SIZE,
  CONFIG_EXTENSIONS,
} from './utils/helpers';

// Import state management
import { initState, getState, disposeState } from './state/context';

// Import services - these replace local implementations
import { scheduleScan, runScan, rescanActiveEditor } from './services/scanner';
import { getDisabledRulesSet, getAllRules, getRuleById } from './services/ruleManager';
import {
  handlePackDisables,
  handleLicenseRevocation,
  checkAndDownloadUpdates,
  loadPacks,
  initializePacks,
  updateLicenseTree,
} from './services/packManager';

// Import handlers
import { onDocumentChange, onDocumentClose, onActiveEditorChange, onConfigurationChange } from './handlers/events';

// Import UI
import { updateStatusBar, updateVendorStatusBar } from './ui/statusBar';

// Import all command handlers from extracted modules
import {
  // License commands
  cmdEnterLicenseKey,
  cmdClearLicenseKey,
  cmdShowLicenseStatus,
  cmdCheckForUpdates,
  cmdDownloadUpdates,
  cmdReloadPacks,
  cmdShowEncryptedPackStatus,
  // Scanning commands
  cmdScanFile,
  cmdScanSelection,
  cmdScanBulk,
  cmdSetLanguage,
  cmdToggleDebug,
  // Rules commands
  cmdShowRulePacks,
  cmdDisableTreeItem,
  cmdEnableTreeItem,
  cmdCopyRuleId,
  cmdViewRuleDetails,
  cmdTogglePack,
  cmdToggleVendor,
  cmdDisableRuleById,
  cmdEnableRuleById,
  cmdShowDisabled,
  cmdFilterTagType,
  cmdFilterByCategory,
  cmdSelectVendor,
  // Custom rules commands
  cmdCreateCustomRulesFile,
  cmdCopyRuleToCustom,
  cmdDeleteCustomRule,
  cmdEditCustomRule,
} from './commands';

// Re-export parseCommaSeparated for external consumers (testing)
export { parseCommaSeparated } from './utils/helpers';

// ============================================================================
// Configuration Constants
// ============================================================================

// Note: SUPPORTED_LANGUAGES, DEBOUNCE_MS, MAX_FILE_SIZE, CONFIG_EXTENSIONS
// are now imported from './utils/helpers'

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

// Note: ruleAppliesToVendor is now imported from @sentriflow/core

// Note: parseCommaSeparated() is now imported from './utils/helpers'
// Note: getDisabledRulesSet, getAllRules, getRuleById, rescanActiveEditor moved to services/ruleManager.ts and services/scanner.ts


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

// Note: getRuleById moved to services/ruleManager.ts
// Note: formatCategory() is now imported from './utils/helpers'

// Track current vendor for status bar display
let currentVendor: VendorSchema | null = null;

// Category filter for diagnostics (undefined = show all)
let categoryFilter: string | undefined = undefined;

/**
 * Get unique categories from current rules.
 */
function getUniqueCategories(): string[] {
  return getUniqueCategoriesFromRules(currentRuleMap.values());
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
let customRulesLoader: CustomRulesLoader;

// Debounce timers per document URI
const debounceTimers = new Map<string, NodeJS.Timeout>();

// Track scan version to cancel stale results
const scanVersions = new Map<string, number>();

// Note: DEBOUNCE_MS, MAX_FILE_SIZE, CONFIG_EXTENSIONS are now imported from './utils/helpers'

// Debug mode - only log when explicitly enabled (read from settings on activation)
let debugMode = vscode.workspace.getConfiguration('sentriflow').get<boolean>('debug', false);


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
        encryptedPacksInfo.some((p) => p.feedId === packName && p.loaded),
      () => customRulesLoader?.getRules(true) ?? [] // true = include disabled for tree display
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

    // Create and initialize Custom Rules Loader
    customRulesLoader = new CustomRulesLoader(context);
    customRulesLoader.initialize(); // Async initialization - will complete in background
    context.subscriptions.push({ dispose: () => customRulesLoader.dispose() });

    // Re-scan when custom rules change
    context.subscriptions.push(
      customRulesLoader.onDidChangeRules(() => {
        log('Custom rules changed, triggering rescan');
        rescanActiveEditor();
      })
    );

    // Create and register License TreeView
    licenseTreeProvider = new LicenseTreeProvider();
    const licenseTreeView = vscode.window.createTreeView('sentriflowLicense', {
      treeDataProvider: licenseTreeProvider,
      showCollapseAll: false,
    });
    context.subscriptions.push(licenseTreeView);

    // Initialize centralized state for extracted modules
    // This allows services, handlers, and UI modules to access shared state via getState()
    initState({
      // VS Code Integration
      context,
      outputChannel,
      diagnosticCollection,

      // UI Components
      statusBarItem,
      vendorStatusBarItem,

      // Tree Providers
      rulesTreeProvider,
      ipAddressesTreeProvider,
      licenseTreeProvider,
      settingsWebviewProvider,
      customRulesLoader,

      // Parser & Engine (from module-level singletons)
      incrementalParser,
      engine,

      // Rules State
      rulesVersion,
      lastIndexedVersion,
      lastIndexedVendorId,
      currentRuleMap,
      currentVendor,
      categoryFilter,

      // Pack & License State
      licenseManager,
      cloudClient,
      encryptedPacksInfo,
      lastUpdateCheck,

      // Pack Management State
      registeredPacks,
      disabledRuleIds,
      defaultPack,

      // Scan State
      debounceTimers,
      scanVersions,
      debugMode,
    });

    // Register hover provider for diagnostic tooltips with category and tags
    const hoverProvider = new SentriFlowHoverProvider(
      diagnosticCollection,
      getRuleById
    );
    context.subscriptions.push(
      vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider)
    );

    // Register completion provider for custom rules JSON files
    const customRulesCompletionProvider = new CustomRulesCompletionProvider();
    context.subscriptions.push(
      vscode.languages.registerCompletionItemProvider(
        { scheme: 'file', pattern: '**/.sentriflow/rules/*.json' },
        customRulesCompletionProvider,
        '"', // Trigger on quote
        ':' // Trigger on colon
      )
    );

    // Register commands
    context.subscriptions.push(
      vscode.commands.registerCommand('sentriflow.scan', cmdScanFile),
      vscode.commands.registerCommand(
        'sentriflow.scanSelection',
        cmdScanSelection
      ),
      vscode.commands.registerCommand('sentriflow.scanBulk', cmdScanBulk),
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
        'sentriflow.reloadPacks',
        cmdReloadPacks
      ),
      vscode.commands.registerCommand(
        'sentriflow.showPackStatus',
        cmdShowEncryptedPackStatus
      ),
      vscode.commands.registerCommand('sentriflow.openLicensingPage', () => {
        vscode.env.openExternal(
          vscode.Uri.parse('https://sentriflow.com.au/pricing')
        );
      })
    );

    // Register Custom Rules commands
    context.subscriptions.push(
      vscode.commands.registerCommand(
        'sentriflow.createCustomRulesFile',
        cmdCreateCustomRulesFile
      ),
      vscode.commands.registerCommand(
        'sentriflow.copyRuleToCustom',
        cmdCopyRuleToCustom
      ),
      vscode.commands.registerCommand(
        'sentriflow.deleteCustomRule',
        cmdDeleteCustomRule
      ),
      vscode.commands.registerCommand(
        'sentriflow.editCustomRule',
        cmdEditCustomRule
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

    // Initialize pack support (GRX2 + GRPX formats, async, don't block activation)
    initializePacks()
      .catch((err) => {
        log(`Failed to initialize packs: ${(err as Error).message}`);
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

          const validationError = validateRulePack(pack, DEFAULT_PACK_NAME);
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

// Event handlers moved to handlers/events.ts
// Scanning logic moved to services/scanner.ts
// Status bar logic moved to ui/statusBar.ts

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

  // Dispose centralized state
  disposeState();
}
