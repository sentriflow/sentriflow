/**
 * Shared Extension State Container
 *
 * Centralizes all module-level state that was previously scattered in extension.ts.
 * Modules access state via getState() which is called at function execution time,
 * not import time, to avoid circular dependency issues.
 */

import * as vscode from 'vscode';
import type {
  IRule,
  RulePack,
  VendorSchema,
  IncrementalParser,
  RuleEngine,
} from '@sentriflow/core';
import type { RulesTreeProvider } from '../providers/RulesTreeProvider';
import type { IPAddressesTreeProvider } from '../providers/IPAddressesTreeProvider';
import type { LicenseTreeProvider } from '../providers/LicenseTreeProvider';
import type { SuppressionsTreeProvider } from '../providers/SuppressionsTreeProvider';
import type { SettingsWebviewProvider } from '../providers/SettingsWebviewProvider';
import type { CustomRulesLoader } from '../providers/CustomRulesLoader';
import type { SuppressionManager } from '../services/suppressionManager';
import type {
  LicenseManager,
  CloudClient,
  UpdateCheckResult,
  EncryptedPackInfo,
} from '../encryption';

// ============================================================================
// Extension State Interface
// ============================================================================

/**
 * Centralized state for the extension.
 * All shared mutable state is stored here and accessed via getState().
 */
export interface ExtensionState {
  // ═══════════════════════════════════════════════════════════════════════════
  // VS Code Integration (immutable after init)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Extension context from VS Code activation */
  context: vscode.ExtensionContext;

  /** Output channel for logging */
  outputChannel: vscode.OutputChannel;

  /** Diagnostic collection for findings */
  diagnosticCollection: vscode.DiagnosticCollection;

  // ═══════════════════════════════════════════════════════════════════════════
  // UI Components (immutable after init)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Main status bar item showing scan status */
  statusBarItem: vscode.StatusBarItem;

  /** Vendor status bar item */
  vendorStatusBarItem: vscode.StatusBarItem;

  // ═══════════════════════════════════════════════════════════════════════════
  // Tree Providers (immutable after init)
  // ═══════════════════════════════════════════════════════════════════════════

  rulesTreeProvider: RulesTreeProvider;
  ipAddressesTreeProvider: IPAddressesTreeProvider;
  licenseTreeProvider: LicenseTreeProvider;
  suppressionsTreeProvider: SuppressionsTreeProvider;
  settingsWebviewProvider: SettingsWebviewProvider;
  customRulesLoader: CustomRulesLoader;

  // ═══════════════════════════════════════════════════════════════════════════
  // Parser & Engine (mutable - reconfigured on vendor change)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Incremental parser instance */
  incrementalParser: IncrementalParser;

  /** Rule engine instance */
  engine: RuleEngine;

  // ═══════════════════════════════════════════════════════════════════════════
  // Rules State (mutable)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Version counter for rule changes (triggers re-index) */
  rulesVersion: number;

  /** Last indexed version */
  lastIndexedVersion: number;

  /** Last indexed vendor ID */
  lastIndexedVendorId: string | null;

  /** Current rules indexed by ID */
  currentRuleMap: Map<string, IRule>;

  /** Currently detected/selected vendor */
  currentVendor: VendorSchema | null;

  /** Active category filter */
  categoryFilter: string | undefined;

  // ═══════════════════════════════════════════════════════════════════════════
  // Pack & License State (mutable)
  // ═══════════════════════════════════════════════════════════════════════════

  /** License manager (null if not initialized) */
  licenseManager: LicenseManager | null;

  /** Cloud client (null if no license) */
  cloudClient: CloudClient | null;

  /** Info about loaded encrypted packs */
  encryptedPacksInfo: EncryptedPackInfo[];

  /** Last update check result */
  lastUpdateCheck: UpdateCheckResult | null;

  // ═══════════════════════════════════════════════════════════════════════════
  // Pack Management State (mutable)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Registered rule packs (excluding default) */
  registeredPacks: Map<string, RulePack>;

  /** Legacy: individually disabled rule IDs (for backward compatibility) */
  disabledRuleIds: Set<string>;

  /** Default pack containing built-in rules */
  defaultPack: RulePack;

  // ═══════════════════════════════════════════════════════════════════════════
  // Scan State (mutable)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Debounce timers by document URI */
  debounceTimers: Map<string, NodeJS.Timeout>;

  /** Scan version counters by document URI */
  scanVersions: Map<string, number>;

  /** Debug mode flag */
  debugMode: boolean;

  /** Per-document vendor overrides (URI → vendor ID) */
  documentVendorOverrides: Map<string, string>;

  // ═══════════════════════════════════════════════════════════════════════════
  // Suppression Management (mutable)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Suppression manager for diagnostic suppressions */
  suppressionManager: SuppressionManager;
}

// ============================================================================
// State Management
// ============================================================================

/** The singleton state instance */
let state: ExtensionState | null = null;

/**
 * Initialize extension state during activation.
 * Must be called exactly once from activate().
 *
 * @param partialState Initial state values (context and UI components are required)
 * @returns The initialized state
 * @throws If state is already initialized
 */
export function initState(partialState: ExtensionState): ExtensionState {
  if (state) {
    throw new Error('Extension state already initialized');
  }
  state = partialState;
  return state;
}

/**
 * Get the current extension state.
 * Call this at function execution time, not at import time.
 *
 * @returns The extension state
 * @throws If state has not been initialized (call initState first)
 */
export function getState(): ExtensionState {
  if (!state) {
    throw new Error(
      'Extension state not initialized - call initState() in activate() first'
    );
  }
  return state;
}

/**
 * Dispose extension state during deactivation.
 * Clears the state singleton to allow re-initialization if needed.
 */
export function disposeState(): void {
  state = null;
}

/**
 * Check if state has been initialized.
 * Useful for conditional logic that may run before activation completes.
 */
export function isStateInitialized(): boolean {
  return state !== null;
}
