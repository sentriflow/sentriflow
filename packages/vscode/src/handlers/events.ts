/**
 * Event Handlers
 *
 * Handles VS Code document and configuration change events.
 * Manages document scanning lifecycle and responds to configuration updates.
 */

import * as vscode from 'vscode';
import { getState } from '../state/context';
import { scheduleScan, rescanActiveEditor } from '../services/scanner';
import { loadPacks } from '../services/packManager';
import { DEBOUNCE_MS } from '../utils/helpers';
import { updateStatusBar } from '../ui/statusBar';

// ============================================================================
// Logging Helpers
// ============================================================================

/**
 * Log a debug message to the output channel.
 */
function log(message: string): void {
  const state = getState();
  if (state.debugMode) {
    state.outputChannel.appendLine(`[DEBUG] ${message}`);
  }
}

/**
 * Log an info message (always visible).
 */
function logInfo(message: string): void {
  const state = getState();
  state.outputChannel.appendLine(message);
}

// ============================================================================
// Document Event Handlers
// ============================================================================

/**
 * Handle document content changes.
 * Triggers a debounced scan when document content changes.
 */
export function onDocumentChange(event: vscode.TextDocumentChangeEvent): void {
  // Skip if no actual changes
  if (event.contentChanges.length === 0) return;

  scheduleScan(event.document, DEBOUNCE_MS);
}

/**
 * Handle document close.
 * Cleans up caches and diagnostics for the closed document.
 */
export function onDocumentClose(document: vscode.TextDocument): void {
  const state = getState();
  const uri = document.uri.toString();

  // Clear pending timer
  const timer = state.debounceTimers.get(uri);
  if (timer) {
    clearTimeout(timer);
    state.debounceTimers.delete(uri);
  }

  // Clear scan version
  state.scanVersions.delete(uri);

  // Clear incremental parser cache for this document
  state.incrementalParser.invalidate(uri);

  // Clear diagnostics
  state.diagnosticCollection.delete(document.uri);
}

/**
 * Handle active editor change.
 * Updates IP view, vendor status, and status bar for the new active editor.
 */
export function onActiveEditorChange(
  editor: vscode.TextEditor | undefined
): void {
  const state = getState();

  // Update IP Addresses TreeView
  state.ipAddressesTreeProvider?.updateFromDocument(editor?.document);

  if (editor) {
    // Update current vendor from cached document
    const uri = editor.document.uri.toString();
    const cachedVendor = state.incrementalParser.getCachedVendor(uri);
    if (cachedVendor) {
      state.currentVendor = cachedVendor;
    }

    // Update status bar for current document
    const diagnostics = state.diagnosticCollection.get(editor.document.uri);
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

// ============================================================================
// Configuration Event Handler
// ============================================================================

/**
 * Handle configuration changes.
 * Responds to sentriflow configuration updates by refreshing caches and UI.
 */
export function onConfigurationChange(
  event: vscode.ConfigurationChangeEvent
): void {
  const state = getState();

  if (event.affectsConfiguration('sentriflow.defaultVendor')) {
    log('Vendor configuration changed');
    // Clear all caches to force re-detection with new settings
    state.incrementalParser.clearAll();
    // Re-scan active editor
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.showVendorInStatusBar')) {
    // Update status bar display
    if (vscode.window.activeTextEditor) {
      const diagnostics = state.diagnosticCollection.get(
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
    log('Default rules setting changed');
    // Update tree view, settings webview, and re-scan
    state.rulesTreeProvider.refresh();
    state.settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.blockedPacks')) {
    log('Blocked packs setting changed - reloading packs');
    // Reload packs to apply blocked/unblocked changes immediately
    loadPacks().then(() => {
      state.rulesTreeProvider.refresh();
      state.settingsWebviewProvider.refresh();
      rescanActiveEditor();
    });
  }

  if (event.affectsConfiguration('sentriflow.packVendorOverrides')) {
    log('Pack vendor overrides changed');
    // Update tree view, settings webview, and re-scan
    state.rulesTreeProvider.refresh();
    state.settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.disabledRules')) {
    const config = vscode.workspace.getConfiguration('sentriflow');
    const disabledRules = config.get<string[]>('disabledRules', []);
    log(`Disabled rules setting changed: ${JSON.stringify(disabledRules)}`);
    // Increment rules version to force index rebuild
    state.rulesVersion++;
    state.rulesTreeProvider.refresh();
    state.settingsWebviewProvider.refresh();
    rescanActiveEditor();
  }

  if (event.affectsConfiguration('sentriflow.ipAddresses.filterSpecialRanges')) {
    log('IP filter setting changed');
    // Re-extract IPs with new filter setting
    state.ipAddressesTreeProvider.updateFromDocument(
      vscode.window.activeTextEditor?.document
    );
    state.settingsWebviewProvider.refresh();
  }

  if (event.affectsConfiguration('sentriflow.debug')) {
    const config = vscode.workspace.getConfiguration('sentriflow');
    state.debugMode = config.get<boolean>('debug', false);
    logInfo(`Debug logging ${state.debugMode ? 'enabled' : 'disabled'}`);
    if (state.debugMode) {
      state.outputChannel.show();
    }
  }
}

// ============================================================================
// Event Handler Registration
// ============================================================================

/**
 * Register all event handlers with VS Code.
 * Returns a disposable that unregisters all handlers.
 */
export function registerEventHandlers(
  context: vscode.ExtensionContext
): vscode.Disposable[] {
  const disposables: vscode.Disposable[] = [];

  // Document change events
  disposables.push(
    vscode.workspace.onDidChangeTextDocument(onDocumentChange)
  );

  // Document close events
  disposables.push(vscode.workspace.onDidCloseTextDocument(onDocumentClose));

  // Active editor change events
  disposables.push(
    vscode.window.onDidChangeActiveTextEditor(onActiveEditorChange)
  );

  // Configuration change events
  disposables.push(
    vscode.workspace.onDidChangeConfiguration(onConfigurationChange)
  );

  // Add all disposables to context
  context.subscriptions.push(...disposables);

  return disposables;
}
