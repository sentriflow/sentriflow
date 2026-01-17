/**
 * Scanning Commands
 *
 * Commands for file and selection scanning.
 * Includes bulk scan functionality for multiple files/folders.
 */

import * as vscode from 'vscode';
import {
  SchemaAwareParser,
  detectVendor,
  getVendor,
  isValidVendor,
} from '@sentriflow/core';
import type { VendorSchema } from '@sentriflow/core';
import { getState } from '../state/context';
import { runScan, scheduleScan, mapSeverity } from '../services/scanner';
import { getAllRules, getRuleById } from '../services/ruleManager';
import {
  formatCategory,
  isConfigFile as isConfigFilePath,
  MAX_FILE_SIZE,
} from '../utils/helpers';
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

// ============================================================================
// Vendor Helpers
// ============================================================================

/**
 * Get the configured vendor from settings.
 * Returns 'auto' if automatic detection is enabled.
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

// ============================================================================
// Single File Commands
// ============================================================================

/**
 * Command: Scan current file
 */
export function cmdScanFile(): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('SENTRIFLOW: No active editor');
    return;
  }
  // Force scan regardless of language
  runScan(editor.document, true);
}

/**
 * Command: Scan current selection
 */
export function cmdScanSelection(): void {
  const state = getState();
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
      state.rulesVersion !== state.lastIndexedVersion ||
      vendorId !== state.lastIndexedVendorId
    ) {
      const rules = getAllRules(vendorId);
      state.engine.buildIndex(rules);
      state.lastIndexedVersion = state.rulesVersion;
      state.lastIndexedVendorId = vendorId;
    }

    const results = state.engine.run(nodes);

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
          if (state.categoryFilter) {
            const ruleCats = rule?.category
              ? Array.isArray(rule.category)
                ? rule.category
                : [rule.category]
              : [];
            if (!ruleCats.includes(state.categoryFilter)) {
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
      state.diagnosticCollection.get(editor.document.uri) ?? [];
    const outsideSelection = [...existingDiagnostics].filter(
      (d) =>
        d.range.end.line < selection.start.line ||
        d.range.start.line > selection.end.line
    );

    state.diagnosticCollection.set(editor.document.uri, [
      ...outsideSelection,
      ...diagnostics,
    ]);

    state.currentVendor = vendor;
    updateStatusBar('ready', errorCount, warningCount);
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Selection scanned (${vendor.name}) - ${errorCount} errors, ${warningCount} warnings`
    );
  } catch (e) {
    updateStatusBar('error');
    log(`Selection scan error: ${e instanceof Error ? e.message : e}`);
  }
}

// ============================================================================
// Bulk Scan Helpers
// ============================================================================

/**
 * Check if a URI has a known network configuration file extension.
 */
function isConfigFile(uri: vscode.Uri): boolean {
  return isConfigFilePath(uri.path);
}

/**
 * Recursively collect files to scan from a list of URIs.
 * Files are filtered by extension; folders are expanded recursively.
 */
async function collectFilesToScan(
  uris: vscode.Uri[],
  token: vscode.CancellationToken
): Promise<vscode.Uri[]> {
  const files: vscode.Uri[] = [];

  for (const uri of uris) {
    if (token.isCancellationRequested) break;

    try {
      const stat = await vscode.workspace.fs.stat(uri);

      if (stat.type === vscode.FileType.File) {
        // Direct file - check extension
        if (isConfigFile(uri)) {
          files.push(uri);
        }
      } else if (stat.type === vscode.FileType.Directory) {
        // Folder - use workspace.findFiles for recursive discovery
        const pattern = new vscode.RelativePattern(uri, '**/*');
        const foundFiles = await vscode.workspace.findFiles(
          pattern,
          '**/node_modules/**',
          undefined,
          token
        );

        // Filter to config files only
        for (const file of foundFiles) {
          if (isConfigFile(file)) {
            files.push(file);
          }
        }
      }
    } catch (e) {
      // File/folder inaccessible - log and skip
      log(
        `Cannot access: ${uri.fsPath}: ${e instanceof Error ? e.message : e}`
      );
    }
  }

  return files;
}

interface BulkScanFileResult {
  errors: number;
  warnings: number;
}

/**
 * Scan a single file by URI and add diagnostics.
 * Uses SchemaAwareParser (no incremental caching needed for batch).
 * Respects existing suppressions for the file.
 */
async function scanFileByUri(uri: vscode.Uri): Promise<BulkScanFileResult> {
  const state = getState();

  // Open document to get TextDocument (needed for suppression checks)
  const document = await vscode.workspace.openTextDocument(uri);
  const text = document.getText();

  // Skip empty files
  if (text.trim().length === 0) {
    state.diagnosticCollection.set(uri, []);
    return { errors: 0, warnings: 0 };
  }

  // Skip oversized files
  if (text.length > MAX_FILE_SIZE) {
    log(`Skipped oversized file: ${uri.fsPath} (${text.length} bytes)`);
    return { errors: 0, warnings: 0 };
  }

  // Get configured vendor option
  const vendorOption = getConfiguredVendor();
  const vendor = vendorOption === 'auto' ? detectVendor(text) : vendorOption;

  // Parse using SchemaAwareParser (better for batch - no incremental caching needed)
  const parser = new SchemaAwareParser({ vendor });
  const nodes = parser.parse(text);

  // Ensure rule index is up to date
  const vendorId = vendor.id;
  if (
    state.rulesVersion !== state.lastIndexedVersion ||
    vendorId !== state.lastIndexedVendorId
  ) {
    const rules = getAllRules(vendorId);
    state.engine.buildIndex(rules);
    state.lastIndexedVersion = state.rulesVersion;
    state.lastIndexedVendorId = vendorId;
  }

  // Run rules
  const results = state.engine.run(nodes);

  // Build diagnostics
  const diagnostics: vscode.Diagnostic[] = [];

  for (const result of results) {
    if (!result.passed && result.loc) {
      const startLine = result.loc.startLine;

      if (startLine >= 0 && startLine < document.lineCount) {
        const line = document.lineAt(startLine);
        const severity = mapSeverity(result.level);
        const rule = getRuleById(result.ruleId);
        const category = formatCategory(rule);

        // Apply category filter if set
        if (state.categoryFilter) {
          const ruleCats = rule?.category
            ? Array.isArray(rule.category)
              ? rule.category
              : [rule.category]
            : [];
          if (!ruleCats.includes(state.categoryFilter)) {
            continue;
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
      }
    }
  }

  // Filter out suppressed diagnostics
  const filteredDiagnostics = diagnostics.filter(
    (d) => !state.suppressionManager.isSuppressed(document, d)
  );

  const suppressedCount = diagnostics.length - filteredDiagnostics.length;
  if (suppressedCount > 0) {
    log(`Filtered ${suppressedCount} suppressed diagnostic(s) from ${uri.fsPath}`);
  }

  // Set diagnostics for this file
  state.diagnosticCollection.set(uri, filteredDiagnostics);

  // Return counts based on filtered diagnostics (what user actually sees)
  const filteredErrors = filteredDiagnostics.filter(
    (d) => d.severity === vscode.DiagnosticSeverity.Error
  ).length;
  const filteredWarnings = filteredDiagnostics.filter(
    (d) => d.severity === vscode.DiagnosticSeverity.Warning
  ).length;

  return { errors: filteredErrors, warnings: filteredWarnings };
}

/**
 * Show summary of bulk scan results.
 */
function showBulkScanSummary(
  filesScanned: number,
  totalErrors: number,
  totalWarnings: number,
  fileErrors: Array<{ file: string; error: string }>
): void {
  const issueCount = totalErrors + totalWarnings;

  let message = `SENTRIFLOW: Scanned ${filesScanned} file${filesScanned !== 1 ? 's' : ''}`;

  if (issueCount === 0 && fileErrors.length === 0) {
    message += ' - no issues found';
    vscode.window.showInformationMessage(message);
  } else {
    if (issueCount > 0) {
      message += ` - ${totalErrors} error${totalErrors !== 1 ? 's' : ''}, ${totalWarnings} warning${totalWarnings !== 1 ? 's' : ''}`;
    }
    if (fileErrors.length > 0) {
      message += ` (${fileErrors.length} file${fileErrors.length !== 1 ? 's' : ''} had errors)`;
    }

    // Offer to show Problems panel
    vscode.window.showWarningMessage(message, 'Show Problems').then((action) => {
      if (action === 'Show Problems') {
        vscode.commands.executeCommand('workbench.panel.markers.view.focus');
      }
    });
  }

  // Log details
  log(
    `Bulk scan complete: ${filesScanned} files, ${totalErrors} errors, ${totalWarnings} warnings`
  );
  if (fileErrors.length > 0) {
    for (const fe of fileErrors) {
      log(`  File error: ${fe.file}: ${fe.error}`);
    }
  }
}

// ============================================================================
// Bulk Scan Commands
// ============================================================================

/**
 * Command: Scan multiple files/folders from explorer context menu.
 * @param uri - The right-clicked URI
 * @param selectedUris - All selected URIs (includes the clicked one)
 */
export async function cmdScanBulk(
  uri?: vscode.Uri,
  selectedUris?: vscode.Uri[]
): Promise<void> {
  // Resolve URIs to scan
  const urisToProcess = selectedUris?.length ? selectedUris : uri ? [uri] : [];
  if (urisToProcess.length === 0) {
    vscode.window.showWarningMessage('SENTRIFLOW: No files or folders selected');
    return;
  }

  // Run with progress
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'SentriFlow: Scanning...',
      cancellable: true,
    },
    async (progress, token) => {
      // 1. Discover files
      progress.report({ message: 'Discovering files...' });
      const files = await collectFilesToScan(urisToProcess, token);

      if (token.isCancellationRequested) {
        vscode.window.showInformationMessage('SENTRIFLOW: Scan cancelled');
        return;
      }

      if (files.length === 0) {
        vscode.window.showInformationMessage(
          'SENTRIFLOW: No configuration files found'
        );
        return;
      }

      // 2. Scan each file
      let scanned = 0;
      let totalErrors = 0;
      let totalWarnings = 0;
      const fileErrors: Array<{ file: string; error: string }> = [];

      for (const fileUri of files) {
        if (token.isCancellationRequested) {
          vscode.window.showInformationMessage(
            `SENTRIFLOW: Scan cancelled (${scanned}/${files.length} files scanned)`
          );
          return;
        }

        progress.report({
          message: `${scanned + 1}/${files.length}: ${vscode.workspace.asRelativePath(fileUri)}`,
          increment: 100 / files.length,
        });

        try {
          const result = await scanFileByUri(fileUri);
          totalErrors += result.errors;
          totalWarnings += result.warnings;
        } catch (e) {
          fileErrors.push({
            file: fileUri.fsPath,
            error: e instanceof Error ? e.message : String(e),
          });
        }

        scanned++;
      }

      // 3. Show summary
      showBulkScanSummary(scanned, totalErrors, totalWarnings, fileErrors);
    }
  );
}

// ============================================================================
// Language/Debug Commands
// ============================================================================

/**
 * Command: Set current file language to network-config
 */
export async function cmdSetLanguage(): Promise<void> {
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

/**
 * Command: Toggle debug logging mode
 */
export async function cmdToggleDebug(): Promise<void> {
  const state = getState();
  state.debugMode = !state.debugMode;

  // Update the setting to keep in sync
  const config = vscode.workspace.getConfiguration('sentriflow');
  await config.update('debug', state.debugMode, vscode.ConfigurationTarget.Global);

  vscode.window.showInformationMessage(
    `SENTRIFLOW: Debug logging ${state.debugMode ? 'enabled' : 'disabled'}`
  );

  if (state.debugMode) {
    state.outputChannel.show();
  }
}
