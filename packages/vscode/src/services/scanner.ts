/**
 * Scanner Service
 *
 * Core scanning logic for document validation.
 * Handles incremental parsing, rule execution, and diagnostics generation.
 */

import * as vscode from 'vscode';
import { getState } from '../state/context';
import {
  SUPPORTED_LANGUAGES,
  MAX_FILE_SIZE,
  formatCategory,
} from '../utils/helpers';
import { getAllRules, getDisabledRulesSet } from './ruleManager';

// ============================================================================
// Severity Mapping
// ============================================================================

/**
 * Map rule severity level to VS Code diagnostic severity.
 */
export function mapSeverity(level: string): vscode.DiagnosticSeverity {
  switch (level) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ============================================================================
// Scan Scheduling
// ============================================================================

/**
 * Schedule a document scan with debouncing.
 * Multiple rapid changes will be coalesced into a single scan.
 */
export function scheduleScan(document: vscode.TextDocument, delay: number): void {
  const state = getState();

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
    if (state.debugMode) {
      state.outputChannel.appendLine(`[DEBUG] Skipping large file: ${document.fileName}`);
    }
    return;
  }

  const uri = document.uri.toString();

  // Clear existing timer for this document
  const existingTimer = state.debounceTimers.get(uri);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }

  // Schedule new scan
  const timer = setTimeout(() => {
    state.debounceTimers.delete(uri);
    runScan(document, false);
  }, delay);

  state.debounceTimers.set(uri, timer);
}

// ============================================================================
// Core Scanning
// ============================================================================

/**
 * Run a scan on a document.
 * This is the main entry point for document validation.
 */
export function runScan(document: vscode.TextDocument, force: boolean): void {
  const state = getState();

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
  const currentVersion = (state.scanVersions.get(uri) ?? 0) + 1;
  state.scanVersions.set(uri, currentVersion);

  // Update status bar to scanning state
  state.statusBarItem.text = '$(sync~spin) SENTRIFLOW';
  state.statusBarItem.backgroundColor = undefined;
  state.statusBarItem.tooltip = 'Scanning configuration...';

  try {
    const text = document.getText();

    // Quick exit for empty documents
    if (text.trim().length === 0) {
      state.diagnosticCollection.set(document.uri, []);
      updateStatusBarReady(state, 0, 0);
      return;
    }

    // Get configured vendor option
    const config = vscode.workspace.getConfiguration('sentriflow');
    const vendorSetting = config.get<string>('defaultVendor', 'auto');
    const vendorOption = vendorSetting === 'auto' ? 'auto' : vendorSetting;

    // Use incremental parser with document URI and version for caching
    const nodes = state.incrementalParser.parse(
      uri,
      text,
      document.version,
      vendorOption as any
    );

    // Get the vendor that was actually used
    const usedVendor = state.incrementalParser.getCachedVendor(uri);
    if (usedVendor) {
      state.currentVendor = usedVendor;
    }

    // Log incremental parsing stats in debug mode
    if (state.debugMode) {
      const parseStats = state.incrementalParser.getLastStats();
      if (parseStats) {
        if (!parseStats.fullParse) {
          state.outputChannel.appendLine(
            `[DEBUG] Incremental parse: ${parseStats.sectionsReparsed} sections reparsed in ${parseStats.parseTimeMs.toFixed(2)}ms (${parseStats.vendorId})`
          );
        } else {
          state.outputChannel.appendLine(
            `[DEBUG] Full parse in ${parseStats.parseTimeMs.toFixed(2)}ms (${parseStats.vendorId})`
          );
        }
      }
    }

    // Rebuild rule index when rules or vendor have changed
    const currentVendorId = state.currentVendor?.id ?? null;
    if (
      state.rulesVersion !== state.lastIndexedVersion ||
      currentVendorId !== state.lastIndexedVendorId
    ) {
      const rules = getAllRules(currentVendorId ?? undefined);
      state.engine.buildIndex(rules);
      state.lastIndexedVersion = state.rulesVersion;
      state.lastIndexedVendorId = currentVendorId;
      if (state.debugMode) {
        state.outputChannel.appendLine(
          `[DEBUG] Rule index rebuilt (version ${state.rulesVersion}, vendor: ${currentVendorId ?? 'all'}, ${rules.length} rules)`
        );
      }
    }

    // Run with pre-indexed rules
    const results = state.engine.run(nodes);

    // Check if this scan is still current (not superseded by newer scan)
    if (state.scanVersions.get(uri) !== currentVersion) {
      if (state.debugMode) {
        state.outputChannel.appendLine(`[DEBUG] Scan cancelled (superseded): ${document.fileName}`);
      }
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
          const rule = state.currentRuleMap.get(result.ruleId);
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

    // Final check before setting diagnostics
    if (state.scanVersions.get(uri) !== currentVersion) {
      return;
    }

    state.diagnosticCollection.set(document.uri, diagnostics);
    updateStatusBarReady(state, errorCount, warningCount);

    if (state.debugMode) {
      state.outputChannel.appendLine(
        `[DEBUG] Scanned ${document.fileName}: ${errorCount} errors, ${warningCount} warnings`
      );
    }
  } catch (e) {
    // Update status bar to error state
    state.statusBarItem.text = '$(error) SENTRIFLOW';
    state.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    state.statusBarItem.tooltip = 'Scan error - click to retry';

    if (state.debugMode) {
      state.outputChannel.appendLine(`[DEBUG] Scan error: ${e instanceof Error ? e.message : e}`);
    }
  }
}

/**
 * Helper to update status bar to ready state with counts.
 */
function updateStatusBarReady(
  state: ReturnType<typeof getState>,
  errors: number,
  warnings: number
): void {
  const disabledRulesCount = getDisabledRulesSet().size;

  const tooltip = new vscode.MarkdownString();
  tooltip.isTrusted = true;
  tooltip.supportThemeIcons = true;
  tooltip.appendMarkdown('**SentriFlow Compliance Validator**\n\n');

  if (errors > 0) {
    state.statusBarItem.text = `$(error) SENTRIFLOW: ${errors}`;
    state.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    tooltip.appendMarkdown(`$(error) **Errors:** ${errors}\n\n`);
    tooltip.appendMarkdown(`$(warning) **Warnings:** ${warnings}\n\n`);
  } else if (warnings > 0) {
    state.statusBarItem.text = `$(warning) SENTRIFLOW: ${warnings}`;
    state.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    tooltip.appendMarkdown(`$(warning) **Warnings:** ${warnings}\n\n`);
  } else {
    state.statusBarItem.text = '$(check) SENTRIFLOW';
    state.statusBarItem.backgroundColor = undefined;
    tooltip.appendMarkdown('$(check) **No issues found**\n\n');
  }

  if (disabledRulesCount > 0) {
    tooltip.appendMarkdown(`$(circle-slash) **Disabled Rules:** ${disabledRulesCount}\n\n`);
  }

  if (state.currentVendor) {
    tooltip.appendMarkdown(`$(server) **Vendor:** ${state.currentVendor.name}\n\n`);
  }

  tooltip.appendMarkdown('---\n\n');
  tooltip.appendMarkdown('[$(search) Scan](command:sentriflow.scan) · ');
  tooltip.appendMarkdown('[$(list-tree) Rules](command:sentriflow.focusRulesView) · ');
  tooltip.appendMarkdown('[$(circle-slash) Disabled](command:sentriflow.showDisabled)');

  state.statusBarItem.tooltip = tooltip;
}

// ============================================================================
// Rescan Utilities
// ============================================================================

/**
 * Re-scan all open config documents after rule changes.
 */
export function rescanActiveEditor(): void {
  const state = getState();

  // Increment rules version to trigger index rebuild
  state.rulesVersion++;

  // Rescan all open documents with supported languages
  for (const doc of vscode.workspace.textDocuments) {
    if (SUPPORTED_LANGUAGES.includes(doc.languageId)) {
      scheduleScan(doc, 0);
    }
  }
}
