/**
 * Status Bar Module
 *
 * Manages the SentriFlow status bar items showing scan status and vendor info.
 * Updates visual indicators based on diagnostic results and configuration.
 */

import * as vscode from 'vscode';
import { getState } from '../state/context';
import { getDisabledRulesSet } from '../services/ruleManager';

// ============================================================================
// Configuration Helpers
// ============================================================================

/**
 * Check if vendor should be shown in status bar based on configuration.
 */
function shouldShowVendorInStatusBar(): boolean {
  const config = vscode.workspace.getConfiguration('sentriflow');
  return config.get<boolean>('showVendorInStatusBar', true);
}

// ============================================================================
// Status Bar Updates
// ============================================================================

/**
 * Update the main status bar item based on scan state.
 *
 * @param statusState - Current status: 'ready', 'scanning', or 'error'
 * @param errors - Number of error diagnostics (for ready state)
 * @param warnings - Number of warning diagnostics (for ready state)
 */
export function updateStatusBar(
  statusState: 'ready' | 'scanning' | 'error',
  errors = 0,
  warnings = 0
): void {
  const state = getState();
  const { statusBarItem, currentVendor } = state;

  // Count disabled items for tooltip
  const disabledRulesCount = getDisabledRulesSet().size;

  switch (statusState) {
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

      // Add suppression count if any
      const suppressionCount = state.suppressionManager.getSuppressionCount();
      if (suppressionCount > 0) {
        tooltip.appendMarkdown(
          `$(eye-closed) **Suppressions:** ${suppressionCount}\n\n`
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
        '[$(eye-closed) Suppressions](command:sentriflow.focusSuppressionsView) · '
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

/**
 * Update the vendor status bar item.
 * Shows current vendor and detection mode.
 */
export function updateVendorStatusBar(): void {
  const state = getState();
  const { vendorStatusBarItem, currentVendor, documentVendorOverrides } = state;

  if (!shouldShowVendorInStatusBar()) {
    vendorStatusBarItem.hide();
    return;
  }

  vendorStatusBarItem.show();

  // Check for per-document override on active editor
  const activeEditor = vscode.window.activeTextEditor;
  const uri = activeEditor?.document.uri.toString();
  const hasOverride = uri ? documentVendorOverrides.has(uri) : false;

  // Build rich markdown tooltip
  const tooltip = new vscode.MarkdownString();
  tooltip.isTrusted = true;
  tooltip.supportThemeIcons = true;

  if (hasOverride) {
    // Per-document override is active
    const vendorName = currentVendor?.name ?? 'Unknown';
    vendorStatusBarItem.text = `$(server) ${vendorName} (override)`;
    tooltip.appendMarkdown(`**Vendor:** ${vendorName}\n\n`);
    tooltip.appendMarkdown('$(pin) *Override set for this file*\n\n');
  } else {
    const config = vscode.workspace.getConfiguration('sentriflow');
    const vendorSetting = config.get<string>('defaultVendor', 'auto');

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
      // Global manual vendor selection
      const vendorName = currentVendor?.name ?? vendorSetting;
      vendorStatusBarItem.text = `$(server) ${vendorName}`;
      tooltip.appendMarkdown(`**Vendor:** ${vendorName}\n\n`);
      tooltip.appendMarkdown('$(gear) *Globally configured*\n\n');
    }
  }

  tooltip.appendMarkdown('---\n\n');
  tooltip.appendMarkdown(
    '[$(server) Change Vendor](command:sentriflow.selectVendor)'
  );

  vendorStatusBarItem.tooltip = tooltip;
}

// ============================================================================
// Status Bar Creation
// ============================================================================

/**
 * Create and configure the main status bar item.
 * @returns The configured status bar item
 */
export function createStatusBarItem(): vscode.StatusBarItem {
  const statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = 'sentriflow.scan';
  statusBarItem.tooltip = 'Click to scan current file';
  statusBarItem.show();
  return statusBarItem;
}

/**
 * Create and configure the vendor status bar item.
 * @returns The configured vendor status bar item
 */
export function createVendorStatusBarItem(): vscode.StatusBarItem {
  const vendorStatusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    99
  );
  vendorStatusBarItem.command = 'sentriflow.selectVendor';
  vendorStatusBarItem.tooltip = 'Click to change vendor';
  vendorStatusBarItem.show();
  return vendorStatusBarItem;
}
