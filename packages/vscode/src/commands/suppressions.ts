/**
 * Suppression Commands
 *
 * Commands for managing diagnostic suppressions.
 * Includes commands for suppressing occurrences, file-level suppressions,
 * and removing/clearing suppressions.
 */

import * as vscode from 'vscode';
import { getState } from '../state/context';
import { runScan } from '../services/scanner';
import type { Suppression } from '../services/suppressionManager';

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
// Suppress Commands (US1 & US2)
// ============================================================================

/**
 * Arguments passed to suppress commands via command links.
 */
interface SuppressCommandArgs {
  ruleId: string;
  filePath: string;
  lineNumber: number;
}

/**
 * Command: Suppress a specific diagnostic occurrence on a line.
 * Called from hover tooltip or code action.
 */
export async function cmdSuppressOccurrence(args: SuppressCommandArgs): Promise<void> {
  const state = getState();
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    vscode.window.showErrorMessage('SENTRIFLOW: No active editor');
    return;
  }

  // Verify the active editor matches the expected file to prevent race conditions
  const currentFilePath = vscode.workspace.asRelativePath(editor.document.uri);
  if (currentFilePath !== args.filePath) {
    vscode.window.showErrorMessage('SENTRIFLOW: File has changed, please try again');
    return;
  }

  try {
    const result = await state.suppressionManager.suppressLine(
      editor.document,
      args.lineNumber,
      args.ruleId
    );

    if (result.success) {
      log(`Suppressed ${args.ruleId} at line ${args.lineNumber + 1}`);
      // Close the hover popup so it refreshes with updated diagnostics
      vscode.commands.executeCommand('editor.action.hideHover');
      // Trigger rescan to update diagnostics immediately
      runScan(editor.document, true);
    } else {
      vscode.window.showWarningMessage(
        `SENTRIFLOW: ${result.error || 'Failed to suppress occurrence'}`
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`SENTRIFLOW: Failed to suppress - ${message}`);
    log(`Error suppressing occurrence: ${message}`);
  }
}

/**
 * Command: Suppress all occurrences of a rule in the current file.
 * Called from hover tooltip or code action.
 */
export async function cmdSuppressRuleInFile(args: { ruleId: string; filePath: string }): Promise<void> {
  const state = getState();
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    vscode.window.showErrorMessage('SENTRIFLOW: No active editor');
    return;
  }

  // Verify the active editor matches the expected file to prevent race conditions
  const currentFilePath = vscode.workspace.asRelativePath(editor.document.uri);
  if (currentFilePath !== args.filePath) {
    vscode.window.showErrorMessage('SENTRIFLOW: File has changed, please try again');
    return;
  }

  try {
    const result = await state.suppressionManager.suppressFile(
      editor.document,
      args.ruleId
    );

    if (result.success) {
      log(`Suppressed ${args.ruleId} in file ${editor.document.fileName}`);
      // Close the hover popup so it refreshes with updated diagnostics
      vscode.commands.executeCommand('editor.action.hideHover');
      // Trigger rescan to update diagnostics immediately
      runScan(editor.document, true);
    } else {
      vscode.window.showWarningMessage(
        `SENTRIFLOW: ${result.error || 'Failed to suppress rule in file'}`
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`SENTRIFLOW: Failed to suppress - ${message}`);
    log(`Error suppressing rule in file: ${message}`);
  }
}

// ============================================================================
// Remove Commands (US3)
// ============================================================================

/**
 * Tree item interface for type checking.
 * Matches the SuppressionTreeItem class from SuppressionsTreeProvider.
 */
interface SuppressionTreeItem {
  suppression?: Suppression;
  filePath?: string;
}

/**
 * Command: Remove a specific suppression.
 * Called from TreeView inline action. Receives a SuppressionTreeItem.
 */
export async function cmdRemoveSuppression(item: SuppressionTreeItem): Promise<void> {
  const state = getState();

  // Extract suppression from tree item
  const suppression = item.suppression;
  if (!suppression) {
    vscode.window.showErrorMessage('SENTRIFLOW: Invalid suppression item');
    return;
  }

  try {
    const removed = await state.suppressionManager.removeSuppression(suppression);

    if (removed) {
      log(`Removed suppression: ${suppression.ruleId} in ${suppression.filePath}`);

      // Trigger rescan for the affected file
      await rescanFileByPath(suppression.filePath);
    } else {
      vscode.window.showWarningMessage('SENTRIFLOW: Suppression not found');
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`SENTRIFLOW: Failed to remove suppression - ${message}`);
    log(`Error removing suppression: ${message}`);
  }
}

/**
 * Command: Clear all suppressions for a file.
 * Called from TreeView inline action on file node. Receives a SuppressionTreeItem.
 */
export async function cmdClearFileSuppressions(item: SuppressionTreeItem): Promise<void> {
  const state = getState();

  // Extract filePath from tree item
  const filePath = item.filePath;
  if (!filePath) {
    vscode.window.showErrorMessage('SENTRIFLOW: Invalid file item');
    return;
  }

  try {
    const count = await state.suppressionManager.clearFileSuppressions(filePath);

    if (count > 0) {
      log(`Cleared ${count} suppression(s) from ${filePath}`);
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Removed ${count} suppression${count !== 1 ? 's' : ''} from file`
      );

      // Trigger rescan for the affected file
      await rescanFileByPath(filePath);
    } else {
      vscode.window.showInformationMessage('SENTRIFLOW: No suppressions to clear in this file');
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`SENTRIFLOW: Failed to clear suppressions - ${message}`);
    log(`Error clearing file suppressions: ${message}`);
  }
}

/**
 * Command: Clear all suppressions in the workspace.
 * Called from TreeView title action.
 */
export async function cmdClearAllSuppressions(): Promise<void> {
  const state = getState();

  // Confirm before clearing all
  const totalCount = state.suppressionManager.getSuppressionCount();
  if (totalCount === 0) {
    vscode.window.showInformationMessage('SENTRIFLOW: No suppressions to clear');
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    `Clear all ${totalCount} suppression${totalCount !== 1 ? 's' : ''}?`,
    { modal: true },
    'Clear All'
  );

  if (confirm !== 'Clear All') {
    return;
  }

  try {
    // Get all affected files before clearing
    const allSuppressions = state.suppressionManager.getAllSuppressions();
    const affectedFiles = Array.from(allSuppressions.keys());

    const count = await state.suppressionManager.clearAllSuppressions();

    if (count > 0) {
      log(`Cleared all ${count} suppression(s)`);
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Removed all ${count} suppression${count !== 1 ? 's' : ''}`
      );

      // Trigger rescan for all affected files
      for (const filePath of affectedFiles) {
        await rescanFileByPath(filePath);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(`SENTRIFLOW: Failed to clear suppressions - ${message}`);
    log(`Error clearing all suppressions: ${message}`);
  }
}

/**
 * Command: Focus the Suppressions TreeView.
 */
export function cmdFocusSuppressionsView(): void {
  vscode.commands.executeCommand('sentriflowSuppressions.focus');
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Find and rescan a file by its relative path.
 */
async function rescanFileByPath(filePath: string): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    return;
  }

  // Try to find and rescan the document
  for (const folder of workspaceFolders) {
    const uri = vscode.Uri.joinPath(folder.uri, filePath);

    // Check if document is open
    const openDoc = vscode.workspace.textDocuments.find(
      (doc) => doc.uri.toString() === uri.toString()
    );

    if (openDoc) {
      runScan(openDoc, true);
      return;
    }
  }

  // Document not open - clear diagnostics for the file
  // The diagnostics will be recalculated when the file is opened
  for (const folder of workspaceFolders) {
    const uri = vscode.Uri.joinPath(folder.uri, filePath);
    const state = getState();
    state.diagnosticCollection.delete(uri);
  }
}
