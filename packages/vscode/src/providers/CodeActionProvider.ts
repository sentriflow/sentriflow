/**
 * SentriFlow Code Action Provider
 *
 * Provides quick fix actions for SentriFlow diagnostics.
 * Allows users to suppress diagnostics via the quick fix menu (Cmd+. / Ctrl+.).
 */

import * as vscode from 'vscode';

/**
 * Code action provider for SentriFlow diagnostics.
 * Offers suppression options in the quick fix menu.
 */
export class SentriFlowCodeActionProvider implements vscode.CodeActionProvider {
  /**
   * Supported code action kinds.
   */
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  /**
   * Provide code actions for SentriFlow diagnostics.
   */
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      // Only process SentriFlow diagnostics
      if (diagnostic.source !== 'SentriFlow') {
        continue;
      }

      const ruleId = typeof diagnostic.code === 'string' ? diagnostic.code : undefined;
      if (!ruleId) {
        continue;
      }

      // Action 1: Suppress this occurrence (line-level)
      const suppressLine = new vscode.CodeAction(
        `Suppress ${ruleId} on this line`,
        vscode.CodeActionKind.QuickFix
      );
      suppressLine.command = {
        command: 'sentriflow.suppressOccurrence',
        title: 'Suppress Occurrence',
        arguments: [
          {
            ruleId,
            filePath: vscode.workspace.asRelativePath(document.uri, false),
            lineNumber: diagnostic.range.start.line,
          },
        ],
      };
      suppressLine.diagnostics = [diagnostic];
      actions.push(suppressLine);

      // Action 2: Suppress in this file (file-level)
      const suppressFile = new vscode.CodeAction(
        `Suppress ${ruleId} in this file`,
        vscode.CodeActionKind.QuickFix
      );
      suppressFile.command = {
        command: 'sentriflow.suppressRuleInFile',
        title: 'Suppress in File',
        arguments: [{ ruleId, filePath: vscode.workspace.asRelativePath(document.uri, false) }],
      };
      suppressFile.diagnostics = [diagnostic];
      actions.push(suppressFile);

      // Action 3: Disable rule globally (links to existing feature)
      const disableGlobally = new vscode.CodeAction(
        `Disable ${ruleId} globally`,
        vscode.CodeActionKind.QuickFix
      );
      disableGlobally.command = {
        command: 'sentriflow.disableRuleById',
        title: 'Disable Rule Globally',
        arguments: [ruleId],
      };
      disableGlobally.diagnostics = [diagnostic];
      disableGlobally.isPreferred = false; // Not the preferred action
      actions.push(disableGlobally);
    }

    return actions;
  }
}
