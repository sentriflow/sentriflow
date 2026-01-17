import * as vscode from 'vscode';
import type { IRule } from '@sentriflow/core';

/**
 * Hover provider for SentriFlow diagnostics.
 * Shows category, tags, description, and remediation when hovering over violations.
 * Handles multiple stacked diagnostics at the same position.
 */
export class SentriFlowHoverProvider implements vscode.HoverProvider {
  constructor(
    private diagnosticCollection: vscode.DiagnosticCollection,
    private getRuleById: (id: string) => IRule | undefined
  ) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken
  ): vscode.Hover | undefined {
    // Find ALL diagnostics at this position (not just the first one)
    const allDiagnostics = this.diagnosticCollection.get(document.uri) ?? [];
    const diagnosticsAtPosition = allDiagnostics.filter((d) => d.range.contains(position));

    if (diagnosticsAtPosition.length === 0) {
      return undefined;
    }

    // Build markdown content for all diagnostics
    // SEC-001: Enable isTrusted for command links (suppression commands)
    // Rule metadata is trusted internal content
    const markdown = new vscode.MarkdownString();
    markdown.isTrusted = true;
    markdown.supportThemeIcons = true;

    // Track the union range of all diagnostics
    // Safe access since we checked length > 0 above
    const firstDiagnostic = diagnosticsAtPosition[0]!;
    let unionRange = firstDiagnostic.range;

    for (let i = 0; i < diagnosticsAtPosition.length; i++) {
      const diagnostic = diagnosticsAtPosition[i]!;
      const ruleId = typeof diagnostic.code === 'string' ? diagnostic.code : undefined;

      // Update union range
      unionRange = unionRange.union(diagnostic.range);

      if (!ruleId) {
        continue;
      }

      const rule = this.getRuleById(ruleId);
      if (!rule) {
        continue;
      }

      // Add separator between multiple diagnostics
      if (i > 0) {
        markdown.appendMarkdown('\n\n---\n\n');
      }

      // Title with severity icon
      const severityIcon = this.getSeverityIcon(diagnostic.severity);
      markdown.appendMarkdown(`## ${severityIcon} ${rule.id}\n\n`);

      // Category
      const category = this.formatCategory(rule);
      markdown.appendMarkdown(`**Category:** \`${category}\`\n\n`);

      // Tags
      if (rule.metadata.tags && rule.metadata.tags.length > 0) {
        markdown.appendMarkdown(`**Tags:**\n`);
        for (const tag of rule.metadata.tags) {
          const text = tag.text ? ` *(${tag.text})*` : '';
          const score = tag.score !== undefined ? ` [${tag.score}/10]` : '';
          markdown.appendMarkdown(`- \`${tag.type}\`: **${tag.label}**${text}${score}\n`);
        }
        markdown.appendMarkdown('\n');
      }

      // Description
      if (rule.metadata.description) {
        markdown.appendMarkdown(`${rule.metadata.description}\n\n`);
      }

      // Remediation
      if (rule.metadata.remediation) {
        markdown.appendMarkdown(`**Remediation:** ${rule.metadata.remediation}\n`);
      }

      // Owner info
      if (rule.metadata.obu || rule.metadata.owner) {
        markdown.appendMarkdown(`\n*OBU: ${rule.metadata.obu}*`);
        if (rule.metadata.owner) {
          markdown.appendMarkdown(` | *Owner: ${rule.metadata.owner}*`);
        }
      }

      // Suppression actions
      const lineNumber = diagnostic.range.start.line;
      const filePath = vscode.workspace.asRelativePath(document.uri, false);
      const suppressArgs = encodeURIComponent(
        JSON.stringify({ ruleId, filePath, lineNumber })
      );
      const suppressFileArgs = encodeURIComponent(JSON.stringify({ ruleId, filePath }));

      markdown.appendMarkdown('\n\n---\n');
      markdown.appendMarkdown(
        `[$(circle-slash) Suppress this occurrence](command:sentriflow.suppressOccurrence?${suppressArgs}) · `
      );
      markdown.appendMarkdown(
        `[$(file-code) Suppress in file](command:sentriflow.suppressRuleInFile?${suppressFileArgs})`
      );
    }

    return new vscode.Hover(markdown, unionRange);
  }

  private formatCategory(rule: IRule): string {
    if (!rule.category) return 'general';
    return Array.isArray(rule.category) ? rule.category.join(', ') : rule.category;
  }

  private getSeverityIcon(severity: vscode.DiagnosticSeverity | undefined): string {
    switch (severity) {
      case vscode.DiagnosticSeverity.Error:
        return '🔴';
      case vscode.DiagnosticSeverity.Warning:
        return '🟡';
      case vscode.DiagnosticSeverity.Information:
        return '🔵';
      case vscode.DiagnosticSeverity.Hint:
        return '💡';
      default:
        return '⚪';
    }
  }
}
