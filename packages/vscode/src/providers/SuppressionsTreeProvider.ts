/**
 * Suppressions Tree Provider
 *
 * TreeDataProvider for displaying and managing diagnostic suppressions.
 * Shows a hierarchical view: File → Suppression items
 */

import * as vscode from 'vscode';
import type { Suppression, SuppressionManager } from '../services/suppressionManager';

// ============================================================================
// Tree Item Class
// ============================================================================

/**
 * Tree item for suppressions display.
 */
class SuppressionTreeItem extends vscode.TreeItem {
  public readonly children?: SuppressionTreeItem[];

  constructor(
    itemId: string,
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    contextValue: string,
    description?: string,
    icon?: vscode.ThemeIcon,
    children?: SuppressionTreeItem[],
    command?: vscode.Command,
    public readonly suppression?: Suppression,
    public readonly filePath?: string
  ) {
    super(label, collapsibleState);
    this.id = itemId;
    this.description = description;
    this.iconPath = icon;
    this.contextValue = contextValue;
    this.children = children;
    if (command) {
      this.command = command;
    }
  }
}

// ============================================================================
// Tree Provider Class
// ============================================================================

/**
 * Provides tree data for suppressions display.
 *
 * Structure:
 * - File nodes (collapsible) with context "suppressionFile"
 *   - Suppression items (leaf) with context "suppression"
 */
export class SuppressionsTreeProvider
  implements vscode.TreeDataProvider<SuppressionTreeItem>, vscode.Disposable
{
  private _onDidChangeTreeData = new vscode.EventEmitter<SuppressionTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private _suppressionManager: SuppressionManager | undefined;
  private _managerSubscription: vscode.Disposable | undefined;

  /**
   * Set the suppression manager and subscribe to changes.
   */
  setSuppressionManager(manager: SuppressionManager): void {
    // Dispose existing subscription to prevent memory leaks
    this._managerSubscription?.dispose();

    this._suppressionManager = manager;
    this._managerSubscription = manager.onDidChange(() => this.refresh());
  }

  /**
   * Dispose of resources.
   */
  dispose(): void {
    this._managerSubscription?.dispose();
    this._onDidChangeTreeData.dispose();
  }

  /**
   * Refresh the tree view.
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: SuppressionTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: SuppressionTreeItem): SuppressionTreeItem[] {
    if (!this._suppressionManager) {
      return [];
    }

    // If element provided, return its children
    if (element) {
      return element.children || [];
    }

    // Root level - group by file
    const allSuppressions = this._suppressionManager.getAllSuppressions();

    if (allSuppressions.size === 0) {
      return [
        new SuppressionTreeItem(
          'no-suppressions',
          'No Suppressions',
          vscode.TreeItemCollapsibleState.None,
          'no-suppressions',
          'All diagnostics visible',
          new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
        ),
      ];
    }

    const items: SuppressionTreeItem[] = [];

    // Sort files alphabetically
    const sortedFiles = Array.from(allSuppressions.keys()).sort();

    for (const filePath of sortedFiles) {
      const suppressions = allSuppressions.get(filePath) || [];

      // Create child items for each suppression
      const children = suppressions.map((s, index) =>
        this.createSuppressionItem(s, filePath, index)
      );

      // Get filename for display
      const fileName = filePath.split('/').pop() || filePath;

      // File node
      items.push(
        new SuppressionTreeItem(
          `file-${filePath}`,
          fileName,
          vscode.TreeItemCollapsibleState.Expanded,
          'suppressionFile',
          `${suppressions.length}`,
          new vscode.ThemeIcon('file'),
          children,
          undefined,
          undefined,
          filePath
        )
      );
    }

    return items;
  }

  /**
   * Create a tree item for a single suppression.
   */
  private createSuppressionItem(
    suppression: Suppression,
    filePath: string,
    index: number
  ): SuppressionTreeItem {
    const isFileSuppression = suppression.type === 'file';

    // Build label: Rule ID
    const label = suppression.ruleId;

    // Build description based on type
    let description: string;
    if (isFileSuppression) {
      description = 'entire file';
    } else {
      description = suppression.lineText || 'line suppression';
    }

    // Icon based on type
    const icon = isFileSuppression
      ? new vscode.ThemeIcon('file-code', new vscode.ThemeColor('foreground'))
      : new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('foreground'));

    // Tooltip with full details
    const tooltip = new vscode.MarkdownString();
    tooltip.appendMarkdown(`**Rule:** \`${suppression.ruleId}\`\n\n`);
    tooltip.appendMarkdown(`**Type:** ${isFileSuppression ? 'File' : 'Line'}\n\n`);
    if (suppression.lineText) {
      tooltip.appendMarkdown(`**Content:** \`${suppression.lineText}\`\n\n`);
    }
    tooltip.appendMarkdown(`**Added:** ${new Date(suppression.timestamp).toLocaleString()}`);

    const item = new SuppressionTreeItem(
      `suppression-${filePath}-${index}-${suppression.ruleId}-${suppression.contentHash || 'file'}`,
      label,
      vscode.TreeItemCollapsibleState.None,
      'suppression',
      description,
      icon,
      undefined,
      undefined,
      suppression
    );

    item.tooltip = tooltip;

    return item;
  }
}
