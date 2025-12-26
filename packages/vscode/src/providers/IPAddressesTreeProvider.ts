import * as vscode from 'vscode';
import { extractIPSummary, type IPSummary } from '@sentriflow/core';

/**
 * Tree item types for IP addresses hierarchy
 */
export type IPTreeItemType = 'category' | 'ip' | 'subnet' | 'empty';

/**
 * Category identifiers for copy operations
 */
export type IPCategory = 'ipv4-addresses' | 'ipv6-addresses' | 'ipv4-subnets' | 'ipv6-subnets';

/**
 * Tree item for IP addresses view
 */
export class IPTreeItem extends vscode.TreeItem {
  constructor(
    public override readonly label: string,
    public override readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: IPTreeItemType,
    public readonly ipValue?: string,
    public readonly categoryId?: IPCategory,
    public readonly line?: number
  ) {
    super(label, collapsibleState);
    this.updateAppearance();
  }

  private updateAppearance(): void {
    switch (this.itemType) {
      case 'category':
        this.contextValue = `ip-category-${this.categoryId}`;
        // Set icon based on category
        if (this.categoryId === 'ipv4-addresses') {
          this.iconPath = new vscode.ThemeIcon('globe', new vscode.ThemeColor('charts.blue'));
        } else if (this.categoryId === 'ipv6-addresses') {
          this.iconPath = new vscode.ThemeIcon('globe', new vscode.ThemeColor('charts.purple'));
        } else if (this.categoryId === 'ipv4-subnets') {
          this.iconPath = new vscode.ThemeIcon('type-hierarchy-sub', new vscode.ThemeColor('charts.green'));
        } else if (this.categoryId === 'ipv6-subnets') {
          this.iconPath = new vscode.ThemeIcon('type-hierarchy-sub', new vscode.ThemeColor('charts.orange'));
        }
        break;

      case 'ip':
        this.iconPath = new vscode.ThemeIcon('symbol-numeric');
        this.contextValue = 'ip-address';
        this.tooltip = `IP Address: ${this.ipValue}`;
        // Make clickable to copy
        this.command = {
          command: 'sentriflow.copyIPValue',
          title: 'Copy IP Address',
          arguments: [this.ipValue],
        };
        break;

      case 'subnet':
        this.iconPath = new vscode.ThemeIcon('symbol-class');
        this.contextValue = 'ip-subnet';
        this.tooltip = `Subnet: ${this.ipValue}`;
        // Make clickable to copy
        this.command = {
          command: 'sentriflow.copyIPValue',
          title: 'Copy Subnet',
          arguments: [this.ipValue],
        };
        break;

      case 'empty':
        this.iconPath = new vscode.ThemeIcon('info');
        this.contextValue = 'ip-empty';
        break;
    }
  }
}

/**
 * TreeDataProvider for IP addresses extracted from the active document
 */
export class IPAddressesTreeProvider implements vscode.TreeDataProvider<IPTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<IPTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private currentSummary: IPSummary | undefined;
  private currentFileName: string = '';

  constructor() {}

  /**
   * Update the IP summary from document content
   */
  updateFromDocument(document: vscode.TextDocument | undefined): void {
    if (!document) {
      this.currentSummary = undefined;
      this.currentFileName = '';
    } else {
      const content = document.getText();
      // Include subnet network addresses in the addresses lists
      this.currentSummary = extractIPSummary(content, { includeSubnetNetworks: true });
      this.currentFileName = document.fileName.split(/[/\\]/).pop() || 'Unknown';
    }
    this.refresh();
  }

  /**
   * Refresh the tree
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Get all IPs as a formatted string for clipboard
   */
  getAllIPsForClipboard(): string {
    if (!this.currentSummary) return '';

    const lines: string[] = [];

    if (this.currentSummary.ipv4Addresses.length > 0) {
      lines.push(...this.currentSummary.ipv4Addresses);
    }
    if (this.currentSummary.ipv6Addresses.length > 0) {
      lines.push(...this.currentSummary.ipv6Addresses);
    }
    if (this.currentSummary.ipv4Subnets.length > 0) {
      lines.push(...this.currentSummary.ipv4Subnets);
    }
    if (this.currentSummary.ipv6Subnets.length > 0) {
      lines.push(...this.currentSummary.ipv6Subnets);
    }

    return lines.join('\n');
  }

  /**
   * Get IPs from a specific category for clipboard
   */
  getCategoryIPsForClipboard(category: IPCategory): string {
    if (!this.currentSummary) return '';

    switch (category) {
      case 'ipv4-addresses':
        return this.currentSummary.ipv4Addresses.join('\n');
      case 'ipv6-addresses':
        return this.currentSummary.ipv6Addresses.join('\n');
      case 'ipv4-subnets':
        return this.currentSummary.ipv4Subnets.join('\n');
      case 'ipv6-subnets':
        return this.currentSummary.ipv6Subnets.join('\n');
      default:
        return '';
    }
  }

  /**
   * Get count for a specific category
   */
  getCategoryCount(category: IPCategory): number {
    if (!this.currentSummary) return 0;

    switch (category) {
      case 'ipv4-addresses':
        return this.currentSummary.ipv4Addresses.length;
      case 'ipv6-addresses':
        return this.currentSummary.ipv6Addresses.length;
      case 'ipv4-subnets':
        return this.currentSummary.ipv4Subnets.length;
      case 'ipv6-subnets':
        return this.currentSummary.ipv6Subnets.length;
      default:
        return 0;
    }
  }

  /**
   * Get current counts
   */
  getCounts(): { total: number; ipv4: number; ipv6: number; subnets: number } {
    if (!this.currentSummary) {
      return { total: 0, ipv4: 0, ipv6: 0, subnets: 0 };
    }
    return {
      total: this.currentSummary.counts.total,
      ipv4: this.currentSummary.counts.ipv4,
      ipv6: this.currentSummary.counts.ipv6,
      subnets: this.currentSummary.counts.ipv4Subnets + this.currentSummary.counts.ipv6Subnets,
    };
  }

  getTreeItem(element: IPTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: IPTreeItem): IPTreeItem[] {
    if (!this.currentSummary) {
      return [new IPTreeItem(
        'Open a file to extract IP addresses',
        vscode.TreeItemCollapsibleState.None,
        'empty'
      )];
    }

    if (this.currentSummary.counts.total === 0) {
      return [new IPTreeItem(
        'No IP addresses found',
        vscode.TreeItemCollapsibleState.None,
        'empty'
      )];
    }

    if (!element) {
      // Root level - show categories
      return this.getCategoryNodes();
    }

    // Category level - show IPs or subnets
    return this.getIPNodes(element.categoryId);
  }

  private getCategoryNodes(): IPTreeItem[] {
    // T022/T023: Add null check guard and remove non-null assertion
    if (!this.currentSummary) {
      return [];
    }
    const items: IPTreeItem[] = [];
    const summary = this.currentSummary;

    if (summary.ipv4Addresses.length > 0) {
      items.push(new IPTreeItem(
        `IPv4 Addresses (${summary.ipv4Addresses.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        undefined,
        'ipv4-addresses'
      ));
    }

    if (summary.ipv6Addresses.length > 0) {
      items.push(new IPTreeItem(
        `IPv6 Addresses (${summary.ipv6Addresses.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        undefined,
        'ipv6-addresses'
      ));
    }

    if (summary.ipv4Subnets.length > 0) {
      items.push(new IPTreeItem(
        `IPv4 Subnets (${summary.ipv4Subnets.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        undefined,
        'ipv4-subnets'
      ));
    }

    if (summary.ipv6Subnets.length > 0) {
      items.push(new IPTreeItem(
        `IPv6 Subnets (${summary.ipv6Subnets.length})`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        undefined,
        'ipv6-subnets'
      ));
    }

    return items;
  }

  private getIPNodes(categoryId: IPCategory | undefined): IPTreeItem[] {
    // T024/T025/T026: Add null checks and remove non-null assertion
    if (!categoryId || !this.currentSummary) {
      return [];
    }
    const summary = this.currentSummary;

    switch (categoryId) {
      case 'ipv4-addresses':
        return summary.ipv4Addresses.map(ip =>
          new IPTreeItem(ip, vscode.TreeItemCollapsibleState.None, 'ip', ip)
        );
      case 'ipv6-addresses':
        return summary.ipv6Addresses.map(ip =>
          new IPTreeItem(ip, vscode.TreeItemCollapsibleState.None, 'ip', ip)
        );
      case 'ipv4-subnets':
        return summary.ipv4Subnets.map(subnet =>
          new IPTreeItem(subnet, vscode.TreeItemCollapsibleState.None, 'subnet', subnet)
        );
      case 'ipv6-subnets':
        return summary.ipv6Subnets.map(subnet =>
          new IPTreeItem(subnet, vscode.TreeItemCollapsibleState.None, 'subnet', subnet)
        );
      default:
        return [];
    }
  }
}
