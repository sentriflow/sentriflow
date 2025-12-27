import * as vscode from 'vscode';
import type { LicenseInfo, EncryptedPackInfo } from '../encryption/types';

/**
 * Tree item for license information display
 */
class LicenseTreeItem extends vscode.TreeItem {
  constructor(
    public readonly itemId: string,
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue: string,
    public readonly description?: string,
    public readonly icon?: vscode.ThemeIcon,
    public readonly children?: LicenseTreeItem[],
    public readonly command?: vscode.Command
  ) {
    super(label, collapsibleState);
    this.id = itemId; // Unique ID to prevent tree refresh errors
    this.description = description;
    this.iconPath = icon;
    this.contextValue = contextValue;
    if (command) {
      this.command = command;
    }
  }
}

/**
 * Provides tree data for license status display
 */
export class LicenseTreeProvider implements vscode.TreeDataProvider<LicenseTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<LicenseTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private licenseInfo: LicenseInfo | null = null;
  private encryptedPacks: EncryptedPackInfo[] = [];
  private hasLicenseKey = false;

  /**
   * Update the license info and refresh tree
   */
  setLicenseInfo(info: LicenseInfo | null, hasKey: boolean): void {
    this.licenseInfo = info;
    this.hasLicenseKey = hasKey;
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Update encrypted packs info and refresh tree
   */
  setEncryptedPacks(packs: EncryptedPackInfo[]): void {
    this.encryptedPacks = packs;
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Refresh the tree view
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: LicenseTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: LicenseTreeItem): LicenseTreeItem[] {
    if (element) {
      return element.children || [];
    }

    // Root level
    if (!this.hasLicenseKey) {
      return [
        new LicenseTreeItem(
          'no-license-key',
          'No License Key',
          vscode.TreeItemCollapsibleState.None,
          'no-license',
          'Click to enter',
          new vscode.ThemeIcon('key'),
          undefined,
          {
            command: 'sentriflow.enterLicenseKey',
            title: 'Enter License Key',
          }
        ),
      ];
    }

    if (!this.licenseInfo) {
      return [
        new LicenseTreeItem(
          'invalid-license',
          'Invalid License',
          vscode.TreeItemCollapsibleState.None,
          'invalid-license',
          'Click to re-enter',
          new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
          undefined,
          {
            command: 'sentriflow.enterLicenseKey',
            title: 'Enter License Key',
          }
        ),
      ];
    }

    const items: LicenseTreeItem[] = [];

    // Status section
    const statusIcon = this.licenseInfo.isExpired
      ? new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'))
      : this.licenseInfo.daysUntilExpiry <= 14
        ? new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'))
        : new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));

    const statusLabel = this.licenseInfo.isExpired
      ? 'Expired'
      : this.licenseInfo.daysUntilExpiry <= 14
        ? `Expires in ${this.licenseInfo.daysUntilExpiry} days`
        : 'Active';

    items.push(
      new LicenseTreeItem(
        'license-status',
        'Status',
        vscode.TreeItemCollapsibleState.None,
        'license-status',
        statusLabel,
        statusIcon
      )
    );

    // Tier
    const tierIcon = this.licenseInfo.payload.tier === 'enterprise'
      ? new vscode.ThemeIcon('star-full')
      : this.licenseInfo.payload.tier === 'professional'
        ? new vscode.ThemeIcon('star-half')
        : new vscode.ThemeIcon('star-empty');

    items.push(
      new LicenseTreeItem(
        'license-tier',
        'Tier',
        vscode.TreeItemCollapsibleState.None,
        'license-tier',
        this.licenseInfo.payload.tier.charAt(0).toUpperCase() + this.licenseInfo.payload.tier.slice(1),
        tierIcon
      )
    );

    // Expiry date
    items.push(
      new LicenseTreeItem(
        'license-expiry',
        'Expires',
        vscode.TreeItemCollapsibleState.None,
        'license-expiry',
        this.licenseInfo.expiryDate,
        new vscode.ThemeIcon('calendar')
      )
    );

    // Customer (if name available)
    if (this.licenseInfo.payload.name) {
      items.push(
        new LicenseTreeItem(
          'license-customer',
          'Customer',
          vscode.TreeItemCollapsibleState.None,
          'license-customer',
          this.licenseInfo.payload.name,
          new vscode.ThemeIcon('account')
        )
      );
    }

    // Entitled feeds section
    if (this.licenseInfo.payload.feeds.length > 0) {
      const feedChildren = this.licenseInfo.payload.feeds.map((feedId, index) => {
        const pack = this.encryptedPacks.find((p) => p.feedId === feedId);
        const loadedIcon = pack?.loaded
          ? new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon('circle-outline');
        const description = pack
          ? pack.loaded
            ? `${pack.ruleCount} rules`
            : pack.error || 'Not loaded'
          : 'Not installed';

        return new LicenseTreeItem(
          `feed-${index}-${feedId}`,
          feedId,
          vscode.TreeItemCollapsibleState.None,
          'feed-item',
          description,
          loadedIcon
        );
      });

      items.push(
        new LicenseTreeItem(
          'license-feeds',
          'Entitled Feeds',
          vscode.TreeItemCollapsibleState.Expanded,
          'license-feeds',
          `${this.licenseInfo.payload.feeds.length}`,
          new vscode.ThemeIcon('package'),
          feedChildren
        )
      );
    }

    // Loaded packs section
    const loadedPacks = this.encryptedPacks.filter((p) => p.loaded);
    if (loadedPacks.length > 0) {
      const packChildren = loadedPacks.map((pack, index) =>
        new LicenseTreeItem(
          `pack-${index}-${pack.feedId}`,
          pack.name || pack.feedId,
          vscode.TreeItemCollapsibleState.None,
          'pack-item',
          `v${pack.version} • ${pack.ruleCount} rules`,
          new vscode.ThemeIcon('lock')
        )
      );

      items.push(
        new LicenseTreeItem(
          'license-packs',
          'Loaded Packs',
          vscode.TreeItemCollapsibleState.Expanded,
          'license-packs',
          `${loadedPacks.length}`,
          new vscode.ThemeIcon('verified'),
          packChildren
        )
      );
    }

    // Actions section
    items.push(
      new LicenseTreeItem(
        'action-check-updates',
        'Check for Updates',
        vscode.TreeItemCollapsibleState.None,
        'action-check-updates',
        undefined,
        new vscode.ThemeIcon('cloud-download'),
        undefined,
        {
          command: 'sentriflow.checkForUpdates',
          title: 'Check for Updates',
        }
      )
    );

    items.push(
      new LicenseTreeItem(
        'action-reload',
        'Reload Packs',
        vscode.TreeItemCollapsibleState.None,
        'action-reload',
        undefined,
        new vscode.ThemeIcon('refresh'),
        undefined,
        {
          command: 'sentriflow.reloadEncryptedPacks',
          title: 'Reload Encrypted Packs',
        }
      )
    );

    return items;
  }
}
