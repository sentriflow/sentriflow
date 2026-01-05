import * as vscode from 'vscode';
import type { LicenseInfo, EncryptedPackInfo, CloudConnectionStatus } from '../encryption/types';

/**
 * Tree item for license information display
 */
class LicenseTreeItem extends vscode.TreeItem {
  public readonly children?: LicenseTreeItem[];

  constructor(
    itemId: string,
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    contextValue: string,
    description?: string,
    icon?: vscode.ThemeIcon,
    children?: LicenseTreeItem[],
    command?: vscode.Command
  ) {
    super(label, collapsibleState);
    this.id = itemId; // Unique ID to prevent tree refresh errors
    this.description = description;
    this.iconPath = icon;
    this.contextValue = contextValue;
    this.children = children;
    if (command) {
      this.command = command;
    }
  }
}

/**
 * Compact license summary for display
 */
interface LicenseSummary {
  type: 'cloud' | 'offline';
  isExpired: boolean;
  tier: string;
  expiryDate: string;
  daysUntilExpiry: number;
  customerName?: string;
}

/**
 * Provides tree data for license status display
 *
 * Supports displaying both cloud and offline licenses with clear differentiation:
 * - Cloud License: For cloud-delivered packs (XXXX-XXXX-XXXX-XXXX format)
 * - Offline License: For extended GRX2 packs (JWT format)
 */
export class LicenseTreeProvider implements vscode.TreeDataProvider<LicenseTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<LicenseTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private cloudLicense: LicenseSummary | null = null;
  private offlineLicense: LicenseSummary | null = null;
  private encryptedPacks: EncryptedPackInfo[] = [];
  private connectionStatus: CloudConnectionStatus = 'unknown';
  private cacheHoursRemaining = 0;

  /**
   * Update cloud license info and refresh tree
   */
  setCloudLicense(info: LicenseInfo | null): void {
    if (info) {
      this.cloudLicense = {
        type: 'cloud',
        isExpired: info.isExpired,
        tier: info.payload.tier,
        expiryDate: info.expiryDate,
        daysUntilExpiry: info.daysUntilExpiry,
        customerName: info.payload.name,
      };
    } else {
      this.cloudLicense = null;
    }
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Update offline license info and refresh tree
   */
  setOfflineLicense(info: LicenseInfo | null): void {
    if (info) {
      this.offlineLicense = {
        type: 'offline',
        isExpired: info.isExpired,
        tier: info.payload.tier,
        expiryDate: info.expiryDate,
        daysUntilExpiry: info.daysUntilExpiry,
        customerName: info.payload.name,
      };
    } else {
      this.offlineLicense = null;
    }
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Legacy method for backward compatibility
   * Sets the primary license (cloud if available, otherwise treats as cloud)
   */
  setLicenseInfo(info: LicenseInfo | null, _hasKey: boolean): void {
    this.setCloudLicense(info);
  }

  /**
   * Update encrypted packs info and refresh tree
   */
  setEncryptedPacks(packs: EncryptedPackInfo[]): void {
    this.encryptedPacks = packs;
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Update connection status and cache info
   */
  setConnectionStatus(status: CloudConnectionStatus, cacheHoursRemaining = 0): void {
    this.connectionStatus = status;
    this.cacheHoursRemaining = cacheHoursRemaining;
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

  /**
   * Format tier for compact display
   */
  private formatTier(tier: string): string {
    const tierMap: Record<string, string> = {
      enterprise: 'Enterprise',
      professional: 'Pro',
      community: 'Community',
    };
    return tierMap[tier] || tier;
  }

  /**
   * Build compact status string for license
   */
  private buildLicenseStatus(license: LicenseSummary): string {
    const parts: string[] = [];

    // Status
    if (license.isExpired) {
      parts.push('Expired');
    } else if (license.daysUntilExpiry <= 14) {
      parts.push(`${license.daysUntilExpiry}d left`);
    } else {
      parts.push('Active');
    }

    // Tier
    parts.push(this.formatTier(license.tier));

    // Expiry (compact format)
    parts.push(license.expiryDate);

    return parts.join(' • ');
  }

  /**
   * Get icon for license based on status
   */
  private getLicenseIcon(license: LicenseSummary, isCloud: boolean): vscode.ThemeIcon {
    const baseIcon = isCloud ? 'cloud' : 'key';

    if (license.isExpired) {
      return new vscode.ThemeIcon(baseIcon, new vscode.ThemeColor('errorForeground'));
    } else if (license.daysUntilExpiry <= 14) {
      return new vscode.ThemeIcon(baseIcon, new vscode.ThemeColor('warningForeground'));
    }
    return new vscode.ThemeIcon(baseIcon, new vscode.ThemeColor('testing.iconPassed'));
  }

  getChildren(element?: LicenseTreeItem): LicenseTreeItem[] {
    if (element) {
      return element.children || [];
    }

    const items: LicenseTreeItem[] = [];
    const hasAnyLicense = this.cloudLicense || this.offlineLicense;

    // No licenses configured
    if (!hasAnyLicense) {
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

    // === LICENSES SECTION ===

    // Cloud License (for cloud-delivered packs)
    if (this.cloudLicense) {
      items.push(
        new LicenseTreeItem(
          'cloud-license',
          'Cloud License',
          vscode.TreeItemCollapsibleState.None,
          'cloud-license',
          this.buildLicenseStatus(this.cloudLicense),
          this.getLicenseIcon(this.cloudLicense, true)
        )
      );
    }

    // Offline License (for extended GRX2 packs)
    if (this.offlineLicense) {
      items.push(
        new LicenseTreeItem(
          'offline-license',
          'Offline License',
          vscode.TreeItemCollapsibleState.None,
          'offline-license',
          this.buildLicenseStatus(this.offlineLicense),
          this.getLicenseIcon(this.offlineLicense, false)
        )
      );
    }

    // === CONNECTION STATUS ===
    if (this.cloudLicense && this.connectionStatus !== 'unknown') {
      const isOnline = this.connectionStatus === 'online';
      const connectionIcon = isOnline
        ? new vscode.ThemeIcon('cloud', new vscode.ThemeColor('testing.iconPassed'))
        : new vscode.ThemeIcon('cloud-offline', new vscode.ThemeColor('warningForeground'));

      let connectionDescription: string;
      if (isOnline) {
        connectionDescription = 'Connected';
      } else if (this.cacheHoursRemaining > 0) {
        connectionDescription = `Offline (${this.cacheHoursRemaining}h cache)`;
      } else {
        connectionDescription = 'Offline';
      }

      items.push(
        new LicenseTreeItem(
          'connection-status',
          'Cloud Status',
          vscode.TreeItemCollapsibleState.None,
          'connection-status',
          connectionDescription,
          connectionIcon
        )
      );
    }

    // === RULE PACKS SECTION ===
    const loadedPacks = this.encryptedPacks.filter((p) => p.loaded);
    if (loadedPacks.length > 0) {
      const packChildren = loadedPacks.map((pack, index) => {
        // Format indicator: GRX2 or GRPX
        const formatLabel = pack.format ? ` [${pack.format.toUpperCase()}]` : '';
        return new LicenseTreeItem(
          `pack-${index}-${pack.feedId}`,
          pack.name || pack.feedId,
          vscode.TreeItemCollapsibleState.None,
          'pack-item',
          `v${pack.version} • ${pack.ruleCount} rules${formatLabel}`,
          new vscode.ThemeIcon('package')
        );
      });

      items.push(
        new LicenseTreeItem(
          'license-packs',
          'Rule Packs',
          vscode.TreeItemCollapsibleState.Expanded,
          'license-packs',
          `${loadedPacks.length}`,
          new vscode.ThemeIcon('verified'),
          packChildren
        )
      );
    }

    // === ACTIONS SECTION ===
    if (this.cloudLicense) {
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
    }

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
          command: 'sentriflow.reloadPacks',
          title: 'Reload Rule Packs',
        }
      )
    );

    return items;
  }
}
