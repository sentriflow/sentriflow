import * as vscode from 'vscode';
import type { IRule, RulePack, RuleVendor } from '@sentriflow/core';

/**
 * Tree item types for the rules hierarchy
 */
export type TreeItemType = 'pack' | 'vendor' | 'rule';

/**
 * Extended tree item with metadata for the rules tree
 */
export class RuleTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: TreeItemType,
    public readonly packName?: string,
    public readonly vendorId?: string,
    public readonly rule?: IRule,
    public readonly isEnabled: boolean = true,
  ) {
    super(label, collapsibleState);
    // Encode enabled state in contextValue for conditional menu icons
    this.contextValue = `${itemType}-${isEnabled ? 'enabled' : 'disabled'}`;
    this.updateAppearance();
  }

  private updateAppearance(): void {
    switch (this.itemType) {
      case 'pack':
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon('package', new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon('package', new vscode.ThemeColor('testing.iconSkipped'));
        this.tooltip = this.isEnabled
          ? `Pack: ${this.packName} (enabled)`
          : `Pack: ${this.packName} (disabled)`;
        break;

      case 'vendor':
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon('server', new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon('server', new vscode.ThemeColor('testing.iconSkipped'));
        this.tooltip = this.isEnabled
          ? `Vendor: ${this.vendorId} (enabled)`
          : `Vendor: ${this.vendorId} (disabled)`;
        break;

      case 'rule':
        if (!this.rule) break;
        // Use eye/eye-closed for state (consistent with packs/vendors)
        // Color indicates severity level
        const levelColor = this.getLevelColor(this.rule.metadata.level);
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon('eye', new vscode.ThemeColor(levelColor))
          : new vscode.ThemeIcon('eye-closed', new vscode.ThemeColor('testing.iconSkipped'));
        this.description = `[${this.rule.metadata.level}]${this.isEnabled ? '' : ' (disabled)'}`;
        this.tooltip = new vscode.MarkdownString();
        this.tooltip.appendMarkdown(`**${this.rule.id}**\n\n`);
        this.tooltip.appendMarkdown(`Level: ${this.rule.metadata.level}\n\n`);
        if (this.rule.metadata.description) {
          this.tooltip.appendMarkdown(`${this.rule.metadata.description}\n\n`);
        }
        if (this.rule.metadata.remediation) {
          this.tooltip.appendMarkdown(`*Remediation:* ${this.rule.metadata.remediation}`);
        }
        break;
    }
  }

  private getLevelColor(level: string): string {
    switch (level) {
      case 'error': return 'testing.iconFailed';      // red
      case 'warning': return 'testing.iconQueued';    // yellow/orange
      case 'info': return 'testing.iconPassed';       // green/blue
      default: return 'foreground';
    }
  }
}

/**
 * Interface for pack state information
 */
interface PackState {
  pack: RulePack;
  isDefault: boolean;
  isEnabled: boolean;
  disabledVendors: Set<string>;
}

/**
 * TreeDataProvider for the SentriFlow rules hierarchy
 * Shows: Packs -> Vendors -> Rules with toggle support at each level
 */
export class RulesTreeProvider implements vscode.TreeDataProvider<RuleTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<RuleTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  // These will be set by extension.ts
  private _getDefaultPack: () => RulePack = () => ({ name: 'sf-default', version: '0.0.0', publisher: '', description: '', license: '', priority: 0, rules: [] });
  private _getRegisteredPacks: () => Map<string, RulePack> = () => new Map();
  private _getAllRules: () => IRule[] = () => [];
  private _getDisabledRulesSet: () => Set<string> = () => new Set();

  constructor() {}

  /**
   * Initialize the provider with callbacks to access extension state
   */
  initialize(
    getDefaultPack: () => RulePack,
    getRegisteredPacks: () => Map<string, RulePack>,
    getAllRules: () => IRule[],
    getDisabledRulesSet: () => Set<string>,
  ): void {
    this._getDefaultPack = getDefaultPack;
    this._getRegisteredPacks = getRegisteredPacks;
    this._getAllRules = getAllRules;
    this._getDisabledRulesSet = getDisabledRulesSet;
  }

  /**
   * Refresh the entire tree
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: RuleTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: RuleTreeItem): RuleTreeItem[] {
    if (!element) {
      // Root level: show packs
      return this.getPackNodes();
    }

    switch (element.itemType) {
      case 'pack':
        return this.getVendorNodes(element.packName!);
      case 'vendor':
        return this.getRuleNodes(element.packName!, element.vendorId!);
      default:
        return [];
    }
  }

  /**
   * Get the root pack nodes
   */
  private getPackNodes(): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const config = vscode.workspace.getConfiguration('sentriflow');
    const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
    const blockedPacks = new Set(config.get<string[]>('blockedPacks', []));

    // Default pack
    const defaultPack = this._getDefaultPack();
    const defaultRules = this._getAllRules();
    items.push(new RuleTreeItem(
      `${defaultPack.name} (${defaultRules.length} rules)`,
      vscode.TreeItemCollapsibleState.Collapsed,
      'pack',
      defaultPack.name,
      undefined,
      undefined,
      enableDefaultRules,
    ));

    // External packs
    const registeredPacks = this._getRegisteredPacks();
    for (const [name, pack] of registeredPacks) {
      const isEnabled = !blockedPacks.has(name);
      items.push(new RuleTreeItem(
        `${name} (${pack.rules.length} rules)`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'pack',
        name,
        undefined,
        undefined,
        isEnabled,
      ));
    }

    return items;
  }

  /**
   * Get vendor nodes for a pack
   */
  private getVendorNodes(packName: string): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const config = vscode.workspace.getConfiguration('sentriflow');

    // Use inspect() to get fresh config values
    const overridesInspect = config.inspect<Record<string, { disabledVendors?: string[] }>>('packVendorOverrides');
    const packVendorOverrides = overridesInspect?.workspaceValue
      ?? overridesInspect?.globalValue
      ?? overridesInspect?.defaultValue
      ?? {};
    const disabledVendors = new Set(packVendorOverrides[packName]?.disabledVendors ?? []);

    // Get all rules for this pack
    const defaultPack = this._getDefaultPack();
    const registeredPacks = this._getRegisteredPacks();
    const isDefault = packName === defaultPack.name;
    const rules = isDefault ? this._getAllRules() : (registeredPacks.get(packName)?.rules ?? []);

    // Group rules by vendor
    const vendorRules = new Map<string, IRule[]>();
    for (const rule of rules) {
      const vendors = rule.vendor
        ? (Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor])
        : ['common'];
      for (const vendor of vendors) {
        if (!vendorRules.has(vendor)) {
          vendorRules.set(vendor, []);
        }
        vendorRules.get(vendor)!.push(rule);
      }
    }

    // Create vendor nodes
    const sortedVendors = Array.from(vendorRules.keys()).sort();
    for (const vendor of sortedVendors) {
      const vendorRuleList = vendorRules.get(vendor)!;
      const isEnabled = !disabledVendors.has(vendor);
      items.push(new RuleTreeItem(
        `${vendor} (${vendorRuleList.length} rules)`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'vendor',
        packName,
        vendor,
        undefined,
        isEnabled,
      ));
    }

    return items;
  }

  /**
   * Get rule nodes for a vendor within a pack
   */
  private getRuleNodes(packName: string, vendorId: string): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const disabledRules = this._getDisabledRulesSet();

    // Get all rules for this pack
    const defaultPack = this._getDefaultPack();
    const registeredPacks = this._getRegisteredPacks();
    const isDefault = packName === defaultPack.name;
    const rules = isDefault ? this._getAllRules() : (registeredPacks.get(packName)?.rules ?? []);

    // Filter rules for this vendor
    const vendorRules = rules.filter(rule => {
      if (!rule.vendor) return vendorId === 'common';
      if (Array.isArray(rule.vendor)) {
        return rule.vendor.includes(vendorId as RuleVendor);
      }
      return rule.vendor === vendorId;
    });

    // Sort by level (errors first), then by ID
    vendorRules.sort((a, b) => {
      const levelOrder = { error: 0, warning: 1, info: 2 };
      const aLevel = levelOrder[a.metadata.level as keyof typeof levelOrder] ?? 3;
      const bLevel = levelOrder[b.metadata.level as keyof typeof levelOrder] ?? 3;
      if (aLevel !== bLevel) return aLevel - bLevel;
      return a.id.localeCompare(b.id);
    });

    // Create rule nodes
    for (const rule of vendorRules) {
      const isEnabled = !disabledRules.has(rule.id);
      items.push(new RuleTreeItem(
        rule.id,
        vscode.TreeItemCollapsibleState.None,
        'rule',
        packName,
        vendorId,
        rule,
        isEnabled,
      ));
    }

    return items;
  }
}
