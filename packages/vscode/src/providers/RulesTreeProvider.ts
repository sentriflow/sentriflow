import * as vscode from 'vscode';
import type { IRule, RulePack, RuleVendor, Tag, TagType } from '@sentriflow/core';

/**
 * Tree grouping modes for the rules hierarchy
 */
export type TreeGrouping = 'vendor' | 'category' | 'category-vendor' | 'vendor-category';

/**
 * Tree item types for the rules hierarchy
 */
export type TreeItemType = 'pack' | 'vendor' | 'category' | 'rule' | 'tags-section' | 'tag';

/**
 * Metadata about a tag for tooltip display
 */
export interface TagMeta {
  type: TagType;
  label: string;
  score?: number;
}

/**
 * Extended tree item with metadata for the rules tree
 */
export class RuleTreeItem extends vscode.TreeItem {
  public tagId?: string;  // For 'tag' type items - stores the tag name for children lookup
  public tagMeta?: TagMeta;  // For 'tag' type items - stores type and score for tooltip

  constructor(
    public override readonly label: string,
    public override readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly itemType: TreeItemType,
    public readonly packName?: string,
    public readonly vendorId?: string,
    public readonly categoryId?: string,
    public readonly rule?: IRule,
    public readonly isEnabled: boolean = true,
    public readonly isEncrypted: boolean = false,
  ) {
    super(label, collapsibleState);
    // Encode enabled state in contextValue for conditional menu icons
    this.contextValue = `${itemType}-${isEnabled ? 'enabled' : 'disabled'}`;
    this.updateAppearance();
  }

  private updateAppearance(): void {
    switch (this.itemType) {
      case 'pack':
        // Use lock icon for encrypted packs, package icon for regular packs
        const packIcon = this.isEncrypted ? 'lock' : 'package';
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon(packIcon, new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon(packIcon, new vscode.ThemeColor('testing.iconSkipped'));
        const encryptedLabel = this.isEncrypted ? ' [encrypted]' : '';
        this.tooltip = this.isEnabled
          ? `Pack: ${this.packName}${encryptedLabel} (enabled)`
          : `Pack: ${this.packName}${encryptedLabel} (disabled)`;
        break;

      case 'vendor':
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon('server', new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon('server', new vscode.ThemeColor('testing.iconSkipped'));
        this.tooltip = this.isEnabled
          ? `Vendor: ${this.vendorId} (enabled)`
          : `Vendor: ${this.vendorId} (disabled)`;
        break;

      case 'category':
        this.iconPath = this.isEnabled
          ? new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconPassed'))
          : new vscode.ThemeIcon('shield', new vscode.ThemeColor('testing.iconSkipped'));
        this.tooltip = this.isEnabled
          ? `Category: ${this.categoryId} (enabled)`
          : `Category: ${this.categoryId} (disabled)`;
        break;

      case 'rule':
        if (!this.rule) break;
        // Use severity icon with appropriate color
        // State (enabled/disabled) is shown via toggle button on the right
        const levelIcon = this.getLevelIcon(this.rule.metadata.level);
        const levelColor = this.getLevelColor(this.rule.metadata.level);
        this.iconPath = new vscode.ThemeIcon(
          levelIcon,
          new vscode.ThemeColor(this.isEnabled ? levelColor : 'testing.iconSkipped')
        );
        this.description = this.isEnabled ? undefined : '(disabled)';
        this.tooltip = new vscode.MarkdownString();
        this.tooltip.appendMarkdown(`**${this.rule.id}** [${this.rule.metadata.level}]\n\n`);
        if (this.rule.metadata.description) {
          this.tooltip.appendMarkdown(`${this.rule.metadata.description}\n\n`);
        }
        if (this.rule.metadata.remediation) {
          this.tooltip.appendMarkdown(`*Remediation:* ${this.rule.metadata.remediation}`);
        }
        break;

      case 'tags-section':
        this.iconPath = new vscode.ThemeIcon('symbol-keyword', new vscode.ThemeColor('testing.iconQueued'));
        this.tooltip = 'Browse rules by tag';
        break;

      case 'tag':
        this.iconPath = new vscode.ThemeIcon('tag', new vscode.ThemeColor('charts.orange'));
        if (this.tagMeta) {
          const tooltip = new vscode.MarkdownString();
          tooltip.appendMarkdown(`**${this.tagMeta.label}** [${this.tagMeta.type}]\n\n`);
          if (this.tagMeta.score !== undefined) {
            tooltip.appendMarkdown(`Score: ${this.tagMeta.score}/10`);
          }
          this.tooltip = tooltip;
        } else {
          this.tooltip = `Tag: ${this.tagId ?? this.label}`;
        }
        break;
    }
  }

  private getLevelIcon(level: string): string {
    switch (level) {
      case 'error': return 'error';
      case 'warning': return 'warning';
      case 'info': return 'info';
      default: return 'circle-outline';
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
 * TreeDataProvider for the SentriFlow rules hierarchy
 * Supports flexible grouping: Pack -> [Vendor|Category] -> [Category|Vendor] -> Rules
 */
export class RulesTreeProvider implements vscode.TreeDataProvider<RuleTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<RuleTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  // These will be set by extension.ts
  private _getDefaultPack: () => RulePack = () => ({ name: 'sf-default', version: '0.0.0', publisher: '', description: '', license: '', priority: 0, rules: [] });
  private _getRegisteredPacks: () => Map<string, RulePack> = () => new Map();
  private _getAllRules: () => IRule[] = () => [];
  private _getDisabledRulesSet: () => Set<string> = () => new Set();
  private _isPackEncrypted: (packName: string) => boolean = () => false;

  constructor() {}

  /**
   * Initialize the provider with callbacks to access extension state
   */
  initialize(
    getDefaultPack: () => RulePack,
    getRegisteredPacks: () => Map<string, RulePack>,
    getAllRules: () => IRule[],
    getDisabledRulesSet: () => Set<string>,
    isPackEncrypted?: (packName: string) => boolean,
  ): void {
    this._getDefaultPack = getDefaultPack;
    this._getRegisteredPacks = getRegisteredPacks;
    this._getAllRules = getAllRules;
    this._getDisabledRulesSet = getDisabledRulesSet;
    this._isPackEncrypted = isPackEncrypted ?? (() => false);
  }

  /**
   * Refresh the entire tree
   */
  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Get the current tree grouping mode from settings
   */
  private getGroupingMode(): TreeGrouping {
    const config = vscode.workspace.getConfiguration('sentriflow');
    return config.get<TreeGrouping>('treeGrouping', 'vendor');
  }

  getTreeItem(element: RuleTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: RuleTreeItem): RuleTreeItem[] {
    if (!element) {
      // Root level: show packs + optional tags section
      const items = this.getPackNodes();

      // Only show tags section if enabled AND has tagged rules
      if (this.getTagsSectionEnabled() && this.getAllTags().size > 0) {
        items.push(this.getTagsSectionItem());
      }

      return items;
    }

    const grouping = this.getGroupingMode();

    switch (element.itemType) {
      case 'pack':
        return this.getFirstLevelNodes(element.packName!, grouping);
      case 'vendor':
        // Pass both vendorId and categoryId (categoryId may be set in three-level mode)
        return this.getNodesUnderVendor(element.packName!, element.vendorId!, element.categoryId, grouping);
      case 'category':
        // Pass both categoryId and vendorId (vendorId may be set in three-level mode)
        return this.getNodesUnderCategory(element.packName!, element.categoryId!, element.vendorId, grouping);
      case 'tags-section':
        // Return individual tag items
        return this.getTagItems();
      case 'tag':
        // Return rules for this specific tag
        return this.getRulesForTag(element.tagId!);
      default:
        return [];
    }
  }

  /**
   * Get first level nodes under a pack (vendor or category based on grouping)
   */
  private getFirstLevelNodes(packName: string, grouping: TreeGrouping): RuleTreeItem[] {
    switch (grouping) {
      case 'vendor':
      case 'vendor-category':
        return this.getVendorNodes(packName);
      case 'category':
      case 'category-vendor':
        return this.getCategoryNodes(packName);
      default:
        return this.getVendorNodes(packName);
    }
  }

  /**
   * Get children under a vendor node
   */
  private getNodesUnderVendor(
    packName: string,
    vendorId: string,
    categoryId: string | undefined,
    grouping: TreeGrouping
  ): RuleTreeItem[] {
    switch (grouping) {
      case 'vendor':
        // Two-level: Pack -> Vendor -> Rules
        return this.getRuleNodesFiltered(packName, vendorId, undefined);
      case 'vendor-category':
        // Three-level: Pack -> Vendor -> Category -> Rules
        // At vendor level, show categories
        return this.getCategoryNodesForVendor(packName, vendorId);
      case 'category-vendor':
        // Three-level: Pack -> Category -> Vendor -> Rules
        // At vendor level (under category), show rules filtered by BOTH
        return this.getRuleNodesFiltered(packName, vendorId, categoryId);
      default:
        return this.getRuleNodesFiltered(packName, vendorId, undefined);
    }
  }

  /**
   * Get children under a category node
   */
  private getNodesUnderCategory(
    packName: string,
    categoryId: string,
    vendorId: string | undefined,
    grouping: TreeGrouping
  ): RuleTreeItem[] {
    switch (grouping) {
      case 'category':
        // Two-level: Pack -> Category -> Rules
        return this.getRuleNodesFiltered(packName, undefined, categoryId);
      case 'category-vendor':
        // Three-level: Pack -> Category -> Vendor -> Rules
        // At category level, show vendors
        return this.getVendorNodesForCategory(packName, categoryId);
      case 'vendor-category':
        // Three-level: Pack -> Vendor -> Category -> Rules
        // At category level (under vendor), show rules filtered by BOTH
        return this.getRuleNodesFiltered(packName, vendorId, categoryId);
      default:
        return this.getRuleNodesFiltered(packName, undefined, categoryId);
    }
  }

  /**
   * Get rules for this pack
   */
  private getPackRules(packName: string): IRule[] {
    const defaultPack = this._getDefaultPack();
    const registeredPacks = this._getRegisteredPacks();
    const isDefault = packName === defaultPack.name;
    return isDefault ? this._getAllRules() : (registeredPacks.get(packName)?.rules ?? []);
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
      undefined,
      enableDefaultRules,
    ));

    // External packs
    const registeredPacks = this._getRegisteredPacks();
    for (const [name, pack] of registeredPacks) {
      const isEnabled = !blockedPacks.has(name);
      const isEncrypted = this._isPackEncrypted(name);
      items.push(new RuleTreeItem(
        `${name} (${pack.rules.length} rules)`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'pack',
        name,
        undefined,
        undefined,
        undefined,
        isEnabled,
        isEncrypted,
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

    const rules = this.getPackRules(packName);

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
        undefined,
        isEnabled,
      ));
    }

    return items;
  }

  /**
   * Get category nodes for a pack
   */
  private getCategoryNodes(packName: string): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const rules = this.getPackRules(packName);

    // Group rules by category
    const categoryRules = new Map<string, IRule[]>();
    for (const rule of rules) {
      const categories = this.getRuleCategories(rule);
      for (const category of categories) {
        if (!categoryRules.has(category)) {
          categoryRules.set(category, []);
        }
        categoryRules.get(category)!.push(rule);
      }
    }

    // Create category nodes
    const sortedCategories = Array.from(categoryRules.keys()).sort();
    for (const category of sortedCategories) {
      const categoryRuleList = categoryRules.get(category)!;
      items.push(new RuleTreeItem(
        `${category} (${categoryRuleList.length} rules)`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        packName,
        undefined,
        category,
        undefined,
        true, // Categories don't have enable/disable state yet
      ));
    }

    return items;
  }

  /**
   * Get category nodes for a specific vendor within a pack (for vendor-category mode)
   */
  private getCategoryNodesForVendor(packName: string, vendorId: string): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const rules = this.getPackRules(packName);

    // Filter rules for this vendor first
    const vendorRules = rules.filter(rule => {
      if (!rule.vendor) return vendorId === 'common';
      if (Array.isArray(rule.vendor)) {
        return rule.vendor.includes(vendorId as RuleVendor);
      }
      return rule.vendor === vendorId;
    });

    // Group by category
    const categoryRules = new Map<string, IRule[]>();
    for (const rule of vendorRules) {
      const categories = this.getRuleCategories(rule);
      for (const category of categories) {
        if (!categoryRules.has(category)) {
          categoryRules.set(category, []);
        }
        categoryRules.get(category)!.push(rule);
      }
    }

    // Create category nodes (with vendor context stored for rule filtering)
    const sortedCategories = Array.from(categoryRules.keys()).sort();
    for (const category of sortedCategories) {
      const categoryRuleList = categoryRules.get(category)!;
      items.push(new RuleTreeItem(
        `${category} (${categoryRuleList.length} rules)`,
        vscode.TreeItemCollapsibleState.Collapsed,
        'category',
        packName,
        vendorId, // Store parent vendor
        category,
        undefined,
        true,
      ));
    }

    return items;
  }

  /**
   * Get vendor nodes for a specific category within a pack (for category-vendor mode)
   */
  private getVendorNodesForCategory(packName: string, categoryId: string): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const config = vscode.workspace.getConfiguration('sentriflow');

    const overridesInspect = config.inspect<Record<string, { disabledVendors?: string[] }>>('packVendorOverrides');
    const packVendorOverrides = overridesInspect?.workspaceValue
      ?? overridesInspect?.globalValue
      ?? overridesInspect?.defaultValue
      ?? {};
    const disabledVendors = new Set(packVendorOverrides[packName]?.disabledVendors ?? []);

    const rules = this.getPackRules(packName);

    // Filter rules for this category first
    const categoryRules = rules.filter(rule => {
      const categories = this.getRuleCategories(rule);
      return categories.includes(categoryId);
    });

    // Group by vendor
    const vendorRules = new Map<string, IRule[]>();
    for (const rule of categoryRules) {
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

    // Create vendor nodes (with category context stored for rule filtering)
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
        categoryId, // Store parent category
        undefined,
        isEnabled,
      ));
    }

    return items;
  }

  /**
   * Get rule nodes filtered by vendor and/or category
   */
  private getRuleNodesFiltered(
    packName: string,
    vendorId: string | undefined,
    categoryId: string | undefined
  ): RuleTreeItem[] {
    const items: RuleTreeItem[] = [];
    const disabledRules = this._getDisabledRulesSet();
    const rules = this.getPackRules(packName);

    // Filter rules
    let filteredRules = rules;

    if (vendorId) {
      filteredRules = filteredRules.filter(rule => {
        if (!rule.vendor) return vendorId === 'common';
        if (Array.isArray(rule.vendor)) {
          return rule.vendor.includes(vendorId as RuleVendor);
        }
        return rule.vendor === vendorId;
      });
    }

    if (categoryId) {
      filteredRules = filteredRules.filter(rule => {
        const categories = this.getRuleCategories(rule);
        return categories.includes(categoryId);
      });
    }

    // Sort by level (errors first), then by ID
    filteredRules.sort((a, b) => {
      const levelOrder = { error: 0, warning: 1, info: 2 };
      const aLevel = levelOrder[a.metadata.level as keyof typeof levelOrder] ?? 3;
      const bLevel = levelOrder[b.metadata.level as keyof typeof levelOrder] ?? 3;
      if (aLevel !== bLevel) return aLevel - bLevel;
      return a.id.localeCompare(b.id);
    });

    // Create rule nodes
    for (const rule of filteredRules) {
      const isEnabled = !disabledRules.has(rule.id);
      items.push(new RuleTreeItem(
        rule.id,
        vscode.TreeItemCollapsibleState.None,
        'rule',
        packName,
        vendorId,
        categoryId,
        rule,
        isEnabled,
      ));
    }

    return items;
  }

  /**
   * Get categories for a rule (no longer falls back to security tags - they are separate)
   */
  private getRuleCategories(rule: IRule): string[] {
    if (rule.category) {
      return Array.isArray(rule.category) ? rule.category : [rule.category];
    }
    return ['Uncategorized'];
  }

  // ============================================================================
  // Tags Section Support
  // ============================================================================

  /**
   * Check if the tags section is enabled in settings
   */
  private getTagsSectionEnabled(): boolean {
    const config = vscode.workspace.getConfiguration('sentriflow');
    return config.get<boolean>('showTagsSection', true);
  }

  /**
   * Get the current tag type filter setting
   */
  private getTagTypeFilter(): TagType | 'all' {
    const config = vscode.workspace.getConfiguration('sentriflow');
    return config.get<TagType | 'all'>('tagTypeFilter', 'all');
  }

  /**
   * Get all tags across all rules, mapped to the rules that have them
   * Rules with multiple tags will appear under each tag they have
   * Returns both the rules and the first Tag object found for metadata display
   * Only includes rules from enabled packs (respects enableDefaultRules and blockedPacks)
   */
  private getAllTags(): Map<string, { rules: IRule[]; tagMeta: TagMeta }> {
    const tagMap = new Map<string, { rules: IRule[]; tagMeta: TagMeta }>();
    const config = vscode.workspace.getConfiguration('sentriflow');
    const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
    const blockedPacks = new Set(config.get<string[]>('blockedPacks', []));

    // Collect rules from enabled packs only
    const rulesToProcess: IRule[] = [];

    // Include default pack rules only if enabled
    if (enableDefaultRules) {
      rulesToProcess.push(...this._getAllRules());
    }

    // Include rules from enabled external packs
    const registeredPacks = this._getRegisteredPacks();
    for (const [packName, pack] of registeredPacks) {
      if (!blockedPacks.has(packName)) {
        rulesToProcess.push(...pack.rules);
      }
    }

    // Build tag map from filtered rules
    for (const rule of rulesToProcess) {
      const tags = rule.metadata.tags ?? [];
      for (const tag of tags) {
        if (!tagMap.has(tag.label)) {
          tagMap.set(tag.label, {
            rules: [],
            tagMeta: { type: tag.type, label: tag.label, score: tag.score }
          });
        }
        tagMap.get(tag.label)!.rules.push(rule);
      }
    }
    return tagMap;
  }

  /**
   * Create the "By Tag" section header item
   */
  private getTagsSectionItem(): RuleTreeItem {
    const tagCount = this.getAllTags().size;
    const item = new RuleTreeItem(
      `By Tag (${tagCount} tags)`,
      vscode.TreeItemCollapsibleState.Collapsed,
      'tags-section'
    );
    return item;
  }

  /**
   * Get individual tag items (children of tags-section)
   */
  private getTagItems(): RuleTreeItem[] {
    const tagMap = this.getAllTags();
    const disabledRules = this._getDisabledRulesSet();
    const typeFilter = this.getTagTypeFilter();

    return Array.from(tagMap.entries())
      .filter(([, { tagMeta }]) => typeFilter === 'all' || tagMeta.type === typeFilter)
      .sort((a, b) => a[0].localeCompare(b[0]))  // Sort alphabetically
      .map(([tagLabel, { rules, tagMeta }]) => {
        // Count enabled rules for this tag
        const enabledCount = rules.filter(r => !disabledRules.has(r.id)).length;
        const item = new RuleTreeItem(
          `${tagLabel} (${rules.length} rules)`,
          vscode.TreeItemCollapsibleState.Collapsed,
          'tag',
          undefined,
          undefined,
          undefined,
          undefined,
          enabledCount > 0  // Mark as enabled if at least one rule is enabled
        );
        item.tagId = tagLabel;
        item.tagMeta = tagMeta;
        return item;
      });
  }

  /**
   * Get rule items for a specific tag
   */
  private getRulesForTag(tagId: string): RuleTreeItem[] {
    const tagMap = this.getAllTags();
    const entry = tagMap.get(tagId);
    const rules = entry?.rules ?? [];
    const disabledRules = this._getDisabledRulesSet();

    // Sort by level (errors first), then by ID
    const sortedRules = [...rules].sort((a, b) => {
      const levelOrder = { error: 0, warning: 1, info: 2 };
      const aLevel = levelOrder[a.metadata.level as keyof typeof levelOrder] ?? 3;
      const bLevel = levelOrder[b.metadata.level as keyof typeof levelOrder] ?? 3;
      if (aLevel !== bLevel) return aLevel - bLevel;
      return a.id.localeCompare(b.id);
    });

    return sortedRules.map(rule => {
      const isEnabled = !disabledRules.has(rule.id);
      return new RuleTreeItem(
        rule.id,
        vscode.TreeItemCollapsibleState.None,
        'rule',
        undefined,  // No pack context for tag-based view
        undefined,
        undefined,
        rule,
        isEnabled
      );
    });
  }
}
