/**
 * Rules Commands
 *
 * Commands for managing rules via tree view and command palette.
 * Includes toggle, filter, and detail viewing operations.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { getAvailableVendorInfo, getVendor, detectVendor } from '@sentriflow/core';
import type { RuleVendor } from '@sentriflow/core';
import { allRules } from '@sentriflow/rules-default';
import { RuleTreeItem } from '../providers/RulesTreeProvider';
import { getState } from '../state/context';
import {
  getDisabledRulesSet,
  toggleRule as toggleRuleService,
} from '../services/ruleManager';
import { rescanActiveEditor, scheduleScan, runScan } from '../services/scanner';
import { updateVendorStatusBar } from '../ui/statusBar';
import { saveDocumentVendorOverrides } from '../extension';
import { getUniqueCategoriesFromRules } from '../utils/helpers';
import { DEFAULT_PACK_NAME } from './packs';

/** Pack name for custom rules (must match RulesTreeProvider.CUSTOM_RULES_PACK) */
const CUSTOM_RULES_PACK = 'Custom Rules';

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
// TreeView Command Handlers
// ============================================================================

/**
 * Disable a tree item (pack, vendor, or rule)
 */
export async function cmdDisableTreeItem(item: RuleTreeItem): Promise<void> {
  if (!item) return;

  const state = getState();
  const config = vscode.workspace.getConfiguration('sentriflow');

  switch (item.itemType) {
    case 'pack': {
      const packName = item.packName!;
      if (packName === DEFAULT_PACK_NAME) {
        await config.update(
          'enableDefaultRules',
          false,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Default rules disabled`
        );
      } else if (packName === CUSTOM_RULES_PACK) {
        await config.update(
          'customRules.enabled',
          false,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Custom rules disabled`
        );
      } else {
        const blockedPacks = config.get<string[]>('blockedPacks', []);
        if (!blockedPacks.includes(packName)) {
          await config.update(
            'blockedPacks',
            [...blockedPacks, packName],
            vscode.ConfigurationTarget.Workspace
          );
        }
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Pack '${packName}' disabled`
        );
      }
      break;
    }

    case 'vendor': {
      const packName = item.packName!;
      const vendorId = item.vendorId!;
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      if (!disabledVendors.includes(vendorId)) {
        const newOverrides = {
          ...overrides,
          [packName]: { disabledVendors: [...disabledVendors, vendorId] },
        };
        await config.update(
          'packVendorOverrides',
          newOverrides,
          vscode.ConfigurationTarget.Workspace
        );
      }
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Vendor '${vendorId}' in pack '${packName}' disabled`
      );
      break;
    }

    case 'rule': {
      const ruleId = item.rule!.id;
      const isCustomRule = item.packName === 'Custom Rules';
      await toggleRuleService(ruleId, false, isCustomRule);
      break;
    }
  }

  state.rulesTreeProvider.refresh();
  rescanActiveEditor();
}

/**
 * Enable a tree item (pack, vendor, or rule)
 */
export async function cmdEnableTreeItem(item: RuleTreeItem): Promise<void> {
  if (!item) return;

  const state = getState();
  const config = vscode.workspace.getConfiguration('sentriflow');

  switch (item.itemType) {
    case 'pack': {
      const packName = item.packName!;
      if (packName === DEFAULT_PACK_NAME) {
        await config.update(
          'enableDefaultRules',
          true,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Default rules enabled`
        );
      } else if (packName === CUSTOM_RULES_PACK) {
        await config.update(
          'customRules.enabled',
          true,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Custom rules enabled`
        );
      } else {
        const blockedPacks = config.get<string[]>('blockedPacks', []);
        const newBlockedPacks = blockedPacks.filter((p) => p !== packName);
        await config.update(
          'blockedPacks',
          newBlockedPacks.length > 0 ? newBlockedPacks : undefined,
          vscode.ConfigurationTarget.Workspace
        );
        vscode.window.showInformationMessage(
          `SENTRIFLOW: Pack '${packName}' enabled`
        );
      }
      break;
    }

    case 'vendor': {
      const packName = item.packName!;
      const vendorId = item.vendorId!;
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      const newDisabledVendors = disabledVendors.filter((v) => v !== vendorId);
      const newOverrides = { ...overrides };

      if (newDisabledVendors.length === 0) {
        delete newOverrides[packName];
      } else {
        newOverrides[packName] = { disabledVendors: newDisabledVendors };
      }

      await config.update(
        'packVendorOverrides',
        Object.keys(newOverrides).length > 0 ? newOverrides : undefined,
        vscode.ConfigurationTarget.Workspace
      );
      vscode.window.showInformationMessage(
        `SENTRIFLOW: Vendor '${vendorId}' in pack '${packName}' enabled`
      );
      break;
    }

    case 'rule': {
      const ruleId = item.rule!.id;
      const packName = item.packName!;
      const vendorId = item.vendorId;
      const isCustomRule = packName === 'Custom Rules';

      // Custom rules don't have vendor hierarchy
      if (isCustomRule) {
        await toggleRuleService(ruleId, true, true);
        break;
      }

      // Check if parent vendor is disabled
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const packOverride = overrides[packName] ?? { disabledVendors: [] };
      const disabledVendors = packOverride.disabledVendors ?? [];

      if (vendorId && disabledVendors.includes(vendorId)) {
        // Vendor is disabled - need to enable vendor but disable all other rules
        const isDefault = packName === DEFAULT_PACK_NAME;
        const packRules = isDefault
          ? allRules
          : state.registeredPacks.get(packName)?.rules ?? [];
        const vendorRules = packRules.filter((r) => {
          if (!r.vendor) return vendorId === 'common';
          if (Array.isArray(r.vendor))
            return r.vendor.includes(vendorId as RuleVendor);
          return r.vendor === vendorId;
        });

        // Enable the vendor (remove from disabledVendors)
        const newDisabledVendors = disabledVendors.filter(
          (v) => v !== vendorId
        );
        const newOverrides = { ...overrides };
        if (newDisabledVendors.length === 0) {
          delete newOverrides[packName];
        } else {
          newOverrides[packName] = { disabledVendors: newDisabledVendors };
        }
        await config.update(
          'packVendorOverrides',
          Object.keys(newOverrides).length > 0 ? newOverrides : undefined,
          vscode.ConfigurationTarget.Workspace
        );

        // Disable all OTHER rules in this vendor (except the one we're enabling)
        const currentDisabled = config.get<string[]>('disabledRules', []);
        const disabledSet = new Set(currentDisabled);
        for (const rule of vendorRules) {
          if (rule.id !== ruleId) {
            disabledSet.add(rule.id);
          }
        }
        disabledSet.delete(ruleId);
        await config.update(
          'disabledRules',
          disabledSet.size > 0 ? Array.from(disabledSet) : undefined,
          vscode.ConfigurationTarget.Workspace
        );

        vscode.window.showInformationMessage(
          `SENTRIFLOW: Enabled rule '${ruleId}' - vendor '${vendorId}' enabled, ${
            vendorRules.length - 1
          } other rules disabled`
        );
      } else {
        // Vendor is enabled, just toggle the rule
        await toggleRuleService(ruleId, true, false);
      }
      break;
    }
  }

  state.rulesTreeProvider.refresh();
  rescanActiveEditor();
}

/**
 * Copy rule ID to clipboard
 */
export async function cmdCopyRuleId(item: RuleTreeItem): Promise<void> {
  if (!item || !item.rule) return;
  await vscode.env.clipboard.writeText(item.rule.id);
  vscode.window.showInformationMessage(
    `SENTRIFLOW: Copied '${item.rule.id}' to clipboard`
  );
}

/**
 * View details for a tree item in the output channel
 */
export async function cmdViewRuleDetails(item: RuleTreeItem): Promise<void> {
  if (!item) return;

  const state = getState();
  state.outputChannel.show(true);
  state.outputChannel.appendLine(`\n${'='.repeat(60)}`);

  switch (item.itemType) {
    case 'pack': {
      const pack =
        item.packName === DEFAULT_PACK_NAME
          ? state.defaultPack
          : state.registeredPacks.get(item.packName!);
      if (pack) {
        state.outputChannel.appendLine(`Pack: ${pack.name}`);
        state.outputChannel.appendLine(`${'='.repeat(60)}`);
        state.outputChannel.appendLine(`Publisher:   ${pack.publisher}`);
        state.outputChannel.appendLine(`Version:     ${pack.version}`);
        state.outputChannel.appendLine(`Description: ${pack.description}`);
        state.outputChannel.appendLine(`Priority:    ${pack.priority}`);
        state.outputChannel.appendLine(
          `Rules:       ${
            item.packName === DEFAULT_PACK_NAME
              ? allRules.length
              : pack.rules.length
          }`
        );
        state.outputChannel.appendLine(
          `Status:      ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
        );
      }
      break;
    }

    case 'vendor': {
      state.outputChannel.appendLine(`Vendor: ${item.vendorId}`);
      state.outputChannel.appendLine(`${'='.repeat(60)}`);
      state.outputChannel.appendLine(`Pack:   ${item.packName}`);
      state.outputChannel.appendLine(
        `Status: ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
      );
      break;
    }

    case 'rule': {
      const rule = item.rule!;
      state.outputChannel.appendLine(`Rule: ${rule.id}`);
      state.outputChannel.appendLine(`${'='.repeat(60)}`);
      state.outputChannel.appendLine(`Level:       ${rule.metadata.level}`);
      state.outputChannel.appendLine(`Vendor:      ${rule.vendor ?? 'common'}`);
      state.outputChannel.appendLine(`Selector:    ${rule.selector ?? '(none)'}`);
      state.outputChannel.appendLine(
        `Status:      ${item.isEnabled ? 'Enabled' : 'DISABLED'}`
      );
      if (rule.metadata.description) {
        state.outputChannel.appendLine(`Description: ${rule.metadata.description}`);
      }
      if (rule.metadata.remediation) {
        state.outputChannel.appendLine(`Remediation: ${rule.metadata.remediation}`);
      }
      if (rule.metadata.obu) {
        state.outputChannel.appendLine(`OBU:         ${rule.metadata.obu}`);
      }
      if (rule.metadata.owner) {
        state.outputChannel.appendLine(`Owner:       ${rule.metadata.owner}`);
      }
      if (rule.metadata.security) {
        const sec = rule.metadata.security;
        if (sec.cwe?.length) {
          state.outputChannel.appendLine(`CWE:         ${sec.cwe.join(', ')}`);
        }
        if (sec.cvssScore !== undefined) {
          state.outputChannel.appendLine(`CVSS Score:  ${sec.cvssScore}`);
        }
      }
      if (rule.metadata.tags?.length) {
        state.outputChannel.appendLine(
          `Tags:        ${rule.metadata.tags.map((t) => t.label).join(', ')}`
        );
      }
      break;
    }
  }

  state.outputChannel.appendLine('');
}

// ============================================================================
// Direct Command Handlers (Command Palette)
// ============================================================================

/**
 * Toggle a pack via command palette
 */
export async function cmdTogglePack(): Promise<void> {
  const state = getState();

  interface PackPickItem extends vscode.QuickPickItem {
    packName: string;
    isEnabled: boolean;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const blockedPacks = new Set(config.get<string[]>('blockedPacks', []));

  const items: PackPickItem[] = [];

  // Default pack
  items.push({
    label: `${
      enableDefaultRules ? '$(check)' : '$(circle-slash)'
    } ${DEFAULT_PACK_NAME}`,
    description: enableDefaultRules ? 'Enabled' : 'Disabled',
    detail: `${allRules.length} rules`,
    packName: DEFAULT_PACK_NAME,
    isEnabled: enableDefaultRules,
  });

  // External packs
  for (const [name, pack] of state.registeredPacks) {
    const isEnabled = !blockedPacks.has(name);
    items.push({
      label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${name}`,
      description: isEnabled ? 'Enabled' : 'Disabled',
      detail: `${pack.rules.length} rules | ${pack.publisher}`,
      packName: name,
      isEnabled,
    });
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a pack to toggle',
    title: 'SENTRIFLOW: Toggle Pack',
  });

  if (!selected) return;

  // Create a synthetic tree item to reuse toggle logic
  const item = new RuleTreeItem(
    selected.packName,
    vscode.TreeItemCollapsibleState.None,
    'pack',
    selected.packName,
    undefined,
    undefined,
    undefined,
    selected.isEnabled
  );

  // Toggle: if enabled, disable it; if disabled, enable it
  if (selected.isEnabled) {
    await cmdDisableTreeItem(item);
  } else {
    await cmdEnableTreeItem(item);
  }
}

/**
 * Toggle a vendor via command palette
 */
export async function cmdToggleVendor(): Promise<void> {
  const state = getState();

  interface VendorPickItem extends vscode.QuickPickItem {
    packName: string;
    vendorId: string;
    isEnabled: boolean;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );

  const items: VendorPickItem[] = [];

  // Collect vendors from default pack
  const defaultVendors = new Set<string>();
  for (const rule of allRules) {
    if (rule.vendor) {
      const vendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
      vendors.forEach((v) => defaultVendors.add(v));
    } else {
      defaultVendors.add('common');
    }
  }

  const defaultDisabled = new Set(
    overrides[DEFAULT_PACK_NAME]?.disabledVendors ?? []
  );
  for (const vendor of Array.from(defaultVendors).sort()) {
    const isEnabled = !defaultDisabled.has(vendor);
    items.push({
      label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${vendor}`,
      description: `${DEFAULT_PACK_NAME}`,
      packName: DEFAULT_PACK_NAME,
      vendorId: vendor,
      isEnabled,
    });
  }

  // Collect vendors from external packs
  for (const [packName, pack] of state.registeredPacks) {
    const packVendors = new Set<string>();
    for (const rule of pack.rules) {
      if (rule.vendor) {
        const vendors = Array.isArray(rule.vendor)
          ? rule.vendor
          : [rule.vendor];
        vendors.forEach((v) => packVendors.add(v));
      } else {
        packVendors.add('common');
      }
    }

    const packDisabled = new Set(overrides[packName]?.disabledVendors ?? []);
    for (const vendor of Array.from(packVendors).sort()) {
      const isEnabled = !packDisabled.has(vendor);
      items.push({
        label: `${isEnabled ? '$(check)' : '$(circle-slash)'} ${vendor}`,
        description: packName,
        packName,
        vendorId: vendor,
        isEnabled,
      });
    }
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a vendor to toggle',
    title: 'SENTRIFLOW: Toggle Vendor',
    matchOnDescription: true,
  });

  if (!selected) return;

  const item = new RuleTreeItem(
    selected.vendorId,
    vscode.TreeItemCollapsibleState.None,
    'vendor',
    selected.packName,
    selected.vendorId,
    undefined,
    undefined,
    selected.isEnabled
  );

  if (selected.isEnabled) {
    await cmdDisableTreeItem(item);
  } else {
    await cmdEnableTreeItem(item);
  }
}

/**
 * Disable a rule via command palette with fuzzy search
 */
export async function cmdDisableRuleById(): Promise<void> {
  const disabledRules = getDisabledRulesSet();

  interface RulePickItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RulePickItem[] = allRules
    .filter((r) => !disabledRules.has(r.id))
    .map((r) => ({
      label: `$(${r.metadata.level}) ${r.id}`,
      description: r.vendor
        ? Array.isArray(r.vendor)
          ? r.vendor.join(', ')
          : r.vendor
        : 'common',
      detail: r.metadata.remediation ?? r.metadata.description,
      ruleId: r.id,
    }));

  if (items.length === 0) {
    vscode.window.showInformationMessage(
      'SENTRIFLOW: All rules are already disabled'
    );
    return;
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Type to search rules to disable...',
    title: 'SENTRIFLOW: Disable Rule',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  await toggleRuleService(selected.ruleId, false);
}

/**
 * Enable a disabled rule via command palette
 */
export async function cmdEnableRuleById(): Promise<void> {
  const disabledRules = Array.from(getDisabledRulesSet());

  if (disabledRules.length === 0) {
    vscode.window.showInformationMessage('SENTRIFLOW: No rules are disabled');
    return;
  }

  interface RulePickItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RulePickItem[] = disabledRules.map((id) => {
    const rule = allRules.find((r) => r.id === id);
    return {
      label: `$(circle-slash) ${id}`,
      description: rule?.vendor
        ? Array.isArray(rule.vendor)
          ? rule.vendor.join(', ')
          : rule.vendor
        : 'common',
      detail:
        rule?.metadata.remediation ??
        rule?.metadata.description ??
        'Currently disabled',
      ruleId: id,
    };
  });

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a rule to enable',
    title: 'SENTRIFLOW: Enable Disabled Rule',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  await toggleRuleService(selected.ruleId, true);
}

/**
 * Show all disabled items in the output channel
 */
export async function cmdShowDisabled(): Promise<void> {
  const state = getState();
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const blockedPacks = config.get<string[]>('blockedPacks', []);
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );
  const disabledRules = Array.from(getDisabledRulesSet());

  state.outputChannel.show(true);
  state.outputChannel.appendLine(`\n${'='.repeat(60)}`);
  state.outputChannel.appendLine('SENTRIFLOW: Disabled Items Summary');
  state.outputChannel.appendLine(`${'='.repeat(60)}`);

  // Packs
  state.outputChannel.appendLine('\n--- Disabled Packs ---');
  if (!enableDefaultRules) {
    state.outputChannel.appendLine(
      `  - ${DEFAULT_PACK_NAME} (default rules disabled)`
    );
  }
  for (const pack of blockedPacks) {
    state.outputChannel.appendLine(`  - ${pack}`);
  }
  if (enableDefaultRules && blockedPacks.length === 0) {
    state.outputChannel.appendLine('  (none)');
  }

  // Vendors
  state.outputChannel.appendLine('\n--- Disabled Vendors ---');
  let hasDisabledVendors = false;
  for (const [packName, packOverride] of Object.entries(overrides)) {
    if (
      packOverride.disabledVendors &&
      packOverride.disabledVendors.length > 0
    ) {
      for (const vendor of packOverride.disabledVendors) {
        state.outputChannel.appendLine(`  - ${vendor} (in ${packName})`);
        hasDisabledVendors = true;
      }
    }
  }
  if (!hasDisabledVendors) {
    state.outputChannel.appendLine('  (none)');
  }

  // Rules
  state.outputChannel.appendLine('\n--- Disabled Rules ---');
  if (disabledRules.length > 0) {
    for (const ruleId of disabledRules.sort()) {
      state.outputChannel.appendLine(`  - ${ruleId}`);
    }
  } else {
    state.outputChannel.appendLine('  (none)');
  }

  const totalDisabled =
    (enableDefaultRules ? 0 : 1) +
    blockedPacks.length +
    Object.values(overrides).reduce(
      (sum, o) => sum + (o.disabledVendors?.length ?? 0),
      0
    ) +
    disabledRules.length;

  state.outputChannel.appendLine(`\nTotal disabled items: ${totalDisabled}`);
  state.outputChannel.appendLine('');
}

/**
 * Filter tags by type via quick pick
 */
export async function cmdFilterTagType(): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const current = config.get<string>('tagTypeFilter', 'all');

  interface TypePickItem extends vscode.QuickPickItem {
    value: string;
  }

  const items: TypePickItem[] = [
    {
      label: 'All Types',
      description: 'Show all tags regardless of type',
      value: 'all',
    },
    {
      label: 'Security',
      description: 'Show only security-related tags',
      value: 'security',
    },
    {
      label: 'Operational',
      description: 'Show only operational tags',
      value: 'operational',
    },
    {
      label: 'Compliance',
      description: 'Show only compliance-related tags',
      value: 'compliance',
    },
    {
      label: 'General',
      description: 'Show only general tags',
      value: 'general',
    },
  ];

  // Mark current selection
  for (const item of items) {
    if (item.value === current) {
      item.label = `$(check) ${item.label}`;
    }
  }

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select tag type to filter',
    title: 'Filter Tags by Type',
  });

  if (selected) {
    await config.update(
      'tagTypeFilter',
      selected.value,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Tag filter set to "${selected.value}"`
    );
  }
}

/**
 * Filter diagnostics by category via quick pick
 */
export async function cmdFilterByCategory(): Promise<void> {
  const state = getState();
  const categories = getUniqueCategoriesFromRules(state.currentRuleMap.values());

  interface CategoryPickItem extends vscode.QuickPickItem {
    value: string | undefined;
  }

  const items: CategoryPickItem[] = [
    {
      label:
        state.categoryFilter === undefined
          ? '$(check) All Categories'
          : 'All Categories',
      description: 'Show diagnostics from all categories',
      value: undefined,
    },
    ...categories.map((cat) => ({
      label: state.categoryFilter === cat ? `$(check) ${cat}` : cat,
      description: `Filter to "${cat}" category only`,
      value: cat,
    })),
  ];

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select category to filter diagnostics',
    title: 'Filter Diagnostics by Category',
  });

  if (selected !== undefined) {
    state.categoryFilter = selected.value;

    // Re-scan active editor to apply filter
    if (vscode.window.activeTextEditor) {
      scheduleScan(vscode.window.activeTextEditor.document, 0);
    }

    const filterMsg = state.categoryFilter
      ? `"${state.categoryFilter}"`
      : 'all categories';
    vscode.window.showInformationMessage(
      `SENTRIFLOW: Showing diagnostics from ${filterMsg}`
    );
  }
}

/**
 * Select vendor for current document via command palette.
 * Sets a per-document override that persists for this file.
 */
export async function cmdSelectVendor(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active editor');
    return;
  }

  const state = getState();
  const uri = editor.document.uri.toString();

  // Get current override for this document (if any)
  const currentOverride = state.documentVendorOverrides.get(uri);

  interface VendorPickItem extends vscode.QuickPickItem {
    vendorId: string;
  }

  const items: VendorPickItem[] = [
    {
      label: !currentOverride ? '$(check) $(search) Auto-detect' : '$(search) Auto-detect',
      description: 'Automatically detect vendor from configuration content',
      vendorId: 'auto',
    },
  ];

  // Add all available vendors
  const vendors = getAvailableVendorInfo();
  for (const vendor of vendors) {
    const isSelected = currentOverride === vendor.id;
    items.push({
      label: isSelected ? `$(check) ${vendor.name}` : vendor.name,
      description: vendor.id,
      vendorId: vendor.id,
    });
  }

  // Show QuickPick
  const fileName = path.basename(editor.document.fileName);
  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: `Select vendor for ${fileName}`,
    title: 'SENTRIFLOW: Select Vendor for This File',
  });

  if (selected) {
    if (selected.vendorId === 'auto') {
      // Remove override - use auto-detect
      state.documentVendorOverrides.delete(uri);
      log(`Vendor override removed for ${fileName} - using auto-detect`);
    } else {
      // Set per-document override
      state.documentVendorOverrides.set(uri, selected.vendorId);
      log(`Vendor override set for ${fileName}: ${selected.vendorId}`);
    }

    // Persist to workspace state
    await saveDocumentVendorOverrides();

    // Clear parser cache for this document to force re-parse with new vendor
    state.incrementalParser.invalidate(uri);

    // Update current vendor immediately for status bar
    if (selected.vendorId === 'auto') {
      const text = editor.document.getText();
      state.currentVendor = detectVendor(text);
    } else {
      state.currentVendor = getVendor(selected.vendorId);
    }

    // Update status bar immediately
    updateVendorStatusBar();

    // Re-scan document with forced re-parse
    runScan(editor.document, true);
  }
}
