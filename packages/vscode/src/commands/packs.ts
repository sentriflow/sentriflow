/**
 * Pack Management Commands
 *
 * Commands for viewing and managing rule packs.
 * Includes pack viewer, vendor management, and rule browsing.
 */

import * as vscode from 'vscode';
import type { IRule, RulePack } from '@sentriflow/core';
import { allRules } from '@sentriflow/rules-default';
import { getState } from '../state/context';
import {
  getDisabledRulesSet,
  toggleRule as toggleRuleService,
} from '../services/ruleManager';
import { rescanActiveEditor } from '../services/scanner';
import {
  formatPackDetails,
  getPackVendorCoverage,
} from '../utils/helpers';

// ============================================================================
// Constants
// ============================================================================

export const DEFAULT_PACK_NAME = 'sf-default';

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
// Pack Management Commands
// ============================================================================

/**
 * Command: Show all rule packs
 */
export async function cmdShowRulePacks(): Promise<void> {
  const state = getState();

  interface PackPickItem extends vscode.QuickPickItem {
    packName: string;
    action: 'showAll' | 'selectPack';
  }

  const items: PackPickItem[] = [];

  // Add "Show All Details" option first
  items.push({
    label: '$(info) Show All Details',
    description: 'Dump all pack information to output channel',
    packName: '',
    action: 'showAll',
  });

  // Add separator
  items.push({
    label: '',
    kind: vscode.QuickPickItemKind.Separator,
    packName: '',
    action: 'selectPack',
  });

  // Add default pack
  items.push({
    label: `$(package) ${DEFAULT_PACK_NAME}`,
    description: `${allRules.length} rules | Priority: 0`,
    detail: `Built-in rules | Vendors: all`,
    packName: DEFAULT_PACK_NAME,
    action: 'selectPack',
  });

  // Add registered packs
  for (const [name, pack] of state.registeredPacks) {
    const vendors = getPackVendorCoverage(pack);
    const vendorSummary =
      vendors.length > 3
        ? `${vendors.slice(0, 3).join(', ')}... (+${vendors.length - 3})`
        : vendors.join(', ');

    items.push({
      label: `$(package) ${name}`,
      description: `${pack.rules.length} rules | Priority: ${pack.priority}`,
      detail: `${pack.publisher} | v${pack.version} | Vendors: ${vendorSummary}${
        pack.disables?.all ? ' | Disables defaults' : ''
      }`,
      packName: name,
      action: 'selectPack',
    });
  }

  // Show message if no external packs registered
  if (state.registeredPacks.size === 0) {
    items.push({
      label: '$(warning) No external packs registered',
      description: 'Install rule pack extensions to add more rules',
      packName: '',
      action: 'selectPack',
    });
  }

  // Show QuickPick
  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select a pack to manage',
    title: 'SENTRIFLOW: Rule Packs',
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  if (selected.action === 'showAll') {
    state.outputChannel.show(true);
    state.outputChannel.appendLine(`\n${'#'.repeat(60)}`);
    state.outputChannel.appendLine(
      `SENTRIFLOW Rule Packs - ${new Date().toISOString()}`
    );
    state.outputChannel.appendLine(`${'#'.repeat(60)}`);
    state.outputChannel.appendLine(
      `\nTotal Packs: ${state.registeredPacks.size + 1} (1 default + ${
        state.registeredPacks.size
      } external)`
    );
    state.outputChannel.appendLine(formatPackDetails(state.defaultPack, allRules));
    for (const pack of state.registeredPacks.values()) {
      state.outputChannel.appendLine(formatPackDetails(pack, pack.rules));
    }
    state.outputChannel.appendLine(`\n${'='.repeat(60)}\n`);
    return;
  }

  if (!selected.packName) return;

  // Show pack action menu
  await showPackActions(selected.packName);
}

/**
 * Show action menu for a specific pack
 */
async function showPackActions(packName: string): Promise<void> {
  const state = getState();
  const isDefault = packName === DEFAULT_PACK_NAME;
  const pack = isDefault ? state.defaultPack : state.registeredPacks.get(packName);
  if (!pack) return;

  // Check current disabled state
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);
  const packVendorOverrides = config.get<
    Record<string, { disabledVendors?: string[] }>
  >('packVendorOverrides', {});

  // For non-default packs, check if all vendors are disabled
  let isPackDisabled = false;
  if (!isDefault) {
    const packOverride = packVendorOverrides[packName];
    const disabledVendors = new Set(packOverride?.disabledVendors ?? []);
    if (disabledVendors.size > 0) {
      // Get all vendors in this pack
      const vendorSet = new Set<string>();
      for (const rule of pack.rules) {
        if (rule.vendor) {
          const vendors = Array.isArray(rule.vendor)
            ? rule.vendor
            : [rule.vendor];
          vendors.forEach((v) => vendorSet.add(v));
        } else {
          vendorSet.add('common');
        }
      }
      // Check if all non-common vendors are disabled
      isPackDisabled = Array.from(vendorSet).every(
        (v) => v === 'common' || disabledVendors.has(v)
      );
    }
  }

  interface ActionItem extends vscode.QuickPickItem {
    action: 'details' | 'vendors' | 'rules' | 'disable' | 'enable' | 'back';
  }

  const actions: ActionItem[] = [
    {
      label: '$(info) View Details',
      description: 'Show pack metadata in output channel',
      action: 'details',
    },
    {
      label: '$(list-unordered) View All Rules',
      description: `Browse ${
        isDefault ? allRules.length : pack.rules.length
      } rules with descriptions`,
      action: 'rules',
    },
  ];

  // Add disable/enable option
  if (isDefault) {
    // For default pack, toggle sentriflow.enableDefaultRules
    if (enableDefaultRules) {
      actions.splice(1, 0, {
        label: '$(circle-slash) Disable Pack',
        description: 'Disable all default rules',
        action: 'disable',
      });
    } else {
      actions.splice(1, 0, {
        label: '$(check) Enable Pack',
        description: 'Enable default rules',
        action: 'enable',
      });
    }
  } else {
    // For external packs, toggle all vendors
    actions.splice(1, 0, {
      label: '$(settings-gear) Manage Vendors',
      description: 'Enable/disable vendors for this pack',
      action: 'vendors',
    });

    if (isPackDisabled) {
      actions.splice(2, 0, {
        label: '$(check) Enable Pack',
        description: 'Enable all vendors for this pack',
        action: 'enable',
      });
    } else {
      actions.splice(2, 0, {
        label: '$(circle-slash) Disable Pack',
        description: 'Disable all vendors for this pack',
        action: 'disable',
      });
    }
  }

  actions.push({
    label: '$(arrow-left) Back',
    description: 'Return to pack list',
    action: 'back',
  });

  const action = await vscode.window.showQuickPick(actions, {
    placeHolder: `${packName} - Select action`,
    title: `SENTRIFLOW: ${packName}`,
  });

  if (!action) return;

  switch (action.action) {
    case 'details':
      state.outputChannel.show(true);
      state.outputChannel.appendLine(
        formatPackDetails(pack, isDefault ? allRules : pack.rules)
      );
      break;
    case 'vendors':
      await managePackVendors(packName, pack);
      break;
    case 'rules':
      await showPackRules(packName, pack, isDefault);
      break;
    case 'disable':
      await disablePack(packName, pack, isDefault);
      break;
    case 'enable':
      await enablePack(packName, pack, isDefault);
      break;
    case 'back':
      await cmdShowRulePacks();
      break;
  }
}

/**
 * Disable a pack entirely
 */
async function disablePack(
  packName: string,
  pack: RulePack,
  isDefault: boolean
): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentriflow');

  if (isDefault) {
    // Disable default rules via configuration
    await config.update(
      'enableDefaultRules',
      false,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage('SENTRIFLOW: Default rules disabled');
  } else {
    // Disable all vendors for this pack
    const vendorSet = new Set<string>();
    for (const rule of pack.rules) {
      if (rule.vendor) {
        const vendors = Array.isArray(rule.vendor)
          ? rule.vendor
          : [rule.vendor];
        vendors.forEach((v) => vendorSet.add(v));
      }
    }
    const allVendors = Array.from(vendorSet).filter((v) => v !== 'common');

    if (allVendors.length > 0) {
      const overrides = config.get<
        Record<string, { disabledVendors?: string[] }>
      >('packVendorOverrides', {});
      const newOverrides = { ...overrides };
      newOverrides[packName] = { disabledVendors: allVendors };
      await config.update(
        'packVendorOverrides',
        newOverrides,
        vscode.ConfigurationTarget.Workspace
      );
    }

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Pack '${packName}' disabled`
    );
  }

  rescanActiveEditor();
}

/**
 * Enable a pack (re-enable all vendors or default rules)
 */
async function enablePack(
  packName: string,
  _pack: RulePack,
  isDefault: boolean
): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentriflow');

  if (isDefault) {
    // Enable default rules via configuration
    await config.update(
      'enableDefaultRules',
      true,
      vscode.ConfigurationTarget.Workspace
    );
    vscode.window.showInformationMessage('SENTRIFLOW: Default rules enabled');
  } else {
    // Remove all vendor overrides for this pack
    const overrides = config.get<
      Record<string, { disabledVendors?: string[] }>
    >('packVendorOverrides', {});
    const newOverrides = { ...overrides };
    delete newOverrides[packName];
    await config.update(
      'packVendorOverrides',
      newOverrides,
      vscode.ConfigurationTarget.Workspace
    );

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Pack '${packName}' enabled`
    );
  }

  rescanActiveEditor();
}

/**
 * Manage vendor settings for a pack
 */
async function managePackVendors(
  packName: string,
  pack: RulePack
): Promise<void> {
  // Get unique vendors in this pack
  const vendorSet = new Set<string>();
  for (const rule of pack.rules) {
    if (rule.vendor) {
      const vendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
      vendors.forEach((v) => vendorSet.add(v));
    } else {
      vendorSet.add('common');
    }
  }
  const vendors = Array.from(vendorSet).sort();

  if (vendors.length === 0) {
    vscode.window.showInformationMessage(
      'This pack has no vendor-specific rules.'
    );
    return;
  }

  // Get current disabled vendors
  const config = vscode.workspace.getConfiguration('sentriflow');
  const overrides = config.get<Record<string, { disabledVendors?: string[] }>>(
    'packVendorOverrides',
    {}
  );
  const currentDisabled = new Set(overrides[packName]?.disabledVendors ?? []);

  // Count rules per vendor
  const vendorCounts = new Map<string, number>();
  for (const rule of pack.rules) {
    const v = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(',')
        : rule.vendor
      : 'common';
    vendorCounts.set(v, (vendorCounts.get(v) ?? 0) + 1);
  }

  // Build multi-select items
  interface VendorItem extends vscode.QuickPickItem {
    vendorId: string;
  }

  const items: VendorItem[] = vendors.map((v) => ({
    label: v,
    description: `${vendorCounts.get(v) ?? 0} rules`,
    picked: !currentDisabled.has(v),
    vendorId: v,
  }));

  const selected = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    placeHolder: 'Check vendors to enable, uncheck to disable',
    title: `SENTRIFLOW: ${packName} - Vendor Settings`,
  });

  if (selected === undefined) return; // User cancelled

  // Calculate newly disabled vendors
  const enabledVendors = new Set(selected.map((s) => s.vendorId));
  const disabledVendors = vendors.filter((v) => !enabledVendors.has(v));

  // Update configuration
  const newOverrides = { ...overrides };
  if (disabledVendors.length > 0) {
    newOverrides[packName] = { disabledVendors };
  } else {
    delete newOverrides[packName];
  }

  await config.update(
    'packVendorOverrides',
    newOverrides,
    vscode.ConfigurationTarget.Workspace
  );

  const msg =
    disabledVendors.length > 0
      ? `Disabled ${disabledVendors.length} vendor(s) for ${packName}`
      : `All vendors enabled for ${packName}`;
  vscode.window.showInformationMessage(`SENTRIFLOW: ${msg}`);

  // Rescan to apply changes
  rescanActiveEditor();
}

/**
 * Show all rules in a pack with their details
 */
async function showPackRules(
  packName: string,
  pack: RulePack,
  isDefault: boolean
): Promise<void> {
  const rules = isDefault ? allRules : pack.rules;

  // Get currently disabled rules from settings
  const disabledRules = getDisabledRulesSet();

  interface RuleItem extends vscode.QuickPickItem {
    ruleId: string;
  }

  const items: RuleItem[] = rules.map((rule) => {
    const isDisabled = disabledRules.has(rule.id);
    const levelIcon =
      rule.metadata.level === 'error'
        ? '$(error)'
        : rule.metadata.level === 'warning'
        ? '$(warning)'
        : '$(info)';
    const statusIcon = isDisabled ? '$(circle-slash)' : '$(check)';
    const vendor = rule.vendor
      ? Array.isArray(rule.vendor)
        ? rule.vendor.join(', ')
        : rule.vendor
      : 'common';

    return {
      label: `${statusIcon} ${levelIcon} ${rule.id}`,
      description: `${vendor}${isDisabled ? ' (disabled)' : ''}`,
      detail:
        rule.metadata.remediation ??
        rule.metadata.description ??
        'No description',
      ruleId: rule.id,
    };
  });

  // Add back option at the top
  items.unshift({
    label: '$(arrow-left) Back to pack actions',
    description: '',
    ruleId: '',
  });

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: `${rules.length} rules - Select to view/toggle`,
    title: `SENTRIFLOW: ${packName} - Rules`,
    matchOnDescription: true,
    matchOnDetail: true,
  });

  if (!selected) return;

  if (!selected.ruleId) {
    await showPackActions(packName);
    return;
  }

  // Show rule action menu
  await showRuleActions(selected.ruleId, packName, pack, isDefault);
}

/**
 * Show action menu for a specific rule
 */
async function showRuleActions(
  ruleId: string,
  packName: string,
  pack: RulePack,
  isDefault: boolean
): Promise<void> {
  const state = getState();
  const rules = isDefault ? allRules : pack.rules;
  const rule = rules.find((r) => r.id === ruleId);
  if (!rule) return;

  // Check if rule is disabled
  const disabledRulesSet = getDisabledRulesSet();
  const isDisabled = disabledRulesSet.has(ruleId);

  interface ActionItem extends vscode.QuickPickItem {
    action: 'details' | 'toggle' | 'back';
  }

  const actions: ActionItem[] = [
    {
      label: '$(info) View Details',
      description: 'Show rule metadata in output channel',
      action: 'details',
    },
    {
      label: isDisabled
        ? '$(check) Enable Rule'
        : '$(circle-slash) Disable Rule',
      description: isDisabled
        ? 'Remove from disabled rules list'
        : 'Add to disabled rules list',
      action: 'toggle',
    },
    {
      label: '$(arrow-left) Back to rules list',
      description: '',
      action: 'back',
    },
  ];

  const action = await vscode.window.showQuickPick(actions, {
    placeHolder: `${ruleId} - Select action`,
    title: `SENTRIFLOW: ${ruleId}`,
  });

  if (!action) return;

  switch (action.action) {
    case 'details':
      state.outputChannel.show(true);
      state.outputChannel.appendLine(`\n${'='.repeat(60)}`);
      state.outputChannel.appendLine(`Rule: ${rule.id}`);
      state.outputChannel.appendLine(`${'='.repeat(60)}`);
      state.outputChannel.appendLine(
        `Status:      ${isDisabled ? 'DISABLED' : 'Enabled'}`
      );
      state.outputChannel.appendLine(`Level:       ${rule.metadata.level}`);
      state.outputChannel.appendLine(`Vendor:      ${rule.vendor ?? 'common'}`);
      state.outputChannel.appendLine(`Selector:    ${rule.selector ?? '(none)'}`);
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
      state.outputChannel.appendLine('');
      // Stay in rule actions
      await showRuleActions(ruleId, packName, pack, isDefault);
      break;

    case 'toggle':
      await toggleRuleService(ruleId, isDisabled);
      // Return to rules list to see updated state
      await showPackRules(packName, pack, isDefault);
      break;

    case 'back':
      await showPackRules(packName, pack, isDefault);
      break;
  }
}
