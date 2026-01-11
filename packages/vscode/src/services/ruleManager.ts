/**
 * Rule Manager Service
 *
 * Manages rule state, filtering, and toggling.
 * Provides functions for querying and manipulating rules across packs.
 */

import * as vscode from 'vscode';
import {
  ruleAppliesToVendor,
  compileJsonRules,
} from '@sentriflow/core';
import type { IRule, RuleVendor } from '@sentriflow/core';
import { allRules, getRulesByVendor } from '@sentriflow/rules-default';
import { getState } from '../state/context';
import { parseCommaSeparated } from '../utils/helpers';

// ============================================================================
// Disabled Rules Management
// ============================================================================

/**
 * Parse disabledRules setting, handling comma-separated values.
 * Users might enter "NET-001,NET-002" as a single item instead of separate items.
 * Also includes disabled custom rules from customRules.disabledRules setting.
 */
export function getDisabledRulesSet(): Set<string> {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const disabledRules = config.get<string[]>('disabledRules', []);
  const disabledCustomRules = config.get<string[]>('customRules.disabledRules', []);

  return new Set([
    ...parseCommaSeparated(disabledRules),
    ...parseCommaSeparated(disabledCustomRules),
  ]);
}

/**
 * Check if a rule should be disabled based on settings and pack disable configs.
 * @param ruleId The rule ID to check
 * @param vendorId Optional vendor ID for vendor-specific disable checks
 * @param checkPackDisables Whether to check pack disable configs (for default rules only)
 */
export function isRuleDisabled(
  ruleId: string,
  vendorId: string | undefined,
  checkPackDisables: boolean = true
): boolean {
  const state = getState();

  // Check user's disabledRules setting (applies to ALL rules)
  const disabledRulesSet = getDisabledRulesSet();
  if (disabledRulesSet.has(ruleId)) {
    if (state.debugMode) {
      state.outputChannel.appendLine(`[DEBUG] Rule ${ruleId} disabled via settings`);
    }
    return true;
  }

  // Check legacy disabled set (programmatic API)
  if (state.disabledRuleIds.has(ruleId)) {
    return true;
  }

  // Check pack disable configs (only for default rules)
  if (checkPackDisables) {
    for (const pack of state.registeredPacks.values()) {
      if (!pack.disables) continue;

      // Check if all defaults are disabled
      if (pack.disables.all) {
        return true;
      }

      // Check if this specific rule is disabled
      if (pack.disables.rules?.includes(ruleId)) {
        return true;
      }

      // Check if vendor is disabled (only if we know the vendor)
      if (vendorId && pack.disables.vendors?.includes(vendorId as RuleVendor)) {
        return true;
      }
    }
  }

  return false;
}

// ============================================================================
// Rule Retrieval
// ============================================================================

/**
 * Get all rules from all packs, filtered by vendor and respecting priorities.
 *
 * Rule resolution order:
 * 1. Default pack rules (priority 0) - filtered by vendor, can be disabled
 * 2. Registered packs sorted by priority (higher wins)
 * 3. Same rule ID: higher priority pack wins
 *
 * @param vendorId Optional vendor ID to filter rules. If not provided, returns all rules.
 */
export function getAllRules(vendorId?: string): IRule[] {
  const state = getState();

  // Track rules by ID with their source priority
  const ruleMap = new Map<string, { rule: IRule; priority: number }>();

  // Check if default rules are enabled
  const config = vscode.workspace.getConfiguration('sentriflow');
  const enableDefaultRules = config.get<boolean>('enableDefaultRules', true);

  // 1. Add default pack rules (priority 0) - only if enabled
  if (enableDefaultRules) {
    const defaultRules = vendorId ? getRulesByVendor(vendorId) : allRules;
    for (const rule of defaultRules) {
      // Check if this default rule is disabled (check pack disables for default rules)
      if (isRuleDisabled(rule.id, vendorId, true)) {
        continue;
      }
      ruleMap.set(rule.id, { rule, priority: 0 });
    }
  }

  // 2. Get all registered packs sorted by priority (ascending, so higher priority processes last and wins)
  const sortedPacks = Array.from(state.registeredPacks.values()).sort(
    (a, b) => a.priority - b.priority
  );

  // Get per-pack vendor overrides and blocked packs
  const packVendorOverrides = config.get<
    Record<string, { disabledVendors?: string[] }>
  >('packVendorOverrides', {});
  const blockedPacks = new Set(config.get<string[]>('blockedPacks', []));

  // 3. Process each pack's rules
  for (const pack of sortedPacks) {
    // Skip blocked packs entirely
    if (blockedPacks.has(pack.name)) {
      continue;
    }

    // Get disabled vendors for this pack
    const packOverride = packVendorOverrides[pack.name];
    const disabledVendors = new Set(packOverride?.disabledVendors ?? []);

    for (const rule of pack.rules) {
      // Check if rule is globally disabled via settings (don't check pack disables for non-default packs)
      if (isRuleDisabled(rule.id, vendorId, false)) {
        continue;
      }

      // Filter by vendor if specified
      if (vendorId && !ruleAppliesToVendor(rule, vendorId)) {
        continue;
      }

      // Check if rule's vendor is disabled for this pack
      if (disabledVendors.size > 0) {
        // Rules without vendor or with vendor='common' are treated as 'common'
        const ruleVendors = rule.vendor
          ? Array.isArray(rule.vendor)
            ? rule.vendor
            : [rule.vendor]
          : ['common'];
        // Check if all of the rule's vendors are disabled
        const allVendorsDisabled = ruleVendors.every((v) =>
          disabledVendors.has(v)
        );
        if (allVendorsDisabled) {
          continue;
        }
      }

      // Check if this rule ID already exists
      const existing = ruleMap.get(rule.id);
      if (existing) {
        // Only override if this pack has higher or equal priority
        if (pack.priority >= existing.priority) {
          ruleMap.set(rule.id, { rule, priority: pack.priority });
        }
      } else {
        ruleMap.set(rule.id, { rule, priority: pack.priority });
      }
    }
  }

  // 4. Add custom rules with highest priority (1000)
  const CUSTOM_RULES_PRIORITY = 1000;
  const customRulesEnabled = config.get<boolean>('customRules.enabled', true);
  if (customRulesEnabled && state.customRulesLoader) {
    try {
      const jsonRules = state.customRulesLoader.getRules();
      if (jsonRules.length > 0) {
        const compiledRules = compileJsonRules(jsonRules);
        for (const rule of compiledRules) {
          // Filter by vendor if specified
          if (vendorId && !ruleAppliesToVendor(rule, vendorId)) {
            continue;
          }
          // Custom rules always override with highest priority
          ruleMap.set(rule.id, { rule, priority: CUSTOM_RULES_PRIORITY });
        }
      }
    } catch (error) {
      // Log but don't fail - custom rules compilation errors shouldn't break scanning
      if (state.debugMode) {
        state.outputChannel.appendLine(
          `[DEBUG] Custom rules compilation error: ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }
  }

  const rules = Array.from(ruleMap.values()).map((entry) => entry.rule);

  // Update state's rule map for O(1) lookup in diagnostics
  state.currentRuleMap = new Map(rules.map((r) => [r.id, r]));

  return rules;
}

/**
 * Get a rule by its ID from the current rule map.
 */
export function getRuleById(ruleId: string): IRule | undefined {
  const state = getState();
  return state.currentRuleMap.get(ruleId);
}

// ============================================================================
// Rule Toggling
// ============================================================================

/**
 * Toggle a rule's enabled/disabled state.
 */
export async function toggleRule(
  ruleId: string,
  currentlyDisabled: boolean,
  isCustomRule: boolean = false
): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentriflow');
  const settingKey = isCustomRule ? 'customRules.disabledRules' : 'disabledRules';
  const currentDisabled = config.get<string[]>(settingKey, []);
  const disabledSet = new Set(parseCommaSeparated(currentDisabled));

  if (currentlyDisabled) {
    // Enable the rule
    disabledSet.delete(ruleId);
  } else {
    // Disable the rule
    disabledSet.add(ruleId);
  }

  await config.update(
    settingKey,
    Array.from(disabledSet),
    vscode.ConfigurationTarget.Workspace
  );
}
