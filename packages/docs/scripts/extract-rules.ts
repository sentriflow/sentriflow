#!/usr/bin/env bun
/**
 * Extract rules from @sentriflow/rules-default for documentation.
 * Outputs a JSON file with all rule metadata (excluding check functions).
 *
 * Usage:
 *   bun run scripts/extract-rules.ts
 *   bun run extract-rules
 */

import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import type { IRule, RuleMetadata, SecurityMetadata, Tag } from '@sentriflow/core';

// Import all rules from rules-default
import { allRules } from '@sentriflow/rules-default';

/**
 * Serializable rule data for documentation.
 * Excludes the `check` function which cannot be serialized.
 */
interface RuleData {
  id: string;
  selector?: string;
  vendor?: string | string[];
  category?: string | string[];
  metadata: {
    level: 'error' | 'warning' | 'info';
    obu: string;
    owner: string;
    description?: string;
    remediation?: string;
    security?: SecurityMetadata;
    tags?: Tag[];
  };
}

/**
 * Output format for the rules JSON file.
 */
interface RulesOutput {
  version: string;
  generatedAt: string;
  totalRules: number;
  rules: RuleData[];
  summary: {
    byVendor: Record<string, number>;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
}

/**
 * Extract serializable data from an IRule.
 */
function extractRuleData(rule: IRule): RuleData {
  return {
    id: rule.id,
    selector: rule.selector,
    vendor: rule.vendor,
    category: rule.category,
    metadata: {
      level: rule.metadata.level,
      obu: rule.metadata.obu,
      owner: rule.metadata.owner,
      description: rule.metadata.description,
      remediation: rule.metadata.remediation,
      security: rule.metadata.security,
      tags: rule.metadata.tags,
    },
  };
}

/**
 * Count rules by a field that can be string or string[].
 */
function countByField(
  rules: RuleData[],
  getField: (rule: RuleData) => string | string[] | undefined
): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const rule of rules) {
    const value = getField(rule);
    if (value === undefined) {
      counts['common'] = (counts['common'] || 0) + 1;
    } else if (Array.isArray(value)) {
      for (const v of value) {
        counts[v] = (counts[v] || 0) + 1;
      }
    } else {
      counts[value] = (counts[value] || 0) + 1;
    }
  }

  return counts;
}

/**
 * Main extraction function.
 */
function extractRules(): void {
  console.log(`Extracting ${allRules.length} rules from @sentriflow/rules-default...`);

  // Extract serializable data from all rules
  const rulesData = allRules.map(extractRuleData);

  // Generate summary statistics
  const summary = {
    byVendor: countByField(rulesData, (r) => r.vendor),
    bySeverity: {
      error: rulesData.filter((r) => r.metadata.level === 'error').length,
      warning: rulesData.filter((r) => r.metadata.level === 'warning').length,
      info: rulesData.filter((r) => r.metadata.level === 'info').length,
    },
    byCategory: countByField(rulesData, (r) => r.category),
  };

  // Build output
  const output: RulesOutput = {
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    totalRules: rulesData.length,
    rules: rulesData,
    summary,
  };

  // Ensure data directory exists
  const outputPath = join(dirname(import.meta.path), '..', 'data', 'rules.json');
  const outputDir = dirname(outputPath);

  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  // Write output
  writeFileSync(outputPath, JSON.stringify(output, null, 2));

  console.log(`\nExtracted ${rulesData.length} rules to ${outputPath}`);
  console.log('\nSummary:');
  console.log(`  By Severity:`);
  console.log(`    - error: ${summary.bySeverity.error}`);
  console.log(`    - warning: ${summary.bySeverity.warning}`);
  console.log(`    - info: ${summary.bySeverity.info}`);
  console.log(`  By Vendor: ${Object.keys(summary.byVendor).length} vendors`);
  console.log(`  By Category: ${Object.keys(summary.byCategory).length} categories`);
}

// Run extraction
extractRules();
