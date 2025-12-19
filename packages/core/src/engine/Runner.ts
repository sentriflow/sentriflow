// packages/core/src/engine/Runner.ts

import type { ConfigNode } from '../types/ConfigNode';
import type { IRule, RuleResult, Context } from '../types/IRule';
import { RuleExecutor } from './RuleExecutor';
import type { ExecutionOptions } from './RuleExecutor';

/**
 * Index structure for fast rule lookup.
 * Reduces selector matching from O(N×R) to O(N×k) where k << R.
 */
interface RuleIndex {
  /** Rules indexed by first keyword of selector (lowercase) */
  byPrefix: Map<string, IRule[]>;
  /** Rules with no selector (global rules that run on all nodes) */
  global: IRule[];
  /** Rules indexed by exact selector match (lowercase) */
  exact: Map<string, IRule[]>;
}

/**
 * Options for RuleEngine.
 */
export interface EngineOptions {
  /** Enable timeout protection for rule execution */
  enableTimeoutProtection?: boolean;
  /** Options for the rule executor (timeout settings) */
  executionOptions?: ExecutionOptions;
}

/**
 * Rule Engine with selector indexing for high-performance rule evaluation.
 *
 * Performance characteristics:
 * - Index build: O(R) where R = number of rules
 * - Per-node lookup: O(1) average case (hash map lookup)
 * - Total scan: O(N×k) where N = nodes, k = average matching rules per node
 *
 * For 500 rules with good selector distribution, k is typically 5-20,
 * giving ~25-100× improvement over naive O(N×R) scanning.
 */
export class RuleEngine {
  private index: RuleIndex | null = null;
  private indexedRules: IRule[] = [];
  private indexVersion = 0;
  private executor: RuleExecutor | null = null;
  private options: EngineOptions;

  constructor(options: EngineOptions = {}) {
    this.options = {
      enableTimeoutProtection: options.enableTimeoutProtection ?? false,
      executionOptions: options.executionOptions,
    };

    if (this.options.enableTimeoutProtection) {
      this.executor = new RuleExecutor(this.options.executionOptions);
    }
  }

  /**
   * Build an index for fast rule lookup.
   * Call this once when rules change, not on every scan.
   *
   * @param rules The rules to index
   */
  public buildIndex(rules: IRule[]): void {
    this.index = {
      byPrefix: new Map(),
      global: [],
      exact: new Map(),
    };
    this.indexedRules = rules;
    this.indexVersion++;

    for (const rule of rules) {
      if (!rule.selector) {
        // No selector = global rule, runs on everything
        this.index.global.push(rule);
        continue;
      }

      const selector = rule.selector.toLowerCase();

      // Index by exact selector
      const exactBucket = this.index.exact.get(selector);
      if (exactBucket) {
        exactBucket.push(rule);
      } else {
        this.index.exact.set(selector, [rule]);
      }

      // Index by first word (prefix) for partial matches
      const prefix = selector.split(/\s+/)[0] ?? selector;
      const prefixBucket = this.index.byPrefix.get(prefix);
      if (prefixBucket) {
        prefixBucket.push(rule);
      } else {
        this.index.byPrefix.set(prefix, [rule]);
      }
    }
  }

  /**
   * Get rules that might match a node.
   * Returns a small subset of total rules based on prefix matching.
   *
   * @param node The configuration node to find candidate rules for
   * @returns Array of rules that may match the node
   */
  private getCandidateRules(node: ConfigNode): IRule[] {
    if (!this.index) {
      return this.indexedRules; // Fallback to all rules if no index
    }

    const nodeId = node.id.toLowerCase();
    const nodePrefix = nodeId.split(/\s+/)[0] ?? nodeId;

    // Start with global rules (always run)
    const candidates: IRule[] = [...this.index.global];

    // Add rules matching the node's prefix
    const prefixRules = this.index.byPrefix.get(nodePrefix);
    if (prefixRules) {
      candidates.push(...prefixRules);
    }

    return candidates;
  }

  /**
   * Run rules against nodes using the index for fast lookup.
   *
   * @param nodes The root nodes of the configuration AST
   * @param rules Optional rules array - if provided and different from indexed rules, rebuilds index
   * @param context Optional global context to pass to rules
   * @returns Array of RuleResult objects
   */
  public run(
    nodes: ConfigNode[],
    rules?: IRule[],
    context: Partial<Context> = {}
  ): RuleResult[] {
    // Rebuild index if rules provided and different
    if (rules && rules !== this.indexedRules) {
      this.buildIndex(rules);
    }

    // If no rules indexed, return empty results
    if (this.indexedRules.length === 0) {
      return [];
    }

    const results: RuleResult[] = [];

    // Create context once with lazy AST getter
    const ruleContext: Context = {
      ...context,
      getAst: () => nodes,
    };

    const visit = (node: ConfigNode): void => {
      // Only check candidate rules, not all rules
      const candidates = this.getCandidateRules(node);

      for (const rule of candidates) {
        if (this.matchesSelector(node, rule.selector)) {
          // Use executor if timeout protection is enabled
          if (this.executor) {
            const result = this.executor.execute(rule, node, ruleContext);
            if (result) {
              results.push(result);
            }
          } else {
            // Direct execution without timeout protection
            try {
              const result = rule.check(node, ruleContext);
              if (result) {
                results.push(result);
              }
            } catch (error) {
              results.push({
                passed: false,
                message: `Rule execution error: ${
                  error instanceof Error ? error.message : String(error)
                }`,
                ruleId: rule.id,
                nodeId: node.id,
                level: 'error',
                loc: node.loc,
              });
            }
          }
        }
      }

      // Recurse into children
      for (const child of node.children) {
        visit(child);
      }
    };

    for (const node of nodes) {
      visit(node);
    }

    return results;
  }

  /**
   * Checks if a node matches a rule's selector.
   * Uses case-insensitive prefix matching.
   *
   * @param node The configuration node
   * @param selector The selector string (e.g., "interface", "router bgp")
   * @returns True if the node matches the selector
   */
  private matchesSelector(node: ConfigNode, selector?: string): boolean {
    if (!selector) return true;
    return node.id.toLowerCase().startsWith(selector.toLowerCase());
  }

  /**
   * Check if the index needs rebuilding.
   * Useful for determining when to call buildIndex().
   *
   * @param rules The rules to check against
   * @returns True if the rules differ from the indexed rules
   */
  public needsReindex(rules: IRule[]): boolean {
    return rules !== this.indexedRules;
  }

  /**
   * Get the current index version.
   * Increments each time buildIndex() is called.
   */
  public getIndexVersion(): number {
    return this.indexVersion;
  }

  /**
   * Get statistics about the current index.
   * Useful for debugging and performance monitoring.
   */
  public getIndexStats(): {
    totalRules: number;
    globalRules: number;
    prefixBuckets: number;
    exactBuckets: number;
    avgRulesPerPrefix: number;
  } {
    if (!this.index) {
      return {
        totalRules: 0,
        globalRules: 0,
        prefixBuckets: 0,
        exactBuckets: 0,
        avgRulesPerPrefix: 0,
      };
    }

    const prefixBuckets = this.index.byPrefix.size;
    let totalPrefixRules = 0;
    for (const bucket of this.index.byPrefix.values()) {
      totalPrefixRules += bucket.length;
    }

    return {
      totalRules: this.indexedRules.length,
      globalRules: this.index.global.length,
      prefixBuckets,
      exactBuckets: this.index.exact.size,
      avgRulesPerPrefix: prefixBuckets > 0 ? totalPrefixRules / prefixBuckets : 0,
    };
  }

  /**
   * Clear the index and release memory.
   */
  public clearIndex(): void {
    this.index = null;
    this.indexedRules = [];
  }

  /**
   * Get the rule executor (if timeout protection is enabled).
   */
  public getExecutor(): RuleExecutor | null {
    return this.executor;
  }

  /**
   * Get list of auto-disabled rules (if timeout protection is enabled).
   */
  public getDisabledRules(): string[] {
    return this.executor?.getDisabledRules() ?? [];
  }

  /**
   * Re-enable a previously disabled rule.
   */
  public enableRule(ruleId: string): void {
    this.executor?.enableRule(ruleId);
  }

  /**
   * Reset executor state (timeout counts, disabled rules).
   */
  public resetExecutor(): void {
    this.executor?.resetAll();
  }
}
