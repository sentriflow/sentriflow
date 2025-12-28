// packages/core/src/engine/RuleExecutor.ts

import type { ConfigNode } from '../types/ConfigNode';
import type { IRule, RuleResult, Context } from '../types/IRule';
import { RULE_PER_NODE_TIMEOUT_MS } from '../constants';

/**
 * Options for rule execution.
 */
export interface ExecutionOptions {
  /** Timeout in milliseconds per rule per node. Default: RULE_PER_NODE_TIMEOUT_MS */
  timeoutMs?: number;
  /** Number of timeouts before auto-disabling a rule. Default: 3 */
  maxTimeouts?: number;
  /** Callback when a rule times out */
  onTimeout?: (ruleId: string, nodeId: string, elapsedMs: number) => void;
  /** Callback when a rule is auto-disabled */
  onRuleDisabled?: (ruleId: string, reason: string) => void;
  /** Callback when a rule throws an error during execution */
  onError?: (ruleId: string, nodeId: string, error: unknown) => void;
}

/**
 * Statistics about rule execution.
 */
export interface ExecutionStats {
  /** Total rules executed */
  rulesExecuted: number;
  /** Total execution time in milliseconds */
  totalTimeMs: number;
  /** Number of timeouts detected */
  timeoutCount: number;
  /** Rules that exceeded timeout threshold */
  slowRules: Map<string, { count: number; totalMs: number }>;
}

/**
 * Handles rule execution with timeout protection and auto-disabling of slow rules.
 *
 * Features:
 * - Tracks execution time per rule
 * - Auto-disables rules that repeatedly timeout
 * - Provides execution statistics for debugging
 * - Graceful error handling
 *
 * Usage:
 * ```typescript
 * const executor = new RuleExecutor();
 *
 * const result = executor.execute(rule, node, context);
 *
 * // Check for disabled rules
 * const disabled = executor.getDisabledRules();
 * ```
 */
export class RuleExecutor {
  private timeoutCounts = new Map<string, number>();
  private executionTimes = new Map<string, { count: number; totalMs: number }>();
  private disabledRules = new Set<string>();
  private options: Required<Omit<ExecutionOptions, 'onError'>> & Pick<ExecutionOptions, 'onError'>;

  constructor(options: ExecutionOptions = {}) {
    this.options = {
      timeoutMs: options.timeoutMs ?? RULE_PER_NODE_TIMEOUT_MS,
      maxTimeouts: options.maxTimeouts ?? 3,
      onTimeout: options.onTimeout ?? (() => {}),
      onRuleDisabled: options.onRuleDisabled ?? (() => {}),
      onError: options.onError,
    };
  }

  /**
   * Execute a rule against a node with timeout protection.
   *
   * @param rule The rule to execute
   * @param node The configuration node to check
   * @param context The execution context
   * @returns RuleResult or null if rule is disabled/skipped
   */
  public execute(
    rule: IRule,
    node: ConfigNode,
    context: Context
  ): RuleResult | null {
    // Skip disabled rules
    if (this.disabledRules.has(rule.id)) {
      return null;
    }

    const startTime = performance.now();

    try {
      const result = rule.check(node, context);
      const elapsed = performance.now() - startTime;

      // Track execution time
      this.trackExecutionTime(rule.id, elapsed);

      // Check for timeout
      if (elapsed > this.options.timeoutMs) {
        this.handleTimeout(rule.id, node.id, elapsed);
      }

      return result;
    } catch (error) {
      const elapsed = performance.now() - startTime;
      this.trackExecutionTime(rule.id, elapsed);

      // Call error callback if provided (for debugging)
      this.options.onError?.(rule.id, node.id, error);

      // SEC-005: Sanitize error message to prevent information disclosure
      // Don't expose internal error details which could reveal file paths or sensitive data
      return {
        passed: false,
        message: `Rule ${rule.id} failed to execute. Check rule implementation.`,
        ruleId: rule.id,
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }
  }

  /**
   * Track execution time for a rule.
   */
  private trackExecutionTime(ruleId: string, elapsedMs: number): void {
    const existing = this.executionTimes.get(ruleId) ?? { count: 0, totalMs: 0 };
    existing.count++;
    existing.totalMs += elapsedMs;
    this.executionTimes.set(ruleId, existing);
  }

  /**
   * Handle a rule timeout.
   */
  private handleTimeout(ruleId: string, nodeId: string, elapsedMs: number): void {
    const currentCount = (this.timeoutCounts.get(ruleId) ?? 0) + 1;
    this.timeoutCounts.set(ruleId, currentCount);

    this.options.onTimeout(ruleId, nodeId, elapsedMs);

    // Auto-disable after max timeouts
    if (currentCount >= this.options.maxTimeouts) {
      this.disabledRules.add(ruleId);
      this.options.onRuleDisabled(
        ruleId,
        `Auto-disabled after ${currentCount} timeouts (>${this.options.timeoutMs}ms)`
      );
    }
  }

  /**
   * Check if a rule is disabled.
   */
  public isDisabled(ruleId: string): boolean {
    return this.disabledRules.has(ruleId);
  }

  /**
   * Get list of auto-disabled rule IDs.
   */
  public getDisabledRules(): string[] {
    return Array.from(this.disabledRules);
  }

  /**
   * Get timeout count for a specific rule.
   */
  public getTimeoutCount(ruleId: string): number {
    return this.timeoutCounts.get(ruleId) ?? 0;
  }

  /**
   * Manually disable a rule.
   */
  public disableRule(ruleId: string): void {
    this.disabledRules.add(ruleId);
  }

  /**
   * Re-enable a previously disabled rule.
   */
  public enableRule(ruleId: string): void {
    this.disabledRules.delete(ruleId);
    this.timeoutCounts.delete(ruleId);
  }

  /**
   * Reset timeout counts (e.g., when rules are reloaded).
   * Does not re-enable disabled rules.
   */
  public resetTimeoutCounts(): void {
    this.timeoutCounts.clear();
  }

  /**
   * Reset all state including disabled rules.
   */
  public resetAll(): void {
    this.timeoutCounts.clear();
    this.executionTimes.clear();
    this.disabledRules.clear();
  }

  /**
   * Get execution statistics.
   */
  public getStats(): ExecutionStats {
    let totalExecutions = 0;
    let totalTime = 0;
    const slowRules = new Map<string, { count: number; totalMs: number }>();

    for (const [ruleId, stats] of this.executionTimes) {
      totalExecutions += stats.count;
      totalTime += stats.totalMs;

      // Consider rules slow if average time > 10ms
      const avgTime = stats.totalMs / stats.count;
      if (avgTime > 10) {
        slowRules.set(ruleId, stats);
      }
    }

    return {
      rulesExecuted: totalExecutions,
      totalTimeMs: totalTime,
      timeoutCount: Array.from(this.timeoutCounts.values()).reduce((a, b) => a + b, 0),
      slowRules,
    };
  }

  /**
   * Get average execution time for a rule.
   */
  public getAverageTime(ruleId: string): number {
    const stats = this.executionTimes.get(ruleId);
    if (!stats || stats.count === 0) return 0;
    return stats.totalMs / stats.count;
  }

  /**
   * Get the slowest rules by average execution time.
   *
   * @param limit Maximum number of rules to return
   * @returns Array of [ruleId, avgTimeMs] sorted by time descending
   */
  public getSlowestRules(limit = 10): Array<[string, number]> {
    const avgTimes: Array<[string, number]> = [];

    for (const [ruleId, stats] of this.executionTimes) {
      if (stats.count > 0) {
        avgTimes.push([ruleId, stats.totalMs / stats.count]);
      }
    }

    return avgTimes
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit);
  }
}
