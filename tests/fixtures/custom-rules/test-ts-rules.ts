/**
 * Test TypeScript Rules for CLI Integration Testing
 *
 * These rules are used to verify custom TypeScript rule loading works correctly.
 */

import type { IRule, ConfigNode, Context, RuleResult } from '@sentriflow/core';

/**
 * TEST-TS-001: VTY Lines Missing exec-timeout
 * Checks that VTY lines have an exec-timeout configured for security
 */
const vtyExecTimeoutRule: IRule = {
  id: 'TEST-TS-001',
  selector: 'line vty',
  vendor: ['cisco-ios', 'cisco-nxos'],
  category: 'security',
  check: (node: ConfigNode, _context: Context): RuleResult => {
    // Look for exec-timeout command in children
    const hasExecTimeout = node.children?.some(
      (child) => child.command?.toLowerCase().startsWith('exec-timeout')
    );

    if (!hasExecTimeout) {
      return {
        passed: false,
        message: `VTY line ${node.params.join(' ')} is missing exec-timeout configuration`,
        ruleId: 'TEST-TS-001',
        nodeId: node.id,
        level: 'warning',
        remediation: 'Add "exec-timeout <minutes> <seconds>" command under the VTY line configuration',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VTY line has exec-timeout configured',
      ruleId: 'TEST-TS-001',
      nodeId: node.id,
      level: 'info',
    };
  },
  metadata: {
    level: 'warning',
    obu: 'Network Security',
    owner: 'Test Suite',
    description: 'VTY lines should have exec-timeout configured to automatically disconnect idle sessions',
    remediation: 'Add "exec-timeout <minutes> <seconds>" command under the VTY line configuration',
  },
};

/**
 * TEST-TS-002: Console Line Missing logging synchronous
 * Checks that console line has logging synchronous for better usability
 */
const consoleLoggingSyncRule: IRule = {
  id: 'TEST-TS-002',
  selector: 'line con',
  vendor: ['cisco-ios', 'cisco-nxos'],
  category: 'usability',
  check: (node: ConfigNode, _context: Context): RuleResult => {
    // Look for logging synchronous command in children
    const hasLoggingSync = node.children?.some(
      (child) => child.command?.toLowerCase().includes('logging synchronous')
    );

    if (!hasLoggingSync) {
      return {
        passed: false,
        message: 'Console line is missing "logging synchronous" configuration',
        ruleId: 'TEST-TS-002',
        nodeId: node.id,
        level: 'info',
        remediation: 'Add "logging synchronous" command under the console line configuration',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Console line has logging synchronous configured',
      ruleId: 'TEST-TS-002',
      nodeId: node.id,
      level: 'info',
    };
  },
  metadata: {
    level: 'info',
    obu: 'Network Operations',
    owner: 'Test Suite',
    description: 'Console line should have logging synchronous to prevent log messages from interrupting command input',
    remediation: 'Add "logging synchronous" command under the console line configuration',
  },
};

// Export rules array for dynamic loading
export const rules: IRule[] = [vtyExecTimeoutRule, consoleLoggingSyncRule];

// Default export for compatibility
export default rules;
