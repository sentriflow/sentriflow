// packages/rules-default/src/mikrotik/routeros-rules.ts
// MikroTik RouterOS demo rules (basic rules for demonstration purposes)
// Full security rule pack available in @sentriflow/netsec-pack

import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import {
  equalsIgnoreCase,
  isFeatureDisabled,
} from '@sentriflow/core';
import {
  getAddCommands,
  parseProperty,
  getFirewallChain,
  getFirewallAction,
  isServiceDisabled,
  getSystemIdentity,
} from '@sentriflow/core/helpers/mikrotik';

// ============================================================================
// Demo Rules - Basic configuration checks for MikroTik RouterOS
// For comprehensive security rules, use @sentriflow/netsec-pack
// ============================================================================

/**
 * MIK-SYS-001: System identity (hostname) must be configured
 * Basic rule to ensure the router has a meaningful hostname
 */
export const MikrotikSystemIdentity: IRule = {
  id: 'MIK-SYS-001',
  selector: '/system identity',
  vendor: 'mikrotik-routeros',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure system identity: /system identity set name=MyRouter',
  },
  check: (node: ConfigNode): RuleResult => {
    const identity = getSystemIdentity(node);

    if (!identity || equalsIgnoreCase(identity, 'mikrotik') || equalsIgnoreCase(identity, 'routerboard')) {
      return {
        passed: false,
        message: 'System identity should be changed from default. Configure a meaningful hostname.',
        ruleId: 'MIK-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `System identity is configured: ${identity}`,
      ruleId: 'MIK-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * MIK-SEC-001: Disable unused services
 * Basic security rule to check for dangerous enabled services
 */
export const MikrotikDisableUnusedServices: IRule = {
  id: 'MIK-SEC-001',
  selector: '/ip service',
  vendor: 'mikrotik-routeros',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable unused services: /ip service disable telnet,ftp,www,api,api-ssl',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];
    const dangerousServices = ['telnet', 'ftp', 'api', 'www'];

    for (const child of node.children) {
      const childId = child.id.toLowerCase();

      for (const service of dangerousServices) {
        if (childId.includes(service) && !isServiceDisabled(child)) {
          const disabled = parseProperty(child.id, 'disabled');
          if (!disabled || !equalsIgnoreCase(disabled, 'yes')) {
            issues.push(`Service '${service}' is enabled. Consider disabling it.`);
          }
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'MIK-SEC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Dangerous services appear to be managed.',
      ruleId: 'MIK-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * MIK-FW-001: Input chain should have drop rule
 * Basic firewall rule to ensure default-deny policy
 */
export const MikrotikInputChainDrop: IRule = {
  id: 'MIK-FW-001',
  selector: '/ip firewall filter',
  vendor: 'mikrotik-routeros',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Add drop rule for input chain: add chain=input action=drop',
  },
  check: (node: ConfigNode): RuleResult => {
    const addCommands = getAddCommands(node);

    let hasInputDrop = false;
    for (const cmd of addCommands) {
      const chain = getFirewallChain(cmd);
      const action = getFirewallAction(cmd);

      if (chain && equalsIgnoreCase(chain, 'input') && action && equalsIgnoreCase(action, 'drop')) {
        hasInputDrop = true;
        break;
      }
    }

    if (!hasInputDrop) {
      return {
        passed: false,
        message: 'Firewall input chain has no default drop rule. This may leave the router exposed.',
        ruleId: 'MIK-FW-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Firewall input chain has drop rule.',
      ruleId: 'MIK-FW-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export demo rules
// ============================================================================

export const allMikroTikRules: IRule[] = [
  MikrotikSystemIdentity,
  MikrotikDisableUnusedServices,
  MikrotikInputChainDrop,
];
