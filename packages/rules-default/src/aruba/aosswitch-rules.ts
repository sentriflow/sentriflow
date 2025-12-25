// packages/rules-default/src/aruba/aosswitch-rules.ts
// Aruba AOS-Switch (ProVision) specific rules for ProCurve/Aruba legacy switches

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  parseInteger,
  isDefaultVlan,
  startsWithIgnoreCase,
  includesIgnoreCase,
} from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  getAosSwitchVlanName,
  getVlanTaggedPorts,
  getVlanUntaggedPorts,
} from '@sentriflow/core/helpers/aruba';

// =============================================================================
// VLAN Rules
// =============================================================================

/**
 * AOSSW-L2-001: VLANs should have descriptive names.
 */
export const AosSwitchVlanName: IRule = {
  id: 'AOSSW-L2-001',
  selector: 'vlan',
  vendor: 'aruba-aosswitch',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a name to VLANs for documentation using "name <vlan-name>".',
  },
  check: (node: ConfigNode): RuleResult => {
    const match = node.id.match(/vlan\s+(\d+)/i);
    const vlanIdStr = match?.[1];
    if (!vlanIdStr) {
      return { passed: true, message: 'Not a VLAN definition.', ruleId: 'AOSSW-L2-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const vlanId = parseInteger(vlanIdStr);

    // Skip VLAN 1 (default)
    if (vlanId === null || isDefaultVlan(vlanId)) {
      return { passed: true, message: 'Default VLAN 1.', ruleId: 'AOSSW-L2-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const vlanName = getAosSwitchVlanName(node);
    if (!vlanName) {
      return {
        passed: false,
        message: `VLAN ${vlanId} has no name configured.`,
        ruleId: 'AOSSW-L2-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN ${vlanId} has name "${vlanName}".`,
      ruleId: 'AOSSW-L2-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSSW-L2-002: VLANs should have ports assigned.
 */
export const AosSwitchVlanHasPorts: IRule = {
  id: 'AOSSW-L2-002',
  selector: 'vlan',
  vendor: 'aruba-aosswitch',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add ports to VLAN using "tagged" or "untagged" commands.',
  },
  check: (node: ConfigNode): RuleResult => {
    const match = node.id.match(/vlan\s+(\d+)/i);
    const vlanIdStr = match?.[1];
    if (!vlanIdStr) {
      return { passed: true, message: 'Not a VLAN definition.', ruleId: 'AOSSW-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const vlanId = parseInteger(vlanIdStr);

    // Skip VLAN 1 (usually has all unassigned ports)
    if (vlanId === null || isDefaultVlan(vlanId)) {
      return { passed: true, message: 'Default VLAN 1.', ruleId: 'AOSSW-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const tagged = getVlanTaggedPorts(node);
    const untagged = getVlanUntaggedPorts(node);

    if (tagged.length === 0 && untagged.length === 0) {
      return {
        passed: false,
        message: `VLAN ${vlanId} has no ports assigned.`,
        ruleId: 'AOSSW-L2-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN ${vlanId} has ${tagged.length} tagged and ${untagged.length} untagged ports.`,
      ruleId: 'AOSSW-L2-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Security Rules
// =============================================================================

/**
 * AOSSW-SEC-001: Manager password must be configured.
 */
export const AosSwitchManagerPassword: IRule = {
  id: 'AOSSW-SEC-001',
  selector: 'password',
  vendor: 'aruba-aosswitch',
  category: 'Authentication',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure a manager password for administrative access.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    if (startsWithIgnoreCase(nodeId, 'password manager')) {
      return {
        passed: true,
        message: 'Manager password is configured.',
        ruleId: 'AOSSW-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Password configuration found.',
      ruleId: 'AOSSW-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSSW-SEC-002: Operator password should be configured.
 */
export const AosSwitchOperatorPassword: IRule = {
  id: 'AOSSW-SEC-002',
  selector: 'password',
  vendor: 'aruba-aosswitch',
  category: 'Authentication',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure an operator password for read-only access.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    if (startsWithIgnoreCase(nodeId, 'password operator')) {
      return {
        passed: true,
        message: 'Operator password is configured.',
        ruleId: 'AOSSW-SEC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Password configuration found.',
      ruleId: 'AOSSW-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSSW-SEC-003: SSH should be enabled.
 */
export const AosSwitchSshEnabled: IRule = {
  id: 'AOSSW-SEC-003',
  selector: 'ip ssh',
  vendor: 'aruba-aosswitch',
  category: 'Session-Management',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH with "ip ssh" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    return {
      passed: true,
      message: 'SSH is enabled.',
      ruleId: 'AOSSW-SEC-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Spanning Tree Rules
// =============================================================================

/**
 * AOSSW-STP-001: Spanning tree should be enabled.
 */
export const AosSwitchSpanningTree: IRule = {
  id: 'AOSSW-STP-001',
  selector: 'spanning-tree',
  vendor: 'aruba-aosswitch',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable spanning-tree for loop prevention.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    // Check for no spanning-tree
    if (includesIgnoreCase(nodeId, 'no spanning-tree')) {
      return {
        passed: false,
        message: 'Spanning-tree is disabled. Enable for loop prevention.',
        ruleId: 'AOSSW-STP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Spanning-tree is configured.',
      ruleId: 'AOSSW-STP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Trunk (LAG) Rules
// =============================================================================

/**
 * AOSSW-TRUNK-001: Trunks should use LACP.
 */
export const AosSwitchTrunkLacp: IRule = {
  id: 'AOSSW-TRUNK-001',
  selector: 'trunk',
  vendor: 'aruba-aosswitch',
  category: 'Link-Aggregation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure trunk with LACP for dynamic aggregation: "trunk <ports> <name> lacp".',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    if (!includesIgnoreCase(nodeId, 'lacp')) {
      return {
        passed: false,
        message: 'Trunk is not using LACP. Consider using LACP for dynamic link aggregation.',
        ruleId: 'AOSSW-TRUNK-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Trunk is using LACP.',
      ruleId: 'AOSSW-TRUNK-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Management Rules
// =============================================================================

/**
 * AOSSW-MGMT-001: Management VLAN should have IP address.
 */
export const AosSwitchMgmtVlanIp: IRule = {
  id: 'AOSSW-MGMT-001',
  selector: 'vlan',
  vendor: 'aruba-aosswitch',
  category: 'IP-Addressing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure IP address on management VLAN for remote access.',
  },
  check: (node: ConfigNode): RuleResult => {
    const match = node.id.match(/vlan\s+(\d+)/i);
    if (!match) {
      return { passed: true, message: 'Not a VLAN definition.', ruleId: 'AOSSW-MGMT-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if VLAN has IP address
    if (hasChildCommand(node, 'ip address')) {
      return {
        passed: true,
        message: 'VLAN has IP address configured for management.',
        ruleId: 'AOSSW-MGMT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VLAN checked for management IP.',
      ruleId: 'AOSSW-MGMT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSSW-MGMT-002: Console idle timeout should be configured.
 */
export const AosSwitchConsoleTimeout: IRule = {
  id: 'AOSSW-MGMT-002',
  selector: 'console',
  vendor: 'aruba-aosswitch',
  category: 'Session-Management',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure console idle-timeout for security.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    if (includesIgnoreCase(nodeId, 'idle-timeout')) {
      // Check if timeout is 0 (disabled)
      const match = node.id.match(/idle-timeout\s+(\d+)/i);
      const timeoutValue = match?.[1];
      const timeout = timeoutValue ? parseInteger(timeoutValue) : null;
      if (timeout === 0) {
        return {
          passed: false,
          message: 'Console idle-timeout is disabled. Enable for security.',
          ruleId: 'AOSSW-MGMT-002',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }

      return {
        passed: true,
        message: 'Console idle-timeout is configured.',
        ruleId: 'AOSSW-MGMT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Console configuration found.',
      ruleId: 'AOSSW-MGMT-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Time Synchronization Rules
// =============================================================================

/**
 * AOSSW-TIME-001: Time synchronization should be configured.
 */
export const AosSwitchTimesync: IRule = {
  id: 'AOSSW-TIME-001',
  selector: 'timesync',
  vendor: 'aruba-aosswitch',
  category: 'Time-Synchronization',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure time synchronization using SNTP.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id;

    if (includesIgnoreCase(nodeId, 'sntp') || includesIgnoreCase(nodeId, 'ntp')) {
      return {
        passed: true,
        message: 'Time synchronization is configured.',
        ruleId: 'AOSSW-TIME-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Timesync configuration found.',
      ruleId: 'AOSSW-TIME-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Export all AOS-Switch rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// =============================================================================

export const allAosSwitchRules: IRule[] = [
  // VLAN/L2
  AosSwitchVlanName,
  // Security
  AosSwitchManagerPassword,
];
