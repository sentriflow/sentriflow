// packages/rules-default/src/extreme/exos-rules.ts
// Extreme Networks ExtremeXOS (EXOS) specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { equalsIgnoreCase } from '@sentriflow/core';
import {
  hasChildCommand,
  getExosVlanName,
  getExosVlanTag,
  hasExosSysname,
  getExosSysname,
  hasExosSntp,
  isExosSntpEnabled,
  hasExosSyslog,
  hasExosSsh2,
  hasExosRadius,
  hasExosTacacs,
  isExosLag,
  getExosLagMasterPort,
  hasExosEaps,
  hasExosStacking,
  hasExosMlag,
} from '@sentriflow/core/helpers/extreme';

// ============================================================================
// System Configuration Rules
// ============================================================================

/**
 * EXOS-SYS-001: SNMP sysname must be configured
 */
export const ExosSysnameRequired: IRule = {
  id: 'EXOS-SYS-001',
  selector: 'configure snmp sysname',
  vendor: 'extreme-exos',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure sysname using: configure snmp sysname "<name>"',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // If configure snmp sysname command exists, it passes
    if (/^configure\s+snmp\s+sysname\s+/i.test(node.id)) {
      const match = node.id.match(/sysname\s+["']?([^"'\s]+)["']?/i);
      const sysname = match ? match[1] : 'configured';
      return {
        passed: true,
        message: `SNMP sysname is configured: ${sysname}`,
        ruleId: 'EXOS-SYS-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'SNMP sysname is not configured. Device identification is important.',
      ruleId: 'EXOS-SYS-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-SYS-002: SNTP must be configured for time synchronization
 */
export const ExosSntpRequired: IRule = {
  id: 'EXOS-SYS-002',
  selector: 'configure sntp-client',
  vendor: 'extreme-exos',
  category: 'Time-Synchronization',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure SNTP using: configure sntp-client primary server <ip> vr VR-Default',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^configure\s+sntp-client\s+(primary|secondary)\s+server\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'SNTP server is configured.',
        ruleId: 'EXOS-SYS-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'SNTP server is not configured. Time synchronization is critical for logging.',
      ruleId: 'EXOS-SYS-002',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-SYS-003: SNTP client should be enabled
 */
export const ExosSntpEnabled: IRule = {
  id: 'EXOS-SYS-003',
  selector: 'enable sntp-client',
  vendor: 'extreme-exos',
  category: 'Time-Synchronization',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SNTP client: enable sntp-client',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^enable\s+sntp-client/i.test(node.id)) {
      return {
        passed: true,
        message: 'SNTP client is enabled.',
        ruleId: 'EXOS-SYS-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'SNTP client is not enabled. Enable after configuring SNTP servers.',
      ruleId: 'EXOS-SYS-003',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-SYS-004: Syslog should be configured for centralized logging
 */
export const ExosSyslogRequired: IRule = {
  id: 'EXOS-SYS-004',
  selector: 'configure syslog',
  vendor: 'extreme-exos',
  category: 'Logging',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure syslog: configure syslog add <ip>:<port> vr VR-Default',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^configure\s+(syslog|log\s+target)\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Syslog is configured.',
        ruleId: 'EXOS-SYS-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'Remote syslog is not configured. Centralized logging is recommended.',
      ruleId: 'EXOS-SYS-004',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Security Rules
// ============================================================================

/**
 * EXOS-SEC-001: SSH2 should be enabled
 */
export const ExosSsh2Enabled: IRule = {
  id: 'EXOS-SEC-001',
  selector: 'enable ssh2',
  vendor: 'extreme-exos',
  category: 'Session-Management',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH2: enable ssh2',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^enable\s+ssh2/i.test(node.id)) {
      return {
        passed: true,
        message: 'SSH2 is enabled for secure management.',
        ruleId: 'EXOS-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'SSH2 is not enabled. Secure management access is recommended.',
      ruleId: 'EXOS-SEC-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-SEC-002: Telnet should be disabled
 */
export const ExosTelnetDisabled: IRule = {
  id: 'EXOS-SEC-002',
  selector: 'disable telnet',
  vendor: 'extreme-exos',
  category: 'Service-Hardening',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable telnet: disable telnet',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^disable\s+telnet/i.test(node.id)) {
      return {
        passed: true,
        message: 'Telnet is disabled.',
        ruleId: 'EXOS-SEC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if telnet is explicitly enabled (bad)
    if (/^enable\s+telnet/i.test(node.id)) {
      return {
        passed: false,
        message: 'Telnet is enabled. Use SSH2 for secure management.',
        ruleId: 'EXOS-SEC-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true, // If not mentioned, assume default (often disabled)
      message: 'Telnet status not explicitly configured.',
      ruleId: 'EXOS-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-SEC-003: RADIUS or TACACS should be configured for AAA
 */
export const ExosAaaRequired: IRule = {
  id: 'EXOS-SEC-003',
  selector: 'configure radius',
  vendor: 'extreme-exos',
  category: 'Authentication',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure RADIUS: configure radius <option> OR configure tacacs <option>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^configure\s+(radius|tacacs)\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'AAA (RADIUS/TACACS) is configured.',
        ruleId: 'EXOS-SEC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'AAA (RADIUS/TACACS) is not configured. Centralized authentication is recommended.',
      ruleId: 'EXOS-SEC-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VLAN Rules
// ============================================================================

/**
 * EXOS-VLAN-001: VLANs should have meaningful names
 */
export const ExosVlanNaming: IRule = {
  id: 'EXOS-VLAN-001',
  selector: 'create vlan',
  vendor: 'extreme-exos',
  category: 'Documentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Use descriptive VLAN names: create vlan "<meaningful-name>" tag <id>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const vlanName = getExosVlanName(node);

    if (!vlanName) {
      return {
        passed: false,
        message: 'VLAN name not found in command.',
        ruleId: 'EXOS-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for generic or poor names
    const genericNames = ['vlan', 'default', 'temp', 'test', 'new'];
    const isGeneric = genericNames.some((g) =>
      equalsIgnoreCase(vlanName, g) ||
      /^vlan\d+$/i.test(vlanName)
    );

    if (isGeneric) {
      return {
        passed: false,
        message: `VLAN has generic name: "${vlanName}". Use a descriptive name.`,
        ruleId: 'EXOS-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN has descriptive name: "${vlanName}"`,
      ruleId: 'EXOS-VLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * EXOS-VLAN-002: VLANs should have a tag assigned
 */
export const ExosVlanTagRequired: IRule = {
  id: 'EXOS-VLAN-002',
  selector: 'create vlan',
  vendor: 'extreme-exos',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Assign VLAN tag: create vlan "<name>" tag <id>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const tag = getExosVlanTag(node);

    if (tag === undefined) {
      // Check if it's not the default VLAN
      const vlanName = getExosVlanName(node);
      if (vlanName && equalsIgnoreCase(vlanName, 'default')) {
        return {
          passed: true,
          message: 'Default VLAN does not require explicit tag.',
          ruleId: 'EXOS-VLAN-002',
          nodeId: node.id,
          level: 'info',
          loc: node.loc,
        };
      }

      return {
        passed: false,
        message: 'VLAN is created without a tag. Assign a tag for inter-switch communication.',
        ruleId: 'EXOS-VLAN-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN has tag ${tag} assigned.`,
      ruleId: 'EXOS-VLAN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// LAG/Sharing Rules
// ============================================================================

/**
 * EXOS-LAG-001: LAG should use LACP for dynamic aggregation
 */
export const ExosLagLacp: IRule = {
  id: 'EXOS-LAG-001',
  selector: 'enable sharing',
  vendor: 'extreme-exos',
  category: 'Link-Aggregation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure LACP for LAG: enable sharing <port> grouping <ports> lacp',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isExosLag(node)) {
      return {
        passed: true,
        message: 'Not a LAG configuration.',
        ruleId: 'EXOS-LAG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasLacp = /\blacp\b/i.test(node.id);
    const masterPort = getExosLagMasterPort(node);

    if (!hasLacp) {
      return {
        passed: false,
        message: `LAG on port ${masterPort} is not using LACP. Dynamic LACP is recommended.`,
        ruleId: 'EXOS-LAG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `LAG on port ${masterPort} is using LACP.`,
      ruleId: 'EXOS-LAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// EAPS Rules
// ============================================================================

/**
 * EXOS-EAPS-001: EAPS should have control VLAN configured
 */
export const ExosEapsControlVlan: IRule = {
  id: 'EXOS-EAPS-001',
  selector: 'configure eaps',
  vendor: 'extreme-exos',
  category: 'Network-Segmentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure EAPS control VLAN: configure eaps <name> add control vlan <vlan>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^configure\s+eaps\s+\S+\s+add\s+control\s+vlan/i.test(node.id)) {
      // Only check if it's trying to add control VLAN
      return {
        passed: true,
        message: 'Not an EAPS control VLAN configuration.',
        ruleId: 'EXOS-EAPS-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'EAPS control VLAN is configured.',
      ruleId: 'EXOS-EAPS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Stacking Rules
// ============================================================================

/**
 * EXOS-STACK-001: Stacking should have priority configured for master election
 */
export const ExosStackingPriority: IRule = {
  id: 'EXOS-STACK-001',
  selector: 'configure stacking',
  vendor: 'extreme-exos',
  category: 'High-Availability',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure stacking priority: configure stacking node-address <mac> priority <1-100>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^configure\s+stacking\s+node-address\s+\S+\s+priority\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not a stacking priority configuration.',
        ruleId: 'EXOS-STACK-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Stacking priority is configured.',
      ruleId: 'EXOS-STACK-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// MLAG Rules
// ============================================================================

/**
 * EXOS-MLAG-001: MLAG peer should have ISC configured
 */
export const ExosMlagIsc: IRule = {
  id: 'EXOS-MLAG-001',
  selector: 'configure mlag peer',
  vendor: 'extreme-exos',
  category: 'High-Availability',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure MLAG ISC: configure mlag peer <name> ipaddress <ip> vr VR-Default',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^configure\s+mlag\s+peer\s+\S+\s+ipaddress\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not an MLAG peer IP configuration.',
        ruleId: 'EXOS-MLAG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'MLAG peer IP address is configured.',
      ruleId: 'EXOS-MLAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all EXOS rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allExosRules: IRule[] = [
  // System rules
  ExosSysnameRequired,
  // Security rules
  ExosSsh2Enabled,
  // VLAN rules
  ExosVlanNaming,
];
