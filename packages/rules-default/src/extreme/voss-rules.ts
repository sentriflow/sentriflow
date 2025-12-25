// packages/rules-default/src/extreme/voss-rules.ts
// Extreme Networks VOSS (VSP Operating System Software) specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { equalsIgnoreCase, parseInteger } from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  isVossVlanCreate,
  getVossVlanId,
  hasVossSpbm,
  hasVossIsis,
  hasVossVlanIsid,
  getVossVlanIsid,
  isVossGigabitEthernet,
  isVossMlt,
  getVossMltId,
  isVossShutdown,
  hasVossSnmpName,
  getVossSnmpName,
  hasVossNtp,
  hasVossLogging,
  hasVossSsh,
  hasVossLacp,
  hasVossDvr,
  hasVossCfm,
  getVossDefaultVlan,
} from '@sentriflow/core/helpers/extreme';

// ============================================================================
// System Configuration Rules
// ============================================================================

/**
 * VOSS-SYS-001: SNMP server name must be configured
 */
export const VossSysNameRequired: IRule = {
  id: 'VOSS-SYS-001',
  selector: 'snmp-server name',
  vendor: 'extreme-voss',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure system name: snmp-server name "<name>"',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^snmp-server\s+name\s+/i.test(node.id)) {
      const match = node.id.match(/name\s+["']?([^"'\s]+)["']?/i);
      const sysname = match ? match[1] : 'configured';
      return {
        passed: true,
        message: `System name is configured: ${sysname}`,
        ruleId: 'VOSS-SYS-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'System name is not configured. Device identification is important.',
      ruleId: 'VOSS-SYS-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-SYS-002: NTP must be configured for time synchronization
 */
export const VossNtpRequired: IRule = {
  id: 'VOSS-SYS-002',
  selector: 'ntp server',
  vendor: 'extreme-voss',
  category: 'Time-Synchronization',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP server: ntp server <ip-address>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^ntp\s+server\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'NTP server is configured.',
        ruleId: 'VOSS-SYS-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'NTP server is not configured. Time synchronization is critical.',
      ruleId: 'VOSS-SYS-002',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-SYS-003: Logging should be configured
 */
export const VossLoggingRequired: IRule = {
  id: 'VOSS-SYS-003',
  selector: 'logging',
  vendor: 'extreme-voss',
  category: 'Logging',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure logging: logging host <ip-address>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^logging\s+(host|server)\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Remote logging is configured.',
        ruleId: 'VOSS-SYS-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'Remote logging is not configured. Centralized logging is recommended.',
      ruleId: 'VOSS-SYS-003',
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
 * VOSS-SEC-001: SSH should be enabled
 */
export const VossSshEnabled: IRule = {
  id: 'VOSS-SEC-001',
  selector: 'ssh',
  vendor: 'extreme-voss',
  category: 'Session-Management',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH: ssh / no shutdown',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^ssh\s+/i.test(node.id) || equalsIgnoreCase(node.id, 'ssh')) {
      // Check for explicit shutdown
      const isShut = node.children.some((child) =>
        equalsIgnoreCase(child.id, 'shutdown')
      );
      const hasNoShut = node.children.some((child) =>
        equalsIgnoreCase(child.id, 'no shutdown')
      );

      if (isShut && !hasNoShut) {
        return {
          passed: false,
          message: 'SSH is configured but shutdown.',
          ruleId: 'VOSS-SEC-001',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }

      return {
        passed: true,
        message: 'SSH is configured.',
        ruleId: 'VOSS-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'SSH is not configured. Secure management is recommended.',
      ruleId: 'VOSS-SEC-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VLAN Rules
// ============================================================================

/**
 * VOSS-VLAN-001: VLAN should have I-SID for Fabric Connect
 */
export const VossVlanIsidRequired: IRule = {
  id: 'VOSS-VLAN-001',
  selector: 'vlan create',
  vendor: 'extreme-voss',
  category: 'Network-Segmentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure I-SID for VLAN: vlan i-sid <vlan-id> <isid>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVossVlanCreate(node)) {
      return {
        passed: true,
        message: 'Not a VLAN create command.',
        ruleId: 'VOSS-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const vlanId = getVossVlanId(node);
    if (!vlanId) {
      return {
        passed: false,
        message: 'Unable to determine VLAN ID.',
        ruleId: 'VOSS-VLAN-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check if SPBM VLAN (b-vid) - these don't need I-SID
    if (/type\s+spbm-bvlan/i.test(node.id)) {
      return {
        passed: true,
        message: `VLAN ${vlanId} is a SPBM B-VID (I-SID not required).`,
        ruleId: 'VOSS-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // For Fabric Connect, VLANs should have I-SID
    // This is informational since I-SID might be configured elsewhere
    return {
      passed: true,
      message: `VLAN ${vlanId} created. Ensure I-SID is configured for Fabric Connect.`,
      ruleId: 'VOSS-VLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-VLAN-002: VLAN I-SID should be within valid range
 */
export const VossVlanIsidRange: IRule = {
  id: 'VOSS-VLAN-002',
  selector: 'vlan i-sid',
  vendor: 'extreme-voss',
  category: 'Network-Segmentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Use I-SID within valid range (256 - 16777214)',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const match = node.id.match(/vlan\s+i-sid\s+\d+\s+(\d+)/i);
    const isidStr = match?.[1];
    if (!isidStr) {
      return {
        passed: true,
        message: 'Not a VLAN I-SID command.',
        ruleId: 'VOSS-VLAN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const isid = parseInteger(isidStr);
    // I-SID range: 256 to 16777214 (0x100 to 0xFFFFFE)
    if (isid === null || isid < 256 || isid > 16777214) {
      return {
        passed: false,
        message: `I-SID ${isid} is outside valid range (256-16777214).`,
        ruleId: 'VOSS-VLAN-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `I-SID ${isid} is within valid range.`,
      ruleId: 'VOSS-VLAN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Interface Rules
// ============================================================================

/**
 * VOSS-INT-001: GigabitEthernet interfaces should have default-vlan-id
 */
export const VossInterfaceDefaultVlan: IRule = {
  id: 'VOSS-INT-001',
  selector: 'interface GigabitEthernet',
  vendor: 'extreme-voss',
  category: 'Network-Segmentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure default VLAN: default-vlan-id <vlan-id>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVossGigabitEthernet(node)) {
      return {
        passed: true,
        message: 'Not a GigabitEthernet interface.',
        ruleId: 'VOSS-INT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip shutdown interfaces
    if (isVossShutdown(node)) {
      return {
        passed: true,
        message: 'Interface is shutdown.',
        ruleId: 'VOSS-INT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const defaultVlan = getVossDefaultVlan(node);
    if (!defaultVlan) {
      return {
        passed: false,
        message: 'Interface has no default-vlan-id configured.',
        ruleId: 'VOSS-INT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Interface has default-vlan-id ${defaultVlan}.`,
      ruleId: 'VOSS-INT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-INT-002: Active interfaces should not be shutdown
 */
export const VossInterfaceNoShutdown: IRule = {
  id: 'VOSS-INT-002',
  selector: 'interface GigabitEthernet',
  vendor: 'extreme-voss',
  category: 'Documentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable interface: no shutdown',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVossGigabitEthernet(node)) {
      return {
        passed: true,
        message: 'Not a GigabitEthernet interface.',
        ruleId: 'VOSS-INT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (isVossShutdown(node)) {
      return {
        passed: false,
        message: 'Interface is administratively shutdown.',
        ruleId: 'VOSS-INT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Interface is not shutdown.',
      ruleId: 'VOSS-INT-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// MLT (Multi-Link Trunk) Rules
// ============================================================================

/**
 * VOSS-MLT-001: MLT should have LACP enabled
 */
export const VossMltLacp: IRule = {
  id: 'VOSS-MLT-001',
  selector: 'interface mlt',
  vendor: 'extreme-voss',
  category: 'Link-Aggregation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable LACP on MLT: lacp enable',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVossMlt(node)) {
      return {
        passed: true,
        message: 'Not an MLT interface.',
        ruleId: 'VOSS-MLT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const mltId = getVossMltId(node);
    if (!hasVossLacp(node)) {
      return {
        passed: false,
        message: `MLT ${mltId} does not have LACP enabled. Dynamic LACP is recommended.`,
        ruleId: 'VOSS-MLT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `MLT ${mltId} has LACP enabled.`,
      ruleId: 'VOSS-MLT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// SPBM / Fabric Connect Rules
// ============================================================================

/**
 * VOSS-SPBM-001: SPBM should have B-VIDs configured
 */
export const VossSpbmBvid: IRule = {
  id: 'VOSS-SPBM-001',
  selector: 'spbm',
  vendor: 'extreme-voss',
  category: 'Routing',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure SPBM B-VIDs: spbm <instance> b-vid <primary>-<secondary> primary <primary>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^spbm\s+\d+\s+b-vid\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not an SPBM B-VID configuration.',
        ruleId: 'VOSS-SPBM-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SPBM B-VIDs are configured.',
      ruleId: 'VOSS-SPBM-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-SPBM-002: SPBM should have nick-name configured
 */
export const VossSpbmNickname: IRule = {
  id: 'VOSS-SPBM-002',
  selector: 'spbm',
  vendor: 'extreme-voss',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure SPBM nick-name: spbm <instance> nick-name <x.xx.xx>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^spbm\s+\d+\s+nick-name\s+/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not an SPBM nick-name configuration.',
        ruleId: 'VOSS-SPBM-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Validate nick-name format (x.xx.xx where x is 1-15, xx is 00-ff)
    const match = node.id.match(/nick-name\s+(\d+)\.([0-9a-f]{2})\.([0-9a-f]{2})/i);
    if (!match) {
      return {
        passed: false,
        message: 'SPBM nick-name format is invalid. Use format: x.xx.xx',
        ruleId: 'VOSS-SPBM-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `SPBM nick-name is configured: ${match[0]}`,
      ruleId: 'VOSS-SPBM-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// ISIS Rules
// ============================================================================

/**
 * VOSS-ISIS-001: ISIS should not be shutdown for Fabric Connect
 */
export const VossIsisEnabled: IRule = {
  id: 'VOSS-ISIS-001',
  selector: 'router isis',
  vendor: 'extreme-voss',
  category: 'Routing',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable ISIS: router isis / no shutdown',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^router\s+isis/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not an ISIS router configuration.',
        ruleId: 'VOSS-ISIS-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const isShut = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'shutdown')
    );
    const hasNoShut = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'no shutdown')
    );

    if (isShut && !hasNoShut) {
      return {
        passed: false,
        message: 'ISIS is shutdown. Enable for Fabric Connect operation.',
        ruleId: 'VOSS-ISIS-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'ISIS is enabled.',
      ruleId: 'VOSS-ISIS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VOSS-ISIS-002: ISIS should have SPBM configuration
 */
export const VossIsisSpbm: IRule = {
  id: 'VOSS-ISIS-002',
  selector: 'router isis',
  vendor: 'extreme-voss',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure SPBM under ISIS: spbm <instance> b-vid <vids> primary <vid>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^router\s+isis/i.test(node.id)) {
      return {
        passed: true,
        message: 'Not an ISIS router configuration.',
        ruleId: 'VOSS-ISIS-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasSpbm = node.children.some((child) =>
      /^spbm\s+\d+/i.test(child.id)
    );

    if (!hasSpbm) {
      return {
        passed: false,
        message: 'ISIS does not have SPBM configuration. Required for Fabric Connect.',
        ruleId: 'VOSS-ISIS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'ISIS has SPBM configuration.',
      ruleId: 'VOSS-ISIS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// DVR Rules
// ============================================================================

/**
 * VOSS-DVR-001: DVR domain-id should be configured for DVR nodes
 */
export const VossDvrDomainId: IRule = {
  id: 'VOSS-DVR-001',
  selector: 'dvr',
  vendor: 'extreme-voss',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure DVR domain-id: dvr domain-id <id>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!/^dvr\s+(leaf|controller)/i.test(node.id)) {
      // Only check DVR leaf/controller nodes
      return {
        passed: true,
        message: 'Not a DVR node configuration.',
        ruleId: 'VOSS-DVR-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'DVR node is configured. Ensure domain-id is set.',
      ruleId: 'VOSS-DVR-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all VOSS rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allVossRules: IRule[] = [
  // System rules
  VossSysNameRequired,
  // Interface rules
  VossInterfaceDefaultVlan,
  // VLAN rules
  VossVlanIsidRequired,
];
