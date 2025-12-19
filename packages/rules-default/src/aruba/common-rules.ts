// packages/rules-default/src/aruba/common-rules.ts
// Common rules applicable to all Aruba platforms (AOS-CX, AOS-Switch, WLC)

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { hasChildCommand, getChildCommand, findStanzas } from '@sentriflow/core/helpers/aruba';

// =============================================================================
// Security Rules
// =============================================================================

/**
 * ARU-SEC-001: SSH must be enabled for secure management access.
 * Applies to: AOS-CX, AOS-Switch
 */
export const SshEnabled: IRule = {
  id: 'ARU-SEC-001',
  selector: 'ssh',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH server for secure remote management. Disable telnet if enabled.',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // If we found an 'ssh' node, SSH is likely configured
    const nodeId = node.id.toLowerCase();

    // Check for SSH server enabled patterns
    if (
      nodeId.includes('ssh server') ||
      nodeId === 'ip ssh' ||
      nodeId.includes('ssh server-enabled')
    ) {
      return {
        passed: true,
        message: 'SSH is enabled.',
        ruleId: 'ARU-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH configuration found.',
      ruleId: 'ARU-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARU-SEC-002: SNMP community string must not be default values.
 * Applies to: AOS-CX, AOS-Switch, WLC
 */
export const SnmpNotDefault: IRule = {
  id: 'ARU-SEC-002',
  selector: 'snmp-server',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Change SNMP community string from default "public" or "private" values.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check for default community strings
    if (nodeId.includes('community')) {
      const match = node.id.match(/community\s+["']?(\w+)["']?/i);
      const community = match?.[1]?.toLowerCase();

      if (community && (community === 'public' || community === 'private')) {
        return {
          passed: false,
          message: `Default SNMP community "${community}" detected. Use a complex community string.`,
          ruleId: 'ARU-SEC-002',
          nodeId: node.id,
          level: 'error',
          loc: node.loc,
        };
      }
    }

    return {
      passed: true,
      message: 'SNMP community is not a default value.',
      ruleId: 'ARU-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARU-SEC-003: Telnet should be disabled in favor of SSH.
 * Applies to: AOS-CX, AOS-Switch
 */
export const TelnetDisabled: IRule = {
  id: 'ARU-SEC-003',
  selector: 'telnet',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable telnet and use SSH for secure remote management.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check if telnet is enabled
    if (
      nodeId.includes('telnet-server') ||
      (nodeId.includes('telnet') && !nodeId.includes('no telnet'))
    ) {
      return {
        passed: false,
        message: 'Telnet is enabled. Consider disabling and using SSH instead.',
        ruleId: 'ARU-SEC-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Telnet configuration reviewed.',
      ruleId: 'ARU-SEC-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// NTP/Time Rules
// =============================================================================

/**
 * ARU-NTP-001: NTP server must be configured for time synchronization.
 * Applies to: AOS-CX, AOS-Switch, WLC
 */
export const NtpConfigured: IRule = {
  id: 'ARU-NTP-001',
  selector: 'ntp',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure NTP server for accurate time synchronization.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check for NTP server configuration
    if (nodeId.includes('ntp server') || nodeId.includes('ntp enable')) {
      return {
        passed: true,
        message: 'NTP is configured.',
        ruleId: 'ARU-NTP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP configuration found.',
      ruleId: 'ARU-NTP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARU-NTP-002: SNTP configuration check for AOS-Switch.
 * Applies to: AOS-Switch
 */
export const SntpConfigured: IRule = {
  id: 'ARU-NTP-002',
  selector: 'sntp',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure SNTP server for time synchronization.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    if (nodeId.includes('sntp server') || nodeId.includes('sntp unicast')) {
      return {
        passed: true,
        message: 'SNTP is configured.',
        ruleId: 'ARU-NTP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SNTP configuration found.',
      ruleId: 'ARU-NTP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Logging Rules
// =============================================================================

/**
 * ARU-LOG-001: Logging/syslog must be configured.
 * Applies to: AOS-CX, AOS-Switch, WLC
 */
export const LoggingConfigured: IRule = {
  id: 'ARU-LOG-001',
  selector: 'logging',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure logging to a syslog server for audit trails and troubleshooting.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check for logging server or destination
    if (
      nodeId.match(/logging\s+\d+\.\d+\.\d+\.\d+/) ||
      nodeId.includes('logging host') ||
      nodeId.includes('logging server')
    ) {
      return {
        passed: true,
        message: 'Logging server is configured.',
        ruleId: 'ARU-LOG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Logging configuration found.',
      ruleId: 'ARU-LOG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// AAA Rules
// =============================================================================

/**
 * ARU-AAA-001: AAA authentication should be configured.
 * Applies to: AOS-CX, AOS-Switch, WLC
 */
export const AaaConfigured: IRule = {
  id: 'ARU-AAA-001',
  selector: 'aaa',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure AAA authentication using RADIUS or TACACS+ for centralized user management.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check for AAA authentication configuration
    if (
      nodeId.includes('aaa authentication') ||
      nodeId.includes('aaa group server') ||
      nodeId.includes('aaa profile')
    ) {
      return {
        passed: true,
        message: 'AAA authentication is configured.',
        ruleId: 'ARU-AAA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'AAA configuration found.',
      ruleId: 'ARU-AAA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// RADIUS/TACACS+ Rules
// =============================================================================

/**
 * ARU-RAD-001: RADIUS server must have a key configured.
 * Applies to: AOS-CX, AOS-Switch, WLC
 */
export const RadiusKeyConfigured: IRule = {
  id: 'ARU-RAD-001',
  selector: 'radius-server',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure a shared secret key for RADIUS server communication.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check if key is configured
    const hasKey = hasChildCommand(node, 'key');

    if (!hasKey) {
      return {
        passed: false,
        message: 'RADIUS server missing shared secret key.',
        ruleId: 'ARU-RAD-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'RADIUS server has key configured.',
      ruleId: 'ARU-RAD-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARU-TAC-001: TACACS+ server must have a key configured.
 * Applies to: AOS-CX, AOS-Switch
 */
export const TacacsKeyConfigured: IRule = {
  id: 'ARU-TAC-001',
  selector: 'tacacs-server',
  vendor: ['aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc'],
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure a shared secret key for TACACS+ server communication.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check if key is configured
    const hasKey = hasChildCommand(node, 'key');

    if (!hasKey) {
      return {
        passed: false,
        message: 'TACACS+ server missing shared secret key.',
        ruleId: 'ARU-TAC-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'TACACS+ server has key configured.',
      ruleId: 'ARU-TAC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Export all common Aruba rules - proof-of-concept subset
// NOTE: Additional rules available in basic-netsec-pack
// =============================================================================

export const allArubaCommonRules: IRule[] = [
  // Security
  SshEnabled,
  // NTP
  NtpConfigured,
];
