// packages/rules-default/src/vyos/vyos-rules.ts
// VyOS/EdgeOS specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { startsWithIgnoreCase, includesIgnoreCase } from '@sentriflow/core';
import {
  hasChildCommand,
  findStanza,
  findStanzas,
  findStanzasByPrefix,
  isDisabled,
  isPhysicalVyosPort,
  isLoopback,
  getEthernetInterfaces,
  getFirewallDefaultAction,
  getFirewallRules,
  getFirewallRuleAction,
  hasNtpConfig,
  hasSyslogConfig,
  getLoginConfig,
  getUserConfigs,
  getSshConfig,
  hasSshService,
} from '@sentriflow/core/helpers/vyos';

// ============================================================================
// System Security Rules
// ============================================================================

/**
 * VYOS-SYS-001: System must have a hostname configured
 */
export const VyosHostnameRequired: IRule = {
  id: 'VYOS-SYS-001',
  selector: 'system',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "host-name" under system stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasHostname = hasChildCommand(node, 'host-name');
    if (!hasHostname) {
      return {
        passed: false,
        message: 'System missing host-name configuration.',
        ruleId: 'VYOS-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Hostname is configured.',
      ruleId: 'VYOS-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SYS-002: System must have NTP configured
 */
export const VyosNtpRequired: IRule = {
  id: 'VYOS-SYS-002',
  selector: 'system',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure NTP servers under "system ntp server <address>".',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasNtpConfig(node)) {
      return {
        passed: false,
        message: 'System missing NTP configuration.',
        ruleId: 'VYOS-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const ntp = findStanza(node, 'ntp');
    if (ntp) {
      // Check for at least one server
      const hasServer = hasChildCommand(ntp, 'server');
      if (!hasServer) {
        return {
          passed: false,
          message: 'NTP configured but no servers defined.',
          ruleId: 'VYOS-SYS-002',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    return {
      passed: true,
      message: 'NTP is properly configured.',
      ruleId: 'VYOS-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SYS-003: Syslog must be configured
 */
export const VyosSyslogRequired: IRule = {
  id: 'VYOS-SYS-003',
  selector: 'system',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "syslog" under system stanza with remote host or local file.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasSyslogConfig(node)) {
      return {
        passed: false,
        message: 'System missing syslog configuration.',
        ruleId: 'VYOS-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Syslog is configured.',
      ruleId: 'VYOS-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SYS-004: Users must have authentication configured
 */
export const VyosUserAuthRequired: IRule = {
  id: 'VYOS-SYS-004',
  selector: 'system',
  vendor: 'vyos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure authentication (encrypted-password or public-keys) for all users.',
  },
  check: (node: ConfigNode): RuleResult => {
    const login = getLoginConfig(node);
    if (!login) {
      return {
        passed: true,
        message: 'No login configuration found.',
        ruleId: 'VYOS-SYS-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const users = getUserConfigs(login);
    if (users.length === 0) {
      return {
        passed: true,
        message: 'No users configured.',
        ruleId: 'VYOS-SYS-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const user of users) {
      // Check for authentication stanza
      const auth = findStanza(user, 'authentication');
      if (!auth) {
        const username = user.id.split(/\s+/)[1] || user.id;
        issues.push(`User "${username}" has no authentication configured.`);
        continue;
      }

      // Check for encrypted-password or public-keys
      const hasPassword = hasChildCommand(auth, 'encrypted-password');
      const hasPublicKeys = hasChildCommand(auth, 'public-keys');

      if (!hasPassword && !hasPublicKeys) {
        const username = user.id.split(/\s+/)[1] || user.id;
        issues.push(`User "${username}" has no password or SSH keys configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-SYS-004',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All users have authentication configured.',
      ruleId: 'VYOS-SYS-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SEC-001: Plaintext passwords should not appear in configuration.
 * In VyOS, plaintext-password is only used during configuration entry.
 * Saved configs should only contain encrypted-password with hashes.
 */
export const VyosNoPlaintextPassword: IRule = {
  id: 'VYOS-SEC-001',
  selector: 'authentication',
  vendor: 'vyos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation:
      'Use "encrypted-password" with a pre-hashed password, or let VyOS hash it during configuration.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check if plaintext-password appears in the config
    // This shouldn't happen in a properly saved config
    const hasPlaintext = node.children.some((child) =>
      startsWithIgnoreCase(child.id, 'plaintext-password')
    );

    if (hasPlaintext) {
      return {
        passed: false,
        message:
          'Plaintext password found in configuration. VyOS should store hashed passwords only.',
        ruleId: 'VYOS-SEC-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No plaintext passwords in configuration.',
      ruleId: 'VYOS-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SYS-005: Name servers should be configured
 */
export const VyosNameServersRequired: IRule = {
  id: 'VYOS-SYS-005',
  selector: 'system',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "name-server" under system stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasNameServer = hasChildCommand(node, 'name-server');
    if (!hasNameServer) {
      return {
        passed: false,
        message: 'System has no name servers configured.',
        ruleId: 'VYOS-SYS-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Name servers are configured.',
      ruleId: 'VYOS-SYS-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Service Rules
// ============================================================================

/**
 * VYOS-SVC-001: SSH service must be enabled
 */
export const VyosSshRequired: IRule = {
  id: 'VYOS-SVC-001',
  selector: 'service',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "service ssh" for remote management.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasSshService(node)) {
      return {
        passed: false,
        message: 'SSH service is not configured.',
        ruleId: 'VYOS-SVC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH service is configured.',
      ruleId: 'VYOS-SVC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SVC-002: SSH should disable password authentication (prefer keys)
 */
export const VyosSshKeyAuth: IRule = {
  id: 'VYOS-SVC-002',
  selector: 'service',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Consider disabling password authentication: "set service ssh disable-password-authentication".',
  },
  check: (node: ConfigNode): RuleResult => {
    const ssh = getSshConfig(node);
    if (!ssh) {
      return {
        passed: true,
        message: 'SSH service not configured.',
        ruleId: 'VYOS-SVC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const disablePassword = hasChildCommand(ssh, 'disable-password-authentication');
    if (!disablePassword) {
      return {
        passed: false,
        message: 'SSH password authentication is enabled. Consider using SSH keys only.',
        ruleId: 'VYOS-SVC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH password authentication is disabled.',
      ruleId: 'VYOS-SVC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-SVC-003: SSH should not use default port 22
 */
export const VyosSshNonDefaultPort: IRule = {
  id: 'VYOS-SVC-003',
  selector: 'service',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Consider using a non-standard SSH port: "set service ssh port <port>".',
  },
  check: (node: ConfigNode): RuleResult => {
    const ssh = getSshConfig(node);
    if (!ssh) {
      return {
        passed: true,
        message: 'SSH service not configured.',
        ruleId: 'VYOS-SVC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if port is configured
    const portCmd = ssh.children.find((child) =>
      startsWithIgnoreCase(child.id, 'port')
    );

    if (!portCmd) {
      return {
        passed: false,
        message: 'SSH using default port 22. Consider using a non-standard port.',
        ruleId: 'VYOS-SVC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if port is 22
    const portMatch = portCmd.id.match(/port\s+['"]?(\d+)['"]?/i);
    if (portMatch && portMatch[1] === '22') {
      return {
        passed: false,
        message: 'SSH configured on standard port 22. Consider using a non-standard port.',
        ruleId: 'VYOS-SVC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH using non-default port.',
      ruleId: 'VYOS-SVC-003',
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
 * VYOS-IF-001: Physical interfaces should have descriptions
 */
export const VyosInterfaceDescription: IRule = {
  id: 'VYOS-IF-001',
  selector: 'interfaces',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "description" to each physical interface.',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];
    const ethernetInterfaces = getEthernetInterfaces(node);

    for (const iface of ethernetInterfaces) {
      // Skip disabled interfaces
      if (isDisabled(iface)) {
        continue;
      }

      const hasDesc = hasChildCommand(iface, 'description');
      if (!hasDesc) {
        const ifaceName = iface.id.split(/\s+/).pop() || iface.id;
        issues.push(`Interface "${ifaceName}" missing description.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All physical interfaces have descriptions.',
      ruleId: 'VYOS-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-IF-002: Interfaces should have explicit addresses or DHCP
 */
export const VyosInterfaceAddress: IRule = {
  id: 'VYOS-IF-002',
  selector: 'interfaces',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "address" (static IP or dhcp) for each active interface.',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];
    const ethernetInterfaces = getEthernetInterfaces(node);

    for (const iface of ethernetInterfaces) {
      // Skip disabled interfaces
      if (isDisabled(iface)) {
        continue;
      }

      const hasAddress = hasChildCommand(iface, 'address');
      if (!hasAddress) {
        const ifaceName = iface.id.split(/\s+/).pop() || iface.id;
        issues.push(`Interface "${ifaceName}" has no address configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-IF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All active interfaces have addresses configured.',
      ruleId: 'VYOS-IF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Firewall Rules
// ============================================================================

/**
 * VYOS-FW-001: Firewall rulesets should have a default action
 */
export const VyosFirewallDefaultAction: IRule = {
  id: 'VYOS-FW-001',
  selector: 'firewall',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Set "default-action drop" or "default-action reject" for each firewall ruleset.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Find all named rulesets: "name <ruleset-name>"
    const rulesets = findStanzasByPrefix(node, 'name');
    if (rulesets.length === 0) {
      return {
        passed: true,
        message: 'No firewall rulesets configured.',
        ruleId: 'VYOS-FW-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const ruleset of rulesets) {
      const defaultAction = getFirewallDefaultAction(ruleset);
      if (!defaultAction) {
        const rulesetName = ruleset.id.split(/\s+/)[1] || ruleset.id;
        issues.push(`Firewall ruleset "${rulesetName}" has no default-action configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-FW-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All firewall rulesets have default actions configured.',
      ruleId: 'VYOS-FW-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-FW-002: Firewall rules should have explicit actions
 */
export const VyosFirewallRuleAction: IRule = {
  id: 'VYOS-FW-002',
  selector: 'firewall',
  vendor: 'vyos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Set "action accept", "action drop", or "action reject" for each firewall rule.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rulesets = findStanzasByPrefix(node, 'name');
    if (rulesets.length === 0) {
      return {
        passed: true,
        message: 'No firewall rulesets configured.',
        ruleId: 'VYOS-FW-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const ruleset of rulesets) {
      const rulesetName = ruleset.id.split(/\s+/)[1] || ruleset.id;
      const rules = getFirewallRules(ruleset);

      for (const rule of rules) {
        const action = getFirewallRuleAction(rule);
        if (!action) {
          const ruleNum = rule.id.split(/\s+/)[1] || rule.id;
          issues.push(`Firewall "${rulesetName}" rule ${ruleNum} has no action defined.`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-FW-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All firewall rules have explicit actions.',
      ruleId: 'VYOS-FW-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-FW-003: Stateful firewall should be enabled (established/related)
 */
export const VyosFirewallStateful: IRule = {
  id: 'VYOS-FW-003',
  selector: 'firewall',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure state-policy or add rules to accept established and related connections.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check for state-policy configuration (VyOS 1.3+)
    const statePolicy = findStanza(node, 'state-policy');
    if (statePolicy) {
      return {
        passed: true,
        message: 'Firewall state-policy is configured.',
        ruleId: 'VYOS-FW-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check rulesets for established/related rules
    const rulesets = findStanzasByPrefix(node, 'name');
    if (rulesets.length === 0) {
      return {
        passed: true,
        message: 'No firewall rulesets configured.',
        ruleId: 'VYOS-FW-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    let hasStatefulRules = false;
    for (const ruleset of rulesets) {
      const rules = getFirewallRules(ruleset);
      for (const rule of rules) {
        // Check for state configuration
        const hasState = rule.children.some((child) =>
          includesIgnoreCase(child.id, 'state')
        );
        if (hasState) {
          hasStatefulRules = true;
          break;
        }
      }
      if (hasStatefulRules) break;
    }

    if (!hasStatefulRules) {
      return {
        passed: false,
        message: 'No stateful firewall rules (established/related) found. Consider adding state-policy.',
        ruleId: 'VYOS-FW-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Stateful firewall rules are configured.',
      ruleId: 'VYOS-FW-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// NAT Rules
// ============================================================================

/**
 * VYOS-NAT-001: NAT rules should have outbound-interface specified
 */
export const VyosNatOutboundInterface: IRule = {
  id: 'VYOS-NAT-001',
  selector: 'nat',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "outbound-interface" for source NAT rules.',
  },
  check: (node: ConfigNode): RuleResult => {
    const source = findStanza(node, 'source');
    if (!source) {
      return {
        passed: true,
        message: 'No source NAT configured.',
        ruleId: 'VYOS-NAT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const rules = findStanzasByPrefix(source, 'rule');
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No source NAT rules configured.',
        ruleId: 'VYOS-NAT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      const hasOutboundInterface = hasChildCommand(rule, 'outbound-interface');
      if (!hasOutboundInterface) {
        const ruleNum = rule.id.split(/\s+/)[1] || rule.id;
        issues.push(`Source NAT rule ${ruleNum} missing outbound-interface.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-NAT-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All source NAT rules have outbound-interface configured.',
      ruleId: 'VYOS-NAT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-NAT-002: NAT rules should have translation configured
 */
export const VyosNatTranslation: IRule = {
  id: 'VYOS-NAT-002',
  selector: 'nat',
  vendor: 'vyos',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "translation address" for NAT rules (e.g., masquerade or static IP).',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];

    // Check source NAT
    const source = findStanza(node, 'source');
    if (source) {
      const rules = findStanzasByPrefix(source, 'rule');
      for (const rule of rules) {
        const hasTranslation = hasChildCommand(rule, 'translation');
        if (!hasTranslation) {
          const ruleNum = rule.id.split(/\s+/)[1] || rule.id;
          issues.push(`Source NAT rule ${ruleNum} missing translation configuration.`);
        }
      }
    }

    // Check destination NAT
    const destination = findStanza(node, 'destination');
    if (destination) {
      const rules = findStanzasByPrefix(destination, 'rule');
      for (const rule of rules) {
        const hasTranslation = hasChildCommand(rule, 'translation');
        if (!hasTranslation) {
          const ruleNum = rule.id.split(/\s+/)[1] || rule.id;
          issues.push(`Destination NAT rule ${ruleNum} missing translation configuration.`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-NAT-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All NAT rules have translation configured.',
      ruleId: 'VYOS-NAT-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VPN Rules
// ============================================================================

/**
 * VYOS-VPN-001: IPsec IKE group should use strong encryption
 */
export const VyosIpsecStrongEncryption: IRule = {
  id: 'VYOS-VPN-001',
  selector: 'vpn',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use AES-256 or AES-128 encryption. Avoid DES and 3DES.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ipsec = findStanza(node, 'ipsec');
    if (!ipsec) {
      return {
        passed: true,
        message: 'No IPsec VPN configured.',
        ruleId: 'VYOS-VPN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check IKE groups
    const ikeGroups = findStanzasByPrefix(ipsec, 'ike-group');
    const espGroups = findStanzasByPrefix(ipsec, 'esp-group');
    const issues: string[] = [];

    const checkWeakEncryption = (groupNode: ConfigNode, groupType: string) => {
      const proposals = findStanzasByPrefix(groupNode, 'proposal');
      for (const proposal of proposals) {
        for (const child of proposal.children) {
          const id = child.id;
          if (includesIgnoreCase(id, 'encryption')) {
            if (includesIgnoreCase(id, 'des') && !includesIgnoreCase(id, '3des') && !includesIgnoreCase(id, 'aes')) {
              const groupName = groupNode.id.split(/\s+/)[1] || groupNode.id;
              issues.push(`${groupType} "${groupName}" uses weak DES encryption.`);
            }
            if (includesIgnoreCase(id, '3des')) {
              const groupName = groupNode.id.split(/\s+/)[1] || groupNode.id;
              issues.push(`${groupType} "${groupName}" uses deprecated 3DES encryption.`);
            }
          }
        }
      }
    };

    for (const group of ikeGroups) {
      checkWeakEncryption(group, 'IKE group');
    }

    for (const group of espGroups) {
      checkWeakEncryption(group, 'ESP group');
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-VPN-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'IPsec encryption settings are acceptable.',
      ruleId: 'VYOS-VPN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-VPN-002: WireGuard peers should have allowed-ips configured
 */
export const VyosWireGuardAllowedIps: IRule = {
  id: 'VYOS-VPN-002',
  selector: 'interfaces',
  vendor: 'vyos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "allowed-ips" for each WireGuard peer.',
  },
  check: (node: ConfigNode): RuleResult => {
    const wgInterfaces = findStanzasByPrefix(node, 'wireguard');
    if (wgInterfaces.length === 0) {
      return {
        passed: true,
        message: 'No WireGuard interfaces configured.',
        ruleId: 'VYOS-VPN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const wgIface of wgInterfaces) {
      const peers = findStanzasByPrefix(wgIface, 'peer');
      for (const peer of peers) {
        const hasAllowedIps = hasChildCommand(peer, 'allowed-ips');
        if (!hasAllowedIps) {
          const peerName = peer.id.split(/\s+/)[1] || peer.id;
          const ifaceName = wgIface.id.split(/\s+/)[1] || wgIface.id;
          issues.push(`WireGuard ${ifaceName} peer "${peerName}" missing allowed-ips.`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-VPN-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All WireGuard peers have allowed-ips configured.',
      ruleId: 'VYOS-VPN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Routing Protocol Rules
// ============================================================================

/**
 * VYOS-BGP-001: BGP must have router-id configured
 */
export const VyosBgpRouterId: IRule = {
  id: 'VYOS-BGP-001',
  selector: 'protocols',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "parameters router-id" under BGP stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const bgp = findStanza(node, 'bgp');
    if (!bgp) {
      return {
        passed: true,
        message: 'BGP not configured.',
        ruleId: 'VYOS-BGP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for parameters { router-id } or direct router-id
    const params = findStanza(bgp, 'parameters');
    const hasRouterId = params
      ? hasChildCommand(params, 'router-id')
      : hasChildCommand(bgp, 'router-id');

    if (!hasRouterId) {
      return {
        passed: false,
        message: 'BGP missing explicit router-id.',
        ruleId: 'VYOS-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP router-id is configured.',
      ruleId: 'VYOS-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-BGP-002: BGP neighbors should have description
 */
export const VyosBgpNeighborDescription: IRule = {
  id: 'VYOS-BGP-002',
  selector: 'protocols',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "description" to each BGP neighbor.',
  },
  check: (node: ConfigNode): RuleResult => {
    const bgp = findStanza(node, 'bgp');
    if (!bgp) {
      return {
        passed: true,
        message: 'BGP not configured.',
        ruleId: 'VYOS-BGP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const neighbors = findStanzasByPrefix(bgp, 'neighbor');
    if (neighbors.length === 0) {
      return {
        passed: true,
        message: 'No BGP neighbors configured.',
        ruleId: 'VYOS-BGP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const neighbor of neighbors) {
      const hasDesc = hasChildCommand(neighbor, 'description');
      if (!hasDesc) {
        const neighborAddr = neighbor.id.split(/\s+/)[1] || neighbor.id;
        issues.push(`BGP neighbor "${neighborAddr}" missing description.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-BGP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All BGP neighbors have descriptions.',
      ruleId: 'VYOS-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * VYOS-OSPF-001: OSPF areas should have interfaces assigned
 */
export const VyosOspfAreaInterfaces: IRule = {
  id: 'VYOS-OSPF-001',
  selector: 'protocols',
  vendor: 'vyos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure interfaces under each OSPF area or use "interface" directly under OSPF.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ospf = findStanza(node, 'ospf');
    if (!ospf) {
      return {
        passed: true,
        message: 'OSPF not configured.',
        ruleId: 'VYOS-OSPF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for interfaces directly under OSPF or under areas
    const hasDirectInterfaces = hasChildCommand(ospf, 'interface');
    const areas = findStanzasByPrefix(ospf, 'area');

    if (!hasDirectInterfaces && areas.length === 0) {
      return {
        passed: false,
        message: 'OSPF configured but no interfaces or areas defined.',
        ruleId: 'VYOS-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check areas for interfaces or networks
    const issues: string[] = [];
    for (const area of areas) {
      const hasInterface = hasChildCommand(area, 'interface');
      const hasNetwork = hasChildCommand(area, 'network');
      if (!hasInterface && !hasNetwork) {
        const areaId = area.id.split(/\s+/)[1] || area.id;
        issues.push(`OSPF area "${areaId}" has no interfaces or networks configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF has interfaces configured.',
      ruleId: 'VYOS-OSPF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// High Availability Rules
// ============================================================================

/**
 * VYOS-HA-001: VRRP groups should have preempt delay configured
 */
export const VyosVrrpPreemptDelay: IRule = {
  id: 'VYOS-HA-001',
  selector: 'high-availability',
  vendor: 'vyos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "preempt-delay" in VRRP groups to prevent flapping.',
  },
  check: (node: ConfigNode): RuleResult => {
    const vrrp = findStanza(node, 'vrrp');
    if (!vrrp) {
      return {
        passed: true,
        message: 'VRRP not configured.',
        ruleId: 'VYOS-HA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const groups = findStanzasByPrefix(vrrp, 'group');
    if (groups.length === 0) {
      return {
        passed: true,
        message: 'No VRRP groups configured.',
        ruleId: 'VYOS-HA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const group of groups) {
      const hasPreemptDelay = hasChildCommand(group, 'preempt-delay');
      if (!hasPreemptDelay) {
        const groupName = group.id.split(/\s+/)[1] || group.id;
        issues.push(`VRRP group "${groupName}" has no preempt-delay configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'VYOS-HA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All VRRP groups have preempt-delay configured.',
      ruleId: 'VYOS-HA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all VyOS rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allVyosRules: IRule[] = [
  // System
  VyosHostnameRequired,
  // Security
  VyosNoPlaintextPassword,
  // Firewall
  VyosFirewallDefaultAction,
  // Interfaces
  VyosInterfaceDescription,
];
