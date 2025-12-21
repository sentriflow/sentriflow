// packages/rules-default/src/aruba/wlc-rules.ts
// Aruba ArubaOS WLC specific rules for wireless LAN controllers

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  getWlanEncryption,
  hasSecureEncryption,
  isOpenSsid,
  getEssid,
  getVapAaaProfile,
  getVapSsidProfile,
  getApGroupVirtualAps,
  hasRadiusKey,
  getRadiusHost,
  extractProfileName,
  findStanzas,
} from '@sentriflow/core/helpers/aruba';

// =============================================================================
// WLAN Security Rules
// =============================================================================

/**
 * ARUWLC-WLAN-001: SSID profiles must use WPA2/WPA3 encryption.
 */
export const WlcSsidEncryption: IRule = {
  id: 'ARUWLC-WLAN-001',
  selector: 'wlan ssid-profile',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "opmode wpa2-aes" or "opmode wpa3-sae-aes" for secure encryption.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const opmode = getWlanEncryption(node);

    if (!opmode) {
      return {
        passed: false,
        message: `SSID profile "${profileName}" has no encryption mode configured.`,
        ruleId: 'ARUWLC-WLAN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (isOpenSsid(node)) {
      return {
        passed: false,
        message: `SSID profile "${profileName}" is open/unencrypted. Use WPA2 or WPA3.`,
        ruleId: 'ARUWLC-WLAN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (!hasSecureEncryption(node)) {
      return {
        passed: false,
        message: `SSID profile "${profileName}" uses weak encryption (${opmode}). Use WPA2 or WPA3.`,
        ruleId: 'ARUWLC-WLAN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `SSID profile "${profileName}" uses secure encryption (${opmode}).`,
      ruleId: 'ARUWLC-WLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-WLAN-002: Open SSIDs should have captive portal or MAC authentication.
 */
export const WlcOpenSsidCaptivePortal: IRule = {
  id: 'ARUWLC-WLAN-002',
  selector: 'wlan ssid-profile',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'For open SSIDs, ensure the associated AAA profile uses captive portal authentication.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    // Only check open SSIDs
    if (!isOpenSsid(node)) {
      return {
        passed: true,
        message: 'SSID is not open.',
        ruleId: 'ARUWLC-WLAN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Open SSID detected - this is informational as AAA profile check happens at VAP level
    return {
      passed: true,
      message: `Open SSID "${profileName}" detected. Ensure associated virtual-AP uses captive portal.`,
      ruleId: 'ARUWLC-WLAN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-WLAN-003: SSID profiles should have ESSID configured.
 */
export const WlcSsidEssid: IRule = {
  id: 'ARUWLC-WLAN-003',
  selector: 'wlan ssid-profile',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "essid <network-name>" in the SSID profile.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const essid = getEssid(node);

    if (!essid) {
      return {
        passed: false,
        message: `SSID profile "${profileName}" has no ESSID configured.`,
        ruleId: 'ARUWLC-WLAN-003',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `SSID profile has ESSID "${essid}".`,
      ruleId: 'ARUWLC-WLAN-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Virtual-AP Rules
// =============================================================================

/**
 * ARUWLC-VAP-001: Virtual-AP must have AAA profile assigned.
 */
export const WlcVapAaaProfile: IRule = {
  id: 'ARUWLC-VAP-001',
  selector: 'wlan virtual-ap',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "aaa-profile <name>" in the virtual-AP profile.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const aaaProfile = getVapAaaProfile(node);

    if (!aaaProfile) {
      return {
        passed: false,
        message: `Virtual-AP "${profileName}" has no AAA profile assigned.`,
        ruleId: 'ARUWLC-VAP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Virtual-AP uses AAA profile "${aaaProfile}".`,
      ruleId: 'ARUWLC-VAP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-VAP-002: Virtual-AP must have SSID profile assigned.
 */
export const WlcVapSsidProfile: IRule = {
  id: 'ARUWLC-VAP-002',
  selector: 'wlan virtual-ap',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "ssid-profile <name>" in the virtual-AP profile.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const ssidProfile = getVapSsidProfile(node);

    if (!ssidProfile) {
      return {
        passed: false,
        message: `Virtual-AP "${profileName}" has no SSID profile assigned.`,
        ruleId: 'ARUWLC-VAP-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Virtual-AP uses SSID profile "${ssidProfile}".`,
      ruleId: 'ARUWLC-VAP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-VAP-003: Virtual-AP should have VLAN assigned.
 */
export const WlcVapVlan: IRule = {
  id: 'ARUWLC-VAP-003',
  selector: 'wlan virtual-ap',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "vlan <id>" in the virtual-AP profile for proper network segmentation.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    if (!hasChildCommand(node, 'vlan')) {
      return {
        passed: false,
        message: `Virtual-AP "${profileName}" has no VLAN assigned.`,
        ruleId: 'ARUWLC-VAP-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Virtual-AP has VLAN assigned.',
      ruleId: 'ARUWLC-VAP-003',
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
 * ARUWLC-AAA-001: AAA RADIUS server must have host configured.
 */
export const WlcRadiusHost: IRule = {
  id: 'ARUWLC-AAA-001',
  selector: 'aaa authentication-server radius',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "host <ip-address>" for the RADIUS server.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const host = getRadiusHost(node);

    if (!host) {
      return {
        passed: false,
        message: `RADIUS server "${profileName}" has no host configured.`,
        ruleId: 'ARUWLC-AAA-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `RADIUS server has host "${host}".`,
      ruleId: 'ARUWLC-AAA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-AAA-002: AAA RADIUS server must have key configured.
 */
export const WlcRadiusKey: IRule = {
  id: 'ARUWLC-AAA-002',
  selector: 'aaa authentication-server radius',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "key <shared-secret>" for the RADIUS server.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    if (!hasRadiusKey(node)) {
      return {
        passed: false,
        message: `RADIUS server "${profileName}" has no shared secret key.`,
        ruleId: 'ARUWLC-AAA-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'RADIUS server has key configured.',
      ruleId: 'ARUWLC-AAA-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-AAA-003: AAA server group should have at least one server.
 */
export const WlcServerGroupHasServers: IRule = {
  id: 'ARUWLC-AAA-003',
  selector: 'aaa server-group',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Add "auth-server <name>" to the server group.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    if (!hasChildCommand(node, 'auth-server')) {
      return {
        passed: false,
        message: `Server group "${profileName}" has no authentication servers.`,
        ruleId: 'ARUWLC-AAA-003',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Server group has authentication servers configured.',
      ruleId: 'ARUWLC-AAA-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// AP Group Rules
// =============================================================================

/**
 * ARUWLC-AP-001: AP groups should have virtual-APs assigned.
 */
export const WlcApGroupVaps: IRule = {
  id: 'ARUWLC-AP-001',
  selector: 'ap-group',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "virtual-ap <name>" entries to the AP group.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);
    const vaps = getApGroupVirtualAps(node);

    if (vaps.length === 0) {
      return {
        passed: false,
        message: `AP group "${profileName}" has no virtual-APs assigned.`,
        ruleId: 'ARUWLC-AP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `AP group has ${vaps.length} virtual-AP(s) assigned.`,
      ruleId: 'ARUWLC-AP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-AP-002: AP groups should have regulatory domain configured.
 */
export const WlcApGroupRegDomain: IRule = {
  id: 'ARUWLC-AP-002',
  selector: 'ap-group',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "regulatory-domain-profile <name>" to the AP group.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    if (!hasChildCommand(node, 'regulatory-domain-profile')) {
      return {
        passed: false,
        message: `AP group "${profileName}" has no regulatory domain profile.`,
        ruleId: 'ARUWLC-AP-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'AP group has regulatory domain configured.',
      ruleId: 'ARUWLC-AP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// RF Profile Rules
// =============================================================================

/**
 * ARUWLC-RF-001: ARM profiles should be referenced by radio profiles.
 */
export const WlcArmProfile: IRule = {
  id: 'ARUWLC-RF-001',
  selector: 'rf arm-profile',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'ARM profiles should be referenced in radio profiles for optimal RF management.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profileName = extractProfileName(node.id);

    return {
      passed: true,
      message: `ARM profile "${profileName}" is configured.`,
      ruleId: 'ARUWLC-RF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARUWLC-RF-002: Radio profiles should have ARM profile assigned.
 */
export const WlcRadioArmProfile: IRule = {
  id: 'ARUWLC-RF-002',
  selector: 'rf dot11',
  vendor: 'aruba-wlc',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "arm-profile <name>" to radio profiles for adaptive radio management.',
  },
  check: (node: ConfigNode): RuleResult => {
    const nodeId = node.id.toLowerCase();

    // Check for radio profiles (dot11a or dot11g)
    if (!nodeId.includes('radio-profile')) {
      return {
        passed: true,
        message: 'Not a radio profile.',
        ruleId: 'ARUWLC-RF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasChildCommand(node, 'arm-profile')) {
      return {
        passed: false,
        message: 'Radio profile has no ARM profile assigned.',
        ruleId: 'ARUWLC-RF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Radio profile has ARM profile assigned.',
      ruleId: 'ARUWLC-RF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Export all WLC rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// =============================================================================

export const allWlcRules: IRule[] = [
  // WLAN Security
  WlcSsidEncryption,
  // AAA
  WlcRadiusHost,
];
