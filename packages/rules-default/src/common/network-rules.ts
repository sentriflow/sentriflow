// packages/rules-default/src/common/network-rules.ts
// Vendor-agnostic network configuration rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  parseIp,
  isMulticastAddress,
  isBroadcastAddress,
  isShutdown,
  isInterfaceDefinition,
  startsWithIgnoreCase,
  includesIgnoreCase,
} from '@sentriflow/core';

/**
 * NET-IP-001: Ensure IP addresses are not Multicast, Global Broadcast,
 * or the Subnet Broadcast/Network ID addresses.
 *
 * Works with both Cisco "ip address X.X.X.X Y.Y.Y.Y" format
 * and Juniper "address X.X.X.X/Y" format.
 */
export const NoMulticastBroadcastIp: IRule = {
  id: 'NET-IP-001',
  selector: 'ip address',
  vendor: 'common',
  category: 'IP-Addressing',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    description: 'Ensure IP addresses are not Multicast, Broadcast, or Network ID addresses.',
    remediation:
      'Configure a valid unicast IP address. Do not use Multicast, Broadcast, or Network ID addresses.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Standard Cisco format: "ip address <IP> <MASK>"
    const ipStr = node.params[2];
    const maskStr = node.params[3];

    if (!ipStr) {
      return {
        passed: true,
        message: 'Incomplete ip address command.',
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip validation for dynamic IP assignment commands
    // These don't have actual IP addresses to validate
    const ipStrLower = ipStr.toLowerCase();
    const dynamicKeywords = ['dhcp', 'negotiated', 'ppp-negotiated', 'pool', 'auto'];
    if (dynamicKeywords.some((kw) => ipStrLower === kw || ipStrLower.startsWith(kw))) {
      return {
        passed: true,
        message: `Dynamic IP assignment (${ipStr}) - validation skipped.`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const ipNum = parseIp(ipStr);

    if (ipNum === null) {
      return {
        passed: false,
        message: `Invalid IP address format: ${ipStr}`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check Multicast (224.0.0.0 - 239.255.255.255)
    if (isMulticastAddress(ipNum)) {
      return {
        passed: false,
        message: `Invalid assignment: ${ipStr} is a Multicast address.`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check Global Broadcast (255.255.255.255)
    if (isBroadcastAddress(ipNum)) {
      return {
        passed: false,
        message: `Invalid assignment: ${ipStr} is the Global Broadcast address.`,
        ruleId: 'NET-IP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check Subnet Validity if Mask is provided
    if (maskStr) {
      const maskNum = parseIp(maskStr);
      if (maskNum !== null) {
        // Skip /32 masks (255.255.255.255) - valid for loopbacks and host routes
        if (maskNum === 0xffffffff) {
          return {
            passed: true,
            message: `IP address ${ipStr} with /32 mask is valid (host route/loopback).`,
            ruleId: 'NET-IP-001',
            nodeId: node.id,
            level: 'info',
            loc: node.loc,
          };
        }

        const networkAddr = (ipNum & maskNum) >>> 0;
        const broadcastAddr = (networkAddr | (~maskNum >>> 0)) >>> 0;

        if (ipNum === networkAddr) {
          return {
            passed: false,
            message: `Invalid assignment: ${ipStr} is the Network ID for subnet ${maskStr}.`,
            ruleId: 'NET-IP-001',
            nodeId: node.id,
            level: 'error',
            loc: node.loc,
          };
        }

        if (ipNum === broadcastAddr) {
          return {
            passed: false,
            message: `Invalid assignment: ${ipStr} is the Broadcast address for subnet ${maskStr}.`,
            ruleId: 'NET-IP-001',
            nodeId: node.id,
            level: 'error',
            loc: node.loc,
          };
        }
      }
    }

    return {
      passed: true,
      message: `IP address ${ipStr} is valid.`,
      ruleId: 'NET-IP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NET-DOC-001: Ensure interfaces have a description configured.
 * Applies to both Cisco and Juniper interface sections.
 */
export const InterfaceDescriptionRequired: IRule = {
  id: 'NET-DOC-001',
  selector: 'interface',
  vendor: 'common',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    description: 'Ensure interfaces have descriptive labels for operational clarity.',
    remediation:
      'Add a description to the interface using the "description" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = node.id;

    // Skip nodes that aren't actual interface definitions
    if (!isInterfaceDefinition(node)) {
      return {
        passed: true,
        message: 'Not an interface definition.',
        ruleId: 'NET-DOC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip administratively shutdown interfaces - we don't care about descriptions on disabled interfaces
    if (isShutdown(node)) {
      return {
        passed: true,
        message: 'Shutdown interface - description not required.',
        ruleId: 'NET-DOC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip Null and Loopback interfaces - descriptions often optional
    if (includesIgnoreCase(interfaceName, 'null') || includesIgnoreCase(interfaceName, 'loopback')) {
      return {
        passed: true,
        message: 'Loopback/Null interface - description optional.',
        ruleId: 'NET-DOC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip Juniper lo0 (loopback)
    if (includesIgnoreCase(interfaceName, 'lo0')) {
      return {
        passed: true,
        message: 'Loopback interface - description optional.',
        ruleId: 'NET-DOC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasDescription = node.children.some((child) =>
      startsWithIgnoreCase(child.id, 'description')
    );

    if (!hasDescription) {
      return {
        passed: false,
        message: `Interface "${node.params.slice(1).join(' ')}" is missing a description.`,
        ruleId: 'NET-DOC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Interface has a description.',
      ruleId: 'NET-DOC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// NOTE: NET-SEC-001 moved to cisco/ios-rules.ts (CiscoNoPlaintextPasswords)
// NOTE: Additional rules (NET-SEC-002, NET-SEC-003) available in sf-essentials

/** All common network rules - proof-of-concept subset */
export const allCommonRules: IRule[] = [
  NoMulticastBroadcastIp,
  InterfaceDescriptionRequired,
];
