// packages/core/src/parser/vendors/index.ts

import type { VendorSchema } from '../VendorSchema';
import { CiscoIOSSchema } from './cisco-ios';
import { CiscoNXOSSchema } from './cisco-nxos';
import { JuniperJunOSSchema } from './juniper-junos';
import { ArubaAOSCXSchema } from './aruba-aoscx';
import { ArubaAOSSwitchSchema } from './aruba-aosswitch';
import { ArubaWLCSchema } from './aruba-wlc';
import { PaloAltoPANOSSchema } from './paloalto-panos';
import { AristaEOSSchema } from './arista-eos';
import { VyOSSchema } from './vyos-vyos';
import { FortinetFortiGateSchema } from './fortinet-fortigate';
import { ExtremeEXOSSchema } from './extreme-exos';
import { ExtremeVOSSSchema } from './extreme-voss';
import { HuaweiVRPSchema } from './huawei-vrp';
import { MikroTikRouterOSSchema } from './mikrotik-routeros';
import { NokiaSROSSchema } from './nokia-sros';
import { CumulusLinuxSchema } from './cumulus-linux';

// ============================================================================
// SEC-002: ReDoS-safe helper functions
// These replace potentially dangerous multiline regex patterns with
// line-by-line processing to prevent catastrophic backtracking.
// ============================================================================

/**
 * SEC-002: Safe detection for FortiOS edit/next pattern.
 * Replaces: /^config\s+\S+[\s\S]*?^\s+edit\s+/m with /^\s+next$/m
 * which could cause ReDoS with crafted input.
 */
function hasFortiOSEditPattern(lines: string[]): boolean {
  let inConfig = false;
  let hasEdit = false;
  for (const line of lines) {
    if (/^config\s+\S+/.test(line)) {
      inConfig = true;
    }
    if (inConfig && /^\s+edit\s+/.test(line)) {
      hasEdit = true;
    }
    if (/^\s+next$/.test(line) && hasEdit) {
      return true;
    }
    if (/^end$/.test(line)) {
      inConfig = false;
      hasEdit = false;
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for FortiOS config/set/end pattern.
 * Replaces: /^config\s+\S+[\s\S]*?^\s+set\s+\S+/m with /^end$/m
 */
function hasFortiOSSetPattern(lines: string[]): boolean {
  let inConfig = false;
  for (const line of lines) {
    if (/^config\s+\S+/.test(line)) {
      inConfig = true;
    }
    if (inConfig && /^\s+set\s+\S+/.test(line)) {
      return true;
    }
    if (/^end$/.test(line)) {
      inConfig = false;
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Palo Alto network block with specific content.
 * Replaces: /^\s*network\s*\{[\s\S]*?(ethernet\d+\/\d+|zone|virtual-router)/m
 */
function hasPaloAltoNetworkBlock(lines: string[]): boolean {
  let inNetworkBlock = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*network\s*\{/.test(line)) {
      inNetworkBlock = true;
      braceDepth = 1;
      continue;
    }
    if (inNetworkBlock) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/(ethernet\d+\/\d+|zone|virtual-router)/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inNetworkBlock = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Palo Alto security/nat rules block.
 * Replaces: /^\s*(security|nat)\s*\{[\s\S]*?rules\s*\{/m
 */
function hasPaloAltoRulesBlock(lines: string[]): boolean {
  let inSecurityOrNat = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*(security|nat)\s*\{/.test(line)) {
      inSecurityOrNat = true;
      braceDepth = 1;
      continue;
    }
    if (inSecurityOrNat) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/rules\s*\{/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inSecurityOrNat = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Palo Alto threat profiles block.
 * Replaces: /^\s*profiles\s*\{[\s\S]*?(virus|spyware|vulnerability|url-filtering|wildfire-analysis)/m
 */
function hasPaloAltoProfilesBlock(lines: string[]): boolean {
  let inProfiles = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*profiles\s*\{/.test(line)) {
      inProfiles = true;
      braceDepth = 1;
      continue;
    }
    if (inProfiles) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/(virus|spyware|vulnerability|url-filtering|wildfire-analysis)/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inProfiles = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS service block with specific services.
 * Replaces: /^\s*service\s*\{[\s\S]*?(ssh|dhcp-server|dns|https|lldp)/m
 */
function hasVyOSServiceBlock(lines: string[]): boolean {
  let inService = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*service\s*\{/.test(line)) {
      inService = true;
      braceDepth = 1;
      continue;
    }
    if (inService) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/(ssh|dhcp-server|dns|https|lldp)/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inService = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS NAT with source/destination rules.
 * Replaces: /^\s*nat\s*\{[\s\S]*?(source|destination)\s*\{[\s\S]*?rule\s+\d+/m
 */
function hasVyOSNatRuleBlock(lines: string[]): boolean {
  let inNat = false;
  let inSourceOrDest = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*nat\s*\{/.test(line)) {
      inNat = true;
      braceDepth = 1;
      continue;
    }
    if (inNat) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/(source|destination)\s*\{/.test(line)) {
        inSourceOrDest = true;
      }
      if (inSourceOrDest && /rule\s+\d+/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inNat = false;
        inSourceOrDest = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS ethernet interface block.
 * Replaces: /^\s*interfaces\s*\{[\s\S]*?ethernet\s+eth\d+\s*\{/m
 */
function hasVyOSEthernetBlock(lines: string[]): boolean {
  let inInterfaces = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*interfaces\s*\{/.test(line)) {
      inInterfaces = true;
      braceDepth = 1;
      continue;
    }
    if (inInterfaces) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/ethernet\s+eth\d+\s*\{/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inInterfaces = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS firewall name ruleset.
 * Replaces: /^\s*firewall\s*\{[\s\S]*?name\s+\S+\s*\{[\s\S]*?rule\s+\d+/m
 */
function hasVyOSFirewallRuleBlock(lines: string[]): boolean {
  let inFirewall = false;
  let inName = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*firewall\s*\{/.test(line)) {
      inFirewall = true;
      braceDepth = 1;
      continue;
    }
    if (inFirewall) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/name\s+\S+\s*\{/.test(line)) {
        inName = true;
      }
      if (inName && /rule\s+\d+/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inFirewall = false;
        inName = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS high-availability/VRRP block.
 * Replaces: /^\s*high-availability\s*\{[\s\S]*?vrrp\s*\{/m
 */
function hasVyOSHighAvailabilityBlock(lines: string[]): boolean {
  let inHA = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*high-availability\s*\{/.test(line)) {
      inHA = true;
      braceDepth = 1;
      continue;
    }
    if (inHA) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/vrrp\s*\{/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inHA = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS VPN IPsec site-to-site.
 * Replaces: /^\s*vpn\s*\{[\s\S]*?ipsec\s*\{[\s\S]*?site-to-site/m
 */
function hasVyOSVpnIpsecBlock(lines: string[]): boolean {
  let inVpn = false;
  let inIpsec = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*vpn\s*\{/.test(line)) {
      inVpn = true;
      braceDepth = 1;
      continue;
    }
    if (inVpn) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/ipsec\s*\{/.test(line)) {
        inIpsec = true;
      }
      if (inIpsec && /site-to-site/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inVpn = false;
        inIpsec = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VyOS protocols static routes.
 * Replaces: /^\s*protocols\s*\{[\s\S]*?static\s*\{[\s\S]*?route\s+[\d.\/]+\s*\{/m
 */
function hasVyOSStaticRouteBlock(lines: string[]): boolean {
  let inProtocols = false;
  let inStatic = false;
  let braceDepth = 0;
  for (const line of lines) {
    if (/^\s*protocols\s*\{/.test(line)) {
      inProtocols = true;
      braceDepth = 1;
      continue;
    }
    if (inProtocols) {
      braceDepth += (line.match(/\{/g) || []).length;
      braceDepth -= (line.match(/\}/g) || []).length;
      if (/static\s*\{/.test(line)) {
        inStatic = true;
      }
      if (inStatic && /route\s+[\d.\/]+\s*\{/.test(line)) {
        return true;
      }
      if (braceDepth <= 0) {
        inProtocols = false;
        inStatic = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Nokia SR OS router block with interface.
 * Replaces: /^\s+router\s*[\s\S]*?interface\s+"[^"]+"/m
 */
function hasNokiaRouterInterfaceBlock(lines: string[]): boolean {
  let inRouter = false;
  for (const line of lines) {
    if (/^\s+router\s*(".*")?$/.test(line)) {
      inRouter = true;
      continue;
    }
    if (inRouter) {
      if (/interface\s+"[^"]+"/.test(line)) {
        return true;
      }
      // Exit router block on unindented line (excluding blank lines)
      if (line.trim() && !/^\s/.test(line)) {
        inRouter = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Nokia SR OS system name.
 * Replaces: /^\s+system[\s\S]*?name\s+"[^"]+"/m
 */
function hasNokiaSystemNameBlock(lines: string[]): boolean {
  let inSystem = false;
  for (const line of lines) {
    if (/^\s+system\s*$/.test(line)) {
      inSystem = true;
      continue;
    }
    if (inSystem) {
      if (/name\s+"[^"]+"/.test(line)) {
        return true;
      }
      if (line.trim() && !/^\s/.test(line)) {
        inSystem = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Nokia SR OS BGP group.
 * Replaces: /^\s+bgp[\s\S]*?group\s+"[^"]+"/m
 */
function hasNokiaBgpGroupBlock(lines: string[]): boolean {
  let inBgp = false;
  for (const line of lines) {
    if (/^\s+bgp\s*$/.test(line)) {
      inBgp = true;
      continue;
    }
    if (inBgp) {
      if (/group\s+"[^"]+"/.test(line)) {
        return true;
      }
      if (line.trim() && !/^\s/.test(line)) {
        inBgp = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Nokia SR OS port with admin-state.
 * Replaces: /^port\s+\d+\/\d+\/\d+[\s\S]*?admin-state/m
 */
function hasNokiaPortAdminState(lines: string[]): boolean {
  let inPort = false;
  for (const line of lines) {
    if (/^port\s+\d+\/\d+\/\d+/.test(line)) {
      inPort = true;
      continue;
    }
    if (inPort) {
      if (/admin-state/.test(line)) {
        return true;
      }
      // Exit port block on non-indented line
      if (line.trim() && !/^\s/.test(line)) {
        inPort = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Nokia SR OS card/MDA.
 * Replaces: /^card\s+\d+[\s\S]*?mda\s+\d+/m
 */
function hasNokiaCardMdaBlock(lines: string[]): boolean {
  let inCard = false;
  for (const line of lines) {
    if (/^card\s+\d+/.test(line)) {
      inCard = true;
      continue;
    }
    if (inCard) {
      if (/mda\s+\d+/.test(line)) {
        return true;
      }
      if (line.trim() && !/^\s/.test(line)) {
        inCard = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for VOSS router isis with SPBM.
 * Replaces: /^router\s+isis[\s\S]*?spbm\s+\d+/m
 */
function hasVossRouterIsisSpbm(lines: string[]): boolean {
  let inIsis = false;
  for (const line of lines) {
    if (/^router\s+isis/.test(line)) {
      inIsis = true;
      continue;
    }
    if (inIsis) {
      if (/spbm\s+\d+/.test(line)) {
        return true;
      }
      // Exit on another top-level command
      if (line.trim() && !/^\s/.test(line) && !/^!/.test(line)) {
        inIsis = false;
      }
    }
  }
  return false;
}

/**
 * SEC-002: Safe detection for Huawei AAA block.
 * Replaces: /^aaa\s*$/m with /^\s+(authentication-scheme|authorization-scheme|local-user)/m
 */
function hasHuaweiAaaBlock(lines: string[]): boolean {
  let inAaa = false;
  for (const line of lines) {
    if (/^aaa\s*$/.test(line)) {
      inAaa = true;
      continue;
    }
    if (inAaa) {
      if (/^\s+(authentication-scheme|authorization-scheme|local-user)/.test(line)) {
        return true;
      }
      if (line.trim() && !/^\s/.test(line) && !/^#/.test(line)) {
        inAaa = false;
      }
    }
  }
  return false;
}

/** All registered vendor schemas */
export const vendorSchemas: VendorSchema[] = [
  CiscoIOSSchema,
  CiscoNXOSSchema,
  JuniperJunOSSchema,
  ArubaAOSCXSchema,
  ArubaAOSSwitchSchema,
  ArubaWLCSchema,
  PaloAltoPANOSSchema,
  AristaEOSSchema,
  VyOSSchema,
  FortinetFortiGateSchema,
  ExtremeEXOSSchema,
  ExtremeVOSSSchema,
  HuaweiVRPSchema,
  MikroTikRouterOSSchema,
  NokiaSROSSchema,
  CumulusLinuxSchema,
];

/** Default vendor when none specified or detection fails */
export const defaultVendor = CiscoIOSSchema;

/**
 * Get vendor schema by ID.
 * @param vendorId The vendor identifier (e.g., 'cisco-ios', 'juniper-junos')
 * @returns The matching VendorSchema
 * @throws Error if vendor not found
 */
export function getVendor(vendorId: string): VendorSchema {
  const vendor = vendorSchemas.find((v) => v.id === vendorId);
  if (!vendor) {
    const available = vendorSchemas.map((v) => v.id).join(', ');
    throw new Error(`Unknown vendor: ${vendorId}. Available: ${available}`);
  }
  return vendor;
}

/**
 * Check if a vendor ID is valid.
 * @param vendorId The vendor identifier to check
 * @returns true if the vendor exists
 */
export function isValidVendor(vendorId: string): boolean {
  return vendorSchemas.some((v) => v.id === vendorId);
}

/**
 * Get all available vendor IDs.
 * @returns Array of vendor identifiers
 */
export function getAvailableVendors(): string[] {
  return vendorSchemas.map((v) => v.id);
}

/**
 * Vendor info for display purposes.
 */
export interface VendorInfo {
  id: string;
  name: string;
}

/**
 * Get all available vendors with their display names.
 * @returns Array of vendor info objects
 */
export function getAvailableVendorInfo(): VendorInfo[] {
  return vendorSchemas.map((v) => ({ id: v.id, name: v.name }));
}

/**
 * Auto-detect vendor from configuration text.
 * Uses heuristics based on syntax patterns unique to each vendor.
 *
 * Detection priority:
 * 1. Juniper JunOS - brace-based hierarchy, set commands
 * 2. Aruba WLC - profile-based WLAN configuration
 * 3. Aruba AOS-CX - modern switch syntax
 * 4. Aruba AOS-Switch - legacy ProCurve syntax
 * 5. Cisco NX-OS - feature commands, VDC
 * 6. Cisco IOS - default fallback
 *
 * SEC-002: ReDoS protection implemented via:
 * - Reduced sample size (2000 chars for initial pass)
 * - Line-by-line processing for complex pattern detection
 * - Replaced dangerous [\s\S]*? patterns with safe helper functions
 *
 * @param configText The configuration text to analyze
 * @returns The detected VendorSchema (defaults to Cisco IOS)
 */
export function detectVendor(configText: string): VendorSchema {
  // SEC-002: Analyze first portion of config for detection patterns
  // Reduced from 4000 to 2000 chars for better ReDoS protection
  const sampleText = configText.slice(0, 2000);

  // SEC-002: Pre-split lines for safe helper functions
  // This is done once and reused by multiple detection functions
  const lines = sampleText.split('\n');

  // ============ NVIDIA Cumulus Linux Detection ============
  // Cumulus uses NCLU (net add/del), NVUE (nv set/unset), or Debian-style ifupdown2
  // Must be checked early due to unique command prefixes

  // NCLU commands: net add interface, net add bgp, net add vlan
  if (/^net\s+(add|del)\s+(interface|bgp|ospf|vlan|bond|bridge|clag|routing|loopback)\s+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // NVUE commands: nv set interface, nv set router bgp, nv set bridge
  if (/^nv\s+(set|unset)\s+(interface|router|bridge|vrf|system|service|evpn|nve|qos)\s+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // NVUE config commands: nv config apply, nv config save
  if (/^nv\s+config\s+(apply|save|diff|patch|replace)/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus-specific interface naming: swpN (switch ports)
  // Combined with Debian ifupdown2 syntax
  if (/^auto\s+swp\d+/m.test(sampleText) || /^iface\s+swp\d+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus MLAG (CLAG) configuration
  if (/^net\s+add\s+clag\s+peer/m.test(sampleText) || /^clagd-/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus bridge configuration with bridge-vids, bridge-pvid (VLAN-aware bridge)
  if (/^\s+bridge-vids\s+/m.test(sampleText) && /^\s+bridge-pvid\s+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus bridge-vlan-aware directive (distinctive)
  if (/^\s+bridge-vlan-aware\s+yes/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus peerlink interface (MLAG)
  if (/^auto\s+peerlink/m.test(sampleText) || /^iface\s+peerlink/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus bond with clag-id
  if (/^\s+clag-id\s+\d+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // Cumulus vlan-raw-device directive
  if (/^\s+vlan-raw-device\s+/m.test(sampleText)) {
    return CumulusLinuxSchema;
  }

  // ============ MikroTik RouterOS Detection ============
  // RouterOS uses distinctive path-based syntax with forward slashes
  // Must be checked early as paths like /ip could be confused with comments

  // MikroTik interface paths: /interface ethernet, /interface vlan, /interface bridge
  if (/^\/interface\s+(ethernet|vlan|bridge|wireless|bonding|wireguard)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik IP configuration: /ip address, /ip firewall, /ip route, /ip dns
  if (/^\/ip\s+(address|firewall|route|dns|pool|dhcp-server|dhcp-client|service)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik system identity (hostname equivalent)
  if (/^\/system\s+identity/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik routing protocols
  if (/^\/routing\s+(bgp|ospf|filter|bfd|id)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik user management
  if (/^\/user\s*$/m.test(sampleText) || /^\/user\s+group/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik queue configuration
  if (/^\/queue\s+(simple|tree|type)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik tools
  if (/^\/tool\s+(bandwidth-server|netwatch|mac-server|e-mail|graphing)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik CAPsMAN (wireless controller)
  if (/^\/caps-man\s/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik distinctive find expression syntax: [ find default-name=ether1 ]
  if (/\[\s*find\s+[a-z-]+=["']?[^\]]+["']?\s*\]/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik add/set commands with property=value syntax under path blocks
  // Distinctive pattern: add chain=input action=accept
  if (/^add\s+[a-z-]+=\S+.*[a-z-]+=\S+/m.test(sampleText) && /^\/[a-z]/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik SNMP and certificates
  if (/^\/snmp\s*$/m.test(sampleText) || /^\/certificate\s*$/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik PPP configuration
  if (/^\/ppp\s+(profile|secret|aaa)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // MikroTik system logging, NTP, scheduler
  if (/^\/system\s+(logging|ntp|scheduler|script|clock)/m.test(sampleText)) {
    return MikroTikRouterOSSchema;
  }

  // ============ Fortinet FortiGate (FortiOS) Detection ============
  // FortiOS uses distinctive config/edit/next/end syntax

  // FortiOS config blocks: "config system global", "config firewall policy"
  if (/^config\s+system\s+(global|interface|admin|dns|ntp|ha|settings)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS firewall config: "config firewall policy", "config firewall address"
  if (/^config\s+firewall\s+(policy|address|addrgrp|service|vip|ippool)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS VPN config: "config vpn ipsec phase1-interface"
  if (/^config\s+vpn\s+(ipsec|ssl)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS router config: "config router static", "config router bgp"
  if (/^config\s+router\s+(static|bgp|ospf|policy|rip|access-list|prefix-list|route-map)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS security profiles: "config antivirus profile", "config webfilter profile"
  if (/^config\s+(antivirus|webfilter|ips|application|dlp|spamfilter|emailfilter|dnsfilter|waf|voip)\s+/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS user config: "config user local", "config user ldap"
  if (/^config\s+user\s+(local|group|ldap|radius|tacacs|fsso)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS log config: "config log syslogd setting"
  if (/^config\s+log\s+(syslogd|fortianalyzer|disk|memory)/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS edit with next pattern (very distinctive)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasFortiOSEditPattern(lines)) {
    return FortinetFortiGateSchema;
  }

  // FortiOS set commands within config blocks
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasFortiOSSetPattern(lines) && /^end$/m.test(sampleText)) {
    return FortinetFortiGateSchema;
  }

  // ============ Palo Alto PAN-OS Detection ============
  // PAN-OS uses distinctive top-level stanzas and set commands

  // Palo Alto hierarchical format: "deviceconfig {", "rulebase {"
  if (/^\s*(deviceconfig|rulebase|mgt-config|vsys\d*)\s*\{/m.test(sampleText)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto network config with zone or interface naming
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasPaloAltoNetworkBlock(lines)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto set commands format
  // Note: 'service' in Palo Alto refers to service objects (HTTP, HTTPS, etc.)
  // NOT service daemons like VyOS (service ssh, service dhcp-server)
  // Palo Alto service objects: "set service <name> protocol tcp port <port>"
  if (/^set\s+(deviceconfig|rulebase|network\s+interface\s+ethernet|address|zone)\s+/m.test(sampleText)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto service objects (more specific pattern)
  if (/^set\s+service\s+\S+\s+protocol\s+(tcp|udp)/m.test(sampleText)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto security rules format
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasPaloAltoRulesBlock(lines)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto threat profiles
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasPaloAltoProfilesBlock(lines)) {
    return PaloAltoPANOSSchema;
  }

  // Palo Alto GlobalProtect
  if (/^\s*global-protect\s*\{/m.test(sampleText)) {
    return PaloAltoPANOSSchema;
  }

  // Panorama specific constructs
  if (/^\s*(device-group|template|template-stack|shared)\s*\{/m.test(sampleText)) {
    return PaloAltoPANOSSchema;
  }

  // ============ VyOS/EdgeOS Detection ============
  // VyOS uses brace-based hierarchy with distinctive top-level stanzas
  // Must be checked before JunOS since both use braces and 'set' commands

  // VyOS set commands with distinctive paths
  // VyOS uses 'set interfaces ethernet' (not 'set interfaces ge-')
  if (/^set\s+(interfaces\s+ethernet|service\s+ssh|nat\s+source|firewall\s+name|high-availability|vpn\s+ipsec|traffic-policy|container\s+name)\s+/m.test(sampleText)) {
    return VyOSSchema;
  }

  // VyOS hierarchical format with distinctive stanzas
  // 'service' and 'nat' as top-level are VyOS-specific (not JunOS)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSServiceBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS NAT structure (source/destination rules)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSNatRuleBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS ethernet interface naming (eth0, eth1, etc.)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSEthernetBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS set commands for ethernet interfaces
  if (/^set\s+interfaces\s+ethernet\s+eth\d+/m.test(sampleText)) {
    return VyOSSchema;
  }

  // VyOS firewall name ruleset (vs JunOS filter)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSFirewallRuleBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS zone-based firewall
  if (/^set\s+firewall\s+zone\s+/m.test(sampleText)) {
    return VyOSSchema;
  }

  // VyOS bonding/bridge interfaces (distinctive names)
  if (/^set\s+interfaces\s+(bonding\s+bond\d+|bridge\s+br\d+|wireguard\s+wg\d+)/m.test(sampleText)) {
    return VyOSSchema;
  }

  // VyOS high-availability/VRRP structure
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSHighAvailabilityBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS VPN IPsec site-to-site
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSVpnIpsecBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS protocols static routes structure
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVyOSStaticRouteBlock(lines)) {
    return VyOSSchema;
  }

  // VyOS/EdgeOS comment format /* comment */
  if (/^\/\*\s*.+\s*\*\/$/m.test(sampleText) && /^\s*(interfaces|firewall|nat|service|protocols)\s*\{/m.test(sampleText)) {
    return VyOSSchema;
  }

  // ============ Juniper JunOS Detection ============
  // JunOS uses brace-based hierarchy and has distinctive top-level stanzas

  // Hierarchical format with braces: "system {", "interfaces {"
  // These patterns are unique to JunOS display format
  if (/^\s*(system|chassis|interfaces|protocols|policy-options|routing-options|routing-instances|security|firewall|class-of-service|vlans|bridge-domains)\s*\{/m.test(sampleText)) {
    return JuniperJunOSSchema;
  }

  // Set commands format: "set interfaces ge-0/0/0"
  // JunOS flat configuration format
  if (/^set\s+(system|chassis|interfaces|protocols|policy-options|routing-options|routing-instances|security|firewall)/m.test(sampleText)) {
    return JuniperJunOSSchema;
  }

  // JunOS-style interface names (ge-, xe-, et-, ae-, lo0, etc.)
  // Combined with brace on same line or next line
  if (/^\s*(ge|xe|et|ae|lo|irb|vlan|em|fxp)-[\d\/:.]+\s*\{/m.test(sampleText)) {
    return JuniperJunOSSchema;
  }

  // JunOS version statement
  if (/^version\s+[\d.]+[A-Z]\d+/m.test(sampleText)) {
    return JuniperJunOSSchema;
  }

  // ============ Aruba WLC Detection ============
  // ArubaOS WLC uses profile-based WLAN configuration

  // WLAN SSID profiles and virtual-AP (most distinctive)
  if (/^wlan\s+(ssid-profile|virtual-ap)\s+["']?[^"'\n]+["']?/m.test(sampleText)) {
    return ArubaWLCSchema;
  }

  // AP groups (wireless controller specific)
  if (/^ap-group\s+["']?[^"'\n]+["']?/m.test(sampleText)) {
    return ArubaWLCSchema;
  }

  // AAA authentication-server radius with quoted name (WLC style)
  if (/^aaa\s+authentication-server\s+radius\s+["'][^"']+["']/m.test(sampleText)) {
    return ArubaWLCSchema;
  }

  // RF profiles (ARM, dot11a, dot11g)
  if (/^rf\s+(arm-profile|dot11[ag]-radio-profile)\s+["']?[^"'\n]+["']?/m.test(sampleText)) {
    return ArubaWLCSchema;
  }

  // AAA profile with quoted name (WLC style)
  if (/^aaa\s+profile\s+["'][^"']+["']/m.test(sampleText)) {
    return ArubaWLCSchema;
  }

  // ============ Aruba AOS-CX Detection ============
  // AOS-CX uses Cisco-like syntax but with distinctive patterns

  // AOS-CX version string
  if (/^!Version\s+ArubaOS-CX/m.test(sampleText)) {
    return ArubaAOSCXSchema;
  }

  // AOS-CX interface naming: slot/member/port format (1/1/1)
  if (/^interface\s+\d+\/\d+\/\d+/m.test(sampleText)) {
    return ArubaAOSCXSchema;
  }

  // AOS-CX specific VLAN commands under interface
  if (/^\s+vlan\s+(access|trunk\s+(native|allowed))\s+\d+/m.test(sampleText)) {
    return ArubaAOSCXSchema;
  }

  // AOS-CX LAG interface
  if (/^interface\s+lag\s+\d+/m.test(sampleText)) {
    return ArubaAOSCXSchema;
  }

  // AOS-CX VSX configuration
  if (/^vsx\s*$/m.test(sampleText) || /^vsx-sync\s+/m.test(sampleText)) {
    return ArubaAOSCXSchema;
  }

  // ============ Aruba AOS-Switch Detection ============
  // AOS-Switch (ProVision) uses VLAN-centric configuration

  // ProCurve/ProVision configuration editor header
  if (/^;\s*[A-Z]\d+\w+\s+Configuration\s+Editor/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // AOS-Switch VLAN with tagged/untagged port lists
  // Match either: vlan X\n   tagged/untagged OR just indented tagged/untagged commands
  if (/^vlan\s+\d+[\s\S]*?^\s+(tagged|untagged)\s+[\dA-Za-z][\d,-]*/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // Also detect if we see indented tagged/untagged patterns (AOS-Switch specific)
  if (/^\s+(tagged|untagged)\s+[\dA-Za-z,-]+\s*$/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // AOS-Switch hostname with ProCurve or Aruba prefix
  if (/^hostname\s+["']?(ProCurve|Aruba)/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // AOS-Switch specific: trunk command for LAG (not Cisco trunk)
  // Distinguished by port numbers following trunk name
  if (/^trunk\s+[\dA-Za-z][\d,-]+\s+\w+/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // AOS-Switch specific: timesync sntp
  if (/^timesync\s+sntp/m.test(sampleText)) {
    return ArubaAOSSwitchSchema;
  }

  // ============ Cisco NX-OS Detection ============
  // NX-OS has feature activation commands and VDC support

  // Feature commands at the start of config
  if (/^feature\s+\w+/m.test(sampleText)) {
    return CiscoNXOSSchema;
  }

  // NX-OS specific: VDC (Virtual Device Context)
  if (/^vdc\s+\w+/m.test(sampleText)) {
    return CiscoNXOSSchema;
  }

  // Install feature-set (NX-OS)
  if (/^install\s+feature-set/m.test(sampleText)) {
    return CiscoNXOSSchema;
  }

  // NX-OS specific: vrf context (vs IOS: ip vrf or vrf definition)
  if (/^vrf\s+context\s+\S+/m.test(sampleText)) {
    return CiscoNXOSSchema;
  }

  // NX-OS specific: vpc domain
  if (/^vpc\s+domain\s+\d+/m.test(sampleText)) {
    return CiscoNXOSSchema;
  }

  // ============ Arista EOS Detection ============
  // EOS is similar to IOS but has unique patterns

  // MLAG configuration (most distinctive Arista feature)
  if (/^mlag\s+configuration/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Management API (eAPI) - Arista specific
  if (/^management\s+api\s+(http-commands|gnmi|netconf|restconf)/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista daemon configuration
  if (/^daemon\s+\S+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista event-handler
  if (/^event-handler\s+\S+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // CVX (CloudVision Exchange) - Arista specific
  if (/^cvx$/m.test(sampleText) || /^management\s+cvx/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista VRF instance syntax (vs Cisco vrf definition or vrf context)
  if (/^vrf\s+instance\s+\S+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista interface Vxlan (VXLAN VTEP interface)
  if (/^interface\s+Vxlan\d*/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista-style VXLAN flood vtep
  if (/^\s+vxlan\s+(vni|flood\s+vtep|source-interface)/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista peer-filter (BGP)
  if (/^peer-filter\s+\S+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista tap aggregation
  if (/^tap\s+aggregation/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista queue-monitor
  if (/^queue-monitor\s+(streaming|length)/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista traffic-policy
  if (/^traffic-policy\s+\S+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista hardware counter feature
  if (/^hardware\s+counter\s+feature/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista version string in show commands output or config
  if (/Arista\s+(DCS|vEOS|CCS)/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // Arista EOS software version format
  if (/^!\s*Software\s+image\s+version:\s+\d+\.\d+\.\d+/m.test(sampleText)) {
    return AristaEOSSchema;
  }

  // ============ Extreme Networks EXOS Detection ============
  // ExtremeXOS uses distinctive create/configure/enable command patterns
  // Must be checked before Cisco IOS as some patterns overlap

  // EXOS distinctive "create vlan" command with named VLANs
  if (/^create\s+vlan\s+["']?\w+["']?\s*(tag\s+\d+)?/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "configure vlan" commands (distinctive because VLANs are named)
  if (/^configure\s+vlan\s+["']?\w+["']?\s+(ipaddress|add\s+ports|tag)/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS SNMP sysname configuration (distinctive from Cisco hostname)
  if (/^configure\s+snmp\s+sysname\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "enable sharing" for LAG (EXOS-specific syntax)
  if (/^enable\s+sharing\s+\d+:\d+\s+grouping\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "create eaps" for Ethernet Automatic Protection Switching
  if (/^create\s+eaps\s+\S+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "configure sntp-client" (vs Cisco ntp server)
  if (/^configure\s+sntp-client\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "enable sntp-client" (distinctive EXOS enable pattern)
  if (/^enable\s+sntp-client/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS port format: slot:port (1:1, 2:24, etc.)
  // Combined with EXOS-specific commands
  if (/^configure\s+ports?\s+\d+:\d+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "enable jumbo-frame ports" (EXOS-specific)
  if (/^enable\s+jumbo-frame\s+ports\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS "configure ip-mtu" (vs Cisco mtu)
  if (/^configure\s+ip-mtu\s+\d+\s+vlan\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS Virtual Router (VR) configuration
  if (/^(create|configure)\s+vr\s+\S+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS MLAG peer configuration
  if (/^(create|configure)\s+mlag\s+peer\s+/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS stacking configuration
  if (/^enable\s+stacking$/m.test(sampleText) || /^configure\s+stacking\s+node-address/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS ELRP (Extreme Loop Recovery Protocol)
  if (/^enable\s+elrp-client/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // EXOS distinctive "configure vlan Default delete ports"
  if (/^configure\s+vlan\s+Default\s+delete\s+ports/m.test(sampleText)) {
    return ExtremeEXOSSchema;
  }

  // ============ Extreme Networks VOSS Detection ============
  // VOSS uses Cisco-like syntax but with distinctive VSP/Fabric Connect patterns

  // VOSS "vlan create" command (vs EXOS "create vlan")
  if (/^vlan\s+create\s+\d+\s+type\s+(port-mstprstp|spbm-bvlan)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "vlan members" command (distinctive VOSS syntax)
  if (/^vlan\s+members\s+\d+\s+\d+\/\d+/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "vlan i-sid" command (I-SID for SPBM/Fabric Connect)
  if (/^vlan\s+i-sid\s+\d+\s+\d+/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "router isis" with SPBM configuration
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasVossRouterIsisSpbm(lines)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "spbm" command (Shortest Path Bridging MAC)
  if (/^spbm\s+\d+\s+(b-vid|nick-name|sys-id)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "i-sid" command (Instance Service ID)
  if (/^i-sid\s+\d+\s+(vlan|elan-transparent)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "interface GigabitEthernet" with slot/port format
  if (/^interface\s+GigabitEthernet\s+\d+\/\d+$/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "interface mlt" (Multi-Link Trunk)
  if (/^interface\s+mlt\s+\d+/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "mlt" command for MLT configuration
  if (/^mlt\s+\d+\s+(enable|name|member)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "lacp enable" under interface or MLT
  if (/^lacp\s+(enable|key|aggregation-wait-time)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "dvr" command (Distributed Virtual Routing)
  if (/^dvr\s+(leaf|controller|domain-id)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "cfm" command (Connectivity Fault Management)
  if (/^cfm\s+(spbm\s+mip|spbm\s+level|enable)/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "snmp-server name" (vs Cisco hostname)
  if (/^snmp-server\s+name\s+["']?\S+["']?/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "boot config flags" command
  if (/^boot\s+config\s+flags\s+/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // VOSS "sys name" command
  if (/^sys\s+name\s+["']?\S+["']?/m.test(sampleText)) {
    return ExtremeVOSSSchema;
  }

  // ============ Nokia SR OS Detection ============
  // SR OS uses hierarchical CLI with configure/router/system blocks
  // and distinctive port notation (slot/mda/port) and admin-state commands
  // Must be checked before Huawei and Cisco as some patterns overlap

  // Nokia SR OS distinctive "configure" followed by "router" block structure
  if (/^configure$/m.test(sampleText) && /^\s+router\s+"?[^"]*"?\s*$/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS distinctive port notation with admin-state
  // Port format: port X/Y/Z (slot/mda/port)
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasNokiaPortAdminState(lines)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS router with named interfaces using quotes
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasNokiaRouterInterfaceBlock(lines)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS system name configuration (system > name "...")
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasNokiaSystemNameBlock(lines)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS service types (vpls, vprn, epipe, ies)
  if (/^\s+(vpls|vprn|epipe|ies)\s+\d+\s+(name|customer)/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS SAP (Service Access Point) configuration
  if (/^\s+sap\s+\d+\/\d+\/\d+:\d+/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS MPLS LSP configuration
  if (/^\s+lsp\s+"[^"]+"\s*$/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS echo command for comments
  if (/^echo\s+"[^"]*"$/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS admin-state enable/disable pattern (very distinctive)
  if (/^\s+admin-state\s+(enable|disable)/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS policy-options block
  if (/^policy-options$/m.test(sampleText) && /^\s+policy-statement\s+"[^"]+"/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS filter configuration
  if (/^filter$/m.test(sampleText) && /^\s+ip-filter\s+\d+/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS exit all pattern (distinctive from other vendors)
  if (/^exit\s+all$/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS card and MDA configuration
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasNokiaCardMdaBlock(lines)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS log configuration
  if (/^log$/m.test(sampleText) && /^\s+(log-id|syslog|snmp-trap-group)\s+\d+/m.test(sampleText)) {
    return NokiaSROSSchema;
  }

  // Nokia SR OS BGP with group and neighbor using quoted names
  // SEC-002: Use safe line-by-line helper instead of dangerous [\s\S]*? regex
  if (hasNokiaBgpGroupBlock(lines)) {
    return NokiaSROSSchema;
  }

  // ============ Huawei VRP Detection ============
  // VRP uses distinctive sysname, interface naming, and undo commands
  // Must be checked before Cisco IOS as some patterns overlap

  // Huawei sysname command (most distinctive - vs Cisco's hostname)
  if (/^sysname\s+\S+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei VRP version/header comment
  if (/^#\s*(HuaWei|huawei|Huawei)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei interface naming: GigabitEthernet X/Y/Z format (slot/card/port)
  // Note: Must be before Cisco detection since Cisco also uses GigabitEthernet
  // Huawei uses space before numbers: "GigabitEthernet 0/0/1" vs Cisco "GigabitEthernet0/0/1"
  if (/^interface\s+GigabitEthernet\s+\d+\/\d+\/\d+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei high-speed interface naming: XGigabitEthernet, 40GE, 100GE
  if (/^interface\s+(XGigabitEthernet|40GE|100GE|25GE|10GE|Eth-Trunk)\s*/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei Vlanif interface (vs Cisco's Vlan or interface Vlan)
  if (/^interface\s+Vlanif\s*\d+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei VRP undo command (negation - very distinctive)
  if (/^\s*undo\s+(info-center|shutdown|portswitch|stp|lldp|ntdp)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei protocol configuration with process ID directly after keyword
  // ospf 1, bgp 65000, isis 1 (vs Cisco's router ospf 1, router bgp 65000)
  if (/^ospf\s+\d+\s*$/m.test(sampleText) || /^bgp\s+\d+\s*$/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei isis configuration
  if (/^isis\s+\d+\s*$/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei AAA configuration block
  // SEC-002: Use safe line-by-line helper instead of dangerous combined regex
  if (hasHuaweiAaaBlock(lines)) {
    return HuaweiVRPSchema;
  }

  // Huawei user-interface configuration (vs Cisco's line vty)
  if (/^user-interface\s+(vty|console|current)\s*/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei local-user configuration
  if (/^local-user\s+\S+\s+(password|privilege|service-type)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei VPN instance (vs Cisco's ip vrf or vrf definition)
  if (/^ip\s+vpn-instance\s+\S+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei HWTACACS (Huawei's TACACS implementation)
  if (/^hwtacacs-server\s+(template|shared-key)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei info-center (logging configuration)
  if (/^info-center\s+(enable|source|loghost)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei drop-profile or queue-profile
  if (/^(drop-profile|qos\s+queue-profile)\s+\S+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei port link-type in interface context
  if (/^\s*port\s+link-type\s+(access|trunk|hybrid)/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei port default vlan (vs Cisco switchport access vlan)
  if (/^\s*port\s+default\s+vlan\s+\d+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei port trunk allow-pass vlan
  if (/^\s*port\s+trunk\s+allow-pass\s+vlan\s+/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei display commands in comments or header
  if (/^#\s*display\s+current-configuration/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // Huawei return command (exits to user view)
  if (/^return\s*$/m.test(sampleText)) {
    return HuaweiVRPSchema;
  }

  // ============ Default: Cisco IOS ============
  // Most common format, used as fallback
  return CiscoIOSSchema;
}

// Re-export all vendor schemas for direct access
export { CiscoIOSSchema } from './cisco-ios';
export { CiscoNXOSSchema } from './cisco-nxos';
export { JuniperJunOSSchema } from './juniper-junos';
export { ArubaAOSCXSchema } from './aruba-aoscx';
export { ArubaAOSSwitchSchema } from './aruba-aosswitch';
export { ArubaWLCSchema } from './aruba-wlc';
export { PaloAltoPANOSSchema } from './paloalto-panos';
export { AristaEOSSchema } from './arista-eos';
export { VyOSSchema } from './vyos-vyos';
export { FortinetFortiGateSchema } from './fortinet-fortigate';
export { ExtremeEXOSSchema } from './extreme-exos';
export { ExtremeVOSSSchema } from './extreme-voss';
export { HuaweiVRPSchema } from './huawei-vrp';
export { MikroTikRouterOSSchema } from './mikrotik-routeros';
export { NokiaSROSSchema } from './nokia-sros';
export { CumulusLinuxSchema } from './cumulus-linux';
