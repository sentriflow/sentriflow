# Palo Alto PAN-OS Helper Functions Reference

## Overview

Palo Alto helpers provide validation functions for Palo Alto Networks firewalls running PAN-OS. These next-generation firewalls feature application-aware security policies, integrated threat prevention, and advanced security profiles including WildFire malware analysis.

PAN-OS configurations use a hierarchical stanza-based structure organized into sections like `rulebase`, `zone`, `network`, and `profiles`. The helpers in this module navigate this structure and provide functions for validating security policies, zone protection, high availability, and security profile configurations.

## Import Statement

```typescript
import {
  findStanza,
  hasSecurityProfile,
  isAllowRule,
  getSourceZones,
  getDestinationZones,
  hasAnyApplication,
  getSecurityRules,
  isHAConfigured,
} from '@sentriflow/core/helpers/paloalto';
```

---

## 1. Configuration Navigation Helpers

### findStanza

Find a stanza by name within a node's children (case-insensitive).

**Signature:**
```typescript
function findStanza(node: ConfigNode, stanzaName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent ConfigNode |
| stanzaName | `string` | The stanza name to find |

**Returns:** `ConfigNode | undefined` - The matching child node

**Example:**
```typescript
import { findStanza } from '@sentriflow/core/helpers/paloalto';

const security = findStanza(rulebase, 'security');
const rules = findStanza(security, 'rules');
```

---

### findStanzas

Find all stanzas matching a pattern within a node's children.

**Signature:**
```typescript
function findStanzas(node: ConfigNode, pattern: RegExp): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent ConfigNode |
| pattern | `RegExp` | The regex pattern to match |

**Returns:** `ConfigNode[]` - Array of matching child nodes

**Example:**
```typescript
import { findStanzas } from '@sentriflow/core/helpers/paloalto';

// Find all tunnel interfaces
const tunnels = findStanzas(interfaces, /^tunnel\./i);
```

---

## 2. Security Policy Helpers

### hasLogging

Check if a security rule has logging enabled.

**Signature:**
```typescript
function hasLogging(ruleNode: ConfigNode): { logStart: boolean; logEnd: boolean }
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The security rule ConfigNode |

**Returns:** Object indicating log-start and log-end status

**Example:**
```typescript
import { hasLogging } from '@sentriflow/core/helpers/paloalto';

const logging = hasLogging(ruleNode);
if (!logging.logEnd) {
  // Flag: Security rule should log at session end
}
```

---

### hasSecurityProfile

Check if a security rule has a security profile attached.

**Signature:**
```typescript
function hasSecurityProfile(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The security rule ConfigNode |

**Returns:** `boolean` - `true` if any security profile is attached (virus, spyware, vulnerability, url-filtering, file-blocking, wildfire-analysis, or data-filtering)

---

### isAllowRule

Check if a rule action is "allow" (vs deny/drop/reset).

**Signature:**
```typescript
function isAllowRule(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if the action is allow

---

### isDenyRule

Check if a rule action is "deny", "drop", or "reset".

**Signature:**
```typescript
function isDenyRule(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if the action is deny/drop/reset

---

### isRuleDisabled

Check if a rule is disabled.

**Signature:**
```typescript
function isRuleDisabled(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if the rule is disabled

---

### getSourceZones

Get the source zones from a rule.

**Signature:**
```typescript
function getSourceZones(ruleNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `string[]` - Array of source zone names

**Example:**
```typescript
import { getSourceZones } from '@sentriflow/core/helpers/paloalto';

const sourceZones = getSourceZones(ruleNode);
// Returns: ['untrust', 'dmz']
```

---

### getDestinationZones

Get the destination zones from a rule.

**Signature:**
```typescript
function getDestinationZones(ruleNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `string[]` - Array of destination zone names

---

### getApplications

Get the applications from a rule.

**Signature:**
```typescript
function getApplications(ruleNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `string[]` - Array of application names

**Example:**
```typescript
import { getApplications } from '@sentriflow/core/helpers/paloalto';

const apps = getApplications(ruleNode);
// Returns: ['web-browsing', 'ssl', 'dns']
```

---

### hasAnyApplication

Check if a rule uses "any" application (risky).

**Signature:**
```typescript
function hasAnyApplication(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if application is "any"

---

### hasAnySource

Check if a rule uses "any" source (0.0.0.0/0 or "any").

**Signature:**
```typescript
function hasAnySource(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if source is "any"

---

### hasAnyDestination

Check if a rule uses "any" destination.

**Signature:**
```typescript
function hasAnyDestination(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if destination is "any"

---

### hasAnyService

Check if a rule uses "any" service (all TCP/UDP ports).

**Signature:**
```typescript
function hasAnyService(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The rule ConfigNode |

**Returns:** `boolean` - `true` if service is "any"

---

### getSecurityRules

Get all security rules from a rulebase.

**Signature:**
```typescript
function getSecurityRules(rulebaseNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rulebaseNode | `ConfigNode` | The rulebase ConfigNode |

**Returns:** `ConfigNode[]` - Array of security rule nodes

**Example:**
```typescript
import { getSecurityRules, isAllowRule, hasSecurityProfile } from '@sentriflow/core/helpers/paloalto';

const rules = getSecurityRules(rulebase);
for (const rule of rules) {
  if (isAllowRule(rule) && !hasSecurityProfile(rule)) {
    // Flag: Allow rule without security profile
  }
}
```

---

## 3. NAT Helpers

### getNatRules

Get all NAT rules from a rulebase.

**Signature:**
```typescript
function getNatRules(rulebaseNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rulebaseNode | `ConfigNode` | The rulebase ConfigNode |

**Returns:** `ConfigNode[]` - Array of NAT rule nodes

---

## 4. Decryption Helpers

### getDecryptionRules

Get all decryption rules from a rulebase.

**Signature:**
```typescript
function getDecryptionRules(rulebaseNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| rulebaseNode | `ConfigNode` | The rulebase ConfigNode |

**Returns:** `ConfigNode[]` - Array of decryption rule nodes

---

### isDecryptRule

Check if a decryption rule uses "decrypt" action.

**Signature:**
```typescript
function isDecryptRule(ruleNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ruleNode | `ConfigNode` | The decryption rule ConfigNode |

**Returns:** `boolean` - `true` if the action is decrypt

---

### getDecryptionTlsSettings

Check if decryption profile has secure TLS settings.

**Signature:**
```typescript
function getDecryptionTlsSettings(decryptionProfileNode: ConfigNode): {
  hasMinVersion: boolean;
  minVersion: string | null;
  hasWeakCiphers: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| decryptionProfileNode | `ConfigNode` | The decryption profile ConfigNode |

**Returns:** Object with TLS security assessment

**Example:**
```typescript
import { getDecryptionTlsSettings } from '@sentriflow/core/helpers/paloalto';

const tlsSettings = getDecryptionTlsSettings(profileNode);
if (tlsSettings.hasWeakCiphers) {
  // Flag: Decryption profile uses weak ciphers (RC4, 3DES, DES, NULL)
}
```

---

## 5. Zone Helpers

### getZoneName

Extract zone name from a zone configuration node.

**Signature:**
```typescript
function getZoneName(zoneNode: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zoneNode | `ConfigNode` | The zone ConfigNode |

**Returns:** `string` - The zone name

---

### hasZoneProtectionProfile

Check if zone protection profile is applied to a zone.

**Signature:**
```typescript
function hasZoneProtectionProfile(zoneNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zoneNode | `ConfigNode` | The zone ConfigNode |

**Returns:** `boolean` - `true` if zone protection profile is configured

---

### hasUserIdentification

Check if user identification is enabled on a zone.

**Signature:**
```typescript
function hasUserIdentification(zoneNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zoneNode | `ConfigNode` | The zone ConfigNode |

**Returns:** `boolean` - `true` if user identification is enabled

---

### isUserIdEnabled

Check if User-ID is enabled on a zone (for untrust zone check).

**Signature:**
```typescript
function isUserIdEnabled(zoneNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zoneNode | `ConfigNode` | The zone ConfigNode |

**Returns:** `boolean` - `true` if User-ID is enabled

---

## 6. Zone Protection Helpers

### hasFloodProtection

Check if zone protection profile has flood protection configured.

**Signature:**
```typescript
function hasFloodProtection(zppNode: ConfigNode): {
  hasSyn: boolean;
  hasUdp: boolean;
  hasIcmp: boolean;
  hasOtherIp: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zppNode | `ConfigNode` | The zone protection profile ConfigNode |

**Returns:** Object indicating flood protection status for each protocol type

**Example:**
```typescript
import { hasFloodProtection } from '@sentriflow/core/helpers/paloalto';

const floodProtection = hasFloodProtection(zppNode);
if (!floodProtection.hasSyn) {
  // Flag: Zone protection profile missing SYN flood protection
}
```

---

### hasReconProtection

Check if zone protection profile has reconnaissance protection.

**Signature:**
```typescript
function hasReconProtection(zppNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| zppNode | `ConfigNode` | The zone protection profile ConfigNode |

**Returns:** `boolean` - `true` if scan/reconnaissance protection is configured (TCP port scan, host sweep, or UDP port scan)

---

## 7. Interface Helpers

### isPhysicalEthernetPort

Check if an interface is a physical Ethernet port.

**Signature:**
```typescript
function isPhysicalEthernetPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if it's a physical ethernet port (e.g., "ethernet1/1")

---

### isLoopbackInterface

Check if an interface is a loopback.

**Signature:**
```typescript
function isLoopbackInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if it's a loopback interface (e.g., "loopback.1")

---

### isTunnelInterface

Check if an interface is a tunnel.

**Signature:**
```typescript
function isTunnelInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if it's a tunnel interface (e.g., "tunnel.1")

---

### isAggregateInterface

Check if an interface is an aggregate (LACP).

**Signature:**
```typescript
function isAggregateInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface name |

**Returns:** `boolean` - `true` if it's an aggregate interface (e.g., "ae1")

---

### getInterfaceManagementServices

Get interface management profile settings.

**Signature:**
```typescript
function getInterfaceManagementServices(profileNode: ConfigNode): {
  https: boolean;
  http: boolean;
  ssh: boolean;
  telnet: boolean;
  ping: boolean;
  snmp: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profileNode | `ConfigNode` | The interface-management-profile ConfigNode |

**Returns:** Object indicating enabled services

**Example:**
```typescript
import { getInterfaceManagementServices } from '@sentriflow/core/helpers/paloalto';

const services = getInterfaceManagementServices(profileNode);
if (services.telnet) {
  // Flag: Telnet is insecure, use SSH instead
}
if (services.http) {
  // Flag: HTTP is insecure, use HTTPS instead
}
```

---

## 8. High Availability Helpers

### isHAConfigured

Check if HA (High Availability) is configured.

**Signature:**
```typescript
function isHAConfigured(deviceconfigNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| deviceconfigNode | `ConfigNode` | The deviceconfig ConfigNode |

**Returns:** `boolean` - `true` if HA is configured

---

### getHABackupStatus

Check if HA has backup links configured.

**Signature:**
```typescript
function getHABackupStatus(haNode: ConfigNode): {
  hasHa1Backup: boolean;
  hasHa2Backup: boolean;
  hasHeartbeatBackup: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| haNode | `ConfigNode` | The high-availability ConfigNode |

**Returns:** Object indicating backup link status

**Example:**
```typescript
import { getHABackupStatus } from '@sentriflow/core/helpers/paloalto';

const haBackup = getHABackupStatus(haNode);
if (!haBackup.hasHa1Backup) {
  // Flag: HA1 backup link not configured for redundancy
}
```

---

### hasHALinkMonitoring

Check if HA has link monitoring configured.

**Signature:**
```typescript
function hasHALinkMonitoring(haNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| haNode | `ConfigNode` | The high-availability ConfigNode |

**Returns:** `boolean` - `true` if link monitoring is configured

---

### hasHAPathMonitoring

Check if HA has path monitoring configured.

**Signature:**
```typescript
function hasHAPathMonitoring(haNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| haNode | `ConfigNode` | The high-availability ConfigNode |

**Returns:** `boolean` - `true` if path monitoring is configured

---

## 9. Security Profile Helpers

### hasWildfireProfile

Check if WildFire is configured.

**Signature:**
```typescript
function hasWildfireProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if WildFire analysis is configured

---

### hasUrlFilteringProfile

Check if URL Filtering is configured.

**Signature:**
```typescript
function hasUrlFilteringProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if URL filtering is configured

---

### hasAntiVirusProfile

Check if Anti-Virus profile is configured.

**Signature:**
```typescript
function hasAntiVirusProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if AV profile is configured

---

### hasAntiSpywareProfile

Check if Anti-Spyware profile is configured.

**Signature:**
```typescript
function hasAntiSpywareProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if Anti-Spyware profile is configured

---

### hasVulnerabilityProfile

Check if Vulnerability Protection profile is configured.

**Signature:**
```typescript
function hasVulnerabilityProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if Vulnerability Protection profile is configured

---

### hasFileBlockingProfile

Check if File Blocking profile is configured.

**Signature:**
```typescript
function hasFileBlockingProfile(profilesNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| profilesNode | `ConfigNode` | The profiles ConfigNode |

**Returns:** `boolean` - `true` if File Blocking profile is configured

---

## 10. VPN/IKE Helpers

### getIkeCryptoSettings

Get IKE crypto profile settings for security assessment.

**Signature:**
```typescript
function getIkeCryptoSettings(ikeProfileNode: ConfigNode): {
  hasWeakDH: boolean;
  hasWeakHash: boolean;
  hasWeakEncryption: boolean;
  dhGroups: string[];
  hashes: string[];
  encryptions: string[];
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ikeProfileNode | `ConfigNode` | The IKE crypto profile ConfigNode |

**Returns:** Object with security assessment

**Example:**
```typescript
import { getIkeCryptoSettings } from '@sentriflow/core/helpers/paloalto';

const ikeSettings = getIkeCryptoSettings(ikeProfile);
if (ikeSettings.hasWeakDH) {
  // Flag: IKE profile uses weak DH groups (group1, group2, group5)
}
if (ikeSettings.hasWeakHash) {
  // Flag: IKE profile uses weak hash algorithms (MD5, SHA1)
}
if (ikeSettings.hasWeakEncryption) {
  // Flag: IKE profile uses weak encryption (DES, 3DES)
}
```

---

## 11. System Administration Helpers

### hasPasswordComplexity

Check if password complexity is configured.

**Signature:**
```typescript
function hasPasswordComplexity(systemNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** `boolean` - `true` if password complexity is configured

---

### getPasswordComplexitySettings

Get password complexity settings.

**Signature:**
```typescript
function getPasswordComplexitySettings(systemNode: ConfigNode): {
  enabled: boolean;
  minLength: number | null;
  minUppercase: number | null;
  minLowercase: number | null;
  minNumeric: number | null;
  minSpecial: number | null;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** Object with password complexity settings

**Example:**
```typescript
import { getPasswordComplexitySettings } from '@sentriflow/core/helpers/paloalto';

const pwSettings = getPasswordComplexitySettings(systemNode);
if (!pwSettings.enabled) {
  // Flag: Password complexity is not enabled
}
if (pwSettings.minLength !== null && pwSettings.minLength < 12) {
  // Flag: Minimum password length should be at least 12 characters
}
```

---

### getSnmpConfiguration

Check if SNMP is configured with v3 (secure) or v2c (less secure).

**Signature:**
```typescript
function getSnmpConfiguration(systemNode: ConfigNode): {
  configured: boolean;
  hasV3: boolean;
  hasV2c: boolean;
  hasCommunityPublic: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** Object indicating SNMP configuration status

**Example:**
```typescript
import { getSnmpConfiguration } from '@sentriflow/core/helpers/paloalto';

const snmp = getSnmpConfiguration(systemNode);
if (snmp.hasV2c && !snmp.hasV3) {
  // Flag: SNMPv2c is insecure, upgrade to SNMPv3
}
if (snmp.hasCommunityPublic) {
  // Flag: Default SNMP community string detected
}
```

---

## 12. Logging Helpers

### getLogForwardingStatus

Check if log forwarding is configured.

**Signature:**
```typescript
function getLogForwardingStatus(logSettingsNode: ConfigNode): {
  hasSyslog: boolean;
  hasPanorama: boolean;
  hasEmail: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| logSettingsNode | `ConfigNode` | The log-settings ConfigNode |

**Returns:** Object indicating log forwarding status

**Example:**
```typescript
import { getLogForwardingStatus } from '@sentriflow/core/helpers/paloalto';

const logForwarding = getLogForwardingStatus(logSettingsNode);
if (!logForwarding.hasSyslog && !logForwarding.hasPanorama) {
  // Flag: No external log forwarding configured
}
```

---

## 13. Update Schedule Helpers

### getUpdateScheduleStatus

Check if dynamic content updates are scheduled.

**Signature:**
```typescript
function getUpdateScheduleStatus(systemNode: ConfigNode): {
  hasThreats: boolean;
  hasAntivirus: boolean;
  hasWildfire: boolean;
  wildfireRealtime: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemNode | `ConfigNode` | The system ConfigNode |

**Returns:** Object indicating update schedule status

**Example:**
```typescript
import { getUpdateScheduleStatus } from '@sentriflow/core/helpers/paloalto';

const updates = getUpdateScheduleStatus(systemNode);
if (!updates.hasThreats) {
  // Flag: Threat signature updates not scheduled
}
if (updates.hasWildfire && !updates.wildfireRealtime) {
  // Flag: WildFire updates should be set to real-time
}
```

---

## 14. Utility Helpers

### parsePanosAddress

Parse PAN-OS address format (e.g., "10.0.0.1/24" or "10.0.0.1-10.0.0.255").

**Signature:**
```typescript
function parsePanosAddress(address: string): {
  ip: number;
  prefix?: number;
  rangeEnd?: number;
} | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address string |

**Returns:** Object with parsed address info, or null if invalid

**Example:**
```typescript
import { parsePanosAddress } from '@sentriflow/core/helpers/paloalto';

// CIDR format
const cidr = parsePanosAddress('10.0.0.0/24');
// Returns: { ip: 167772160, prefix: 24 }

// Range format
const range = parsePanosAddress('10.0.0.1-10.0.0.255');
// Returns: { ip: 167772161, rangeEnd: 167772415 }

// Single IP
const single = parsePanosAddress('10.0.0.1');
// Returns: { ip: 167772161 }
```

---

## See Also

- [Common Helpers](./common.md) - Shared utilities including `hasChildCommand`, `getChildCommand`, `parseIp`
- [Fortinet Helpers](./fortinet.md) - Similar next-gen firewall (FortiGate/FortiOS)
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Writing custom validation rules
