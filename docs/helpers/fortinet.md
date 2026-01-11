# Fortinet FortiGate Helper Functions Reference

## Overview

Fortinet helpers provide validation functions for FortiGate firewalls running FortiOS. These helpers handle the unique FortiOS configuration syntax with `config`/`edit`/`set`/`end` structure.

## Import Statement

```typescript
import {
  findConfigSection,
  getSetValue,
  isPolicyAccept,
  hasSecurityProfile,
  getInterfaceAllowAccess,
} from '@sentriflow/core/helpers/fortinet';
```

---

## 1. Configuration Navigation Helpers

### findConfigSection

Find a config section by name within a node's children.

**Signature:**
```typescript
function findConfigSection(node: ConfigNode, sectionName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent ConfigNode |
| sectionName | `string` | The section name (e.g., "system global", "firewall policy") |

**Returns:** `ConfigNode | undefined` - The matching child node

**Example:**
```typescript
import { findConfigSection } from '@sentriflow/core/helpers/fortinet';

const globalSection = findConfigSection(ast, 'system global');
const policySection = findConfigSection(ast, 'firewall policy');
```

---

### findConfigSections

Find all config sections matching a pattern within a node's children.

**Signature:**
```typescript
function findConfigSections(node: ConfigNode, pattern: RegExp): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent ConfigNode |
| pattern | `RegExp` | The regex pattern to match |

**Returns:** `ConfigNode[]` - Array of matching child nodes

---

### findEditEntry

Find an edit entry by name within a config section.

**Signature:**
```typescript
function findEditEntry(configSection: ConfigNode, entryName: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| configSection | `ConfigNode` | The config section ConfigNode |
| entryName | `string` | The entry name to find |

**Returns:** `ConfigNode | undefined` - The matching edit entry

**Example:**
```typescript
import { findConfigSection, findEditEntry } from '@sentriflow/core/helpers/fortinet';

const adminSection = findConfigSection(ast, 'system admin');
const adminUser = findEditEntry(adminSection, 'admin');
```

---

### getEditEntries

Get all edit entries within a config section.

**Signature:**
```typescript
function getEditEntries(configSection: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| configSection | `ConfigNode` | The config section ConfigNode |

**Returns:** `ConfigNode[]` - Array of edit entry nodes

---

### getEditEntryName

Extract the name from an edit entry.

**Signature:**
```typescript
function getEditEntryName(editEntry: ConfigNode): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| editEntry | `ConfigNode` | The edit entry ConfigNode |

**Returns:** `string` - The entry name

---

### getSetValue

Get a "set" command value from a FortiOS config entry.

**Signature:**
```typescript
function getSetValue(node: ConfigNode, paramName: string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode |
| paramName | `string` | The parameter name |

**Returns:** `string | undefined` - The value

**Example:**
```typescript
import { getSetValue } from '@sentriflow/core/helpers/fortinet';

const action = getSetValue(policyNode, 'action');       // 'accept'
const schedule = getSetValue(policyNode, 'schedule');   // 'always'
```

---

### hasSetValue

Check if a "set" command exists for a parameter.

**Signature:**
```typescript
function hasSetValue(node: ConfigNode, paramName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode |
| paramName | `string` | The parameter name |

**Returns:** `boolean` - `true` if the set command exists

---

### getSetValues

Get all "set" command values for a parameter that may appear multiple times.

**Signature:**
```typescript
function getSetValues(node: ConfigNode, paramName: string): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode |
| paramName | `string` | The parameter name |

**Returns:** `string[]` - Array of values

**Example:**
```typescript
import { getSetValues } from '@sentriflow/core/helpers/fortinet';

// For "set allowaccess ping https ssh"
const access = getSetValues(interfaceNode, 'allowaccess');
// Returns: ['ping', 'https', 'ssh']
```

---

## 2. Firewall Policy Helpers

### isPolicyAccept

Check if a firewall policy action is "accept" (allow).

**Signature:**
```typescript
function isPolicyAccept(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if the action is accept

---

### isPolicyDeny

Check if a firewall policy action is "deny" or "drop".

**Signature:**
```typescript
function isPolicyDeny(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if the action is deny

---

### isPolicyDisabled

Check if a firewall policy is disabled (status disable).

**Signature:**
```typescript
function isPolicyDisabled(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if the policy is disabled

---

### hasLogging

Check if a firewall policy has logging enabled.

**Signature:**
```typescript
function hasLogging(policyNode: ConfigNode): {
  logtraffic: string | undefined;
  logtrafficStart: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** Object indicating logtraffic status

---

### hasAnySrcAddr

Check if a policy uses "all" (any) source address.

**Signature:**
```typescript
function hasAnySrcAddr(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if srcaddr includes "all"

---

### hasAnyDstAddr

Check if a policy uses "all" (any) destination address.

**Signature:**
```typescript
function hasAnyDstAddr(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if dstaddr includes "all"

---

### hasAnyService

Check if a policy uses "ALL" service (any service).

**Signature:**
```typescript
function hasAnyService(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if service includes "ALL"

---

### getPolicySchedule

Get the schedule for a firewall policy.

**Signature:**
```typescript
function getPolicySchedule(policyNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `string | undefined` - The schedule name

---

### isAlwaysSchedule

Check if the schedule is "always" (always active).

**Signature:**
```typescript
function isAlwaysSchedule(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if schedule is "always"

---

### getNatSettings

Get NAT settings for a policy.

**Signature:**
```typescript
function getNatSettings(policyNode: ConfigNode): {
  nat: boolean;
  ippool: boolean;
  poolname: string[];
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** Object with NAT settings

---

## 3. Security Profile Helpers

### getSecurityProfiles

Check if a policy has UTM/security profiles attached.

**Signature:**
```typescript
function getSecurityProfiles(policyNode: ConfigNode): {
  avProfile: string | undefined;
  webfilterProfile: string | undefined;
  ipsProfile: string | undefined;
  applicationList: string | undefined;
  dnsfilterProfile: string | undefined;
  emailfilterProfile: string | undefined;
  dlpSensor: string | undefined;
  sslSshProfile: string | undefined;
  profileProtocolOptions: string | undefined;
  utmStatus: string | undefined;
  inspectionMode: string | undefined;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** Object with profile statuses

---

### hasSecurityProfile

Check if a policy has any UTM profile attached.

**Signature:**
```typescript
function hasSecurityProfile(policyNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| policyNode | `ConfigNode` | The firewall policy ConfigNode |

**Returns:** `boolean` - `true` if any security profile is configured

---

## 4. Interface Helpers

### getInterfaceIp

Get the interface IP address and mask from a system interface entry.

**Signature:**
```typescript
function getInterfaceIp(interfaceNode: ConfigNode): { ip: string; mask: string } | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry ConfigNode |

**Returns:** Object with ip and mask, or undefined

---

### getInterfaceAllowAccess

Get allowed access methods on an interface.

**Signature:**
```typescript
function getInterfaceAllowAccess(interfaceNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry ConfigNode |

**Returns:** `string[]` - Array of allowed access methods

**Example:**
```typescript
import { getInterfaceAllowAccess } from '@sentriflow/core/helpers/fortinet';

const access = getInterfaceAllowAccess(interfaceNode);
// Returns: ['ping', 'https', 'ssh']
```

---

### hasHttpManagement

Check if HTTP(S) management is allowed on an interface.

**Signature:**
```typescript
function hasHttpManagement(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry ConfigNode |

**Returns:** `boolean` - `true` if HTTP or HTTPS access is allowed

---

### hasSshAccess

Check if SSH is allowed on an interface.

**Signature:**
```typescript
function hasSshAccess(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry ConfigNode |

**Returns:** `boolean` - `true` if SSH access is allowed

---

### hasTelnetAccess

Check if Telnet is allowed on an interface (insecure).

**Signature:**
```typescript
function hasTelnetAccess(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry ConfigNode |

**Returns:** `boolean` - `true` if Telnet access is allowed

---

### getInterfaceRole

Get interface role.

**Signature:**
```typescript
function getInterfaceRole(interfaceNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry |

**Returns:** `string | undefined` - The interface role (wan, lan, dmz, undefined)

---

### isWanInterface

Check if interface is WAN-facing.

**Signature:**
```typescript
function isWanInterface(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry |

**Returns:** `boolean` - `true` if interface has WAN role

---

### hasWanManagementAccess

Check if interface has management access on WAN.

**Signature:**
```typescript
function hasWanManagementAccess(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface edit entry |

**Returns:** `boolean` - `true` if WAN interface has management protocols enabled

---

## 5. Admin User Helpers

### getAdminPasswordPolicy

Check if admin user has strong password policy.

**Signature:**
```typescript
function getAdminPasswordPolicy(adminNode: ConfigNode): {
  forcePasswordChange: boolean;
  twoFactorAuth: string | undefined;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** Object with password policy info

---

### getAdminProfile

Get the admin profile (permission level) for an admin user.

**Signature:**
```typescript
function getAdminProfile(adminNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `string | undefined` - The profile name

---

### isSuperAdmin

Check if admin is a super_admin.

**Signature:**
```typescript
function isSuperAdmin(adminNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `boolean` - `true` if super_admin profile

---

### getAdminTrustedHosts

Get trusted hosts for admin access restriction.

**Signature:**
```typescript
function getAdminTrustedHosts(adminNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `string[]` - Array of trusted host entries

---

### hasAdminTrustedHosts

Check if admin has any trusted host restriction.

**Signature:**
```typescript
function hasAdminTrustedHosts(adminNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `boolean` - `true` if trusted hosts are configured

---

### hasAdmin2FA

Check if admin has two-factor authentication enabled.

**Signature:**
```typescript
function hasAdmin2FA(adminNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `boolean` - `true` if 2FA is enabled

---

### getAdmin2FAType

Get admin two-factor authentication type.

**Signature:**
```typescript
function getAdmin2FAType(adminNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| adminNode | `ConfigNode` | The admin user edit entry |

**Returns:** `string | undefined` - The 2FA type (fortitoken, email, sms, etc.)

---

## 6. System Hardening Helpers

### isUsbAutoInstallEnabled

Check if USB auto-install is enabled (security risk).

**Signature:**
```typescript
function isUsbAutoInstallEnabled(globalNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| globalNode | `ConfigNode` | The system global config section |

**Returns:** `boolean` - `true` if USB auto-install is enabled

---

### isAdminMaintainerEnabled

Check if admin-maintainer account is enabled.

**Signature:**
```typescript
function isAdminMaintainerEnabled(globalNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| globalNode | `ConfigNode` | The system global config section |

**Returns:** `boolean` - `true` if maintainer account is enabled

---

### isPrivateDataEncryptionEnabled

Check if private data encryption is enabled.

**Signature:**
```typescript
function isPrivateDataEncryptionEnabled(globalNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| globalNode | `ConfigNode` | The system global config section |

**Returns:** `boolean` - `true` if private data encryption is enabled

---

### getAdminLockoutThreshold

Get admin lockout threshold.

**Signature:**
```typescript
function getAdminLockoutThreshold(globalNode: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| globalNode | `ConfigNode` | The system global config section |

**Returns:** `number | undefined` - The lockout threshold

---

### getAdminLockoutDuration

Get admin lockout duration.

**Signature:**
```typescript
function getAdminLockoutDuration(globalNode: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| globalNode | `ConfigNode` | The system global config section |

**Returns:** `number | undefined` - The lockout duration in seconds

---

## 7. Password Policy Helpers

### getPasswordPolicySettings

Get password policy settings.

**Signature:**
```typescript
function getPasswordPolicySettings(passwordPolicyNode: ConfigNode): {
  status: boolean;
  minimumLength: number | undefined;
  minLowerCase: number | undefined;
  minUpperCase: number | undefined;
  minNonAlphanumeric: number | undefined;
  minNumber: number | undefined;
  expireStatus: boolean;
  expireDays: number | undefined;
  reusePassword: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| passwordPolicyNode | `ConfigNode` | The system password-policy config section |

**Returns:** Object with password policy settings

---

## 8. SNMP Helpers

### hasWeakSnmpCommunity

Check if SNMP community has default/weak name.

**Signature:**
```typescript
function hasWeakSnmpCommunity(communityNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| communityNode | `ConfigNode` | The SNMP community edit entry |

**Returns:** `boolean` - `true` if the community name is weak/default (public, private, community, snmp, default)

---

### getSnmpSecurityLevel

Get SNMP user security level.

**Signature:**
```typescript
function getSnmpSecurityLevel(snmpUserNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| snmpUserNode | `ConfigNode` | The SNMP user edit entry |

**Returns:** `string | undefined` - The security level (no-auth-no-priv, auth-no-priv, auth-priv)

---

## 9. SSL/VPN Helpers

### getSslProfileSettings

Get SSL inspection profile settings.

**Signature:**
```typescript
function getSslProfileSettings(sslProfileNode: ConfigNode): {
  minSslVersion: string | undefined;
  unsupportedSslVersion: string | undefined;
  expiredServerCert: string | undefined;
  revokedServerCert: string | undefined;
  untrustedServerCert: string | undefined;
  certValidationFailure: string | undefined;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sslProfileNode | `ConfigNode` | The SSL-SSH profile edit entry |

**Returns:** Object with SSL settings

---

### isWeakSslVersion

Check if SSL profile uses weak SSL version.

**Signature:**
```typescript
function isWeakSslVersion(minSslVersion: string | undefined): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| minSslVersion | `string \| undefined` | The minimum SSL version string |

**Returns:** `boolean` - `true` if the version is considered weak (ssl-3.0, tls-1.0, tls-1.1)

---

### getSslVpnSettings

Get SSL VPN settings.

**Signature:**
```typescript
function getSslVpnSettings(sslSettingsNode: ConfigNode): {
  sslMinProtoVer: string | undefined;
  sslMaxProtoVer: string | undefined;
  idleTimeout: number | undefined;
  authTimeout: number | undefined;
  loginAttemptLimit: number | undefined;
  loginBlockTime: number | undefined;
  reqClientCert: boolean;
  checkReferer: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sslSettingsNode | `ConfigNode` | The vpn ssl settings config section |

**Returns:** Object with SSL VPN settings

---

### getIkeVersion

Get IKE version from IPsec phase1.

**Signature:**
```typescript
function getIkeVersion(phase1Node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| phase1Node | `ConfigNode` | The IPsec phase1-interface edit entry |

**Returns:** `number | undefined` - The IKE version (1 or 2)

---

### getDhGroups

Get DH groups from IPsec configuration.

**Signature:**
```typescript
function getDhGroups(phaseNode: ConfigNode): number[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| phaseNode | `ConfigNode` | The IPsec phase1 or phase2 edit entry |

**Returns:** `number[]` - Array of DH group numbers

---

### hasWeakDhGroup

Check if weak DH groups are used.

**Signature:**
```typescript
function hasWeakDhGroup(dhGroups: number[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| dhGroups | `number[]` | Array of DH group numbers |

**Returns:** `boolean` - `true` if any weak DH group (1, 2, 5) is found

---

### isPfsEnabled

Check if PFS is enabled in phase2.

**Signature:**
```typescript
function isPfsEnabled(phase2Node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| phase2Node | `ConfigNode` | The IPsec phase2-interface edit entry |

**Returns:** `boolean` - `true` if PFS is enabled

---

### getKeyLifetime

Get key lifetime from IPsec phase2.

**Signature:**
```typescript
function getKeyLifetime(phase2Node: ConfigNode): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| phase2Node | `ConfigNode` | The IPsec phase2-interface edit entry |

**Returns:** `number | undefined` - Key lifetime in seconds

---

## 10. High Availability Helpers

### isHAEnabled

Check if HA (High Availability) is configured.

**Signature:**
```typescript
function isHAEnabled(systemHaNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemHaNode | `ConfigNode` | The system ha config section |

**Returns:** `boolean` - `true` if HA is enabled

---

### getHAMode

Get the HA mode.

**Signature:**
```typescript
function getHAMode(systemHaNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| systemHaNode | `ConfigNode` | The system ha config section |

**Returns:** `string | undefined` - The HA mode (standalone, a-a, a-p, etc.)

---

## 11. SD-WAN Helpers

### isSdwanEnabled

Check if SD-WAN is enabled.

**Signature:**
```typescript
function isSdwanEnabled(sdwanNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sdwanNode | `ConfigNode` | The system sdwan config section |

**Returns:** `boolean` - `true` if SD-WAN is enabled

---

### getSdwanHealthChecks

Get SD-WAN health check configurations.

**Signature:**
```typescript
function getSdwanHealthChecks(sdwanNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sdwanNode | `ConfigNode` | The system sdwan config section |

**Returns:** `ConfigNode[]` - Array of health check nodes

---

### getSdwanMembers

Get SD-WAN members.

**Signature:**
```typescript
function getSdwanMembers(sdwanNode: ConfigNode): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| sdwanNode | `ConfigNode` | The system sdwan config section |

**Returns:** `ConfigNode[]` - Array of member configurations

---

## 12. DoS Policy Helpers

### getDosAnomalySettings

Get DoS anomaly settings from a DoS policy.

**Signature:**
```typescript
function getDosAnomalySettings(dosPolicyNode: ConfigNode): Array<{
  name: string;
  status: boolean;
  action: string | undefined;
  threshold: number | undefined;
  log: boolean;
}>
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| dosPolicyNode | `ConfigNode` | The DoS policy edit entry |

**Returns:** Array of anomaly configurations

---

## 13. Utility Helpers

### parseFortiAddress

Parse FortiOS IP address format.

**Signature:**
```typescript
function parseFortiAddress(address: string): { ip: number; mask: string } | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| address | `string` | The address string (e.g., "10.0.0.1 255.255.255.0" or "10.0.0.0/24") |

**Returns:** Object with parsed address info, or null if invalid

---

## See Also

- [Common Helpers](./common.md) - Shared utilities
- [Palo Alto Helpers](./paloalto.md) - Similar next-gen firewall
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Writing rules
