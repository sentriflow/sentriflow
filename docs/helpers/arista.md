# Arista EOS Helper Functions Reference

## Overview

Arista EOS helpers provide validation functions for Arista EOS switches. These helpers cover MLAG, VXLAN/EVPN, management security, and data plane protections. Based on Arista Best Practices.

## Import Statement

```typescript
import {
  hasSshVersion2,
  hasDhcpSnooping,
  getBgpNeighborsWithoutAuth,
  hasMlagConfiguration,
} from '@sentriflow/core/helpers/arista';
```

## Re-exported Common Helpers

The following common helpers are re-exported for convenience:

```typescript
export { hasChildCommand, getChildCommand, getChildCommands, parseIp } from '../common/helpers';
```

---

## 1. Management Plane Security Helpers

### hasStrongPasswordEncryption

Check if password uses SHA-512 encryption (strong).

**Signature:**
```typescript
function hasStrongPasswordEncryption(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node containing password |

**Returns:** `boolean` - `true` if using sha512 encryption

**Example:**
```typescript
import { hasStrongPasswordEncryption } from '@sentriflow/core/helpers/arista';

// Check if username has strong password encryption
if (!hasStrongPasswordEncryption(usernameNode)) {
  // Flag weak password encryption
}
```

---

### hasPlaintextPassword

Check if password is plaintext (cleartext).

**Signature:**
```typescript
function hasPlaintextPassword(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The config node containing password |

**Returns:** `boolean` - `true` if password appears to be plaintext

**Example:**
```typescript
import { hasPlaintextPassword } from '@sentriflow/core/helpers/arista';

if (hasPlaintextPassword(node)) {
  // Flag cleartext password security issue
}
```

---

### hasServicePasswordEncryption

Check if service password-encryption is enabled.

**Signature:**
```typescript
function hasServicePasswordEncryption(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if service password-encryption is configured

**Example:**
```typescript
import { hasServicePasswordEncryption } from '@sentriflow/core/helpers/arista';

if (!hasServicePasswordEncryption(ast)) {
  // Recommend enabling password encryption
}
```

---

### hasSshVersion2

Check if SSH version 2 is configured.

**Signature:**
```typescript
function hasSshVersion2(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SSH v2 is configured

**Example:**
```typescript
import { hasSshVersion2 } from '@sentriflow/core/helpers/arista';

if (!hasSshVersion2(ast)) {
  // Flag missing SSH v2 configuration
}
```

---

### getWeakSshCiphers

Check for weak SSH ciphers.

**Signature:**
```typescript
function getWeakSshCiphers(ast: ConfigNode[]): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string[]` - Array of weak ciphers found (e.g., '3des-cbc', 'aes128-cbc')

**Example:**
```typescript
import { getWeakSshCiphers } from '@sentriflow/core/helpers/arista';

const weakCiphers = getWeakSshCiphers(ast);
if (weakCiphers.length > 0) {
  // Report weak ciphers: 3des-cbc, aes*-cbc, blowfish-cbc
}
```

---

### isTelnetDisabled

Check if telnet management is disabled.

**Signature:**
```typescript
function isTelnetDisabled(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if telnet is properly disabled (default in EOS)

**Example:**
```typescript
import { isTelnetDisabled } from '@sentriflow/core/helpers/arista';

if (!isTelnetDisabled(ast)) {
  // Flag insecure telnet access
}
```

---

### isHttpServerDisabled

Check if HTTP server is disabled (insecure).

**Signature:**
```typescript
function isHttpServerDisabled(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if HTTP server is disabled

**Example:**
```typescript
import { isHttpServerDisabled } from '@sentriflow/core/helpers/arista';

if (!isHttpServerDisabled(ast)) {
  // Flag insecure HTTP management
}
```

---

### getInsecureSnmpCommunities

Check for SNMPv1/v2c community strings (insecure).

**Signature:**
```typescript
function getInsecureSnmpCommunities(ast: ConfigNode[]): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string[]` - Array of insecure community configurations found

**Example:**
```typescript
import { getInsecureSnmpCommunities } from '@sentriflow/core/helpers/arista';

const insecure = getInsecureSnmpCommunities(ast);
// Returns: ['Default community "public"', 'SNMPv2c community configured']
```

---

### hasSnmpV3AuthPriv

Check if SNMPv3 is properly configured with auth and priv.

**Signature:**
```typescript
function hasSnmpV3AuthPriv(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SNMPv3 with priv mode is configured

**Example:**
```typescript
import { hasSnmpV3AuthPriv } from '@sentriflow/core/helpers/arista';

if (!hasSnmpV3AuthPriv(ast)) {
  // Recommend SNMPv3 with authentication and privacy
}
```

---

### hasNtpAuthentication

Check if NTP authentication is enabled.

**Signature:**
```typescript
function hasNtpAuthentication(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if NTP authentication is configured (requires both `ntp authenticate` and `ntp trusted-key`)

**Example:**
```typescript
import { hasNtpAuthentication } from '@sentriflow/core/helpers/arista';

if (!hasNtpAuthentication(ast)) {
  // Flag missing NTP authentication
}
```

---

### hasAaaAuthenticationLogin

Check if AAA authentication login is configured.

**Signature:**
```typescript
function hasAaaAuthenticationLogin(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if AAA authentication login is configured

---

### hasTacacsServer

Check if TACACS+ is configured.

**Signature:**
```typescript
function hasTacacsServer(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if TACACS+ server is configured

---

### hasAaaAccounting

Check if AAA accounting is configured.

**Signature:**
```typescript
function hasAaaAccounting(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if AAA accounting is configured

---

### hasManagementVrf

Check if Management VRF is configured.

**Signature:**
```typescript
function hasManagementVrf(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if management VRF (MGMT or management) is configured

---

### getBannerInfoDisclosure

Check if login banner reveals system information (non-compliant).

**Signature:**
```typescript
function getBannerInfoDisclosure(ast: ConfigNode[]): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string[]` - Array of information disclosure issues found

**Example:**
```typescript
import { getBannerInfoDisclosure } from '@sentriflow/core/helpers/arista';

const issues = getBannerInfoDisclosure(ast);
// Returns: ['Banner contains software version', 'Banner contains vendor name']
```

---

### getConsoleIdleTimeout

Check if console idle timeout is configured.

**Signature:**
```typescript
function getConsoleIdleTimeout(ast: ConfigNode[]): number | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `number | undefined` - The timeout value in minutes, or undefined if not set

---

### isZtpDisabled

Check if ZTP (Zero Touch Provisioning) is disabled.

**Signature:**
```typescript
function isZtpDisabled(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if ZTP is disabled

---

## 2. Control Plane Security Helpers

### hasControlPlaneAcl

Check if Control Plane ACL is configured.

**Signature:**
```typescript
function hasControlPlaneAcl(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if system control-plane ACL is configured

---

### hasCoppPolicy

Check if CoPP (Control Plane Policing) is customized.

**Signature:**
```typescript
function hasCoppPolicy(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if CoPP policy is customized

---

### hasNoIpRedirects

Check if interface has ICMP redirects disabled.

**Signature:**
```typescript
function hasNoIpRedirects(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip redirects are disabled

---

### hasNoIpUnreachables

Check if interface has ICMP unreachables disabled.

**Signature:**
```typescript
function hasNoIpUnreachables(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip unreachables are disabled

---

### hasRoutingProtocolAuth

Check if routing protocol has authentication configured.

**Signature:**
```typescript
function hasRoutingProtocolAuth(routerNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerNode | `ConfigNode` | The router ConfigNode (OSPF, IS-IS, etc.) |

**Returns:** `boolean` - `true` if authentication is configured

---

### hasBfd

Check if BFD (Bidirectional Forwarding Detection) is configured.

**Signature:**
```typescript
function hasBfd(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if BFD is configured

---

## 3. Data Plane Security Helpers

### getStormControlStatus

Check if interface has storm control configured.

**Signature:**
```typescript
function getStormControlStatus(interfaceNode: ConfigNode): {
  broadcast: boolean;
  multicast: boolean;
  unicast: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** Object with storm control status for each type

**Example:**
```typescript
import { getStormControlStatus } from '@sentriflow/core/helpers/arista';

const status = getStormControlStatus(interfaceNode);
if (!status.broadcast || !status.multicast) {
  // Flag missing storm control
}
```

---

### hasDhcpSnooping

Check if DHCP snooping is enabled.

**Signature:**
```typescript
function hasDhcpSnooping(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if DHCP snooping is configured

---

### isDhcpSnoopingTrust

Check if interface is DHCP snooping trusted.

**Signature:**
```typescript
function isDhcpSnoopingTrust(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface is DHCP snooping trusted

---

### hasDynamicArpInspection

Check if Dynamic ARP Inspection is enabled.

**Signature:**
```typescript
function hasDynamicArpInspection(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if DAI is configured

---

### isArpInspectionTrust

Check if interface is ARP inspection trusted.

**Signature:**
```typescript
function isArpInspectionTrust(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface is ARP inspection trusted

---

### hasIpSourceGuard

Check if IP Source Guard is enabled on interface.

**Signature:**
```typescript
function hasIpSourceGuard(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip verify source is configured

---

### hasPortSecurity

Check if port security is enabled on interface.

**Signature:**
```typescript
function hasPortSecurity(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if port security is configured

---

## 4. BGP Security Helpers

### getBgpNeighborsWithoutAuth

Check if BGP neighbor has MD5/password authentication.

**Signature:**
```typescript
function getBgpNeighborsWithoutAuth(
  routerBgpNode: ConfigNode,
  neighborIp?: string
): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |
| neighborIp | `string` | Optional specific neighbor IP to check |

**Returns:** `string[]` - Array of neighbors without authentication

**Example:**
```typescript
import { getBgpNeighborsWithoutAuth } from '@sentriflow/core/helpers/arista';

const unauthenticated = getBgpNeighborsWithoutAuth(routerBgpNode);
// Returns: ['10.0.0.1', '10.0.0.2']
```

---

### getBgpNeighborsWithoutTtlSecurity

Check if BGP neighbor has TTL security (GTSM) configured.

**Signature:**
```typescript
function getBgpNeighborsWithoutTtlSecurity(routerBgpNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `string[]` - Array of eBGP neighbors without TTL security

---

### getBgpNeighborsWithoutMaxRoutes

Check if BGP neighbor has maximum-routes configured.

**Signature:**
```typescript
function getBgpNeighborsWithoutMaxRoutes(routerBgpNode: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `string[]` - Array of neighbors without max-prefix limit

---

### hasBgpGracefulRestart

Check if BGP has graceful restart configured.

**Signature:**
```typescript
function hasBgpGracefulRestart(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if graceful restart is configured

---

### hasBgpLogNeighborChanges

Check if BGP has log-neighbor-changes configured.

**Signature:**
```typescript
function hasBgpLogNeighborChanges(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if log-neighbor-changes is configured

---

## 5. RPKI Helpers

### hasRpkiConfiguration

Check if RPKI is configured.

**Signature:**
```typescript
function hasRpkiConfiguration(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if RPKI cache is configured

---

### hasRpkiOriginValidation

Check if RPKI origin validation is enabled.

**Signature:**
```typescript
function hasRpkiOriginValidation(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if origin validation is configured

---

## 6. Anti-Spoofing Helpers

### getUrpfMode

Check if interface has uRPF (unicast RPF) configured.

**Signature:**
```typescript
function getUrpfMode(interfaceNode: ConfigNode): {
  enabled: boolean;
  mode?: 'strict' | 'loose';
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** Object with uRPF status and mode

**Example:**
```typescript
import { getUrpfMode } from '@sentriflow/core/helpers/arista';

const urpf = getUrpfMode(interfaceNode);
if (!urpf.enabled) {
  // Flag missing uRPF configuration
}
```

---

## 7. MLAG Helpers

### hasMlagConfiguration

Check if MLAG is configured.

**Signature:**
```typescript
function hasMlagConfiguration(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if mlag configuration block exists

---

### getMlagConfiguration

Get MLAG configuration node.

**Signature:**
```typescript
function getMlagConfiguration(ast: ConfigNode[]): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `ConfigNode | undefined` - The MLAG configuration node, or undefined

---

### checkMlagRequirements

Check if MLAG has required settings (domain-id, peer-link, peer-address).

**Signature:**
```typescript
function checkMlagRequirements(mlagNode: ConfigNode): {
  hasDomainId: boolean;
  hasPeerLink: boolean;
  hasPeerAddress: boolean;
  hasLocalInterface: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mlagNode | `ConfigNode` | The MLAG configuration node |

**Returns:** Object with status of each MLAG requirement

**Example:**
```typescript
import { getMlagConfiguration, checkMlagRequirements } from '@sentriflow/core/helpers/arista';

const mlagNode = getMlagConfiguration(ast);
if (mlagNode) {
  const reqs = checkMlagRequirements(mlagNode);
  if (!reqs.hasPeerLink) {
    // Flag missing peer-link configuration
  }
}
```

---

### hasMlagDualPrimaryDetection

Check if MLAG dual-primary detection is configured.

**Signature:**
```typescript
function hasMlagDualPrimaryDetection(mlagNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mlagNode | `ConfigNode` | The MLAG configuration node |

**Returns:** `boolean` - `true` if dual-primary detection is configured

---

### getMlagReloadDelays

Check if MLAG reload delays are configured.

**Signature:**
```typescript
function getMlagReloadDelays(mlagNode: ConfigNode): {
  mlag: boolean;
  nonMlag: boolean;
}
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mlagNode | `ConfigNode` | The MLAG configuration node |

**Returns:** Object with reload delay configuration status

---

### getMlagId

Check if interface has MLAG ID configured.

**Signature:**
```typescript
function getMlagId(interfaceNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `string | undefined` - The MLAG ID if configured

---

### isMlagPeerLink

Check if an interface is an MLAG peer-link.

**Signature:**
```typescript
function isMlagPeerLink(node: ConfigNode, mlagNode?: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |
| mlagNode | `ConfigNode` | The MLAG configuration node (optional) |

**Returns:** `boolean` - `true` if this interface is configured as MLAG peer-link

---

## 8. VXLAN/EVPN Helpers

### isVxlanInterface

Check if an interface is a VXLAN interface.

**Signature:**
```typescript
function isVxlanInterface(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's a VXLAN interface

---

### getVxlanVniMappings

Get all VXLAN VNI mappings from a Vxlan interface.

**Signature:**
```typescript
function getVxlanVniMappings(vxlanNode: ConfigNode): { vni: string; vlan?: string }[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vxlanNode | `ConfigNode` | The Vxlan interface ConfigNode |

**Returns:** Array of VNI mappings with optional VLAN

---

### hasVxlanSourceInterface

Check if VXLAN has source interface configured.

**Signature:**
```typescript
function hasVxlanSourceInterface(vxlanNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vxlanNode | `ConfigNode` | The Vxlan interface ConfigNode |

**Returns:** `boolean` - `true` if vxlan source-interface is configured

---

### hasEvpnAddressFamily

Check if BGP EVPN is configured.

**Signature:**
```typescript
function hasEvpnAddressFamily(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if EVPN address-family is configured

---

### hasEvpnPeerAuth

Check if EVPN peers have password authentication.

**Signature:**
```typescript
function hasEvpnPeerAuth(routerBgpNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| routerBgpNode | `ConfigNode` | The router bgp ConfigNode |

**Returns:** `boolean` - `true` if EVPN peer group has password

---

## 9. Logging/Monitoring Helpers

### hasLoggingLevel

Check if logging is configured with specific level.

**Signature:**
```typescript
function hasLoggingLevel(ast: ConfigNode[], minLevel: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |
| minLevel | `string` | Minimum required logging level |

**Returns:** `boolean` - `true` if logging meets minimum level requirement

**Valid levels:** emergencies, alerts, critical, errors, warnings, notifications, informational, debugging

---

### hasLoggingSourceInterface

Check if logging source interface is configured.

**Signature:**
```typescript
function hasLoggingSourceInterface(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if logging source-interface is configured

---

### hasLoggingHost

Check if syslog/logging is configured.

**Signature:**
```typescript
function hasLoggingHost(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if logging host is configured

---

### hasEventMonitor

Check if event-monitor is enabled.

**Signature:**
```typescript
function hasEventMonitor(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if event-monitor is configured

---

### hasSnmpServer

Check if SNMP is configured.

**Signature:**
```typescript
function hasSnmpServer(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if SNMP is configured

---

## 10. High Availability Helpers

### hasVrrpAuthentication

Check if VRRP has authentication configured.

**Signature:**
```typescript
function hasVrrpAuthentication(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if VRRP authentication is configured

---

### hasVirtualRouterMac

Check if virtual-router MAC is configured (for MLAG VARP).

**Signature:**
```typescript
function hasVirtualRouterMac(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if ip virtual-router mac-address is configured

---

### hasVirtualRouterAddress

Check if interface has IP virtual-router address (VARP).

**Signature:**
```typescript
function hasVirtualRouterAddress(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip virtual-router address is configured

---

## 11. Interface Type Helpers

### isEthernetInterface

Check if interface is an Ethernet port.

**Signature:**
```typescript
function isEthernetInterface(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's an Ethernet interface

---

### isPortChannel

Check if interface is a Port-Channel.

**Signature:**
```typescript
function isPortChannel(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's a Port-Channel interface

---

### isLoopback

Check if interface is a Loopback.

**Signature:**
```typescript
function isLoopback(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's a Loopback interface

---

### isSvi

Check if interface is an SVI (VLAN interface).

**Signature:**
```typescript
function isSvi(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's a VLAN SVI

---

### isManagementInterface

Check if interface is a Management interface.

**Signature:**
```typescript
function isManagementInterface(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if it's a Management interface

---

### isAccessPort

Check if interface is an access (edge/endpoint) port.

**Signature:**
```typescript
function isAccessPort(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface is configured as access port

---

### isTrunkPort

Check if interface is a trunk port.

**Signature:**
```typescript
function isTrunkPort(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface is configured as trunk port

---

### isExternalInterface

Check if interface is a WAN/external facing interface based on description.

**Signature:**
```typescript
function isExternalInterface(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface appears to be external facing (WAN, Internet, ISP, External, Uplink, Peering)

---

### isShutdown

Check if interface is shutdown.

**Signature:**
```typescript
function isShutdown(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if interface is shutdown

---

### hasIpAddress

Check if interface has ip address configured.

**Signature:**
```typescript
function hasIpAddress(interfaceNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip address is configured

---

### getInterfaceDescription

Get interface description.

**Signature:**
```typescript
function getInterfaceDescription(interfaceNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `string | undefined` - The description if configured

---

### getInterfaceVrf

Check if interface is in a VRF.

**Signature:**
```typescript
function getInterfaceVrf(interfaceNode: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceNode | `ConfigNode` | The interface ConfigNode |

**Returns:** `string | undefined` - The VRF name if configured

---

## 12. Infrastructure Helpers

### hasManagementApi

Check if management API (eAPI) is configured.

**Signature:**
```typescript
function hasManagementApi(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if management api http-commands is configured

---

### getManagementApiNodes

Get management API configuration nodes.

**Signature:**
```typescript
function getManagementApiNodes(ast: ConfigNode[]): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `ConfigNode[]` - Array of management API configuration nodes

---

### hasHttpsTransport

Check if management API has HTTPS enabled (secure).

**Signature:**
```typescript
function hasHttpsTransport(apiNode: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| apiNode | `ConfigNode` | The management api configuration node |

**Returns:** `boolean` - `true` if HTTPS transport is configured

---

### hasDaemon

Check if daemon is configured.

**Signature:**
```typescript
function hasDaemon(ast: ConfigNode[], daemonName?: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |
| daemonName | `string` | Optional specific daemon name to check |

**Returns:** `boolean` - `true` if daemon(s) are configured

---

### hasEventHandler

Check if event-handler is configured.

**Signature:**
```typescript
function hasEventHandler(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if event-handler(s) are configured

---

### getVrfInstances

Get all VRF instances.

**Signature:**
```typescript
function getVrfInstances(ast: ConfigNode[]): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `ConfigNode[]` - Array of VRF instance nodes

---

### hasNtpServer

Check if NTP is configured.

**Signature:**
```typescript
function hasNtpServer(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if NTP server(s) are configured

---

### hasAaa

Check if AAA is configured.

**Signature:**
```typescript
function hasAaa(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if AAA is configured

---

### hasSpanningTree

Check if spanning-tree is configured.

**Signature:**
```typescript
function hasSpanningTree(ast: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `boolean` - `true` if spanning-tree is configured

---

### getSpanningTreeMode

Get spanning-tree mode.

**Signature:**
```typescript
function getSpanningTreeMode(ast: ConfigNode[]): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ast | `ConfigNode[]` | The full AST array |

**Returns:** `string | undefined` - The spanning-tree mode (mstp, rapid-pvst, none, etc.)

---

## See Also

- [Common Helpers](./common.md) - Shared utilities
- [Cisco Helpers](./cisco.md) - Similar CLI syntax
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Writing rules
