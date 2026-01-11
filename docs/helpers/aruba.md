# Aruba Helper Functions Reference

## Overview

Aruba helpers provide validation functions for three distinct Aruba platforms:
- **AOS-CX** - Modern data center switches
- **AOS-Switch** - Legacy ProCurve/ArubaOS-Switch
- **WLC** - Wireless LAN Controllers (Mobility Controllers)

## Import Statement

```typescript
import {
  isAosCxPhysicalPort,
  hasAosCxBpduGuard,
  getWlanEncryption,
  hasSecureEncryption,
} from '@sentriflow/core/helpers/aruba';
```

---

## 1. Common Helpers

### getInterfaceName

Extract the interface name from an interface stanza id.

**Signature:**
```typescript
function getInterfaceName(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `string | undefined` - The interface identifier without the leading keyword

**Example:**
```typescript
import { getInterfaceName } from '@sentriflow/core/helpers/aruba';

const name = getInterfaceName(interfaceNode);
// "interface 1/1/1" → "1/1/1"
```

---

### findStanza

Find a child stanza by exact name match.

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

---

### hasDescription

Check if an interface/node has a description configured.

**Signature:**
```typescript
function hasDescription(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode |

**Returns:** `boolean` - `true` if a description command exists

---

### getDescription

Get the description from a node.

**Signature:**
```typescript
function getDescription(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The ConfigNode |

**Returns:** `string | undefined` - The description text

---

## 2. AOS-CX Helpers

### isAosCxPhysicalPort

Check if an AOS-CX interface is a physical port (slot/member/port format).

**Signature:**
```typescript
function isAosCxPhysicalPort(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface identifier |

**Returns:** `boolean` - `true` if it's a physical port (e.g., 1/1/1)

**Example:**
```typescript
import { isAosCxPhysicalPort } from '@sentriflow/core/helpers/aruba';

isAosCxPhysicalPort('1/1/1');     // true
isAosCxPhysicalPort('lag 1');     // false
isAosCxPhysicalPort('vlan 100');  // false
```

---

### isAosCxLag

Check if an AOS-CX interface is a LAG.

**Signature:**
```typescript
function isAosCxLag(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface identifier |

**Returns:** `boolean` - `true` if it's a LAG interface

---

### isAosCxVlanInterface

Check if an AOS-CX interface is a VLAN interface.

**Signature:**
```typescript
function isAosCxVlanInterface(interfaceName: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| interfaceName | `string` | The interface identifier |

**Returns:** `boolean` - `true` if it's a VLAN interface

---

### isAosCxTrunk

Check if an AOS-CX interface is configured as trunk mode.

**Signature:**
```typescript
function isAosCxTrunk(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if the interface has trunk VLAN configuration

---

### isAosCxAccess

Check if an AOS-CX interface is configured as access mode.

**Signature:**
```typescript
function isAosCxAccess(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if the interface has access VLAN configuration

---

### getAosCxVlanAccess

Get the access VLAN ID from an AOS-CX interface.

**Signature:**
```typescript
function getAosCxVlanAccess(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `number | null` - The VLAN ID, or null if not configured

---

### getAosCxTrunkNative

Get the native VLAN ID from an AOS-CX trunk interface.

**Signature:**
```typescript
function getAosCxTrunkNative(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `number | null` - The native VLAN ID, or null if not configured

---

### getAosCxTrunkAllowed

Get allowed VLANs from an AOS-CX trunk interface.

**Signature:**
```typescript
function getAosCxTrunkAllowed(node: ConfigNode): number[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `number[]` - Array of allowed VLAN IDs

---

### hasAosCxBpduGuard

Check if an AOS-CX interface has BPDU guard enabled.

**Signature:**
```typescript
function hasAosCxBpduGuard(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if BPDU guard is configured

---

### isAosCxEdgePort

Check if an AOS-CX interface is an admin-edge port.

**Signature:**
```typescript
function isAosCxEdgePort(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if admin-edge is configured

---

### hasAosCxRootGuard

Check if an AOS-CX interface has root-guard enabled.

**Signature:**
```typescript
function hasAosCxRootGuard(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if root-guard is configured

---

### hasAosCxLoopProtect

Check if an AOS-CX interface has loop-protect enabled.

**Signature:**
```typescript
function hasAosCxLoopProtect(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if loop-protect is configured

---

### hasAosCxStormControl

Check if an AOS-CX interface has storm-control configured.

**Signature:**
```typescript
function hasAosCxStormControl(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if any storm-control setting is configured

---

### hasAosCxDhcpSnooping

Check if an AOS-CX interface has DHCP snooping trust configured.

**Signature:**
```typescript
function hasAosCxDhcpSnooping(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if dhcp-snooping is configured

---

### hasAosCxArpInspection

Check if an AOS-CX interface has ARP inspection trust configured.

**Signature:**
```typescript
function hasAosCxArpInspection(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip arp inspection is configured

---

### hasAosCxIpSourceGuard

Check if an AOS-CX interface has IP source guard (source-binding) configured.

**Signature:**
```typescript
function hasAosCxIpSourceGuard(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if ip source-binding is configured

---

### hasAosCxPortSecurity

Check if an AOS-CX interface has port security configured.

**Signature:**
```typescript
function hasAosCxPortSecurity(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if port-access port-security is configured

---

### hasAosCxDot1x

Check if an AOS-CX interface has 802.1X authenticator configured.

**Signature:**
```typescript
function hasAosCxDot1x(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if dot1x authenticator is configured

---

### hasAosCxMacAuth

Check if an AOS-CX interface has MAC authentication configured.

**Signature:**
```typescript
function hasAosCxMacAuth(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if mac-auth is configured

---

### hasAosCxMacsec

Check if an AOS-CX interface has MACsec configured.

**Signature:**
```typescript
function hasAosCxMacsec(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface ConfigNode |

**Returns:** `boolean` - `true` if MACsec policy is applied

---

### getAosCxMstpRegionName

Get MSTP region name from global config.

**Signature:**
```typescript
function getAosCxMstpRegionName(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The spanning-tree config-name node |

**Returns:** `string | undefined` - The region name

---

## 3. AOS-Switch Helpers

### parsePortRange

Parse port range string to array of port numbers.

**Signature:**
```typescript
function parsePortRange(portStr: string): number[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| portStr | `string` | The port range string (e.g., "1-24", "25,26,27", "1-24,48") |

**Returns:** `number[]` - Array of individual port numbers

**Example:**
```typescript
import { parsePortRange } from '@sentriflow/core/helpers/aruba';

parsePortRange('1-5');      // [1, 2, 3, 4, 5]
parsePortRange('1,3,5');    // [1, 3, 5]
parsePortRange('1-3,5');    // [1, 2, 3, 5]
```

---

### getVlanTaggedPorts

Get tagged ports from an AOS-Switch VLAN node.

**Signature:**
```typescript
function getVlanTaggedPorts(node: ConfigNode): (number | string)[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VLAN ConfigNode |

**Returns:** `(number | string)[]` - Array of tagged port numbers (includes trunk names like 'trk1')

---

### getVlanUntaggedPorts

Get untagged ports from an AOS-Switch VLAN node.

**Signature:**
```typescript
function getVlanUntaggedPorts(node: ConfigNode): (number | string)[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VLAN ConfigNode |

**Returns:** `(number | string)[]` - Array of untagged port numbers

---

### getAosSwitchVlanName

Get the VLAN name from an AOS-Switch VLAN node.

**Signature:**
```typescript
function getAosSwitchVlanName(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The VLAN ConfigNode |

**Returns:** `string | undefined` - The VLAN name

---

### hasManagerPassword

Check if AOS-Switch has manager password configured.

**Signature:**
```typescript
function hasManagerPassword(nodes: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodes | `ConfigNode[]` | Array of top-level ConfigNodes (AST children) |

**Returns:** `boolean` - `true` if manager password is configured

---

### hasOperatorPassword

Check if AOS-Switch has operator password configured.

**Signature:**
```typescript
function hasOperatorPassword(nodes: ConfigNode[]): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodes | `ConfigNode[]` | Array of top-level ConfigNodes (AST children) |

**Returns:** `boolean` - `true` if operator password is configured

---

## 4. WLC Helpers

### getWlanEncryption

Get the WLAN encryption mode from an SSID profile.

**Signature:**
```typescript
function getWlanEncryption(node: ConfigNode): string | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `string | null` - The opmode value (e.g., 'wpa3-sae-aes', 'wpa2-aes', 'opensystem')

---

### hasSecureEncryption

Check if a WLAN SSID profile has secure encryption (WPA2/WPA3).

**Signature:**
```typescript
function hasSecureEncryption(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if encryption is WPA2 or WPA3

---

### isOpenSsid

Check if a WLAN SSID profile is open (no encryption).

**Signature:**
```typescript
function isOpenSsid(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if the SSID is open/unencrypted

---

### hasWpa3Encryption

Check if a WLAN SSID profile uses WPA3.

**Signature:**
```typescript
function hasWpa3Encryption(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if encryption is WPA3

---

### hasWpa3Enterprise

Check if a WLAN SSID profile uses WPA3-Enterprise.

**Signature:**
```typescript
function hasWpa3Enterprise(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if encryption is WPA3-Enterprise

---

### hasWpa3Sae

Check if a WLAN SSID profile uses WPA3-SAE (Personal).

**Signature:**
```typescript
function hasWpa3Sae(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if encryption is WPA3-SAE

---

### getEssid

Get the ESSID from a WLAN SSID profile.

**Signature:**
```typescript
function getEssid(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `string | undefined` - The ESSID value

---

### getPmfMode

Check if Protected Management Frames (PMF/802.11w) is enabled.

**Signature:**
```typescript
function getPmfMode(node: ConfigNode): 'required' | 'optional' | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `'required' | 'optional' | null` - The PMF mode

---

### is6GhzSsid

Check if SSID profile is configured for 6 GHz band.

**Signature:**
```typescript
function is6GhzSsid(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `boolean` - `true` if 6ghz band is configured

---

### getMaxClients

Get max clients limit from SSID profile.

**Signature:**
```typescript
function getMaxClients(node: ConfigNode): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The SSID profile ConfigNode |

**Returns:** `number | null` - The max clients value

---

### getVapAaaProfile

Get the AAA profile reference from a virtual-AP profile.

**Signature:**
```typescript
function getVapAaaProfile(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The virtual-AP ConfigNode |

**Returns:** `string | undefined` - The AAA profile name

---

### getVapSsidProfile

Get the SSID profile reference from a virtual-AP profile.

**Signature:**
```typescript
function getVapSsidProfile(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The virtual-AP ConfigNode |

**Returns:** `string | undefined` - The SSID profile name

---

### getApGroupVirtualAps

Get virtual-APs from an AP group.

**Signature:**
```typescript
function getApGroupVirtualAps(node: ConfigNode): string[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The AP group ConfigNode |

**Returns:** `string[]` - Array of virtual-AP names

---

### hasRadiusKey

Check if RADIUS server has a key configured.

**Signature:**
```typescript
function hasRadiusKey(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The RADIUS server ConfigNode |

**Returns:** `boolean` - `true` if a key is configured

---

### getRadiusHost

Get the RADIUS server host address.

**Signature:**
```typescript
function getRadiusHost(node: ConfigNode): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The RADIUS server ConfigNode |

**Returns:** `string | undefined` - The host IP/hostname

---

### extractProfileName

Extract profile name from a profile definition node.

**Signature:**
```typescript
function extractProfileName(nodeId: string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| nodeId | `string` | The node identifier string |

**Returns:** `string | undefined` - The profile name

---

### hasCpsecEnabled

Check if CPsec (Control Plane Security) is enabled on WLC.

**Signature:**
```typescript
function hasCpsecEnabled(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The control-plane-security ConfigNode |

**Returns:** `boolean` - `true` if cpsec is enabled

---

### hasWhitelistDb

Check if whitelist-db is enabled for AP authorization.

**Signature:**
```typescript
function hasWhitelistDb(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The cpsec ConfigNode |

**Returns:** `boolean` - `true` if whitelist-db is enabled

---

## See Also

- [Common Helpers](./common.md) - Shared utilities
- [Cisco Helpers](./cisco.md) - Similar CLI syntax for wired networks
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md) - Writing rules
