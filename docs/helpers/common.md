# Common Helper Functions Reference

Common helpers are shared utilities used across all vendor-specific rules. They provide fundamental operations for IP address parsing, VLAN validation, MAC address handling, and AST node navigation.

## Import Statement

```typescript
import {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
  parseIp,
  isValidIpAddress,
  parseVlanId,
  isValidVlanId,
  // ... other helpers
} from '@sentriflow/core/helpers/common';
```

Or import everything:

```typescript
import * as common from '@sentriflow/core/helpers/common';
```

---

## Categories

### 1. Node Navigation

Functions for traversing and querying the configuration AST.

---

#### hasChildCommand

Check if a node has a specific child command (case-insensitive prefix match).

**Signature:**
```typescript
function hasChildCommand(node: ConfigNode, prefix: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The command prefix to match |

**Returns:** `boolean` - `true` if a matching child exists, `false` if node/children is nullish.

**Example:**
```typescript
import { hasChildCommand } from '@sentriflow/core/helpers/common';

// Check if interface has a description
if (hasChildCommand(interfaceNode, 'description')) {
  console.log('Interface has description');
}

// Check for shutdown command
const isDown = hasChildCommand(interfaceNode, 'shutdown');
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "hasChildCommand",
  "args": [{ "$ref": "node" }, "description"]
}
```

---

#### getChildCommand

Get the first child command matching a prefix.

**Signature:**
```typescript
function getChildCommand(node: ConfigNode, prefix: string): ConfigNode | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The command prefix to match |

**Returns:** `ConfigNode | undefined` - The matching child node, or `undefined` if not found.

**Example:**
```typescript
import { getChildCommand } from '@sentriflow/core/helpers/common';

// Get the description command
const descCmd = getChildCommand(interfaceNode, 'description');
if (descCmd) {
  // Access description text via descCmd.params[1] or descCmd.id
  console.log('Description:', descCmd.id.slice('description '.length));
}

// Get IP address configuration
const ipCmd = getChildCommand(interfaceNode, 'ip address');
if (ipCmd) {
  const ipAddress = ipCmd.params[2];  // e.g., "10.0.0.1"
  const mask = ipCmd.params[3];       // e.g., "255.255.255.0"
}
```

---

#### getChildCommands

Get all child commands matching a prefix.

**Signature:**
```typescript
function getChildCommands(node: ConfigNode, prefix: string): ConfigNode[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The parent node to search |
| prefix | `string` | The command prefix to match |

**Returns:** `ConfigNode[]` - Array of matching child nodes (empty array if none found).

**Example:**
```typescript
import { getChildCommands } from '@sentriflow/core/helpers/common';

// Get all access-list entries
const aclEntries = getChildCommands(node, 'permit');

// Get all VLAN assignments
const vlanCmds = getChildCommands(interfaceNode, 'switchport access vlan');
```

---

#### getParamValue

Extract a parameter value from a node's params array by keyword.

**Signature:**
```typescript
function getParamValue(node: ConfigNode, keyword: string): string | undefined
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The node containing params |
| keyword | `string` | The keyword to find (case-insensitive) |

**Returns:** `string | undefined` - The value after the keyword, or `undefined` if not found.

**Example:**
```typescript
import { getParamValue } from '@sentriflow/core/helpers/common';

// For node with id: "switchport access vlan 100"
// params: ["switchport", "access", "vlan", "100"]
const vlanId = getParamValue(node, 'vlan');  // Returns "100"

// For node with id: "ip address 10.0.0.1 255.255.255.0"
const ipAddr = getParamValue(node, 'address');  // Returns "10.0.0.1"
```

---

#### isShutdown

Check if an interface is administratively shutdown.

**Signature:**
```typescript
function isShutdown(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The interface node to check |

**Returns:** `boolean` - `true` if interface has `shutdown` or `disable` command.

**Example:**
```typescript
import { isShutdown } from '@sentriflow/core/helpers/common';

// Skip shutdown interfaces in your rule
if (isShutdown(interfaceNode)) {
  return { passed: true, message: 'Interface is shutdown' };
}
```

**JSON Rule Usage:**
```json
{
  "type": "helper",
  "helper": "isShutdown",
  "args": [{ "$ref": "node" }],
  "negate": true
}
```

---

#### isInterfaceDefinition

Check if a node is an actual interface definition (not a reference or sub-command).

**Signature:**
```typescript
function isInterfaceDefinition(node: ConfigNode): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| node | `ConfigNode` | The node to check |

**Returns:** `boolean` - `true` if this is an actual interface definition.

**Details:**

This helper distinguishes real interface definitions from:
- Interface references inside protocol blocks (OSPF, LLDP, etc.)
- Sub-commands like "interface-type", "interface-mode"
- Generic references like "interface all"

**Example:**
```typescript
import { isInterfaceDefinition } from '@sentriflow/core/helpers/common';

// Filter to only real interface definitions
const interfaces = ast.filter(isInterfaceDefinition);

// Use in rule check
if (!isInterfaceDefinition(node)) {
  return { passed: true, message: 'Not an interface definition' };
}
```

---

### 2. IP Address Helpers

Functions for parsing and validating IP addresses.

---

#### parseIp

Parse an IP address string to a 32-bit unsigned integer.

**Signature:**
```typescript
function parseIp(addr: string): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| addr | `string` | The IP address string (e.g., "10.0.0.1") |

**Returns:** `number | null` - The IP as a 32-bit unsigned number, or `null` if invalid.

**Example:**
```typescript
import { parseIp } from '@sentriflow/core/helpers/common';

const ip = parseIp('10.0.0.1');      // Returns 167772161
const invalid = parseIp('invalid');  // Returns null
const overflow = parseIp('256.0.0.1'); // Returns null
```

---

#### numToIp

Convert a 32-bit unsigned integer to an IP address string.

**Signature:**
```typescript
function numToIp(num: number): string
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| num | `number` | The IP as a 32-bit unsigned number |

**Returns:** `string` - The IP address string.

**Example:**
```typescript
import { numToIp } from '@sentriflow/core/helpers/common';

const ip = numToIp(167772161);  // Returns "10.0.0.1"
const broadcast = numToIp(0xffffffff);  // Returns "255.255.255.255"
```

---

#### isValidIpAddress

Check if a string is a valid IP address.

**Signature:**
```typescript
function isValidIpAddress(value: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `string` | The string to validate |

**Returns:** `boolean` - `true` if valid IP address format.

**Example:**
```typescript
import { isValidIpAddress } from '@sentriflow/core/helpers/common';

isValidIpAddress('10.0.0.1');      // true
isValidIpAddress('192.168.1.256'); // false (octet > 255)
isValidIpAddress('10.0.0');        // false (incomplete)
```

---

#### isMulticastAddress

Check if an IP is in the multicast range (224.0.0.0 - 239.255.255.255).

**Signature:**
```typescript
function isMulticastAddress(ipNum: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ipNum | `number` | The IP as a 32-bit unsigned number |

**Returns:** `boolean` - `true` if multicast address (Class D).

**Example:**
```typescript
import { parseIp, isMulticastAddress } from '@sentriflow/core/helpers/common';

const ip = parseIp('224.0.0.1');
if (ip !== null && isMulticastAddress(ip)) {
  console.log('This is a multicast address');
}
```

---

#### isBroadcastAddress

Check if an IP is the global broadcast address (255.255.255.255).

**Signature:**
```typescript
function isBroadcastAddress(ipNum: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ipNum | `number` | The IP as a 32-bit unsigned number |

**Returns:** `boolean` - `true` if broadcast address.

**Example:**
```typescript
import { parseIp, isBroadcastAddress } from '@sentriflow/core/helpers/common';

const ip = parseIp('255.255.255.255');
if (ip !== null && isBroadcastAddress(ip)) {
  console.log('This is the broadcast address');
}
```

---

#### isPrivateAddress

Check if an IP is a private address (RFC 1918).

**Signature:**
```typescript
function isPrivateAddress(ipNum: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ipNum | `number` | The IP as a 32-bit unsigned number |

**Returns:** `boolean` - `true` if in RFC 1918 private ranges.

**Details:**

Checks for:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

**Example:**
```typescript
import { parseIp, isPrivateAddress } from '@sentriflow/core/helpers/common';

const publicIp = parseIp('8.8.8.8');
const privateIp = parseIp('192.168.1.1');

isPrivateAddress(publicIp!);   // false
isPrivateAddress(privateIp!);  // true
```

---

#### prefixToMask

Convert a CIDR prefix length to a subnet mask number.

**Signature:**
```typescript
function prefixToMask(prefix: number): number
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| prefix | `number` | The prefix length (0-32) |

**Returns:** `number` - The subnet mask as a 32-bit unsigned number.

**Example:**
```typescript
import { prefixToMask, numToIp } from '@sentriflow/core/helpers/common';

const mask24 = prefixToMask(24);  // 0xFFFFFF00
numToIp(mask24);  // "255.255.255.0"

const mask16 = prefixToMask(16);  // 0xFFFF0000
numToIp(mask16);  // "255.255.0.0"
```

---

#### maskToPrefix

Convert a subnet mask to CIDR prefix length.

**Signature:**
```typescript
function maskToPrefix(mask: number): number
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mask | `number` | The subnet mask as a 32-bit unsigned number |

**Returns:** `number` - The prefix length (0-32).

**Example:**
```typescript
import { parseIp, maskToPrefix } from '@sentriflow/core/helpers/common';

const mask = parseIp('255.255.255.0');
const prefix = maskToPrefix(mask!);  // 24
```

---

#### parseCidr

Parse CIDR notation to network, prefix, and mask.

**Signature:**
```typescript
function parseCidr(cidr: string): CidrInfo | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| cidr | `string` | CIDR notation string (e.g., "10.0.0.0/24") |

**Returns:** `CidrInfo | null` - Object with `network`, `prefix`, `mask`, or `null` if invalid.

**CidrInfo Interface:**
```typescript
interface CidrInfo {
  network: number;  // Network address as 32-bit number
  prefix: number;   // CIDR prefix length (0-32)
  mask: number;     // Subnet mask as 32-bit number
}
```

**Example:**
```typescript
import { parseCidr, numToIp } from '@sentriflow/core/helpers/common';

const cidr = parseCidr('10.0.0.0/24');
if (cidr) {
  console.log('Network:', numToIp(cidr.network));  // "10.0.0.0"
  console.log('Prefix:', cidr.prefix);              // 24
  console.log('Mask:', numToIp(cidr.mask));         // "255.255.255.0"
}
```

---

#### isIpInCidr

Check if an IP address is within a CIDR block.

**Signature:**
```typescript
function isIpInCidr(ipStr: string, cidrStr: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ipStr | `string` | IP address string |
| cidrStr | `string` | CIDR notation string |

**Returns:** `boolean` - `true` if IP is in the CIDR block.

**Example:**
```typescript
import { isIpInCidr } from '@sentriflow/core/helpers/common';

isIpInCidr('10.0.0.5', '10.0.0.0/24');    // true
isIpInCidr('10.0.1.5', '10.0.0.0/24');    // false
isIpInCidr('192.168.1.1', '192.168.0.0/16');  // true
```

---

#### isIpInNetwork

Check if an IP is within a network (using numeric values).

**Signature:**
```typescript
function isIpInNetwork(ip: number, network: number, mask: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| ip | `number` | IP address as 32-bit number |
| network | `number` | Network address as 32-bit number |
| mask | `number` | Subnet mask as 32-bit number |

**Returns:** `boolean` - `true` if IP is in the network.

**Example:**
```typescript
import { parseIp, prefixToMask, isIpInNetwork } from '@sentriflow/core/helpers/common';

const ip = parseIp('10.0.0.5')!;
const network = parseIp('10.0.0.0')!;
const mask = prefixToMask(24);

isIpInNetwork(ip, network, mask);  // true
```

---

### 3. VLAN Helpers

Functions for VLAN validation.

---

#### parseVlanId

Parse a VLAN ID string to number.

**Signature:**
```typescript
function parseVlanId(vlanStr: string): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vlanStr | `string` | VLAN ID string |

**Returns:** `number | null` - VLAN number (1-4094) or `null` if invalid.

**Example:**
```typescript
import { parseVlanId } from '@sentriflow/core/helpers/common';

parseVlanId('100');   // 100
parseVlanId('4095');  // null (out of range)
parseVlanId('abc');   // null (not a number)
```

---

#### isValidVlanId

Check if a VLAN ID is valid (1-4094).

**Signature:**
```typescript
function isValidVlanId(vlanId: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vlanId | `number` | VLAN ID to validate |

**Returns:** `boolean` - `true` if valid VLAN ID.

**Example:**
```typescript
import { isValidVlanId } from '@sentriflow/core/helpers/common';

isValidVlanId(100);   // true
isValidVlanId(4094);  // true
isValidVlanId(4095);  // false
isValidVlanId(0);     // false
```

---

#### isDefaultVlan

Check if VLAN is the default VLAN (VLAN 1).

**Signature:**
```typescript
function isDefaultVlan(vlanId: string | number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vlanId | `string \| number` | VLAN ID |

**Returns:** `boolean` - `true` if VLAN 1.

**Example:**
```typescript
import { isDefaultVlan } from '@sentriflow/core/helpers/common';

isDefaultVlan(1);     // true
isDefaultVlan('1');   // true
isDefaultVlan(100);   // false
```

---

#### isReservedVlan

Check if VLAN is in the Cisco reserved range (1002-1005).

**Signature:**
```typescript
function isReservedVlan(vlanId: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| vlanId | `number` | VLAN ID |

**Returns:** `boolean` - `true` if in reserved range (1002-1005).

**Example:**
```typescript
import { isReservedVlan } from '@sentriflow/core/helpers/common';

isReservedVlan(1002);  // true (fddi-default)
isReservedVlan(1003);  // true (token-ring-default)
isReservedVlan(100);   // false
```

---

### 4. Port Helpers

Functions for port number validation.

---

#### parsePort

Parse and validate a port number (1-65535).

**Signature:**
```typescript
function parsePort(value: string): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `string` | Port string to parse |

**Returns:** `number | null` - Port number or `null` if invalid.

**Example:**
```typescript
import { parsePort } from '@sentriflow/core/helpers/common';

parsePort('443');    // 443
parsePort('80');     // 80
parsePort('65536');  // null (out of range)
parsePort('abc');    // null
```

---

#### isValidPort

Check if a port number is valid (1-65535).

**Signature:**
```typescript
function isValidPort(port: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| port | `number` | Port number to validate |

**Returns:** `boolean` - `true` if valid port.

**Example:**
```typescript
import { isValidPort } from '@sentriflow/core/helpers/common';

isValidPort(443);    // true
isValidPort(0);      // false
isValidPort(65536);  // false
```

---

#### parsePortRange

Parse a port range string to array of port numbers.

**Signature:**
```typescript
function parsePortRange(portStr: string): number[]
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| portStr | `string` | Port range string (e.g., "1-24", "80,443", "1-10,20,30-32") |

**Returns:** `number[]` - Array of individual port numbers.

**Example:**
```typescript
import { parsePortRange } from '@sentriflow/core/helpers/common';

parsePortRange('1-5');          // [1, 2, 3, 4, 5]
parsePortRange('80,443');       // [80, 443]
parsePortRange('1-3,10,20-22'); // [1, 2, 3, 10, 20, 21, 22]
```

---

### 5. MAC Address Helpers

Functions for MAC address validation and normalization.

---

#### isValidMacAddress

Validate MAC address format.

**Signature:**
```typescript
function isValidMacAddress(mac: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mac | `string` | MAC address string |

**Returns:** `boolean` - `true` if valid MAC format.

**Supported Formats:**
- Colon-separated (Linux/Unix): `XX:XX:XX:XX:XX:XX`
- Hyphen-separated (Windows): `XX-XX-XX-XX-XX-XX`
- Dot-separated (Cisco): `XXXX.XXXX.XXXX`

**Example:**
```typescript
import { isValidMacAddress } from '@sentriflow/core/helpers/common';

isValidMacAddress('00:1a:2b:3c:4d:5e');  // true
isValidMacAddress('00-1A-2B-3C-4D-5E');  // true
isValidMacAddress('001a.2b3c.4d5e');     // true
isValidMacAddress('invalid');            // false
```

---

#### normalizeMacAddress

Normalize MAC address to lowercase colon-separated format.

**Signature:**
```typescript
function normalizeMacAddress(mac: string): string | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| mac | `string` | MAC address in any supported format |

**Returns:** `string | null` - Normalized MAC or `null` if invalid.

**Example:**
```typescript
import { normalizeMacAddress } from '@sentriflow/core/helpers/common';

normalizeMacAddress('00-1A-2B-3C-4D-5E');  // "00:1a:2b:3c:4d:5e"
normalizeMacAddress('001a.2b3c.4d5e');     // "00:1a:2b:3c:4d:5e"
normalizeMacAddress('invalid');            // null
```

---

### 6. String Helpers

Case-insensitive string comparison utilities.

---

#### equalsIgnoreCase

Case-insensitive string equality check.

**Signature:**
```typescript
function equalsIgnoreCase(a: string, b: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| a | `string` | First string |
| b | `string` | Second string |

**Returns:** `boolean` - `true` if equal (case-insensitive).

**Example:**
```typescript
import { equalsIgnoreCase } from '@sentriflow/core/helpers/common';

equalsIgnoreCase('Hello', 'hello');  // true
equalsIgnoreCase('Test', 'TEST');    // true
equalsIgnoreCase('Foo', 'Bar');      // false
```

---

#### includesIgnoreCase

Case-insensitive substring check.

**Signature:**
```typescript
function includesIgnoreCase(haystack: string, needle: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| haystack | `string` | String to search in |
| needle | `string` | String to search for |

**Returns:** `boolean` - `true` if needle is found (case-insensitive).

**Example:**
```typescript
import { includesIgnoreCase } from '@sentriflow/core/helpers/common';

includesIgnoreCase('GigabitEthernet0/1', 'gigabit');  // true
includesIgnoreCase('interface Vlan100', 'VLAN');      // true
```

---

#### startsWithIgnoreCase

Case-insensitive prefix check.

**Signature:**
```typescript
function startsWithIgnoreCase(str: string, prefix: string): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| str | `string` | String to check |
| prefix | `string` | Prefix to match |

**Returns:** `boolean` - `true` if str starts with prefix (case-insensitive).

**Example:**
```typescript
import { startsWithIgnoreCase } from '@sentriflow/core/helpers/common';

startsWithIgnoreCase('GigabitEthernet0/1', 'gigabit');  // true
startsWithIgnoreCase('interface Vlan100', 'INTERFACE'); // true
```

---

### 7. Numeric Helpers

General numeric parsing and validation.

---

#### parseInteger

Parse a string to integer.

**Signature:**
```typescript
function parseInteger(value: string): number | null
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `string` | String to parse |

**Returns:** `number | null` - Parsed integer or `null` if invalid.

**Example:**
```typescript
import { parseInteger } from '@sentriflow/core/helpers/common';

parseInteger('42');     // 42
parseInteger('-10');    // -10
parseInteger('3.14');   // 3 (truncates)
parseInteger('abc');    // null
```

---

#### isInRange

Check if a number is within a range (inclusive).

**Signature:**
```typescript
function isInRange(value: number, min: number, max: number): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `number` | Number to check |
| min | `number` | Minimum value (inclusive) |
| max | `number` | Maximum value (inclusive) |

**Returns:** `boolean` - `true` if value is in range.

**Example:**
```typescript
import { isInRange } from '@sentriflow/core/helpers/common';

isInRange(50, 1, 100);   // true
isInRange(0, 1, 100);    // false
isInRange(100, 1, 100);  // true (inclusive)
```

---

### 8. Feature State Helpers

Functions for checking feature enabled/disabled states.

---

#### isFeatureEnabled

Check if a feature value represents "enabled" state.

**Signature:**
```typescript
function isFeatureEnabled(value: string | undefined): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `string \| undefined` | Feature state string |

**Returns:** `boolean` - `true` if enabled.

**Recognized Values:** `enable`, `enabled`, `yes`, `true`, `on`, `1`

**Example:**
```typescript
import { isFeatureEnabled } from '@sentriflow/core/helpers/common';

isFeatureEnabled('enabled');  // true
isFeatureEnabled('yes');      // true
isFeatureEnabled('1');        // true
isFeatureEnabled('disabled'); // false
isFeatureEnabled(undefined);  // false
```

---

#### isFeatureDisabled

Check if a feature value represents "disabled" state.

**Signature:**
```typescript
function isFeatureDisabled(value: string | undefined): boolean
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| value | `string \| undefined` | Feature state string |

**Returns:** `boolean` - `true` if disabled.

**Recognized Values:** `disable`, `disabled`, `no`, `false`, `off`, `0`

**Example:**
```typescript
import { isFeatureDisabled } from '@sentriflow/core/helpers/common';

isFeatureDisabled('disabled');  // true
isFeatureDisabled('no');        // true
isFeatureDisabled('0');         // true
isFeatureDisabled('enabled');   // false
```

---

## See Also

- [Helper Functions Overview](./README.md)
- [Cisco Helpers](./cisco.md)
- [Juniper Helpers](./juniper.md)
- [Rule Authoring Guide](../RULE_AUTHORING_GUIDE.md)
