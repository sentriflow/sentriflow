// packages/core/test/helpers/fixture-pairs.ts

/**
 * Represents a pair of indented and non-indented configuration fixtures
 * for AST equivalence testing.
 */
export interface TestFixturePair {
  /** Unique name for this fixture pair (e.g., "comprehensive-router") */
  name: string;

  /** Vendor ID for parsing ('cisco-ios' | 'cisco-nxos') */
  vendor: 'cisco-ios' | 'cisco-nxos';

  /** Path to indented fixture file (relative to packages/core/) */
  indentedPath: string;

  /** Path to non-indented (flat) fixture file (relative to packages/core/) */
  flatPath: string;

  /** Expected number of section nodes in the AST */
  expectedSections: number;

  /** Expected number of command nodes in the AST */
  expectedCommands: number;

  /** Block starter categories covered by this fixture (for coverage tracking) */
  coverageCategories: string[];

  /**
   * Whether the indented and flat versions should produce identical AST structures.
   * Set to false for fixtures with context-dependent nesting that the parser
   * cannot replicate without indentation (e.g., police sub-commands, neighbor address-family).
   * When false, only node counts are validated, not exact tree structure.
   */
  strictEquivalence: boolean;
}

/**
 * Registry of all Cisco IOS fixture pairs for AST equivalence testing.
 */
export const CISCO_IOS_FIXTURE_PAIRS: TestFixturePair[] = [
  {
    name: 'comprehensive-router',
    vendor: 'cisco-ios',
    indentedPath: 'test/fixtures/cisco-ios/comprehensive-router.txt',
    flatPath: 'test/fixtures/cisco-ios/comprehensive-router-flat.txt',
    expectedSections: 29,
    expectedCommands: 65,
    coverageCategories: ['interface', 'router', 'vrf', 'address-family', 'ip-sla', 'track', 'redundancy', 'archive', 'key-chain'],
    strictEquivalence: true,
  },
  {
    name: 'comprehensive-switch',
    vendor: 'cisco-ios',
    indentedPath: 'test/fixtures/cisco-ios/comprehensive-switch.txt',
    flatPath: 'test/fixtures/cisco-ios/comprehensive-switch-flat.txt',
    expectedSections: 13,
    expectedCommands: 58,
    coverageCategories: ['vlan', 'interface', 'port-channel'],
    strictEquivalence: true,
  },
  {
    name: 'routing-protocols',
    vendor: 'cisco-ios',
    indentedPath: 'test/fixtures/cisco-ios/routing-protocols.txt',
    flatPath: 'test/fixtures/cisco-ios/routing-protocols-flat.txt',
    expectedSections: 35,
    expectedCommands: 84,
    coverageCategories: ['vrf', 'interface', 'router', 'address-family', 'af-interface', 'topology', 'ip-prefix-list', 'route-map', 'key-chain'],
    strictEquivalence: true,
  },
  {
    name: 'security-hardening',
    vendor: 'cisco-ios',
    indentedPath: 'test/fixtures/cisco-ios/security-hardening.txt',
    flatPath: 'test/fixtures/cisco-ios/security-hardening-flat.txt',
    expectedSections: 33,
    expectedCommands: 72,
    coverageCategories: ['aaa-group', 'tacacs-server', 'radius-server', 'ip-access-list', 'class-map', 'policy-map', 'control-plane', 'line'],
    strictEquivalence: true,
  },
];

/**
 * Registry of all Cisco NX-OS fixture pairs for AST equivalence testing.
 */
export const CISCO_NXOS_FIXTURE_PAIRS: TestFixturePair[] = [
  {
    name: 'comprehensive-nexus',
    vendor: 'cisco-nxos',
    indentedPath: 'test/fixtures/cisco-nxos/comprehensive-nexus.txt',
    flatPath: 'test/fixtures/cisco-nxos/comprehensive-nexus-flat.txt',
    expectedSections: 46,
    expectedCommands: 76,
    coverageCategories: ['feature', 'vrf-context', 'interface', 'router', 'address-family', 'neighbor', 'route-map', 'ip-prefix-list'],
    // Has address-family inside neighbor block - parser can't distinguish context without indentation
    strictEquivalence: false,
  },
  {
    name: 'vpc-fabricpath',
    vendor: 'cisco-nxos',
    indentedPath: 'test/fixtures/cisco-nxos/vpc-fabricpath.txt',
    flatPath: 'test/fixtures/cisco-nxos/vpc-fabricpath-flat.txt',
    expectedSections: 25,
    expectedCommands: 82,
    coverageCategories: ['feature', 'fabricpath-domain', 'vpc-domain', 'vlan', 'interface', 'port-channel', 'spanning-tree-mst'],
    // Has interface sub-blocks that rely on indentation for nesting
    strictEquivalence: false,
  },
];

/**
 * Registry of all Cisco ASA fixture pairs for AST equivalence testing.
 * Note: ASA uses cisco-ios schema but separate fixtures directory.
 */
export const CISCO_ASA_FIXTURE_PAIRS: TestFixturePair[] = [
  {
    name: 'comprehensive-asa',
    vendor: 'cisco-ios',  // ASA uses IOS schema
    indentedPath: 'test/fixtures/cisco-asa/comprehensive-asa.txt',
    flatPath: 'test/fixtures/cisco-asa/comprehensive-asa-flat.txt',
    expectedSections: 35,
    expectedCommands: 57,
    coverageCategories: ['interface', 'object', 'object-group', 'access-list', 'crypto-map', 'crypto-ipsec', 'crypto-ikev2'],
    // Has tunnel-group attributes and crypto map sub-commands that rely on indentation
    strictEquivalence: false,
  },
  {
    name: 'mpf-security',
    vendor: 'cisco-ios',  // ASA uses IOS schema
    indentedPath: 'test/fixtures/cisco-asa/mpf-security.txt',
    flatPath: 'test/fixtures/cisco-asa/mpf-security-flat.txt',
    expectedSections: 30,
    expectedCommands: 61,
    coverageCategories: ['object-group', 'class-map', 'policy-map'],
    // Has class/inspect commands inside policy-map that rely on indentation
    strictEquivalence: false,
  },
];

/**
 * Gets all registered fixture pairs across all vendors.
 */
export function getAllFixturePairs(): TestFixturePair[] {
  return [
    ...CISCO_IOS_FIXTURE_PAIRS,
    ...CISCO_NXOS_FIXTURE_PAIRS,
    ...CISCO_ASA_FIXTURE_PAIRS,
  ];
}

/**
 * Gets fixture pairs for a specific vendor.
 */
export function getFixturePairsByVendor(vendor: 'cisco-ios' | 'cisco-nxos'): TestFixturePair[] {
  return getAllFixturePairs().filter(pair => pair.vendor === vendor);
}
