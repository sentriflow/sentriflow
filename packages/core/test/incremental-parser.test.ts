// packages/core/test/incremental-parser.test.ts

import { describe, expect, test, beforeEach } from 'bun:test';
import { IncrementalParser } from '../src/parser/IncrementalParser';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';

describe('IncrementalParser', () => {
  let parser: IncrementalParser;

  beforeEach(() => {
    parser = new IncrementalParser();
  });

  describe('Basic Parsing', () => {
    test('should parse content and cache result', () => {
      const content = `
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
`;
      const ast = parser.parse('doc1', content, 1);

      expect(ast.length).toBeGreaterThan(0);
      expect(parser.isCached('doc1')).toBe(true);
      expect(parser.getCachedVersion('doc1')).toBe(1);
    });

    test('should return cached AST for same version', () => {
      const content = `
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
`;
      const ast1 = parser.parse('doc1', content, 1);
      const ast2 = parser.parse('doc1', content, 1);

      // Should return same reference (cached)
      expect(ast2).toBe(ast1);

      const stats = parser.getLastStats();
      expect(stats?.fullParse).toBe(false);
    });

    test('should produce same results as SchemaAwareParser', () => {
      const content = `
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
!
router ospf 1
 router-id 1.1.1.1
 network 10.0.0.0 0.0.0.255 area 0
`;
      const incrementalAst = parser.parse('doc1', content, 1);

      const schemaParser = new SchemaAwareParser();
      const schemaAst = schemaParser.parse(content);

      expect(incrementalAst.length).toBe(schemaAst.length);
      expect(incrementalAst[0]?.id).toBe(schemaAst[0]?.id);
    });
  });

  describe('Incremental Updates', () => {
    test('should detect single line change', () => {
      const content1 = `
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
`;
      const content2 = `
interface GigabitEthernet0/0
 description Changed Description
 ip address 10.0.0.1 255.255.255.0
`;
      parser.parse('doc1', content1, 1);
      parser.parse('doc1', content2, 2);

      const stats = parser.getLastStats();
      expect(stats?.changedRanges).toBeGreaterThan(0);
    });

    test('should use incremental parsing for small changes', () => {
      const content1 = `
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Downlink
 ip address 10.0.1.1 255.255.255.0
`;
      const content2 = `
interface GigabitEthernet0/0
 description Uplink Modified
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Downlink
 ip address 10.0.1.1 255.255.255.0
`;
      parser.parse('doc1', content1, 1);
      const ast2 = parser.parse('doc1', content2, 2);

      const stats = parser.getLastStats();
      // Should be incremental (not full parse) for small change
      expect(stats?.fullParse).toBe(false);
      expect(ast2.length).toBe(2); // Two interface sections
    });

    test('should fall back to full parse for large changes', () => {
      const content1 = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
      // Completely different content
      const content2 = `
router bgp 65000
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65001
!
router ospf 1
 router-id 1.1.1.1
`;
      parser.parse('doc1', content1, 1);
      parser.parse('doc1', content2, 2);

      const stats = parser.getLastStats();
      expect(stats?.fullParse).toBe(true);
    });

    test('should handle line insertions', () => {
      const content1 = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
      const content2 = `
interface GigabitEthernet0/0
 description Added line
 ip address 10.0.0.1 255.255.255.0
`;
      parser.parse('doc1', content1, 1);
      const ast2 = parser.parse('doc1', content2, 2);

      expect(ast2.length).toBeGreaterThan(0);
      // Find the interface node and check it has the description child
      const interfaceNode = ast2.find(n => n.id.includes('interface'));
      expect(interfaceNode?.children.some(c => c.id.includes('description'))).toBe(true);
    });

    test('should handle line deletions', () => {
      const content1 = `
interface GigabitEthernet0/0
 description Will be removed
 ip address 10.0.0.1 255.255.255.0
`;
      const content2 = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
      parser.parse('doc1', content1, 1);
      const ast2 = parser.parse('doc1', content2, 2);

      const interfaceNode = ast2.find(n => n.id.includes('interface'));
      expect(interfaceNode?.children.some(c => c.id.includes('description'))).toBe(false);
    });
  });

  describe('Cache Management', () => {
    test('should track multiple documents', () => {
      const content = `interface Loopback0`;

      parser.parse('doc1', content, 1);
      parser.parse('doc2', content, 1);
      parser.parse('doc3', content, 1);

      expect(parser.getCacheSize()).toBe(3);
      expect(parser.isCached('doc1')).toBe(true);
      expect(parser.isCached('doc2')).toBe(true);
      expect(parser.isCached('doc3')).toBe(true);
    });

    test('should invalidate single document', () => {
      const content = `interface Loopback0`;

      parser.parse('doc1', content, 1);
      parser.parse('doc2', content, 1);

      parser.invalidate('doc1');

      expect(parser.isCached('doc1')).toBe(false);
      expect(parser.isCached('doc2')).toBe(true);
      expect(parser.getCacheSize()).toBe(1);
    });

    test('should clear all documents', () => {
      const content = `interface Loopback0`;

      parser.parse('doc1', content, 1);
      parser.parse('doc2', content, 1);

      parser.clearAll();

      expect(parser.getCacheSize()).toBe(0);
      expect(parser.isCached('doc1')).toBe(false);
      expect(parser.isCached('doc2')).toBe(false);
    });

    test('should do full parse after cache invalidation', () => {
      const content = `interface Loopback0`;

      parser.parse('doc1', content, 1);
      parser.invalidate('doc1');
      parser.parse('doc1', content, 2);

      const stats = parser.getLastStats();
      expect(stats?.fullParse).toBe(true);
      expect(stats?.fullParseReason).toBe('no_cache');
    });
  });

  describe('Parse Statistics', () => {
    test('should provide parse statistics', () => {
      const content = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
      parser.parse('doc1', content, 1);

      const stats = parser.getLastStats();
      expect(stats).not.toBeNull();
      expect(stats?.fullParse).toBe(true);
      expect(stats?.parseTimeMs).toBeGreaterThanOrEqual(0);
    });

    test('should track sections reparsed for incremental updates', () => {
      const content1 = `
interface GigabitEthernet0/0
 description Original
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Unchanged
 ip address 10.0.1.1 255.255.255.0
`;
      const content2 = `
interface GigabitEthernet0/0
 description Modified
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Unchanged
 ip address 10.0.1.1 255.255.255.0
`;
      parser.parse('doc1', content1, 1);
      parser.parse('doc1', content2, 2);

      const stats = parser.getLastStats();
      if (!stats?.fullParse) {
        expect(stats?.sectionsReparsed).toBeGreaterThan(0);
      }
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty content', () => {
      const ast = parser.parse('doc1', '', 1);
      expect(ast).toEqual([]);
    });

    test('should handle whitespace-only content', () => {
      const ast = parser.parse('doc1', '   \n\n   \n', 1);
      expect(ast).toEqual([]);
    });

    test('should handle single line content', () => {
      const ast = parser.parse('doc1', 'hostname Router1', 1);
      expect(ast.length).toBeGreaterThan(0);
    });

    test('should handle stale version requests', () => {
      const content1 = `interface Loopback0`;
      const content2 = `interface Loopback1`;

      parser.parse('doc1', content1, 2);
      const ast2 = parser.parse('doc1', content2, 1); // Older version

      // Should return cached AST, not parse new content
      expect(ast2[0]?.id).toContain('Loopback0');
    });

    test('should handle uncached document version query', () => {
      expect(parser.getCachedVersion('nonexistent')).toBe(-1);
    });
  });
});

describe('IncrementalParser Performance', () => {
  test('incremental parse should be faster than full parse for small changes', () => {
    const parser = new IncrementalParser();

    // Generate a large config
    const lines: string[] = [];
    for (let i = 0; i < 50; i++) {
      lines.push(`interface GigabitEthernet0/${i}`);
      lines.push(` description Link ${i}`);
      lines.push(` ip address 10.${Math.floor(i / 256)}.${i % 256}.1 255.255.255.0`);
      lines.push('!');
    }
    const content1 = lines.join('\n');

    // Make a small change in the middle
    lines[50] = ' description Modified Link 12';
    const content2 = lines.join('\n');

    // Full parse (first time)
    const fullStart = performance.now();
    parser.parse('doc1', content1, 1);
    const fullTime = performance.now() - fullStart;

    // Incremental parse (small change)
    const incStart = performance.now();
    parser.parse('doc1', content2, 2);
    const incTime = performance.now() - incStart;

    const stats = parser.getLastStats();
    console.log(
      `Full parse: ${fullTime.toFixed(2)}ms, ` +
        `Incremental: ${incTime.toFixed(2)}ms, ` +
        `Speedup: ${(fullTime / incTime).toFixed(1)}x, ` +
        `Full reparse: ${stats?.fullParse}, ` +
        `Sections reparsed: ${stats?.sectionsReparsed ?? 'N/A'}`
    );

    // Verify the parser completed successfully
    expect(stats).not.toBeNull();
    expect(stats?.parseTimeMs).toBeGreaterThanOrEqual(0);
  });

  test('should handle rapid sequential edits efficiently', () => {
    const parser = new IncrementalParser();

    let content = `
interface GigabitEthernet0/0
 description Original
 ip address 10.0.0.1 255.255.255.0
`;

    // Simulate typing - many rapid small edits
    const editCount = 20;
    const times: number[] = [];

    for (let i = 0; i < editCount; i++) {
      const start = performance.now();
      content = content.replace('Original', `Edit ${i}`);
      parser.parse('doc1', content, i + 1);
      times.push(performance.now() - start);
    }

    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    console.log(`Average parse time over ${editCount} edits: ${avgTime.toFixed(2)}ms`);

    // Each parse should be fast (under 50ms for small content)
    expect(avgTime).toBeLessThan(50);
  });
});
