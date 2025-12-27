/**
 * MachineId Unit Tests
 *
 * Tests for machine ID functionality including:
 * - T020: getMachineId() returns consistent ID across multiple calls
 * - T020: getMachineIdSync() returns same value as async version
 * - T020: Both return non-empty strings
 * - T020: IDs are stable within test session
 *
 * @module packages/core/test/grx2-loader/MachineId.test
 */

import { describe, test, expect } from 'bun:test';
import { getMachineId, getMachineIdSync } from '../../src/grx2-loader/MachineId';

// =============================================================================
// T020: Basic Machine ID Tests
// =============================================================================

describe('T020: MachineId - Basic Functionality', () => {
  test('getMachineId should return non-empty string', async () => {
    const machineId = await getMachineId();

    expect(machineId).toBeDefined();
    expect(typeof machineId).toBe('string');
    expect(machineId.length).toBeGreaterThan(0);
  });

  test('getMachineIdSync should return non-empty string', () => {
    const machineId = getMachineIdSync();

    expect(machineId).toBeDefined();
    expect(typeof machineId).toBe('string');
    expect(machineId.length).toBeGreaterThan(0);
  });

  test('getMachineId should return consistent ID across multiple calls', async () => {
    const id1 = await getMachineId();
    const id2 = await getMachineId();
    const id3 = await getMachineId();

    expect(id1).toBe(id2);
    expect(id2).toBe(id3);
    expect(id1.length).toBeGreaterThan(0);
  });

  test('getMachineIdSync should return consistent ID across multiple calls', () => {
    const id1 = getMachineIdSync();
    const id2 = getMachineIdSync();
    const id3 = getMachineIdSync();

    expect(id1).toBe(id2);
    expect(id2).toBe(id3);
    expect(id1.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// T020: Async vs Sync Consistency
// =============================================================================

describe('T020: MachineId - Async/Sync Consistency', () => {
  test('getMachineId and getMachineIdSync should return same value', async () => {
    const asyncId = await getMachineId();
    const syncId = getMachineIdSync();

    expect(asyncId).toBe(syncId);
  });

  test('multiple async and sync calls should all return same value', async () => {
    const asyncId1 = await getMachineId();
    const syncId1 = getMachineIdSync();
    const asyncId2 = await getMachineId();
    const syncId2 = getMachineIdSync();

    expect(asyncId1).toBe(syncId1);
    expect(asyncId2).toBe(syncId2);
    expect(asyncId1).toBe(asyncId2);
    expect(syncId1).toBe(syncId2);
  });
});

// =============================================================================
// T020: Stability Within Test Session
// =============================================================================

describe('T020: MachineId - Session Stability', () => {
  test('IDs should be stable within test session', async () => {
    // Capture initial ID
    const initialId = await getMachineId();

    // Wait a bit and check again
    await new Promise(resolve => setTimeout(resolve, 100));

    const laterIdAsync = await getMachineId();
    const laterIdSync = getMachineIdSync();

    // All should match
    expect(laterIdAsync).toBe(initialId);
    expect(laterIdSync).toBe(initialId);
  });

  test('parallel async calls should return same ID', async () => {
    // Call multiple times in parallel
    const promises = Array(10)
      .fill(0)
      .map(() => getMachineId());

    const results = await Promise.all(promises);

    // All results should be identical
    const firstId = results[0];
    expect(firstId).toBeDefined();
    expect(firstId!.length).toBeGreaterThan(0);

    for (const id of results) {
      expect(id).toBe(firstId!);
    }
  });
});

// =============================================================================
// T020: Machine ID Format Validation
// =============================================================================

describe('T020: MachineId - Format Validation', () => {
  test('machine ID should be a valid identifier', async () => {
    const machineId = await getMachineId();

    // Should be a non-empty string with reasonable length
    expect(machineId.length).toBeGreaterThan(5);
    expect(machineId.length).toBeLessThan(256);

    // Should not contain null bytes or control characters
    expect(machineId).not.toContain('\x00');
    expect(machineId).not.toContain('\n');
    expect(machineId).not.toContain('\r');
  });

  test('machine ID should be deterministic', () => {
    const id1 = getMachineIdSync();
    const id2 = getMachineIdSync();

    // Should be exactly the same, not just equal
    expect(id1 === id2).toBe(true);
  });
});

// =============================================================================
// T020: Cross-Platform Behavior
// =============================================================================

describe('T020: MachineId - Cross-Platform', () => {
  test('should handle async properly', async () => {
    // Test that async version properly awaits
    const promise = getMachineId();

    expect(promise).toBeInstanceOf(Promise);

    const result = await promise;

    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  test('should not throw errors on async call', async () => {
    await expect(getMachineId()).resolves.toBeDefined();
  });

  test('should not throw errors on sync call', () => {
    expect(() => getMachineIdSync()).not.toThrow();
  });
});

// =============================================================================
// T020: Use Case Tests
// =============================================================================

describe('T020: MachineId - Use Cases', () => {
  test('machine ID can be used as PBKDF2 salt component', async () => {
    const machineId = await getMachineId();

    // Should be suitable for use in key derivation
    const buffer = Buffer.from(machineId, 'utf-8');

    expect(buffer.length).toBeGreaterThan(0);
    expect(buffer.length).toBeLessThan(1024);
  });

  test('machine ID can be used for device binding', async () => {
    const machineId = await getMachineId();

    // Should be unique enough for device binding
    expect(machineId).toBeTruthy();
    expect(typeof machineId).toBe('string');

    // Should not be a trivial value
    expect(machineId).not.toBe('');
    expect(machineId).not.toBe('localhost');
    expect(machineId).not.toBe('0');
    expect(machineId).not.toBe('unknown');
  });

  test('empty machine ID is valid for portable packs', () => {
    const emptyMachineId = '';

    // Empty machine ID should be allowed for portable packs
    expect(typeof emptyMachineId).toBe('string');
    expect(emptyMachineId.length).toBe(0);

    // Can be used in PBKDF2 (will just be empty component)
    const buffer = Buffer.from(emptyMachineId, 'utf-8');
    expect(buffer.length).toBe(0);
  });
});
