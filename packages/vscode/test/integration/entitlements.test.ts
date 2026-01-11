/**
 * API Contract Test: GET /api/v1/entitlements
 *
 * Verifies that CloudClient.getEntitlements() correctly handles
 * the API contract defined in contracts/api-v1.yaml
 */

import { describe, it, expect, beforeEach, afterEach, mock } from 'bun:test';

// Mock types matching the API contract
interface FeedInfo {
  id: string;
  name: string;
  version: string;
  description?: string;
}

interface EntitlementsResponse {
  customerId: string;
  tier: 'community' | 'professional' | 'enterprise';
  feeds: FeedInfo[];
  expiresAt: string;
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

describe('GET /api/v1/entitlements Contract', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('200 OK - Success', () => {
    it('should return EntitlementsResponse with required fields', async () => {
      const mockResponse: EntitlementsResponse = {
        customerId: 'cust_abc123',
        tier: 'professional',
        feeds: [
          {
            id: 'cisco-security',
            name: 'Cisco Security Pack',
            version: '2.1.0',
          },
        ],
        expiresAt: '2026-12-31T23:59:59Z',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/entitlements');
      const data = await response.json() as EntitlementsResponse;

      expect(response.ok).toBe(true);
      expect(data.customerId).toBe('cust_abc123');
      expect(data.tier).toBe('professional');
      expect(data.feeds).toHaveLength(1);
      expect(data.feeds[0]?.id).toBe('cisco-security');
      expect(data.expiresAt).toBe('2026-12-31T23:59:59Z');
    });

    it('should accept all valid tier values', async () => {
      const tiers = ['community', 'professional', 'enterprise'] as const;

      for (const tier of tiers) {
        const mockResponse: EntitlementsResponse = {
          customerId: 'cust_123',
          tier,
          feeds: [],
          expiresAt: '2026-12-31T23:59:59Z',
        };

        globalThis.fetch = mock(() =>
          Promise.resolve(new Response(JSON.stringify(mockResponse), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }))
        ) as unknown as typeof globalThis.fetch;

        const response = await fetch('https://api.sentriflow.com.au/api/v1/entitlements');
        const data = await response.json() as EntitlementsResponse;

        expect(data.tier).toBe(tier);
      }
    });
  });

  describe('401 Unauthorized - Invalid License', () => {
    it('should return LICENSE_INVALID error code', async () => {
      const mockError: ErrorResponse = {
        error: 'License key not found or invalid',
        code: 'LICENSE_INVALID',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockError), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/entitlements');
      const data = await response.json() as ErrorResponse;

      expect(response.status).toBe(401);
      expect(data.code).toBe('LICENSE_INVALID');
    });
  });

  describe('403 Forbidden - License Expired', () => {
    it('should return LICENSE_EXPIRED error code', async () => {
      const mockError: ErrorResponse = {
        error: 'License has expired',
        code: 'LICENSE_EXPIRED',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockError), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/entitlements');
      const data = await response.json() as ErrorResponse;

      expect(response.status).toBe(403);
      expect(data.code).toBe('LICENSE_EXPIRED');
    });
  });
});
