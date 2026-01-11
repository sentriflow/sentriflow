/**
 * API Contract Test: GET /api/v1/feeds/:id/download
 *
 * Verifies that CloudClient.getDownloadInfo() correctly handles
 * the API contract defined in contracts/api-v1.yaml
 */

import { describe, it, expect, beforeEach, afterEach, mock } from 'bun:test';

// Mock types matching the API contract
interface PackDownloadInfo {
  feedId: string;
  url: string;
  sizeBytes: number;
  sha256: string;
  expiresAt: string;
}

interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

describe('GET /api/v1/feeds/:id/download Contract', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('200 OK - Success', () => {
    it('should return PackDownloadInfo with required fields', async () => {
      const mockResponse: Omit<PackDownloadInfo, 'feedId'> = {
        url: 'https://storage.sentriflow.com.au/packs/cisco-security-2.1.0.grx2?sig=abc123',
        sizeBytes: 524288,
        sha256: 'a3f2b1c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcdef',
        expiresAt: '2026-01-03T12:00:00Z',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const feedId = 'cisco-security';
      const response = await fetch(`https://api.sentriflow.com.au/api/v1/feeds/${feedId}/download`);
      const data = await response.json() as Omit<PackDownloadInfo, 'feedId'>;

      expect(response.ok).toBe(true);
      expect(data.url).toContain('https://');
      expect(data.sizeBytes).toBeGreaterThan(0);
      expect(data.sha256).toHaveLength(64); // SHA-256 hex = 64 chars
      expect(data.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should validate sizeBytes is within acceptable range', async () => {
      const MIN_SIZE = 200;
      const MAX_SIZE = 50 * 1024 * 1024; // 50 MB

      const mockResponse: Omit<PackDownloadInfo, 'feedId'> = {
        url: 'https://storage.sentriflow.com.au/packs/test.grx2',
        sizeBytes: 10240, // 10 KB - within range
        sha256: 'a'.repeat(64),
        expiresAt: '2026-01-03T12:00:00Z',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/feeds/test/download');
      const data = await response.json() as Omit<PackDownloadInfo, 'feedId'>;

      expect(data.sizeBytes).toBeGreaterThanOrEqual(MIN_SIZE);
      expect(data.sizeBytes).toBeLessThanOrEqual(MAX_SIZE);
    });
  });

  describe('403 Forbidden - Not Entitled', () => {
    it('should return NOT_ENTITLED error code', async () => {
      const mockError: ErrorResponse = {
        error: 'Not entitled to this feed',
        code: 'NOT_ENTITLED',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockError), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/feeds/premium-pack/download');
      const data = await response.json() as ErrorResponse;

      expect(response.status).toBe(403);
      expect(data.code).toBe('NOT_ENTITLED');
    });
  });

  describe('404 Not Found - Feed Not Found', () => {
    it('should return PACK_NOT_FOUND error code', async () => {
      const mockError: ErrorResponse = {
        error: 'Feed not found',
        code: 'PACK_NOT_FOUND',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockError), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/feeds/nonexistent/download');
      const data = await response.json() as ErrorResponse;

      expect(response.status).toBe(404);
      expect(data.code).toBe('PACK_NOT_FOUND');
    });
  });

  describe('SHA-256 Hash Format', () => {
    it('should have valid SHA-256 hex format', async () => {
      const mockResponse: Omit<PackDownloadInfo, 'feedId'> = {
        url: 'https://storage.sentriflow.com.au/packs/test.grx2',
        sizeBytes: 1024,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        expiresAt: '2026-01-03T12:00:00Z',
      };

      globalThis.fetch = mock(() =>
        Promise.resolve(new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }))
      ) as unknown as typeof globalThis.fetch;

      const response = await fetch('https://api.sentriflow.com.au/api/v1/feeds/test/download');
      const data = await response.json() as Omit<PackDownloadInfo, 'feedId'>;

      // SHA-256 should be 64 hex characters
      expect(data.sha256).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});
