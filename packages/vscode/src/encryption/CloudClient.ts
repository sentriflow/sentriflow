/**
 * Cloud Client for SentriFlow VS Code Extension
 *
 * Handles communication with the SentriFlow cloud API for:
 * - Fetching entitlements
 * - Checking for pack updates
 * - Downloading pack files
 *
 * @module encryption/CloudClient
 */

import * as vscode from 'vscode';
import { createWriteStream } from 'node:fs';
import { mkdir, unlink, stat, readdir, readFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { homedir } from 'node:os';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import type {
  EntitlementsResponse,
  FeedInfo,
  PackDownloadInfo,
  UpdateCheckResult,
  CachedEntitlements,
  CloudConnectionStatus,
  CacheManifest,
  CacheManifestEntry,
} from './types';
import { EncryptedPackError, CACHE_DIRECTORY } from './types';

/**
 * Cache manifest filename
 */
const CACHE_MANIFEST_FILE = 'manifest.json';

/**
 * Current cache manifest version
 */
const CACHE_MANIFEST_VERSION = 1;

// =============================================================================
// Constants
// =============================================================================

/**
 * Maximum allowed pack file size (50 MB)
 * SECURITY: Prevents resource exhaustion from malicious/corrupted size claims
 */
const MAX_PACK_SIZE_BYTES = 50 * 1024 * 1024;

/**
 * Minimum expected pack file size (must contain at least header + minimal payload)
 * SECURITY: Rejects suspiciously small files that can't be valid packs
 */
const MIN_PACK_SIZE_BYTES = 200;

/**
 * Cache file TTL in days - files older than this are considered stale
 */
const CACHE_FILE_TTL_DAYS = 30;

// =============================================================================
// Types
// =============================================================================

interface CloudClientOptions {
  /** API URL (from license JWT) */
  apiUrl: string;

  /** License JWT for authorization */
  licenseKey: string;

  /** Request timeout in ms */
  timeout?: number;
}

// =============================================================================
// Cloud Client Class
// =============================================================================

/**
 * Cloud Client
 *
 * Handles all cloud API interactions.
 */
export class CloudClient {
  private readonly apiUrl: string;
  private readonly licenseKey: string;
  private readonly timeout: number;
  private readonly cacheDir: string;

  constructor(options: CloudClientOptions) {
    // SECURITY: Enforce HTTPS to prevent credential exposure over plaintext
    const apiUrl = options.apiUrl.replace(/\/$/, ''); // Remove trailing slash
    try {
      const url = new URL(apiUrl);
      if (url.protocol !== 'https:') {
        throw new EncryptedPackError(
          'API URL must use HTTPS for secure communication',
          'API_ERROR'
        );
      }
    } catch (error) {
      if (error instanceof EncryptedPackError) {
        throw error;
      }
      throw new EncryptedPackError(
        `Invalid API URL: ${apiUrl}`,
        'API_ERROR',
        error
      );
    }

    this.apiUrl = apiUrl;
    this.licenseKey = options.licenseKey;
    this.timeout = options.timeout ?? 30000;
    this.cacheDir = this.resolvePath(CACHE_DIRECTORY);
  }

  /**
   * Get the API URL (for logging/debugging)
   */
  getApiUrl(): string {
    return this.apiUrl;
  }

  /**
   * Resolve path with ~ expansion
   */
  private resolvePath(path: string): string {
    if (path.startsWith('~/')) {
      return join(homedir(), path.slice(2));
    }
    return path;
  }

  /**
   * Load cache manifest from disk
   *
   * @returns Manifest or null if not found/invalid
   */
  async loadCacheManifest(): Promise<CacheManifest | null> {
    const manifestPath = join(this.cacheDir, CACHE_MANIFEST_FILE);

    if (!existsSync(manifestPath)) {
      return null;
    }

    try {
      const content = await readFile(manifestPath, 'utf-8');
      const manifest = JSON.parse(content) as CacheManifest;

      // Validate manifest version
      if (manifest.version !== CACHE_MANIFEST_VERSION) {
        // Incompatible version, return null to force re-download
        return null;
      }

      return manifest;
    } catch {
      // Invalid manifest, return null
      return null;
    }
  }

  /**
   * Save cache manifest to disk
   *
   * @param manifest - Manifest to save
   */
  async saveCacheManifest(manifest: CacheManifest): Promise<void> {
    // Ensure cache directory exists with restrictive permissions (owner only)
    if (!existsSync(this.cacheDir)) {
      await mkdir(this.cacheDir, { recursive: true, mode: 0o700 });
    }

    const manifestPath = join(this.cacheDir, CACHE_MANIFEST_FILE);
    const { writeFile } = await import('node:fs/promises');
    // Write with restrictive permissions (owner read/write only)
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  }

  /**
   * Get manifest entry for a feed
   *
   * @param feedId - Feed ID to look up
   * @returns Entry or null if not found
   */
  async getCacheEntry(feedId: string): Promise<CacheManifestEntry | null> {
    const manifest = await this.loadCacheManifest();
    return manifest?.entries[feedId] ?? null;
  }

  /**
   * Check if a pack is already cached with matching hash
   *
   * @param feedId - Feed ID
   * @param serverHash - Expected hash from server
   * @returns True if cached and hash matches
   */
  async isCachedWithHash(feedId: string, serverHash: string): Promise<boolean> {
    const entry = await this.getCacheEntry(feedId);
    if (!entry || entry.hash !== serverHash) {
      return false;
    }

    // Verify file still exists
    const filePath = join(this.cacheDir, entry.fileName);
    return existsSync(filePath);
  }

  /**
   * Update manifest with a downloaded pack
   *
   * @param feedId - Feed ID
   * @param version - Pack version
   * @param hash - SHA-256 hash
   * @param fileName - Cached file name
   */
  async updateCacheEntry(
    feedId: string,
    version: string,
    hash: string,
    fileName: string
  ): Promise<void> {
    let manifest = await this.loadCacheManifest();

    if (!manifest) {
      manifest = {
        version: CACHE_MANIFEST_VERSION,
        entries: {},
        updatedAt: new Date().toISOString(),
      };
    }

    // Remove old file if different
    const existingEntry = manifest.entries[feedId];
    if (existingEntry && existingEntry.fileName !== fileName) {
      const oldPath = join(this.cacheDir, existingEntry.fileName);
      try {
        if (existsSync(oldPath)) {
          await unlink(oldPath);
        }
      } catch {
        // Ignore cleanup errors
      }
    }

    manifest.entries[feedId] = {
      feedId,
      version,
      hash,
      fileName,
      downloadedAt: new Date().toISOString(),
    };
    manifest.updatedAt = new Date().toISOString();

    await this.saveCacheManifest(manifest);
  }

  /**
   * Get path to cached pack file
   *
   * @param feedId - Feed ID
   * @returns File path or null if not cached
   */
  async getCachedPackPath(feedId: string): Promise<string | null> {
    const entry = await this.getCacheEntry(feedId);
    if (!entry) {
      return null;
    }

    const filePath = join(this.cacheDir, entry.fileName);
    return existsSync(filePath) ? filePath : null;
  }

  /**
   * Make an authenticated API request
   */
  private async fetch(endpoint: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.apiUrl}${endpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.licenseKey}`,
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      return response;
    } catch (error) {
      if ((error as Error).name === 'AbortError') {
        throw new EncryptedPackError(
          'Request timed out',
          'NETWORK_ERROR',
          error
        );
      }
      throw new EncryptedPackError(
        `Network error: ${(error as Error).message}`,
        'NETWORK_ERROR',
        error
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Fetch entitlements from cloud API with offline fallback
   *
   * @param cachedEntitlements - Optional cached entitlements for offline fallback
   * @returns Object with entitlements, connection status, and whether cache was used
   */
  async getEntitlementsWithFallback(
    cachedEntitlements?: CachedEntitlements | null
  ): Promise<{
    entitlements: EntitlementsResponse | null;
    status: CloudConnectionStatus;
    fromCache: boolean;
  }> {
    try {
      const entitlements = await this.getEntitlements();
      return {
        entitlements,
        status: 'online',
        fromCache: false,
      };
    } catch (error) {
      // Network error - try cached entitlements
      if (
        error instanceof EncryptedPackError &&
        error.code === 'NETWORK_ERROR' &&
        cachedEntitlements
      ) {
        return {
          entitlements: cachedEntitlements.entitlements,
          status: 'offline',
          fromCache: true,
        };
      }

      // Other errors (license invalid, expired) - don't use cache
      throw error;
    }
  }

  /**
   * Fetch entitlements from cloud API
   *
   * Calls /api/v1/feeds/versions and maps response to EntitlementsResponse format.
   *
   * @returns Entitlements response with feed list
   */
  async getEntitlements(): Promise<EntitlementsResponse> {
    try {
      // Call the feeds/versions endpoint (not /entitlements which doesn't exist)
      const response = await this.fetch('/api/v1/feeds/versions');

      if (!response.ok) {
        if (response.status === 401) {
          throw new EncryptedPackError(
            'License key not authorized',
            'LICENSE_INVALID'
          );
        }
        if (response.status === 403) {
          throw new EncryptedPackError(
            'License expired or revoked',
            'LICENSE_EXPIRED'
          );
        }
        throw new EncryptedPackError(
          `API error: ${response.status} ${response.statusText}`,
          'API_ERROR'
        );
      }

      // API returns: { feeds: [{ feedId, version, hash, keyType }], serverTime }
      const data = await response.json() as {
        feeds: { feedId: string; version: string; hash: string; keyType: string }[];
        serverTime?: string;
      };

      // Map to EntitlementsResponse format
      // Note: customerId, tier, expiresAt are not in this endpoint response,
      // but they're not needed for update checking (already available from JWT/activation)
      return {
        customerId: '', // Not needed for update check
        tier: 'community', // Safe default - actual tier is in JWT, not used here
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // Far future
        feeds: data.feeds.map((feed) => ({
          id: feed.feedId,
          name: feed.feedId, // Use feedId as name
          version: feed.version,
          sizeBytes: 0, // Not provided by this endpoint
          updatedAt: data.serverTime ?? new Date().toISOString(),
          hash: feed.hash, // Include hash for cache comparison
        })),
      };
    } catch (error) {
      if (error instanceof EncryptedPackError) {
        throw error;
      }
      throw new EncryptedPackError(
        `Failed to fetch entitlements: ${(error as Error).message}`,
        'NETWORK_ERROR',
        error
      );
    }
  }

  /**
   * Get download info for a specific feed
   *
   * @param feedId - Feed ID to download
   * @returns Download info with signed URL
   */
  async getDownloadInfo(feedId: string): Promise<PackDownloadInfo> {
    try {
      const response = await this.fetch(`/api/v1/feeds/${feedId}/download`);

      if (!response.ok) {
        if (response.status === 403) {
          throw new EncryptedPackError(
            `Not entitled to feed: ${feedId}`,
            'NOT_ENTITLED'
          );
        }
        if (response.status === 404) {
          throw new EncryptedPackError(
            `Feed not found: ${feedId}`,
            'PACK_NOT_FOUND'
          );
        }
        throw new EncryptedPackError(
          `API error: ${response.status} ${response.statusText}`,
          'API_ERROR'
        );
      }

      const data = (await response.json()) as {
        signedUrl: string;
        expiresAt: string;
        sizeBytes: number;
        sha256?: string;
        hash?: string;
      };
      return {
        feedId,
        url: data.signedUrl,
        expiresAt: data.expiresAt,
        sizeBytes: data.sizeBytes,
        sha256: data.sha256 ?? data.hash ?? '',
      };
    } catch (error) {
      if (error instanceof EncryptedPackError) {
        throw error;
      }
      throw new EncryptedPackError(
        `Failed to get download info: ${(error as Error).message}`,
        'NETWORK_ERROR',
        error
      );
    }
  }

  /**
   * Download a pack file to cache
   *
   * SECURITY: Pre-validates size before downloading to prevent:
   * - Resource exhaustion from oversized downloads
   * - Invalid packs from undersized downloads
   * - Size mismatch attacks (claimed vs actual)
   *
   * @param downloadInfo - Download info from getDownloadInfo
   * @returns Path to downloaded file
   */
  async downloadPack(downloadInfo: PackDownloadInfo): Promise<string> {
    // SECURITY: Pre-validate claimed size before downloading
    if (downloadInfo.sizeBytes > MAX_PACK_SIZE_BYTES) {
      throw new EncryptedPackError(
        `Pack size ${downloadInfo.sizeBytes} bytes exceeds maximum allowed ${MAX_PACK_SIZE_BYTES} bytes`,
        'PACK_CORRUPTED'
      );
    }

    if (downloadInfo.sizeBytes < MIN_PACK_SIZE_BYTES) {
      throw new EncryptedPackError(
        `Pack size ${downloadInfo.sizeBytes} bytes is below minimum required ${MIN_PACK_SIZE_BYTES} bytes`,
        'PACK_CORRUPTED'
      );
    }

    // Ensure cache directory exists with restrictive permissions (owner only)
    if (!existsSync(this.cacheDir)) {
      await mkdir(this.cacheDir, { recursive: true, mode: 0o700 });
    }

    // SECURITY: Use random filename instead of feedId to prevent path traversal
    // Pack files are self-describing (contain metadata inside), so we don't need
    // predictable names. Random names also prevent cache probing attacks.
    const randomId = randomBytes(16).toString('hex');
    const fileName = `${randomId}.grx2`;
    const tempFileName = `${randomId}.grx2.tmp`;
    const filePath = join(this.cacheDir, fileName);
    const tempFilePath = join(this.cacheDir, tempFileName);

    try {
      // Download to temp file first
      const response = await fetch(downloadInfo.url);

      if (!response.ok) {
        throw new EncryptedPackError(
          `Download failed: ${response.status} ${response.statusText}`,
          'NETWORK_ERROR'
        );
      }

      // SECURITY: Validate Content-Length header matches expected size
      const contentLength = response.headers.get('content-length');
      if (contentLength) {
        const actualSize = parseInt(contentLength, 10);
        if (actualSize !== downloadInfo.sizeBytes) {
          throw new EncryptedPackError(
            `Content-Length mismatch: expected ${downloadInfo.sizeBytes}, server reports ${actualSize}`,
            'PACK_CORRUPTED'
          );
        }
        // Also validate against max size (defense in depth)
        if (actualSize > MAX_PACK_SIZE_BYTES) {
          throw new EncryptedPackError(
            `Server Content-Length ${actualSize} exceeds maximum allowed ${MAX_PACK_SIZE_BYTES} bytes`,
            'PACK_CORRUPTED'
          );
        }
      }

      // Validate response body exists
      if (!response.body) {
        throw new EncryptedPackError(
          'Download failed: Server returned empty response body',
          'NETWORK_ERROR'
        );
      }

      // Stream to file
      const fileStream = createWriteStream(tempFilePath);
      await pipeline(
        Readable.fromWeb(response.body as any),
        fileStream
      );

      // Verify file size
      const fileStats = await stat(tempFilePath);
      if (fileStats.size !== downloadInfo.sizeBytes) {
        await unlink(tempFilePath);
        throw new EncryptedPackError(
          `Download size mismatch: expected ${downloadInfo.sizeBytes}, got ${fileStats.size}`,
          'PACK_CORRUPTED'
        );
      }

      // Verify SHA-256 hash (defense-in-depth)
      const fileBuffer = await readFile(tempFilePath);
      const computedHash = createHash('sha256').update(fileBuffer).digest('hex');
      if (computedHash !== downloadInfo.sha256) {
        await unlink(tempFilePath);
        throw new EncryptedPackError(
          `SHA-256 hash mismatch: expected ${downloadInfo.sha256}, got ${computedHash}`,
          'PACK_CORRUPTED'
        );
      }

      // Move temp file to final location (atomic on same filesystem)
      const { rename } = await import('node:fs/promises');
      await rename(tempFilePath, filePath);

      // Update cache manifest with this download
      // We pass version as empty since downloadInfo doesn't have version,
      // but the hash is the important part for cache validation
      await this.updateCacheEntry(
        downloadInfo.feedId,
        '', // Version is tracked separately by checkForUpdates
        computedHash,
        fileName
      );

      return filePath;
    } catch (error) {
      // Clean up temp file if exists
      try {
        if (existsSync(tempFilePath)) {
          await unlink(tempFilePath);
        }
      } catch {
        // Ignore cleanup errors
      }

      if (error instanceof EncryptedPackError) {
        throw error;
      }
      throw new EncryptedPackError(
        `Download failed: ${(error as Error).message}`,
        'NETWORK_ERROR',
        error
      );
    }
  }

  /**
   * Check for available updates
   *
   * Now includes cache hash checking: if a pack is already cached with
   * matching hash, it's excluded from updates (no re-download needed).
   *
   * @param localPacks - Map of feedId to local version
   * @returns Update check result
   */
  async checkForUpdates(localPacks: Map<string, string>): Promise<UpdateCheckResult> {
    try {
      const entitlements = await this.getEntitlements();

      const updatesAvailable: UpdateCheckResult['updatesAvailable'] = [];
      let skippedByCacheHash = 0;

      for (const feed of entitlements.feeds) {
        const localVersion = localPacks.get(feed.id);
        const serverHash = feed.hash;

        // Check if pack is already cached with matching hash
        // This prevents re-downloading packs that haven't changed
        if (serverHash && await this.isCachedWithHash(feed.id, serverHash)) {
          skippedByCacheHash++;
          continue;
        }

        // New pack (not local)
        if (!localVersion) {
          updatesAvailable.push({
            feedId: feed.id,
            currentVersion: 'none',
            newVersion: feed.version,
            serverHash,
          });
          continue;
        }

        // Version comparison (simple semver-like)
        if (this.isNewerVersion(feed.version, localVersion)) {
          updatesAvailable.push({
            feedId: feed.id,
            currentVersion: localVersion,
            newVersion: feed.version,
            serverHash,
          });
        }
      }

      return {
        hasUpdates: updatesAvailable.length > 0,
        updatesAvailable,
        skippedByCacheHash: skippedByCacheHash > 0 ? skippedByCacheHash : undefined,
        checkedAt: new Date().toISOString(),
      };
    } catch (error) {
      if (error instanceof EncryptedPackError) {
        throw error;
      }
      throw new EncryptedPackError(
        `Update check failed: ${(error as Error).message}`,
        'NETWORK_ERROR',
        error
      );
    }
  }

  /**
   * Download all available updates
   *
   * Checks cache before downloading - if a pack is already cached with
   * matching hash, returns the cached path instead of re-downloading.
   *
   * @param updates - Updates to download
   * @param progress - Progress callback
   * @returns Array of file paths (downloaded or cached)
   */
  async downloadUpdates(
    updates: UpdateCheckResult['updatesAvailable'],
    progress?: (current: number, total: number, feedId: string) => void
  ): Promise<string[]> {
    const resultPaths: string[] = [];
    const total = updates.length;

    for (let i = 0; i < updates.length; i++) {
      const update = updates[i]!;
      progress?.(i + 1, total, update.feedId);

      try {
        // Double-check cache before downloading (defense in depth)
        if (update.serverHash) {
          const cachedPath = await this.getCachedPackPath(update.feedId);
          if (cachedPath) {
            const entry = await this.getCacheEntry(update.feedId);
            if (entry?.hash === update.serverHash) {
              // Already cached with matching hash, skip download
              resultPaths.push(cachedPath);
              continue;
            }
          }
        }

        const downloadInfo = await this.getDownloadInfo(update.feedId);
        const filePath = await this.downloadPack(downloadInfo);
        resultPaths.push(filePath);
      } catch (error) {
        // Log but continue with other downloads
        console.error(`Failed to download ${update.feedId}:`, error);
      }
    }

    return resultPaths;
  }

  /**
   * Get list of cached pack files
   *
   * @returns Array of cached file paths
   */
  async getCachedPacks(): Promise<string[]> {
    if (!existsSync(this.cacheDir)) {
      return [];
    }

    const entries = await readdir(this.cacheDir);
    return entries
      .filter((entry) => entry.endsWith('.grx2'))
      .map((entry) => join(this.cacheDir, entry));
  }

  /**
   * Clear cached packs
   */
  async clearCache(): Promise<void> {
    if (!existsSync(this.cacheDir)) {
      return;
    }

    const files = await this.getCachedPacks();
    for (const file of files) {
      try {
        await unlink(file);
      } catch {
        // Ignore deletion errors
      }
    }
  }

  /**
   * Clean up stale cache files older than CACHE_FILE_TTL_DAYS
   *
   * Should be called periodically (e.g., on extension activation) to
   * prevent unbounded cache growth.
   *
   * @returns Number of files deleted
   */
  async cleanupStaleCache(): Promise<number> {
    if (!existsSync(this.cacheDir)) {
      return 0;
    }

    const files = await this.getCachedPacks();
    const now = Date.now();
    const ttlMs = CACHE_FILE_TTL_DAYS * 24 * 60 * 60 * 1000;
    let deletedCount = 0;

    for (const file of files) {
      try {
        const fileStats = await stat(file);
        const age = now - fileStats.mtimeMs;

        if (age > ttlMs) {
          await unlink(file);
          deletedCount++;
        }
      } catch {
        // Ignore stat/deletion errors
      }
    }

    return deletedCount;
  }

  /**
   * Compare two version strings
   *
   * @returns true if newVersion is newer than oldVersion
   */
  private isNewerVersion(newVersion: string, oldVersion: string): boolean {
    const parseVersion = (v: string): number[] => {
      return v
        .replace(/^v/, '')
        .split('.')
        .map((part) => parseInt(part, 10) || 0);
    };

    const newParts = parseVersion(newVersion);
    const oldParts = parseVersion(oldVersion);

    const maxLength = Math.max(newParts.length, oldParts.length);

    for (let i = 0; i < maxLength; i++) {
      const newPart = newParts[i] ?? 0;
      const oldPart = oldParts[i] ?? 0;

      if (newPart > oldPart) {
        return true;
      }
      if (newPart < oldPart) {
        return false;
      }
    }

    return false;
  }
}

// =============================================================================
// Update Check with Progress
// =============================================================================

/**
 * Options for update check with progress
 */
export interface UpdateCheckOptions {
  /** Cloud client instance */
  cloudClient: CloudClient;

  /** Local pack versions */
  localPacks: Map<string, string>;

  /** Optional cached entitlements for offline fallback */
  cachedEntitlements?: CachedEntitlements | null;

  /** Optional logger for debug messages */
  logger?: (message: string) => void;

  /** Callback when entitlements are fetched (for caching) */
  onEntitlementsFetched?: (entitlements: EntitlementsResponse) => void;

  /** Callback when connection status changes */
  onStatusChange?: (status: CloudConnectionStatus) => void;
}

/**
 * Result of update check with status
 */
export interface UpdateCheckWithStatusResult {
  /** Update check result, or null if failed */
  result: UpdateCheckResult | null;

  /** Connection status */
  status: CloudConnectionStatus;

  /** Whether cached entitlements were used */
  fromCache: boolean;
}

/**
 * Run update check with VS Code progress UI
 *
 * @param cloudClient - Cloud client instance
 * @param localPacks - Local pack versions
 * @param logger - Optional logger for debug messages (errors are logged silently)
 * @returns Update check result, or null if check failed
 */
export async function checkForUpdatesWithProgress(
  cloudClient: CloudClient,
  localPacks: Map<string, string>,
  logger?: (message: string) => void
): Promise<UpdateCheckResult | null> {
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'SentriFlow: Checking for pack updates...',
      cancellable: false,
    },
    async () => {
      try {
        return await cloudClient.checkForUpdates(localPacks);
      } catch (error) {
        // Re-throw license errors so they can be handled by callers
        // These indicate the license has been revoked or expired on the server
        if (error instanceof EncryptedPackError) {
          if (error.code === 'LICENSE_EXPIRED' || error.code === 'LICENSE_INVALID') {
            throw error;
          }
        }

        // Log other errors silently - don't bother users with connection issues
        // Extension will continue using existing/cached packs
        const errorMessage = (error as Error).message;
        logger?.(
          `[EncryptedPacks] Update check failed for ${cloudClient.getApiUrl()}: ${errorMessage}`
        );
        return null;
      }
    }
  );
}

/**
 * Run update check with offline fallback and status tracking
 *
 * @param options - Update check options including cached entitlements
 * @returns Update result with connection status
 */
export async function checkForUpdatesWithFallback(
  options: UpdateCheckOptions
): Promise<UpdateCheckWithStatusResult> {
  const { cloudClient, localPacks, cachedEntitlements, logger, onEntitlementsFetched, onStatusChange } = options;

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'SentriFlow: Checking for pack updates...',
      cancellable: false,
    },
    async () => {
      try {
        // Try to fetch entitlements with fallback
        const entitlementsResult = await cloudClient.getEntitlementsWithFallback(cachedEntitlements);

        // Notify status change
        onStatusChange?.(entitlementsResult.status);

        if (!entitlementsResult.entitlements) {
          return {
            result: null,
            status: entitlementsResult.status,
            fromCache: false,
          };
        }

        // Cache entitlements if fetched fresh
        if (!entitlementsResult.fromCache) {
          onEntitlementsFetched?.(entitlementsResult.entitlements);
        }

        // Build update result from entitlements with cache hash checking
        const updatesAvailable: UpdateCheckResult['updatesAvailable'] = [];
        let skippedByCacheHash = 0;

        for (const feed of entitlementsResult.entitlements.feeds) {
          const localVersion = localPacks.get(feed.id);
          const serverHash = feed.hash;

          // Check if pack is already cached with matching hash
          if (serverHash && await cloudClient.isCachedWithHash(feed.id, serverHash)) {
            skippedByCacheHash++;
            continue;
          }

          if (!localVersion) {
            // New pack not installed locally
            updatesAvailable.push({
              feedId: feed.id,
              currentVersion: 'none',
              newVersion: feed.version,
              serverHash,
            });
          } else if (feed.version !== localVersion) {
            // Version differs
            updatesAvailable.push({
              feedId: feed.id,
              currentVersion: localVersion,
              newVersion: feed.version,
              serverHash,
            });
          }
        }

        const result: UpdateCheckResult = {
          hasUpdates: updatesAvailable.length > 0,
          updatesAvailable,
          skippedByCacheHash: skippedByCacheHash > 0 ? skippedByCacheHash : undefined,
          checkedAt: new Date().toISOString(),
        };

        return {
          result,
          status: entitlementsResult.status,
          fromCache: entitlementsResult.fromCache,
        };
      } catch (error) {
        // Re-throw license errors so they can be handled by callers
        // These indicate the license has been revoked or expired on the server
        if (error instanceof EncryptedPackError) {
          if (error.code === 'LICENSE_EXPIRED' || error.code === 'LICENSE_INVALID') {
            throw error;
          }
        }

        const errorMessage = (error as Error).message;
        logger?.(
          `[EncryptedPacks] Update check failed for ${cloudClient.getApiUrl()}: ${errorMessage}`
        );

        onStatusChange?.('offline');

        return {
          result: null,
          status: 'offline',
          fromCache: false,
        };
      }
    }
  );
}

/**
 * Download updates with VS Code progress UI
 *
 * @param cloudClient - Cloud client instance
 * @param updates - Updates to download
 * @returns Downloaded file paths
 */
export async function downloadUpdatesWithProgress(
  cloudClient: CloudClient,
  updates: UpdateCheckResult['updatesAvailable']
): Promise<string[]> {
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'SentriFlow: Downloading pack updates...',
      cancellable: true,
    },
    async (progress, token) => {
      const downloaded: string[] = [];

      for (let i = 0; i < updates.length; i++) {
        if (token.isCancellationRequested) {
          break;
        }

        const update = updates[i]!;
        progress.report({
          increment: (100 / updates.length),
          message: `${update.feedId} (${i + 1}/${updates.length})`,
        });

        try {
          const downloadInfo = await cloudClient.getDownloadInfo(update.feedId);
          const filePath = await cloudClient.downloadPack(downloadInfo);
          downloaded.push(filePath);
        } catch (error) {
          vscode.window.showWarningMessage(
            `Failed to download ${update.feedId}: ${(error as Error).message}`
          );
        }
      }

      return downloaded;
    }
  );
}
