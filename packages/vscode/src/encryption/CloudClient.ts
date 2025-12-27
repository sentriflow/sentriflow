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
import { createHash } from 'node:crypto';
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
} from './types';
import { EncryptedPackError, CACHE_DIRECTORY } from './types';

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
    this.apiUrl = options.apiUrl.replace(/\/$/, ''); // Remove trailing slash
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
   * Fetch entitlements from cloud API
   *
   * @returns Entitlements response with feed list
   */
  async getEntitlements(): Promise<EntitlementsResponse> {
    try {
      const response = await this.fetch('/api/v1/entitlements');

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

      const data = await response.json();
      return data as EntitlementsResponse;
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

      const data = (await response.json()) as Omit<PackDownloadInfo, 'feedId'>;
      return {
        feedId,
        ...data,
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

    // Ensure cache directory exists
    if (!existsSync(this.cacheDir)) {
      await mkdir(this.cacheDir, { recursive: true });
    }

    const fileName = `${downloadInfo.feedId}.grx2`;
    const tempFileName = `${downloadInfo.feedId}.grx2.tmp`;
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
   * @param localPacks - Map of feedId to local version
   * @returns Update check result
   */
  async checkForUpdates(localPacks: Map<string, string>): Promise<UpdateCheckResult> {
    try {
      const entitlements = await this.getEntitlements();

      const updatesAvailable: UpdateCheckResult['updatesAvailable'] = [];

      for (const feed of entitlements.feeds) {
        const localVersion = localPacks.get(feed.id);

        // New pack (not local)
        if (!localVersion) {
          updatesAvailable.push({
            feedId: feed.id,
            currentVersion: 'none',
            newVersion: feed.version,
          });
          continue;
        }

        // Version comparison (simple semver-like)
        if (this.isNewerVersion(feed.version, localVersion)) {
          updatesAvailable.push({
            feedId: feed.id,
            currentVersion: localVersion,
            newVersion: feed.version,
          });
        }
      }

      return {
        hasUpdates: updatesAvailable.length > 0,
        updatesAvailable,
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
   * @param updates - Updates to download
   * @param progress - Progress callback
   * @returns Array of downloaded file paths
   */
  async downloadUpdates(
    updates: UpdateCheckResult['updatesAvailable'],
    progress?: (current: number, total: number, feedId: string) => void
  ): Promise<string[]> {
    const downloadedPaths: string[] = [];
    const total = updates.length;

    for (let i = 0; i < updates.length; i++) {
      const update = updates[i]!;
      progress?.(i + 1, total, update.feedId);

      try {
        const downloadInfo = await this.getDownloadInfo(update.feedId);
        const filePath = await this.downloadPack(downloadInfo);
        downloadedPaths.push(filePath);
      } catch (error) {
        // Log but continue with other downloads
        console.error(`Failed to download ${update.feedId}:`, error);
      }
    }

    return downloadedPaths;
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
        // Log error silently - don't bother users with connection issues
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
