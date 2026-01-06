/**
 * License Manager for SentriFlow VS Code Extension
 *
 * Handles license key storage, JWT parsing, and entitlement retrieval.
 * License keys are stored securely in VS Code's secrets API.
 *
 * @module encryption/LicenseManager
 */

// Type declaration for node-machine-id (no @types package available)
declare module 'node-machine-id' {
  export function machineIdSync(original?: boolean): string;
  export function machineId(original?: boolean): Promise<string>;
}

import * as vscode from 'vscode';
import * as os from 'os';
import { machineIdSync } from 'node-machine-id';
import { randomUUID, randomBytes } from 'crypto';
import type {
  LicensePayload,
  LicenseInfo,
  CachedEntitlements,
  EntitlementsResponse,
  CloudConnectionStatus,
  LicenseKeyType,
  CloudActivationRequest,
  CloudActivationResponse,
  StoredCloudLicense,
  CloudWrappedTMK,
} from './types';
import { EncryptedPackError } from './types';

// =============================================================================
// Constants
// =============================================================================

/** Secret storage key for license JWT */
const LICENSE_SECRET_KEY = 'sentriflow.licenseKey';

/** Global state key for last update check */
const LAST_UPDATE_CHECK_KEY = 'sentriflow.lastUpdateCheck';

/** Cached machine ID key */
const MACHINE_ID_KEY = 'sentriflow.machineId';

/** Cached entitlements key */
const ENTITLEMENTS_CACHE_KEY = 'sentriflow.entitlementsCache';

/** Entitlements cache TTL in milliseconds (72 hours) */
const ENTITLEMENTS_CACHE_TTL_MS = 72 * 60 * 60 * 1000;

/** Cloud connection status key */
const CONNECTION_STATUS_KEY = 'sentriflow.connectionStatus';

/** Cloud license storage key (for XXXX-XXXX-XXXX-XXXX format licenses) */
const CLOUD_LICENSE_KEY = 'sentriflow.cloudLicense';

/** Cloud wrapped TMK storage key */
const CLOUD_WRAPPED_TMK_KEY = 'sentriflow.cloudWrappedTMK';

/** Offline license storage key (for JWT-based extended pack licenses) */
const OFFLINE_LICENSE_SECRET_KEY = 'sentriflow.offlineLicenseKey';

/** Build-time constant for cloud API URL (injected by esbuild) */
declare const __CLOUD_API_URL__: string;

/** Default cloud API URL (injected at build time, can override via SENTRIFLOW_API_URL env var) */
export const DEFAULT_CLOUD_API_URL = typeof __CLOUD_API_URL__ !== 'undefined'
  ? __CLOUD_API_URL__
  : 'https://api.sentriflow.com.au';

/** Cloud license key format regex (XXXX-XXXX-XXXX-XXXX) */
const CLOUD_LICENSE_FORMAT = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i;

// =============================================================================
// License Key Type Detection
// =============================================================================

/**
 * Detect the type of license key
 *
 * @param key - License key string
 * @returns 'jwt' for JWT format, 'cloud' for cloud license format, null for invalid
 */
function detectLicenseKeyType(key: string): LicenseKeyType | null {
  const trimmed = key.trim();

  // Check for cloud license format first (XXXX-XXXX-XXXX-XXXX)
  if (CLOUD_LICENSE_FORMAT.test(trimmed)) {
    return 'cloud';
  }

  // Check for JWT format (three base64 parts separated by dots)
  const parts = trimmed.split('.');
  if (parts.length === 3) {
    // Verify each part looks like base64
    const base64Pattern = /^[A-Za-z0-9_-]+$/;
    if (parts.every((part) => base64Pattern.test(part))) {
      return 'jwt';
    }
  }

  return null;
}

/**
 * Validate cloud license key format
 *
 * @param key - License key string
 * @returns true if valid cloud license format
 */
function isValidCloudLicenseFormat(key: string): boolean {
  return CLOUD_LICENSE_FORMAT.test(key.trim());
}

// =============================================================================
// JWT Utilities
// =============================================================================

/**
 * Decode JWT payload without signature verification
 *
 * SECURITY MODEL DOCUMENTATION:
 * -----------------------------
 * This open-source extension intentionally does NOT verify JWT signatures locally.
 * This is a deliberate design decision with the following security guarantees:
 *
 * 1. PACK DECRYPTION REQUIRES VALID LICENSE:
 *    - Encrypted packs use AES-256-GCM with TMK (Tier Master Key)
 *    - TMK is wrapped with LDK derived from license key + salt
 *    - Without a valid license key issued by SentriFlow, decryption fails
 *    - Forged JWTs cannot decrypt packs - the crypto enforces authenticity
 *
 * 2. CLOUD API VERIFIES SIGNATURES SERVER-SIDE:
 *    - All API endpoints (/api/v1/entitlements, /api/v1/feeds/*) verify JWT signatures
 *    - Invalid/forged JWTs are rejected with 401 before any data is returned
 *    - Rate limiting and anomaly detection prevent brute-force attacks
 *
 * 3. OPEN-SOURCE TRANSPARENCY:
 *    - Embedding the signing secret in open-source code would defeat the purpose
 *    - The pack encryption provides cryptographic enforcement, not the JWT
 *
 * WHY NOT VERIFY LOCALLY?
 * - Would require embedding secret (security theater)
 * - Encryption already provides stronger guarantee
 * - Server-side verification is the standard pattern for JWTs
 *
 * @param jwt - JWT string
 * @returns Decoded payload
 * @throws EncryptedPackError if JWT is malformed
 */
function decodeJWT(jwt: string): LicensePayload {
  const parts = jwt.split('.');

  if (parts.length !== 3) {
    throw new EncryptedPackError(
      'Invalid license key format (not a valid JWT)',
      'LICENSE_INVALID'
    );
  }

  try {
    // Decode the payload (second part)
    const payloadBase64 = parts[1]!;
    // Handle URL-safe base64
    const payloadBase64Std = payloadBase64
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    const payloadJson = Buffer.from(payloadBase64Std, 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson) as unknown;

    // SECURITY: Runtime type validation to prevent malformed JWT attacks
    // Validates both presence AND type of each field
    if (typeof payload !== 'object' || payload === null) {
      throw new Error('Payload must be an object');
    }

    const p = payload as Record<string, unknown>;

    // Validate required string fields
    if (typeof p.sub !== 'string' || p.sub.length === 0) {
      throw new Error('Invalid or missing "sub" claim');
    }

    // Validate tier is one of the allowed values
    const validTiers = ['community', 'professional', 'enterprise'];
    if (typeof p.tier !== 'string' || !validTiers.includes(p.tier)) {
      throw new Error(`Invalid "tier" claim: must be one of ${validTiers.join(', ')}`);
    }

    // Validate feeds is an array of strings
    if (!Array.isArray(p.feeds)) {
      throw new Error('Invalid "feeds" claim: must be an array');
    }
    for (const feed of p.feeds) {
      if (typeof feed !== 'string') {
        throw new Error('Invalid "feeds" claim: all items must be strings');
      }
    }

    // Validate exp is a number (Unix timestamp)
    if (typeof p.exp !== 'number' || !Number.isInteger(p.exp) || p.exp <= 0) {
      throw new Error('Invalid "exp" claim: must be a positive integer');
    }

    // Validate iat if present
    if (p.iat !== undefined && (typeof p.iat !== 'number' || !Number.isInteger(p.iat))) {
      throw new Error('Invalid "iat" claim: must be an integer');
    }

    // Validate api URL if present (must be HTTPS)
    if (p.api !== undefined) {
      if (typeof p.api !== 'string') {
        throw new Error('Invalid "api" claim: must be a string');
      }
      try {
        const url = new URL(p.api);
        if (url.protocol !== 'https:') {
          throw new Error('Invalid "api" claim: must use HTTPS');
        }
      } catch {
        throw new Error('Invalid "api" claim: must be a valid HTTPS URL');
      }
    }

    // Cast to LicensePayload after validation
    return payload as LicensePayload;
  } catch (error) {
    throw new EncryptedPackError(
      'Failed to parse license key payload',
      'LICENSE_INVALID',
      error
    );
  }
}

/**
 * Check if license is expired
 *
 * @param payload - License payload
 * @returns true if expired
 */
function isLicenseExpired(payload: LicensePayload): boolean {
  const now = Math.floor(Date.now() / 1000);
  return now > payload.exp;
}

/**
 * Calculate days until expiry
 *
 * @param payload - License payload
 * @returns Days until expiry (negative if expired)
 */
function getDaysUntilExpiry(payload: LicensePayload): number {
  const now = Math.floor(Date.now() / 1000);
  const secondsRemaining = payload.exp - now;
  return Math.floor(secondsRemaining / (24 * 60 * 60));
}

/**
 * Format expiry date for display
 *
 * @param payload - License payload
 * @returns Human-readable date string
 */
function formatExpiryDate(payload: LicensePayload): string {
  const date = new Date(payload.exp * 1000);
  return date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

// =============================================================================
// License Manager Class
// =============================================================================

/**
 * License Manager
 *
 * Manages license key storage and retrieval using VS Code's secrets API.
 */
export class LicenseManager {
  private readonly secrets: vscode.SecretStorage;
  private readonly globalState: vscode.Memento;
  private cachedLicense: LicenseInfo | null = null;
  private cachedMachineId: string | null = null;

  constructor(context: vscode.ExtensionContext) {
    this.secrets = context.secrets;
    this.globalState = context.globalState;
  }

  /**
   * Get the machine ID for LDK derivation
   *
   * Uses node-machine-id to get a stable hardware identifier.
   * Falls back to a persistent UUID if machine ID is unavailable.
   *
   * @returns Machine ID string
   */
  async getMachineId(): Promise<string> {
    if (this.cachedMachineId) {
      return this.cachedMachineId;
    }

    try {
      // Try to get hardware machine ID
      const machineId = machineIdSync();
      this.cachedMachineId = machineId;
      return machineId;
    } catch {
      // Fall back to persistent UUID stored in global state
      let storedId = this.globalState.get<string>(MACHINE_ID_KEY);
      if (!storedId) {
        // Use cryptographically secure random for fallback ID
        storedId = `vscode-${randomBytes(16).toString('hex')}`;
        await this.globalState.update(MACHINE_ID_KEY, storedId);
      }
      this.cachedMachineId = storedId;
      return storedId;
    }
  }

  /**
   * Check if a license key is stored
   *
   * @returns true if a license key exists
   */
  async hasLicenseKey(): Promise<boolean> {
    const jwt = await this.secrets.get(LICENSE_SECRET_KEY);
    return !!jwt;
  }

  /**
   * Get the stored license key (raw JWT)
   *
   * @returns JWT string or undefined
   */
  async getLicenseKey(): Promise<string | undefined> {
    return this.secrets.get(LICENSE_SECRET_KEY);
  }

  /**
   * Store a license key
   *
   * Supports both formats (both can be stored simultaneously):
   * - JWT format: Three-part base64 token (for offline/extended packs) - stored in offline slot
   * - Cloud format: XXXX-XXXX-XXXX-XXXX (activates with cloud API) - stored in cloud slot
   *
   * @param key - License key (JWT or cloud format)
   * @param apiUrl - Optional API URL for cloud activation
   * @throws EncryptedPackError if key is invalid or activation fails
   */
  async setLicenseKey(key: string, apiUrl?: string): Promise<void> {
    const keyType = detectLicenseKeyType(key);

    if (!keyType) {
      throw new EncryptedPackError(
        'Invalid license key format. Expected JWT or XXXX-XXXX-XXXX-XXXX format.',
        'LICENSE_INVALID'
      );
    }

    if (keyType === 'cloud') {
      // Cloud license - activate with API
      await this.activateCloudLicense(key.trim(), apiUrl);
    } else {
      // JWT license - validate and store in offline slot
      decodeJWT(key);
      await this.secrets.store(OFFLINE_LICENSE_SECRET_KEY, key);
      // Also store in main slot for backward compatibility
      await this.secrets.store(LICENSE_SECRET_KEY, key);
      this.cachedLicense = null;
    }
  }

  /**
   * Clear the stored license key
   *
   * Clears both JWT and cloud license data if present.
   */
  async clearLicenseKey(): Promise<void> {
    await this.secrets.delete(LICENSE_SECRET_KEY);
    await this.secrets.delete(CLOUD_WRAPPED_TMK_KEY);
    await this.secrets.delete(OFFLINE_LICENSE_SECRET_KEY);
    await this.globalState.update(CLOUD_LICENSE_KEY, undefined);
    this.cachedLicense = null;
  }

  /**
   * Get license info (parsed and validated)
   *
   * For cloud licenses, uses the stored license expiry (subscription end date)
   * rather than the JWT expiry (which is a shorter auth token TTL).
   *
   * @returns License info or null if no license
   */
  async getLicenseInfo(): Promise<LicenseInfo | null> {
    // Return cached if available
    if (this.cachedLicense) {
      return this.cachedLicense;
    }

    const jwt = await this.getLicenseKey();
    if (!jwt) {
      return null;
    }

    try {
      const payload = decodeJWT(jwt);

      // For cloud licenses, use the stored license expiry instead of JWT expiry
      // JWT expiry is short (up to 30 days) but license can be much longer
      const cloudLicense = await this.getStoredCloudLicense();
      let effectiveExpiry = payload.exp;

      if (cloudLicense?.licenseExpiresAt) {
        // Use the actual license expiry date
        effectiveExpiry = Math.floor(new Date(cloudLicense.licenseExpiresAt).getTime() / 1000);
      }

      // Create a modified payload for expiry calculations
      const effectivePayload: LicensePayload = {
        ...payload,
        exp: effectiveExpiry,
      };

      const info: LicenseInfo = {
        jwt,
        payload: effectivePayload,
        isExpired: isLicenseExpired(effectivePayload),
        daysUntilExpiry: getDaysUntilExpiry(effectivePayload),
        expiryDate: formatExpiryDate(effectivePayload),
      };

      this.cachedLicense = info;
      return info;
    } catch {
      // Invalid stored license - clear it
      await this.clearLicenseKey();
      return null;
    }
  }

  /**
   * Get entitled feed IDs from license
   *
   * @returns Array of feed IDs or empty array
   */
  async getEntitledFeeds(): Promise<string[]> {
    const info = await this.getLicenseInfo();
    if (!info || info.isExpired) {
      return [];
    }
    return info.payload.feeds;
  }

  /**
   * Get API URL from license
   *
   * @returns API URL or null
   */
  async getApiUrl(): Promise<string | null> {
    const info = await this.getLicenseInfo();
    return info?.payload.api ?? null;
  }

  /**
   * Get customer tier from license
   *
   * @returns Tier or null
   */
  async getTier(): Promise<'community' | 'professional' | 'enterprise' | null> {
    const info = await this.getLicenseInfo();
    return info?.payload.tier ?? null;
  }

  // ===========================================================================
  // Offline License Management (JWT for extended packs)
  // ===========================================================================

  /**
   * Get the stored offline license key (JWT)
   *
   * Offline licenses are used for extended GRX2 packs and work independently
   * of cloud subscription status.
   *
   * @returns JWT string or undefined
   */
  async getOfflineLicenseKey(): Promise<string | undefined> {
    return this.secrets.get(OFFLINE_LICENSE_SECRET_KEY);
  }

  /**
   * Check if an offline license key is stored
   *
   * @returns true if an offline license key exists
   */
  async hasOfflineLicenseKey(): Promise<boolean> {
    const key = await this.secrets.get(OFFLINE_LICENSE_SECRET_KEY);
    return !!key;
  }

  /**
   * Set offline license key directly (without affecting cloud license)
   *
   * @param key - JWT license key
   * @throws EncryptedPackError if key is invalid
   */
  async setOfflineLicenseKey(key: string): Promise<void> {
    const keyType = detectLicenseKeyType(key);

    if (keyType !== 'jwt') {
      throw new EncryptedPackError(
        'Offline license must be JWT format (for extended packs)',
        'LICENSE_INVALID'
      );
    }

    // Validate the JWT
    decodeJWT(key);

    await this.secrets.store(OFFLINE_LICENSE_SECRET_KEY, key);

    // Update main slot only if no cloud license
    if (!(await this.hasCloudLicense())) {
      await this.secrets.store(LICENSE_SECRET_KEY, key);
      this.cachedLicense = null;
    }
  }

  /**
   * Clear only the offline license key (preserves cloud license)
   */
  async clearOfflineLicenseKey(): Promise<void> {
    await this.secrets.delete(OFFLINE_LICENSE_SECRET_KEY);

    // If we had offline as primary and have cloud, switch to cloud JWT
    const cloudLicense = await this.getStoredCloudLicense();
    if (cloudLicense) {
      await this.secrets.store(LICENSE_SECRET_KEY, cloudLicense.jwt);
      this.cachedLicense = null;
    }
  }

  /**
   * Get offline license info (parsed and validated)
   *
   * @returns License info or null if no offline license
   */
  async getOfflineLicenseInfo(): Promise<LicenseInfo | null> {
    const jwt = await this.getOfflineLicenseKey();
    if (!jwt) {
      return null;
    }

    try {
      const payload = decodeJWT(jwt);
      return {
        jwt,
        payload,
        isExpired: isLicenseExpired(payload),
        daysUntilExpiry: getDaysUntilExpiry(payload),
        expiryDate: formatExpiryDate(payload),
      };
    } catch {
      return null;
    }
  }

  /**
   * Get cloud license info (parsed and validated)
   *
   * Uses the stored license expiry (subscription end date) rather than
   * the JWT expiry (which is a shorter auth token TTL).
   *
   * @returns License info or null if no cloud license
   */
  async getCloudLicenseInfo(): Promise<LicenseInfo | null> {
    const cloudLicense = await this.getStoredCloudLicense();
    if (!cloudLicense?.jwt) {
      return null;
    }

    try {
      const payload = decodeJWT(cloudLicense.jwt);

      // Use the actual license expiry date instead of JWT expiry
      // JWT expiry is short (up to 30 days) but license can be much longer
      let effectiveExpiry = payload.exp;
      if (cloudLicense.licenseExpiresAt) {
        effectiveExpiry = Math.floor(new Date(cloudLicense.licenseExpiresAt).getTime() / 1000);
      }

      // Create a modified payload for expiry calculations
      const effectivePayload: LicensePayload = {
        ...payload,
        exp: effectiveExpiry,
      };

      return {
        jwt: cloudLicense.jwt,
        payload: effectivePayload,
        isExpired: isLicenseExpired(effectivePayload),
        daysUntilExpiry: getDaysUntilExpiry(effectivePayload),
        expiryDate: formatExpiryDate(effectivePayload),
      };
    } catch {
      return null;
    }
  }

  /**
   * Get all available license keys for pack decryption
   *
   * Returns both cloud and offline license keys if available.
   * This allows packs to be decrypted with either license.
   *
   * @returns Array of license keys (may be empty, 1, or 2 keys)
   */
  async getAllLicenseKeys(): Promise<string[]> {
    const keys: string[] = [];

    // Add cloud license JWT if available
    const cloudLicense = await this.getStoredCloudLicense();
    if (cloudLicense?.jwt) {
      keys.push(cloudLicense.jwt);
    }

    // Add offline license if available (and different from cloud)
    const offlineKey = await this.getOfflineLicenseKey();
    if (offlineKey && !keys.includes(offlineKey)) {
      keys.push(offlineKey);
    }

    return keys;
  }

  /**
   * Prompt user to enter license key
   *
   * Accepts both formats:
   * - JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * - Cloud: XXXX-XXXX-XXXX-XXXX
   *
   * @returns true if license was entered, false if cancelled
   */
  async promptForLicenseKey(): Promise<boolean> {
    const input = await vscode.window.showInputBox({
      prompt: 'Enter your SentriFlow license key',
      placeHolder: 'XXXX-XXXX-XXXX-XXXX or eyJhbGciOiJIUzI1NiIs...',
      password: true,
      ignoreFocusOut: true,
      validateInput: (value) => {
        if (!value) {
          return 'License key is required';
        }

        const trimmed = value.trim();
        const keyType = detectLicenseKeyType(trimmed);

        if (!keyType) {
          return 'Invalid format. Use XXXX-XXXX-XXXX-XXXX (cloud) or JWT (offline)';
        }

        return null;
      },
    });

    if (!input) {
      return false;
    }

    const trimmed = input.trim();
    const keyType = detectLicenseKeyType(trimmed);

    try {
      if (keyType === 'cloud') {
        // Show progress for cloud activation (requires network call)
        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: 'Activating SentriFlow license...',
            cancellable: false,
          },
          async () => {
            await this.setLicenseKey(trimmed);
          }
        );
        vscode.window.showInformationMessage('SentriFlow license activated successfully');
      } else {
        await this.setLicenseKey(trimmed);
        vscode.window.showInformationMessage('SentriFlow license key saved successfully');
      }
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid license key';
      vscode.window.showErrorMessage(`Failed to save license key: ${message}`);
      return false;
    }
  }

  /**
   * Show license status in a quick pick
   *
   * Displays both cloud and offline licenses when both are configured.
   */
  async showLicenseStatus(): Promise<void> {
    const cloudLicense = await this.getStoredCloudLicense();
    const cloudInfo = await this.getLicenseInfo();
    const offlineInfo = await this.getOfflineLicenseInfo();

    // Check if any license is configured
    if (!cloudInfo && !offlineInfo) {
      const action = await vscode.window.showWarningMessage(
        'No SentriFlow license key configured',
        'Enter License Key'
      );
      if (action === 'Enter License Key') {
        await this.promptForLicenseKey();
      }
      return;
    }

    const items: vscode.QuickPickItem[] = [];

    // Helper to format remaining time
    const formatRemaining = (info: LicenseInfo): string => {
      if (info.daysUntilExpiry <= 0) {
        const now = Math.floor(Date.now() / 1000);
        const secondsRemaining = Math.max(0, info.payload.exp - now);
        const hoursRemaining = Math.floor(secondsRemaining / 3600);
        const minutesRemaining = Math.floor((secondsRemaining % 3600) / 60);

        if (hoursRemaining > 0) {
          return hoursRemaining === 1 ? '1 hour' : `${hoursRemaining} hours`;
        } else if (minutesRemaining > 0) {
          return minutesRemaining === 1 ? '1 minute' : `${minutesRemaining} minutes`;
        }
        return 'moments';
      } else if (info.daysUntilExpiry === 1) {
        return '1 day';
      }
      return `${info.daysUntilExpiry} days`;
    };

    // Show cloud license info if present
    if (cloudInfo && cloudLicense) {
      const statusIcon = cloudInfo.isExpired ? '$(warning)' : '$(cloud)';
      const statusText = cloudInfo.isExpired
        ? `Expired on ${cloudInfo.expiryDate}`
        : `Valid until ${cloudInfo.expiryDate} (${formatRemaining(cloudInfo)})`;

      items.push(
        {
          label: `${statusIcon} Cloud License`,
          description: statusText,
          detail: `Tier: ${cloudInfo.payload.tier} | Feeds: ${cloudInfo.payload.feeds.join(', ')}`,
        },
        {
          label: '$(sync) Refresh Cloud License',
          description: 'Re-activate to refresh JWT and TMK',
        }
      );
    }

    // Show offline license info if present
    if (offlineInfo) {
      const statusIcon = offlineInfo.isExpired ? '$(warning)' : '$(key)';
      const statusText = offlineInfo.isExpired
        ? `Expired on ${offlineInfo.expiryDate}`
        : `Valid until ${offlineInfo.expiryDate} (${formatRemaining(offlineInfo)})`;

      items.push({
        label: `${statusIcon} Offline License`,
        description: statusText,
        detail: `Tier: ${offlineInfo.payload.tier} | Feeds: ${offlineInfo.payload.feeds.join(', ')}`,
      });
    }

    // Show combined entitled feeds
    const allFeeds = new Set<string>();
    if (cloudInfo && !cloudInfo.isExpired) {
      cloudInfo.payload.feeds.forEach(f => allFeeds.add(f));
    }
    if (offlineInfo && !offlineInfo.isExpired) {
      offlineInfo.payload.feeds.forEach(f => allFeeds.add(f));
    }

    if (allFeeds.size > 0) {
      items.push({
        label: '$(list-tree) Combined Entitled Feeds',
        description: Array.from(allFeeds).join(', '),
        detail: `${allFeeds.size} feed(s) available from ${(cloudInfo ? 1 : 0) + (offlineInfo ? 1 : 0)} license(s)`,
      });
    }

    // Add separator and actions
    items.push(
      {
        label: '',
        kind: vscode.QuickPickItemKind.Separator,
      } as vscode.QuickPickItem,
      {
        label: '$(add) Add License Key',
        description: 'Add a cloud or offline license',
      },
      {
        label: '$(law) Terms of Service',
        description: 'View commercial license terms',
      },
      {
        label: '$(shield) Privacy Policy',
        description: 'View privacy policy',
      }
    );

    // Add clear options based on what's configured
    if (cloudLicense) {
      items.push({
        label: '$(trash) Clear Cloud License',
        description: 'Remove cloud license only',
      });
    }
    if (offlineInfo) {
      items.push({
        label: '$(trash) Clear Offline License',
        description: 'Remove offline license only',
      });
    }
    if (cloudLicense && offlineInfo) {
      items.push({
        label: '$(trash) Clear All Licenses',
        description: 'Remove both licenses',
      });
    }

    const selected = await vscode.window.showQuickPick(items, {
      title: 'SentriFlow Licenses',
      placeHolder: 'License information and actions',
    });

    if (!selected) return;

    if (selected.label.includes('Refresh Cloud License')) {
      try {
        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: 'Refreshing SentriFlow cloud license...',
            cancellable: false,
          },
          async () => {
            await this.refreshCloudLicense();
          }
        );
        vscode.window.showInformationMessage('Cloud license refreshed successfully');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to refresh';
        vscode.window.showErrorMessage(`Failed to refresh license: ${message}`);
      }
    } else if (selected.label.includes('Add License Key')) {
      await this.promptForLicenseKey();
    } else if (selected.label.includes('Clear All Licenses')) {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear all license keys?',
        'Yes',
        'No'
      );
      if (confirm === 'Yes') {
        await this.clearLicenseKey();
        vscode.window.showInformationMessage('All license keys cleared');
      }
    } else if (selected.label.includes('Clear Cloud License')) {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear your cloud license?',
        'Yes',
        'No'
      );
      if (confirm === 'Yes') {
        await this.clearCloudLicense();
        vscode.window.showInformationMessage('Cloud license cleared');
      }
    } else if (selected.label.includes('Clear Offline License')) {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear your offline license?',
        'Yes',
        'No'
      );
      if (confirm === 'Yes') {
        await this.clearOfflineLicenseKey();
        vscode.window.showInformationMessage('Offline license cleared');
      }
    } else if (selected.label.includes('Terms of Service')) {
      vscode.env.openExternal(vscode.Uri.parse('https://sentriflow.com.au/terms'));
    } else if (selected.label.includes('Privacy Policy')) {
      vscode.env.openExternal(vscode.Uri.parse('https://sentriflow.com.au/privacy'));
    }
  }

  /**
   * Get last update check timestamp
   *
   * @returns ISO timestamp or null
   */
  async getLastUpdateCheck(): Promise<string | null> {
    return this.globalState.get<string>(LAST_UPDATE_CHECK_KEY) ?? null;
  }

  /**
   * Set last update check timestamp
   *
   * @param timestamp - ISO timestamp
   */
  async setLastUpdateCheck(timestamp: string): Promise<void> {
    await this.globalState.update(LAST_UPDATE_CHECK_KEY, timestamp);
  }

  /**
   * Check if update check is due based on auto-update setting
   *
   * @param autoUpdate - Auto-update setting
   * @returns true if update check should run
   */
  async isUpdateCheckDue(autoUpdate: 'disabled' | 'on-activation' | 'daily' | 'manual'): Promise<boolean> {
    if (autoUpdate === 'disabled' || autoUpdate === 'manual') {
      return false;
    }

    if (autoUpdate === 'on-activation') {
      return true;
    }

    // Daily check
    const lastCheck = await this.getLastUpdateCheck();
    if (!lastCheck) {
      return true;
    }

    const lastCheckTime = new Date(lastCheck).getTime();
    const now = Date.now();
    const oneDayMs = 24 * 60 * 60 * 1000;

    return now - lastCheckTime > oneDayMs;
  }

  // ===========================================================================
  // Entitlement Cache (24-hour offline mode)
  // ===========================================================================

  /**
   * Cache entitlements for offline use
   *
   * @param entitlements - Entitlements response to cache
   */
  async cacheEntitlements(entitlements: EntitlementsResponse): Promise<void> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ENTITLEMENTS_CACHE_TTL_MS);

    const cached: CachedEntitlements = {
      entitlements,
      cachedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    await this.globalState.update(ENTITLEMENTS_CACHE_KEY, cached);
  }

  /**
   * Get cached entitlements if still valid
   *
   * @returns Cached entitlements or null if expired/missing
   */
  async getCachedEntitlements(): Promise<CachedEntitlements | null> {
    const cached = this.globalState.get<CachedEntitlements>(ENTITLEMENTS_CACHE_KEY);

    if (!cached) {
      return null;
    }

    // Check if cache is still valid
    const now = Date.now();
    const expiresAt = new Date(cached.expiresAt).getTime();

    if (now > expiresAt) {
      // Cache expired - clear it
      await this.globalState.update(ENTITLEMENTS_CACHE_KEY, undefined);
      return null;
    }

    return cached;
  }

  /**
   * Get time remaining on entitlements cache
   *
   * @returns Hours remaining, or 0 if expired/no cache
   */
  async getCacheTimeRemaining(): Promise<number> {
    const cached = await this.getCachedEntitlements();

    if (!cached) {
      return 0;
    }

    const now = Date.now();
    const expiresAt = new Date(cached.expiresAt).getTime();
    const msRemaining = expiresAt - now;

    return Math.max(0, Math.floor(msRemaining / (60 * 60 * 1000)));
  }

  /**
   * Clear the entitlements cache
   */
  async clearEntitlementsCache(): Promise<void> {
    await this.globalState.update(ENTITLEMENTS_CACHE_KEY, undefined);
  }

  // ===========================================================================
  // License Revocation Handling
  // ===========================================================================

  /**
   * Mark cloud license as revoked or expired
   *
   * Called when API returns LICENSE_REVOKED or LICENSE_EXPIRED error.
   * This updates the stored license status and clears security-sensitive data.
   *
   * @param reason - 'revoked' when server indicates license was revoked,
   *                 'expired' when server indicates license has expired
   */
  async markLicenseInvalid(reason: 'revoked' | 'expired'): Promise<void> {
    const storedLicense = await this.getStoredCloudLicense();
    if (!storedLicense) {
      return;
    }

    // SECURITY: Clear TMK FIRST to prevent TOCTOU race condition
    // This ensures pack decryption fails immediately, before status is updated
    await this.clearSecurityData();

    // Clear cached license to force re-read
    this.cachedLicense = null;

    // Then update status in global state
    const updatedLicense: StoredCloudLicense = {
      ...storedLicense,
      status: reason,
      invalidatedAt: new Date().toISOString(),
    };
    const { wrappedTMK, wrappedCustomerTMK, ...licenseWithoutTMK } = updatedLicense;
    await this.globalState.update(CLOUD_LICENSE_KEY, licenseWithoutTMK);
  }

  /**
   * Check if stored cloud license is marked as revoked
   *
   * @returns true if license is marked as revoked
   */
  async isLicenseRevoked(): Promise<boolean> {
    const storedLicense = await this.getStoredCloudLicense();
    return storedLicense?.status === 'revoked';
  }

  /**
   * Check if stored cloud license is marked as expired by server
   *
   * Note: This is different from checking JWT expiry or license expiry date.
   * This flag is set when the server explicitly returns LICENSE_EXPIRED.
   *
   * @returns true if license is marked as expired by server
   */
  async isLicenseExpiredByServer(): Promise<boolean> {
    const storedLicense = await this.getStoredCloudLicense();
    return storedLicense?.status === 'expired';
  }

  /**
   * Check if license has any invalidation status (revoked or expired)
   *
   * @returns true if license is invalidated
   */
  async isLicenseInvalidated(): Promise<boolean> {
    const storedLicense = await this.getStoredCloudLicense();
    return storedLicense?.status === 'revoked' || storedLicense?.status === 'expired';
  }

  /**
   * Get license status
   *
   * @returns License status or undefined if no license
   */
  async getLicenseStatus(): Promise<'active' | 'revoked' | 'expired' | undefined> {
    const storedLicense = await this.getStoredCloudLicense();
    return storedLicense?.status;
  }

  /**
   * Clear security-sensitive data (TMKs from secrets)
   *
   * Called when license is invalidated to prevent pack decryption.
   */
  async clearSecurityData(): Promise<void> {
    await this.secrets.delete(CLOUD_WRAPPED_TMK_KEY);
    // Note: We don't clear the license key itself to preserve the revoked status
    // and allow the user to see that their license was revoked
  }

  // ===========================================================================
  // Connection Status
  // ===========================================================================

  /**
   * Set the cloud connection status
   *
   * @param status - Current connection status
   */
  async setConnectionStatus(status: CloudConnectionStatus): Promise<void> {
    await this.globalState.update(CONNECTION_STATUS_KEY, status);
  }

  /**
   * Get the cloud connection status
   *
   * @returns Current connection status
   */
  async getConnectionStatus(): Promise<CloudConnectionStatus> {
    return this.globalState.get<CloudConnectionStatus>(CONNECTION_STATUS_KEY) ?? 'unknown';
  }

  // ===========================================================================
  // Cloud License Support (XXXX-XXXX-XXXX-XXXX format)
  // ===========================================================================

  /**
   * Activate a cloud license key
   *
   * Calls the cloud API to activate the license and receive:
   * - JWT for API authentication
   * - Wrapped TMK for pack decryption
   *
   * @param licenseKey - Cloud license key (XXXX-XXXX-XXXX-XXXX format)
   * @param apiUrl - Optional API URL override
   * @returns Activation response
   * @throws EncryptedPackError on activation failure
   */
  async activateCloudLicense(
    licenseKey: string,
    apiUrl?: string
  ): Promise<CloudActivationResponse> {
    const effectiveApiUrl = apiUrl ?? DEFAULT_CLOUD_API_URL;
    const machineId = await this.getMachineId();

    // Build activation request
    const request: CloudActivationRequest = {
      licenseKey: licenseKey.toUpperCase(),
      machineId,
      hostname: os.hostname(),
      os: `${os.platform()}-${os.arch()}`,
      cliVersion: vscode.extensions.getExtension('sentriflow.sentriflow-vscode')?.packageJSON.version ?? '0.0.0',
      nonce: randomUUID(),
      timestamp: new Date().toISOString(),
    };

    try {
      // Set up timeout (30 seconds) to prevent VS Code from hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      let response: Response;
      try {
        response = await fetch(`${effectiveApiUrl}/api/v1/license/activate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': `SentriFlow-VSCode/${request.cliVersion}`,
          },
          body: JSON.stringify(request),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      if (!response.ok) {
        // Limit response body size to prevent memory issues
        const errorBody = await response.text().then(text => text.slice(0, 1024));
        let errorMessage = this.sanitizeErrorMessage(response.status, errorBody);

        throw new EncryptedPackError(errorMessage, 'ACTIVATION_FAILED');
      }

      const data = (await response.json()) as CloudActivationResponse;

      if (!data.valid) {
        throw new EncryptedPackError('License activation rejected', 'LICENSE_INVALID');
      }

      // Store cloud license info
      // Explicitly set status to 'active' to ensure any previous revoked/expired status is cleared
      const storedLicense: StoredCloudLicense = {
        licenseKey: licenseKey.toUpperCase(),
        jwt: data.jwt,
        wrappedTMK: data.wrappedTMK,
        wrappedCustomerTMK: data.wrappedCustomerTMK,
        activationId: data.activationId,
        activatedAt: new Date().toISOString(),
        apiUrl: effectiveApiUrl,
        cacheValiditySeconds: data.cacheValiditySeconds,
        licenseExpiresAt: data.expiresAt, // Store actual license expiry
        tier: data.tier,
        status: 'active', // Explicitly set to clear any previous revoked/expired status
      };

      await this.storeCloudLicense(storedLicense);

      // Also store JWT for compatibility with existing code
      await this.secrets.store(LICENSE_SECRET_KEY, data.jwt);
      this.cachedLicense = null;

      await this.setConnectionStatus('online');

      return data;
    } catch (error) {
      if (error instanceof EncryptedPackError) {
        throw error;
      }

      // Network or timeout error
      await this.setConnectionStatus('offline');

      // Provide user-friendly error messages
      let userMessage = 'Failed to connect to licensing server';
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          userMessage = 'Connection timed out. Please check your internet connection and try again.';
        } else if (error.message.includes('fetch')) {
          userMessage = 'Network error. Please check your internet connection.';
        }
      }

      throw new EncryptedPackError(userMessage, 'NETWORK_ERROR', error);
    }
  }

  /**
   * Sanitize API error messages for user display
   *
   * Maps technical error codes to user-friendly messages and prevents
   * exposing internal server details.
   *
   * @param status - HTTP status code
   * @param errorBody - Raw error response body
   * @returns User-friendly error message
   */
  private sanitizeErrorMessage(status: number, errorBody: string): string {
    // Map common status codes to user-friendly messages
    const statusMessages: Record<number, string> = {
      400: 'Invalid license key format',
      401: 'License key not found or invalid',
      403: 'License key is not authorized for this device',
      404: 'License activation service unavailable',
      429: 'Too many activation attempts. Please try again later.',
      500: 'Server error. Please try again later.',
      502: 'Service temporarily unavailable. Please try again.',
      503: 'Service temporarily unavailable. Please try again.',
    };

    // Try to parse error body for specific error code
    try {
      const errorJson = JSON.parse(errorBody) as { error?: { code?: string; message?: string }; message?: string };
      const errorCode = errorJson.error?.code;
      const errorMessage = errorJson.error?.message ?? errorJson.message;

      // Map known error codes to user-friendly messages
      if (errorCode === 'LICENSE_INVALID') {
        return 'License key is invalid or has been revoked';
      }
      if (errorCode === 'LICENSE_EXPIRED') {
        return 'License key has expired';
      }
      if (errorCode === 'ACTIVATION_LIMIT') {
        return 'Maximum device activations reached for this license';
      }
      if (errorCode === 'RATE_LIMITED') {
        return 'Too many requests. Please wait a moment and try again.';
      }

      // Use server message if it looks safe (no stack traces, paths, etc.)
      if (errorMessage && errorMessage.length < 200 && !errorMessage.includes('\n')) {
        return errorMessage;
      }
    } catch {
      // Ignore parse errors
    }

    // Fall back to status-based message
    return statusMessages[status] ?? `Activation failed (error ${status})`;
  }

  /**
   * Store cloud license info
   *
   * @param license - Cloud license info to store
   */
  async storeCloudLicense(license: StoredCloudLicense): Promise<void> {
    // Don't store sensitive TMK data in globalState
    const { wrappedTMK, wrappedCustomerTMK, ...licenseWithoutTMK } = license;

    await this.globalState.update(CLOUD_LICENSE_KEY, licenseWithoutTMK);

    // Store wrapped TMKs separately in secrets for security
    await this.secrets.store(
      CLOUD_WRAPPED_TMK_KEY,
      JSON.stringify({ tier: wrappedTMK, customer: wrappedCustomerTMK })
    );
  }

  /**
   * Get stored cloud license
   *
   * @returns Stored cloud license or null
   */
  async getStoredCloudLicense(): Promise<StoredCloudLicense | null> {
    const licenseBase = this.globalState.get<Omit<StoredCloudLicense, 'wrappedTMK' | 'wrappedCustomerTMK'>>(CLOUD_LICENSE_KEY);

    if (!licenseBase) {
      return null;
    }

    // Retrieve wrapped TMKs from secrets
    const tmks = await this.getWrappedTMKs();

    const license: StoredCloudLicense = {
      ...licenseBase,
      wrappedTMK: tmks?.tier ?? null,
      wrappedCustomerTMK: tmks?.customer,
    };

    return license;
  }

  /**
   * Get wrapped TMKs from secure storage
   *
   * @returns Both tier and customer TMKs or null
   */
  private async getWrappedTMKs(): Promise<{ tier: CloudWrappedTMK; customer?: CloudWrappedTMK | null } | null> {
    const wrappedTMKJson = await this.secrets.get(CLOUD_WRAPPED_TMK_KEY);

    if (!wrappedTMKJson) {
      return null;
    }

    try {
      return JSON.parse(wrappedTMKJson) as { tier: CloudWrappedTMK; customer?: CloudWrappedTMK | null };
    } catch {
      return null;
    }
  }

  /**
   * Get wrapped tier TMK for pack decryption
   *
   * @returns Wrapped tier TMK or null if not available
   */
  async getWrappedTMK(): Promise<CloudWrappedTMK | null> {
    const tmks = await this.getWrappedTMKs();
    return tmks?.tier ?? null;
  }

  /**
   * Get wrapped customer TMK for custom feed decryption
   *
   * @returns Wrapped customer TMK or null if not available
   */
  async getWrappedCustomerTMK(): Promise<CloudWrappedTMK | null> {
    const tmks = await this.getWrappedTMKs();
    return tmks?.customer ?? null;
  }

  /**
   * Check if this is a cloud license
   *
   * @returns true if cloud license is stored
   */
  async hasCloudLicense(): Promise<boolean> {
    const license = this.globalState.get<StoredCloudLicense>(CLOUD_LICENSE_KEY);
    return !!license;
  }

  /**
   * Get the license key type currently stored
   *
   * @returns 'cloud' if cloud license, 'jwt' if JWT only, null if none
   */
  async getLicenseKeyType(): Promise<LicenseKeyType | null> {
    if (await this.hasCloudLicense()) {
      return 'cloud';
    }

    if (await this.hasLicenseKey()) {
      return 'jwt';
    }

    return null;
  }

  /**
   * Clear cloud license data
   */
  async clearCloudLicense(): Promise<void> {
    await this.globalState.update(CLOUD_LICENSE_KEY, undefined);
    await this.secrets.delete(CLOUD_WRAPPED_TMK_KEY);
    // Also clear the JWT
    await this.clearLicenseKey();
  }

  /**
   * Refresh cloud license (re-activate to get fresh JWT and TMK)
   *
   * @returns Updated activation response
   * @throws EncryptedPackError if no cloud license stored or refresh fails
   */
  async refreshCloudLicense(): Promise<CloudActivationResponse> {
    const storedLicense = await this.getStoredCloudLicense();

    if (!storedLicense) {
      throw new EncryptedPackError('No cloud license stored', 'LICENSE_INVALID');
    }

    return this.activateCloudLicense(storedLicense.licenseKey, storedLicense.apiUrl);
  }
}
