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
import { machineIdSync } from 'node-machine-id';
import type { LicensePayload, LicenseInfo } from './types';
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
    const payload = JSON.parse(payloadJson) as LicensePayload;

    // Validate required fields
    if (!payload.sub || !payload.tier || !payload.feeds || !payload.api || !payload.exp) {
      throw new Error('Missing required fields');
    }

    return payload;
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
        storedId = `vscode-${Date.now()}-${Math.random().toString(36).slice(2)}`;
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
   * @param jwt - License JWT to store
   * @throws EncryptedPackError if JWT is invalid
   */
  async setLicenseKey(jwt: string): Promise<void> {
    // Validate JWT format first
    decodeJWT(jwt);

    // Store in secrets
    await this.secrets.store(LICENSE_SECRET_KEY, jwt);

    // Clear cache
    this.cachedLicense = null;
  }

  /**
   * Clear the stored license key
   */
  async clearLicenseKey(): Promise<void> {
    await this.secrets.delete(LICENSE_SECRET_KEY);
    this.cachedLicense = null;
  }

  /**
   * Get license info (parsed and validated)
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
      const info: LicenseInfo = {
        jwt,
        payload,
        isExpired: isLicenseExpired(payload),
        daysUntilExpiry: getDaysUntilExpiry(payload),
        expiryDate: formatExpiryDate(payload),
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

  /**
   * Prompt user to enter license key
   *
   * @returns true if license was entered, false if cancelled
   */
  async promptForLicenseKey(): Promise<boolean> {
    const input = await vscode.window.showInputBox({
      prompt: 'Enter your SentriFlow license key',
      placeHolder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      password: true,
      ignoreFocusOut: true,
      validateInput: (value) => {
        if (!value) {
          return 'License key is required';
        }
        // Basic JWT format check
        if (value.split('.').length !== 3) {
          return 'Invalid license key format';
        }
        return null;
      },
    });

    if (!input) {
      return false;
    }

    try {
      await this.setLicenseKey(input.trim());
      vscode.window.showInformationMessage('SentriFlow license key saved successfully');
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Invalid license key';
      vscode.window.showErrorMessage(`Failed to save license key: ${message}`);
      return false;
    }
  }

  /**
   * Show license status in a quick pick
   */
  async showLicenseStatus(): Promise<void> {
    const info = await this.getLicenseInfo();

    if (!info) {
      const action = await vscode.window.showWarningMessage(
        'No SentriFlow license key configured',
        'Enter License Key'
      );
      if (action === 'Enter License Key') {
        await this.promptForLicenseKey();
      }
      return;
    }

    const statusIcon = info.isExpired ? '$(warning)' : '$(check)';
    const statusText = info.isExpired
      ? `Expired on ${info.expiryDate}`
      : `Valid until ${info.expiryDate} (${info.daysUntilExpiry} days)`;

    const items: vscode.QuickPickItem[] = [
      {
        label: `${statusIcon} License Status`,
        description: statusText,
        detail: `Customer: ${info.payload.name ?? info.payload.sub}`,
      },
      {
        label: '$(list-tree) Entitled Feeds',
        description: info.payload.feeds.join(', '),
        detail: `Tier: ${info.payload.tier}`,
      },
      {
        label: '$(cloud) API Endpoint',
        description: info.payload.api,
      },
      {
        label: '$(law) Terms of Service',
        description: 'View commercial license terms',
      },
      {
        label: '$(shield) Privacy Policy',
        description: 'View privacy policy',
      },
      {
        label: '$(key) Change License Key',
        description: 'Enter a different license key',
      },
      {
        label: '$(trash) Clear License Key',
        description: 'Remove stored license key',
      },
    ];

    const selected = await vscode.window.showQuickPick(items, {
      title: 'SentriFlow License',
      placeHolder: 'License information',
    });

    if (selected?.label.includes('Change License Key')) {
      await this.promptForLicenseKey();
    } else if (selected?.label.includes('Clear License Key')) {
      const confirm = await vscode.window.showWarningMessage(
        'Are you sure you want to clear your license key?',
        'Yes',
        'No'
      );
      if (confirm === 'Yes') {
        await this.clearLicenseKey();
        vscode.window.showInformationMessage('License key cleared');
      }
    } else if (selected?.label.includes('Terms of Service')) {
      vscode.env.openExternal(vscode.Uri.parse('https://sentriflow.com.au/terms'));
    } else if (selected?.label.includes('Privacy Policy')) {
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
}
