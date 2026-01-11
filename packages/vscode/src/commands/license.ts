/**
 * License Commands
 *
 * Commands for license management and pack operations.
 * Handles license key entry/clearing, pack updates, and license status.
 */

import * as vscode from 'vscode';
import {
  LicenseManager,
  CloudClient,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
  EncryptedPackError,
  DEFAULT_CLOUD_API_URL,
} from '../encryption';
import { getState } from '../state/context';
import {
  loadPacks,
  handleLicenseRevocation,
  updateLicenseTree,
} from '../services/packManager';
import { rescanActiveEditor } from '../services/scanner';

// ============================================================================
// Logging Helpers
// ============================================================================

/**
 * Log a debug message to the output channel.
 */
function log(message: string): void {
  const state = getState();
  if (state.debugMode) {
    state.outputChannel.appendLine(`[DEBUG] ${message}`);
  }
}

/**
 * Log an info message (always visible).
 */
function logInfo(message: string): void {
  const state = getState();
  state.outputChannel.appendLine(message);
}

// ============================================================================
// License Commands
// ============================================================================

/**
 * Command: Enter license key
 */
export async function cmdEnterLicenseKey(): Promise<void> {
  const state = getState();

  if (!state.licenseManager) {
    state.licenseManager = new LicenseManager(state.context);
  }

  const success = await state.licenseManager.promptForLicenseKey();
  if (success) {
    // Initialize cloud client for update checks (requires cloud license JWT)
    const cloudLicense = await state.licenseManager.getStoredCloudLicense();
    if (cloudLicense?.jwt) {
      const apiUrl = cloudLicense.apiUrl ?? DEFAULT_CLOUD_API_URL;
      log('[License] Cloud license activated');
      state.cloudClient = new CloudClient({
        apiUrl,
        licenseKey: cloudLicense.jwt,
      });

      // Check for updates and download automatically
      try {
        const localVersions = new Map<string, string>();
        for (const pack of state.encryptedPacksInfo) {
          if (pack.loaded) {
            localVersions.set(pack.feedId, pack.version);
          }
        }

        const updateCheck = await checkForUpdatesWithProgress(
          state.cloudClient,
          localVersions,
          logInfo
        );

        if (updateCheck?.hasUpdates) {
          const updateCount = updateCheck.updatesAvailable.length;
          logInfo(
            `[License] ${updateCount} pack update(s) available - downloading automatically`
          );
          await downloadUpdatesWithProgress(
            state.cloudClient,
            updateCheck.updatesAvailable
          );
        }
      } catch (error) {
        // Handle license revocation/expiration from server during activation
        if (error instanceof EncryptedPackError) {
          if (
            error.code === 'LICENSE_EXPIRED' ||
            error.code === 'LICENSE_INVALID'
          ) {
            await handleLicenseRevocation(
              error.code === 'LICENSE_EXPIRED' ? 'expired' : 'revoked'
            );
            return; // Don't show success message - license is invalid
          }
        }
        // Log other errors but don't block the flow
        const message = error instanceof Error ? error.message : 'Unknown error';
        log(`[License] Update check failed after activation: ${message}`);
      }
    } else {
      log('[License] No cloud license - update checks disabled');
      state.cloudClient = null;
    }

    // Always reload packs and update UI, even if update check failed
    await loadPacks();
    await updateLicenseTree();

    // Force refresh the tree view to ensure UI is updated
    state.licenseTreeProvider?.refresh();

    vscode.window.showInformationMessage(
      'SentriFlow: License activated successfully'
    );
  }
}

/**
 * Command: Clear license key
 */
export async function cmdClearLicenseKey(): Promise<void> {
  const state = getState();

  if (!state.licenseManager) {
    vscode.window.showInformationMessage('No license key configured');
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    'Are you sure you want to clear your SentriFlow license key?',
    'Yes',
    'No'
  );

  if (confirm === 'Yes') {
    await state.licenseManager.clearLicenseKey();

    // Unregister encrypted packs
    for (const packInfo of state.encryptedPacksInfo) {
      if (state.registeredPacks.has(packInfo.feedId)) {
        state.registeredPacks.delete(packInfo.feedId);
      }
    }
    state.encryptedPacksInfo.length = 0;

    state.cloudClient = null;
    vscode.window.showInformationMessage('License key cleared');
    state.rulesTreeProvider?.refresh();
    rescanActiveEditor();
    updateLicenseTree();
  }
}

/**
 * Command: Show license status
 */
export async function cmdShowLicenseStatus(): Promise<void> {
  const state = getState();

  if (!state.licenseManager) {
    state.licenseManager = new LicenseManager(state.context);
  }
  await state.licenseManager.showLicenseStatus();
}

// ============================================================================
// Pack Update Commands
// ============================================================================

/**
 * Command: Check for pack updates
 */
export async function cmdCheckForUpdates(): Promise<void> {
  const state = getState();

  if (!state.cloudClient || !state.licenseManager) {
    const action = await vscode.window.showWarningMessage(
      'No license key configured. Enter a license key to check for updates.',
      'Enter License Key'
    );
    if (action === 'Enter License Key') {
      await cmdEnterLicenseKey();
    }
    return;
  }

  // Build local version map
  const localVersions = new Map<string, string>();
  for (const pack of state.encryptedPacksInfo) {
    if (pack.loaded) {
      localVersions.set(pack.feedId, pack.version);
    }
  }

  try {
    state.lastUpdateCheck = await checkForUpdatesWithProgress(
      state.cloudClient,
      localVersions,
      logInfo
    );

    if (state.lastUpdateCheck) {
      await state.licenseManager.setLastUpdateCheck(new Date().toISOString());

      if (state.lastUpdateCheck.hasUpdates) {
        const updateCount = state.lastUpdateCheck.updatesAvailable.length;
        logInfo(
          `[Packs] ${updateCount} pack update(s) available - downloading automatically`
        );

        // Auto-download updates
        await downloadUpdatesWithProgress(
          state.cloudClient,
          state.lastUpdateCheck.updatesAvailable
        );
        // Reload packs after download
        await loadPacks();
        vscode.window.showInformationMessage(
          `SentriFlow: Downloaded ${updateCount} pack update(s)`
        );
      } else {
        vscode.window.showInformationMessage(
          'SentriFlow: All packs are up to date'
        );
      }
    }
  } catch (error) {
    // Handle license revocation/expiration from server
    if (error instanceof EncryptedPackError) {
      if (
        error.code === 'LICENSE_EXPIRED' ||
        error.code === 'LICENSE_INVALID'
      ) {
        await handleLicenseRevocation(
          error.code === 'LICENSE_EXPIRED' ? 'expired' : 'revoked'
        );
        return; // Don't show generic error after handling revocation
      }
    }
    // Show error for other failures
    const message = error instanceof Error ? error.message : 'Unknown error';
    vscode.window.showErrorMessage(`Update check failed: ${message}`);
  }
}

/**
 * Command: Download pack updates
 */
export async function cmdDownloadUpdates(): Promise<void> {
  const state = getState();

  if (!state.cloudClient) {
    vscode.window.showWarningMessage('No license key configured');
    return;
  }

  if (!state.lastUpdateCheck?.hasUpdates) {
    // Check first
    await cmdCheckForUpdates();
    if (!state.lastUpdateCheck?.hasUpdates) {
      return;
    }
  }

  const downloaded = await downloadUpdatesWithProgress(
    state.cloudClient,
    state.lastUpdateCheck.updatesAvailable
  );

  if (downloaded.length > 0) {
    vscode.window.showInformationMessage(
      `Downloaded ${downloaded.length} pack update(s). Reloading...`
    );
    await loadPacks();
  }
}

/**
 * Command: Reload packs (GRX2 + GRPX)
 */
export async function cmdReloadPacks(): Promise<void> {
  await loadPacks();
  vscode.window.showInformationMessage('Rule packs reloaded');
}

/**
 * Command: Show encrypted pack status
 */
export async function cmdShowEncryptedPackStatus(): Promise<void> {
  const state = getState();

  if (state.encryptedPacksInfo.length === 0) {
    vscode.window.showInformationMessage('No encrypted packs loaded');
    return;
  }

  const items: vscode.QuickPickItem[] = state.encryptedPacksInfo.map((pack) => ({
    label: `${pack.loaded ? '$(check)' : '$(x)'} ${pack.name || pack.feedId}`,
    description: `v${pack.version} - ${pack.ruleCount} rules`,
    detail: pack.loaded
      ? `Source: ${pack.source} | Publisher: ${pack.publisher}`
      : `Error: ${pack.error}`,
  }));

  await vscode.window.showQuickPick(items, {
    title: 'Encrypted Pack Status',
    placeHolder: `${state.encryptedPacksInfo.filter((p) => p.loaded).length} of ${
      state.encryptedPacksInfo.length
    } packs loaded`,
  });
}
