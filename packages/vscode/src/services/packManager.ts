/**
 * Pack Manager Service
 *
 * Manages rule pack lifecycle: loading, licensing, updates, and configuration.
 * Handles encrypted pack decryption, cloud connectivity, and entitlement verification.
 */

import * as vscode from 'vscode';
import type { RulePack } from '@sentriflow/core';
import {
  LicenseManager,
  CloudClient,
  loadAllPacksUnified,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
  EncryptedPackError,
  type CloudPackContext,
  type CloudConnectionStatus,
  type EntitlementInfo,
  DEFAULT_PACKS_DIRECTORY,
  CACHE_DIRECTORY,
  DEFAULT_CLOUD_API_URL,
} from '../encryption';
import { getState } from '../state/context';
import { rescanActiveEditor } from './scanner';

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
// Pack Disable Handling
// ============================================================================

/**
 * Handle pack disable configuration prompts.
 * Prompts the user when a pack requests to disable default rules.
 */
export async function handlePackDisables(pack: RulePack): Promise<void> {
  if (!pack.disables) return;

  const state = getState();

  // Check if we've already prompted for this pack
  const promptedKey = `sentriflow.disablesPrompted.${pack.name}`;
  const alreadyPrompted = state.context.workspaceState.get<boolean>(
    promptedKey,
    false
  );

  if (alreadyPrompted) {
    return;
  }

  // Build description of what will be disabled
  const disableActions: string[] = [];
  if (pack.disables.all) {
    disableActions.push('disable ALL default rules');
  }
  if (pack.disables.vendors?.length) {
    disableActions.push(
      `disable default rules for vendors: ${pack.disables.vendors.join(', ')}`
    );
  }
  if (pack.disables.rules?.length) {
    const ruleCount = pack.disables.rules.length;
    disableActions.push(`disable ${ruleCount} specific default rule(s)`);
  }

  if (disableActions.length === 0) {
    return;
  }

  // Show prompt
  const message = `Pack '${pack.name}' requests to ${disableActions.join(
    ' and '
  )}. Apply these settings?`;

  const result = await vscode.window.showInformationMessage(
    message,
    { modal: false },
    'Yes, Apply',
    'No, Keep Defaults'
  );

  // Mark as prompted regardless of choice
  await state.context.workspaceState.update(promptedKey, true);

  if (result === 'Yes, Apply') {
    const config = vscode.workspace.getConfiguration('sentriflow');

    // Apply disables.all - disable default rules entirely
    if (pack.disables.all) {
      await config.update(
        'enableDefaultRules',
        false,
        vscode.ConfigurationTarget.Workspace
      );
      log(`Pack '${pack.name}': Disabled all default rules per pack request`);
    }

    // Apply disables.vendors - packs with disables.vendors will automatically override
    // those rules since they have higher priority. Just log it.
    if (pack.disables.vendors?.length) {
      log(
        `Pack '${pack.name}': Will override default rules for vendors: ${pack.disables.vendors.join(', ')}`
      );
    }

    // Apply disables.rules - add to legacy disabled rules set
    if (pack.disables.rules?.length) {
      for (const ruleId of pack.disables.rules) {
        state.disabledRuleIds.add(ruleId);
      }
      log(
        `Pack '${pack.name}': Disabled ${pack.disables.rules.length} specific default rules`
      );
    }

    vscode.window.showInformationMessage(
      `SENTRIFLOW: Applied disable settings from '${pack.name}'`
    );
    state.rulesTreeProvider.refresh();
    rescanActiveEditor();
  } else {
    log(`Pack '${pack.name}': User declined disable settings`);
  }
}

// ============================================================================
// License Revocation Handling
// ============================================================================

/**
 * Handle license revocation or expiration from the server.
 *
 * This is called when the cloud API returns LICENSE_EXPIRED or LICENSE_INVALID,
 * indicating the license has been revoked or has expired on the server side.
 */
export async function handleLicenseRevocation(
  reason: 'revoked' | 'expired'
): Promise<void> {
  const state = getState();

  if (!state.licenseManager) {
    return;
  }

  logInfo(`[License] License ${reason} - clearing caches and updating status`);

  // 1. Mark the license as invalid (updates stored status, clears TMK)
  await state.licenseManager.markLicenseInvalid(reason);

  // 2. Clear entitlements cache (prevents offline entitlement use)
  await state.licenseManager.clearEntitlementsCache();

  // 3. Clear pack cache (removes downloaded packs)
  if (state.cloudClient) {
    await state.cloudClient.clearCache();
  }

  // 4. Clear in-memory pack state
  state.encryptedPacksInfo.length = 0;
  state.registeredPacks.clear();

  // 5. Update UI to show revoked status
  if (state.licenseTreeProvider) {
    const cloudLicenseInfo = await state.licenseManager.getCloudLicenseInfo();
    state.licenseTreeProvider.setCloudLicense(cloudLicenseInfo, true); // isRevoked = true
    state.licenseTreeProvider.setEncryptedPacks([]);
  }

  // 6. Refresh rules tree and rescan editor
  try {
    state.rulesTreeProvider?.refresh();
    rescanActiveEditor();
  } catch (error) {
    const msg = error instanceof Error ? error.message : 'Unknown error';
    log(`[License] Error refreshing UI after revocation: ${msg}`);
  }

  // 7. Show user notification
  const message =
    reason === 'revoked'
      ? 'Your SentriFlow license has been revoked. Please contact support or obtain a new license.'
      : 'Your SentriFlow license has expired. Please renew your license.';

  vscode.window
    .showErrorMessage(message, 'Enter New License')
    .then(async (action) => {
      if (action === 'Enter New License') {
        // Execute the command to enter a new license
        vscode.commands.executeCommand('sentriflow.enterLicenseKey');
      }
    });
}

// ============================================================================
// Update Checking
// ============================================================================

/**
 * Check for and download pack updates from cloud.
 */
export async function checkAndDownloadUpdates(): Promise<void> {
  const state = getState();

  if (!state.cloudClient || !state.licenseManager) {
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
    // Check for updates (license errors are re-thrown)
    state.lastUpdateCheck = await checkForUpdatesWithProgress(
      state.cloudClient,
      localVersions,
      logInfo
    );

    if (state.lastUpdateCheck?.hasUpdates) {
      const updateCount = state.lastUpdateCheck.updatesAvailable.length;
      logInfo(
        `[Packs] ${updateCount} pack update(s) available - downloading automatically`
      );

      // Auto-download updates without asking
      await downloadUpdatesWithProgress(
        state.cloudClient,
        state.lastUpdateCheck.updatesAvailable
      );
      // Reload packs after download
      await loadPacks();
    }

    // Record last check time
    await state.licenseManager.setLastUpdateCheck(new Date().toISOString());
  } catch (error) {
    // Handle license revocation/expiration from server
    if (error instanceof EncryptedPackError) {
      if (error.code === 'LICENSE_EXPIRED' || error.code === 'LICENSE_INVALID') {
        await handleLicenseRevocation(
          error.code === 'LICENSE_EXPIRED' ? 'expired' : 'revoked'
        );
      }
    }
    // Re-throw other errors
    throw error;
  }
}

// ============================================================================
// Pack Loading
// ============================================================================

/**
 * Load packs from configured directory and cache.
 * Supports both GRX2 and GRPX formats with auto-detection.
 */
export async function loadPacks(): Promise<void> {
  log('[Packs] Starting loadPacks...');
  const state = getState();

  if (!state.licenseManager) {
    log('[Packs] Cannot load - no license manager initialized');
    return;
  }

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enabled = config.get<boolean>('packs.enabled', true);
  log(`[Packs] Enabled setting: ${enabled}`);

  if (!enabled) {
    log('[Packs] Packs disabled in settings');
    return;
  }

  // Get license info from both sources
  const cloudLicenseInfo = await state.licenseManager.getLicenseInfo();
  const offlineLicenseInfo = await state.licenseManager.getOfflineLicenseInfo();

  // Debug: trace what getLicenseInfo returned
  const hasLicenseKey = await state.licenseManager.hasLicenseKey();
  log(`[Packs] License check: hasKey=${hasLicenseKey}, cloudInfo=${!!cloudLicenseInfo}, offlineInfo=${!!offlineLicenseInfo}`);
  if (cloudLicenseInfo) {
    log(`[Packs] Cloud license info: expired=${cloudLicenseInfo.isExpired}, tier=${cloudLicenseInfo.payload.tier}`);
  }

  // Get offline license key separately (for extended GRX2/GRPX packs)
  const offlineLicenseKey = await state.licenseManager.getOfflineLicenseKey();
  const offlineLicenseKeys = offlineLicenseKey ? [offlineLicenseKey] : [];

  // Check if cloud license has been invalidated by server
  const isCloudLicenseInvalidated =
    await state.licenseManager.isLicenseInvalidated();

  // Check if any valid license exists
  const hasValidCloudLicense =
    cloudLicenseInfo && !cloudLicenseInfo.isExpired && !isCloudLicenseInvalidated;
  const hasValidOfflineLicense =
    offlineLicenseInfo && !offlineLicenseInfo.isExpired;

  log(`[Packs] Validity: cloudValid=${hasValidCloudLicense}, offlineValid=${hasValidOfflineLicense}, cloudInvalidated=${isCloudLicenseInvalidated}`);

  if (!hasValidCloudLicense && !hasValidOfflineLicense) {
    if (isCloudLicenseInvalidated) {
      log('[Packs] Cloud license has been revoked or expired by server');
    } else {
      log('[Packs] No valid license key configured');
    }
    return;
  }

  // Combine entitled feeds from all valid licenses
  const entitledFeeds = new Set<string>();
  if (hasValidCloudLicense) {
    for (const feed of cloudLicenseInfo.payload.feeds) {
      entitledFeeds.add(feed);
    }
    log(
      `[Packs] Cloud license valid - tier: ${cloudLicenseInfo.payload.tier}, feeds: ${cloudLicenseInfo.payload.feeds.join(', ')}`
    );
  }
  if (hasValidOfflineLicense) {
    for (const feed of offlineLicenseInfo.payload.feeds) {
      entitledFeeds.add(feed);
    }
    log(
      `[Packs] Offline license valid - tier: ${offlineLicenseInfo.payload.tier}, feeds: ${offlineLicenseInfo.payload.feeds.join(', ')}`
    );
  }
  log(`[Packs] Combined entitled feeds: ${Array.from(entitledFeeds).join(', ')}`);

  const configDirectory = config.get<string>('packs.directory', '');
  const directory = configDirectory || DEFAULT_PACKS_DIRECTORY;
  log(`[Packs] Scanning directory: ${directory}`);

  // Get actual machine ID for pack decryption
  const machineId = await state.licenseManager.getMachineId();
  log(`[Packs] Machine ID: ${machineId.substring(0, 8)}...`);

  // Check for machine-bound license mismatches (warning only)
  if (hasValidCloudLicense && cloudLicenseInfo.payload.mid) {
    if (cloudLicenseInfo.payload.mid !== machineId) {
      log(
        `[Packs] Warning: Cloud license bound to different machine (${cloudLicenseInfo.payload.mid.substring(0, 8)})`
      );
    }
  }
  if (hasValidOfflineLicense && offlineLicenseInfo.payload.mid) {
    if (offlineLicenseInfo.payload.mid !== machineId) {
      log(
        `[Packs] Warning: Offline license bound to different machine (${offlineLicenseInfo.payload.mid.substring(0, 8)})`
      );
    }
  }

  // Clear existing packs
  for (const packInfo of state.encryptedPacksInfo) {
    if (packInfo.loaded && state.registeredPacks.has(packInfo.feedId)) {
      state.registeredPacks.delete(packInfo.feedId);
    }
  }
  state.encryptedPacksInfo.length = 0;

  // Build cloud pack context for standard GRX2 packs
  let cloudContext: CloudPackContext | undefined;
  const storedCloudLicense = await state.licenseManager.getStoredCloudLicense();

  // Debug: Log what we got from stored license
  log(`[Packs] Stored license check: hasLicense=${!!storedCloudLicense}, hasKey=${!!storedCloudLicense?.licenseKey}, hasTMK=${!!storedCloudLicense?.wrappedTMK}, status=${storedCloudLicense?.status ?? 'none'}`);

  if (
    storedCloudLicense?.licenseKey &&
    storedCloudLicense?.wrappedTMK &&
    storedCloudLicense?.status !== 'revoked' &&
    storedCloudLicense?.status !== 'expired'
  ) {
    cloudContext = {
      licenseKey: storedCloudLicense.licenseKey,
      wrappedTMK: storedCloudLicense.wrappedTMK,
      wrappedTierTMKs: storedCloudLicense.wrappedTierTMKs,
      wrappedCustomerTMK: storedCloudLicense.wrappedCustomerTMK,
    };
    const tierCount = storedCloudLicense.wrappedTierTMKs
      ? Object.keys(storedCloudLicense.wrappedTierTMKs).length
      : 0;
    log(`[Packs] Cloud context available - ${tierCount} tier TMK(s), can load standard GRX2 packs`);
  } else {
    log(`[Packs] No cloud context - only extended GRX2/GRPX packs will load`);
  }

  // Load from main directory
  log(`[Packs] Loading from main directory: ${directory}`);
  const mainResult = await loadAllPacksUnified(
    directory,
    offlineLicenseKeys,
    machineId,
    Array.from(entitledFeeds),
    cloudContext,
    log
  );
  log(
    `[Packs] Main directory result: ${mainResult.packs.length} packs found, ${mainResult.errors.length} errors`
  );

  // Handle cloud connectivity and cache cleanup
  if (state.cloudClient) {
    await handleCloudConnectivity(
      state,
      entitledFeeds,
      hasValidOfflineLicense ? offlineLicenseInfo : null
    );
  }

  // Load from cache directory
  log(`[Packs] Loading from cache directory: ${CACHE_DIRECTORY}`);
  const cacheResult = await loadAllPacksUnified(
    CACHE_DIRECTORY,
    offlineLicenseKeys,
    machineId,
    Array.from(entitledFeeds),
    cloudContext,
    log
  );
  log(
    `[Packs] Cache directory result: ${cacheResult.packs.length} packs found, ${cacheResult.errors.length} errors`
  );

  // Merge results
  const allPackInfo = new Map<
    string,
    (typeof mainResult.packs)[0]
  >();
  const allLoadedPacks = new Map<
    string,
    (typeof mainResult.loadedPacks)[0]
  >();

  // Add main directory results
  for (const pack of mainResult.packs) {
    allPackInfo.set(pack.feedId, pack);
  }
  for (const loaded of mainResult.loadedPacks) {
    allLoadedPacks.set(loaded.info.feedId, loaded);
  }

  // Add cache results (prefer cache for newer versions or if main failed)
  for (const pack of cacheResult.packs) {
    const existing = allPackInfo.get(pack.feedId);
    if (!existing || (pack.loaded && !existing.loaded)) {
      allPackInfo.set(pack.feedId, { ...pack, source: 'cache' });
    }
  }
  for (const loaded of cacheResult.loadedPacks) {
    const existing = allLoadedPacks.get(loaded.info.feedId);
    if (!existing) {
      allLoadedPacks.set(loaded.info.feedId, {
        ...loaded,
        info: { ...loaded.info, source: 'cache' },
      });
    }
  }

  // Update state with merged pack info
  state.encryptedPacksInfo.push(...Array.from(allPackInfo.values()));
  log(`[Packs] Total merged packs: ${state.encryptedPacksInfo.length}`);

  // Register loaded packs with the extension
  let loadedCount = 0;
  let totalRules = 0;

  for (const [feedId, { info, pack }] of allLoadedPacks) {
    state.registeredPacks.set(feedId, {
      ...pack,
      name: feedId,
    });

    loadedCount++;
    totalRules += pack.rules.length;
    const formatLabel = info.format ? ` [${info.format.toUpperCase()}]` : '';
    logInfo(
      `Loaded pack${formatLabel}: ${feedId} v${info.version} (${pack.rules.length} rules)`
    );
  }

  if (loadedCount > 0) {
    logInfo(`Loaded ${loadedCount} pack(s) with ${totalRules} rules`);
    state.rulesTreeProvider?.refresh();
    rescanActiveEditor();
  }

  // Log errors
  const allErrors = [...mainResult.errors, ...cacheResult.errors];
  for (const error of allErrors) {
    log(`Pack error: ${error}`);
  }

  // Update license tree with loaded packs
  await updateLicenseTree();
}

/**
 * Handle cloud connectivity check and cache cleanup.
 */
async function handleCloudConnectivity(
  state: ReturnType<typeof getState>,
  entitledFeeds: Set<string>,
  offlineLicenseInfo: Awaited<
    ReturnType<LicenseManager['getOfflineLicenseInfo']>
  > | null
): Promise<void> {
  if (!state.cloudClient || !state.licenseManager) return;

  const CONNECTIVITY_CHECK_TIMEOUT_MS = 10000;

  interface ConnectivityResult {
    status: CloudConnectionStatus;
    cloudEntitledFeedIds: string[];
  }

  const checkConnectivityWithTimeout =
    async (): Promise<ConnectivityResult> => {
      return new Promise((resolve) => {
        const timeoutId = setTimeout(() => {
          log('[Cloud] Connectivity check timed out - assuming offline');
          resolve({ status: 'offline', cloudEntitledFeedIds: [] });
        }, CONNECTIVITY_CHECK_TIMEOUT_MS);

        (async () => {
          try {
            log('[Cloud] Checking cloud connectivity...');
            const cachedEntitlements =
              await state.licenseManager!.getCachedEntitlements();

            const result = await state.cloudClient!.getEntitlementsWithFallback(
              cachedEntitlements
            );
            clearTimeout(timeoutId);

            log(
              `[Cloud] Connection status: ${result.status}, fromCache: ${result.fromCache}`
            );

            const cloudFeedIds =
              result.entitlements?.feeds.map((f) => f.id) ?? [];

            if (!result.fromCache && result.entitlements) {
              await state.licenseManager!.cacheEntitlements(result.entitlements);
              log('[Cloud] Cached fresh entitlements');
            }

            if (state.licenseTreeProvider) {
              const cacheHours = cachedEntitlements
                ? Math.max(
                    0,
                    Math.floor(
                      (new Date(cachedEntitlements.expiresAt).getTime() -
                        Date.now()) /
                        (1000 * 60 * 60)
                    )
                  )
                : 0;
              state.licenseTreeProvider.setConnectionStatus(
                result.status,
                cacheHours
              );
            }

            resolve({ status: result.status, cloudEntitledFeedIds: cloudFeedIds });
          } catch (error) {
            clearTimeout(timeoutId);

            if (
              error instanceof EncryptedPackError &&
              (error.code === 'LICENSE_INVALID' ||
                error.code === 'LICENSE_EXPIRED')
            ) {
              log(`[Cloud] License error: ${error.code}`);
              resolve({ status: 'online', cloudEntitledFeedIds: [] });
            } else {
              log('[Cloud] Connection failed - operating in offline mode');
              resolve({ status: 'offline', cloudEntitledFeedIds: [] });
            }
          }
        })();
      });
    };

  const connectivityResult = await checkConnectivityWithTimeout();

  // Run cache cleanup if we're online
  if (connectivityResult.status === 'online' && state.cloudClient) {
    const allEntitledForCleanup = new Set<string>(
      connectivityResult.cloudEntitledFeedIds
    );

    // Add offline license feeds
    if (offlineLicenseInfo) {
      for (const feed of offlineLicenseInfo.payload.feeds) {
        allEntitledForCleanup.add(feed);
      }
    }

    log(
      `[Cache] Running cache cleanup. Entitled: [${Array.from(allEntitledForCleanup).join(', ')}]`
    );
    const cleanupResult = await state.cloudClient.cleanupUnentitledCache(
      Array.from(allEntitledForCleanup),
      connectivityResult.status,
      log
    );
    if (cleanupResult.deletedCount > 0) {
      logInfo(
        `[Cache] Removed ${cleanupResult.deletedCount} unentitled pack(s)`
      );
    }

    // Update entitledFeeds with cloud entitlements
    for (const feedId of connectivityResult.cloudEntitledFeedIds) {
      entitledFeeds.add(feedId);
    }
  }
}

// ============================================================================
// Pack Initialization
// ============================================================================

/**
 * Initialize the pack system during extension activation.
 */
export async function initializePacks(): Promise<void> {
  log('[Packs] Initializing pack support...');
  const state = getState();

  // Always initialize license manager
  state.licenseManager = new LicenseManager(state.context);
  log('[Packs] License manager initialized');

  const config = vscode.workspace.getConfiguration('sentriflow');
  const enabled = config.get<boolean>('packs.enabled', true);
  log(`[Packs] packs.enabled = ${enabled}`);

  // Check if we have a license key
  const hasLicense = await state.licenseManager.hasLicenseKey();
  log(`[Packs] Has license key: ${hasLicense}`);
  if (!hasLicense) {
    log('[Packs] No license key configured - packs not available');
    return;
  }

  // Get license info (for display even if packs disabled)
  const licenseInfo = await state.licenseManager.getLicenseInfo();
  if (!licenseInfo) {
    logInfo('[Packs] Failed to parse license info');
    return;
  }
  log(
    `[Packs] License info: tier=${licenseInfo.payload.tier}, expires=${licenseInfo.expiryDate}`
  );

  // Stop here if packs are disabled
  if (!enabled) {
    log('[Packs] Packs disabled by configuration');
    return;
  }

  if (licenseInfo.isExpired) {
    logInfo(`[Packs] License expired on ${licenseInfo.expiryDate}`);
    vscode.window.showWarningMessage(
      `SentriFlow license expired on ${licenseInfo.expiryDate}. Packs will not be loaded.`
    );
    return;
  }

  // Warn if expiring soon
  if (licenseInfo.daysUntilExpiry <= 14) {
    let timeText: string;
    if (licenseInfo.daysUntilExpiry <= 0) {
      const now = Math.floor(Date.now() / 1000);
      const secondsRemaining = Math.max(0, licenseInfo.payload.exp - now);
      const hoursRemaining = Math.floor(secondsRemaining / 3600);
      const minutesRemaining = Math.floor((secondsRemaining % 3600) / 60);

      if (hoursRemaining > 0) {
        timeText = hoursRemaining === 1 ? '1 hour' : `${hoursRemaining} hours`;
      } else if (minutesRemaining > 0) {
        timeText =
          minutesRemaining === 1 ? '1 minute' : `${minutesRemaining} minutes`;
      } else {
        timeText = 'moments';
      }
    } else if (licenseInfo.daysUntilExpiry === 1) {
      timeText = '1 day';
    } else {
      timeText = `${licenseInfo.daysUntilExpiry} days`;
    }
    vscode.window.showWarningMessage(
      `SentriFlow license expires in ${timeText} (${licenseInfo.expiryDate}).`
    );
  }

  // Initialize cloud client for update checks
  const cloudLicense = await state.licenseManager.getStoredCloudLicense();
  if (cloudLicense?.jwt) {
    const apiUrl = cloudLicense.apiUrl ?? DEFAULT_CLOUD_API_URL;
    log('[Packs] Cloud license available');
    state.cloudClient = new CloudClient({
      apiUrl,
      licenseKey: cloudLicense.jwt,
    });
  } else {
    log('[Packs] No cloud license - update checks disabled');
    state.cloudClient = null;
  }

  // Check auto-update setting
  const autoUpdate = config.get<string>('packs.autoUpdate', 'on-activation');
  const shouldCheckUpdates = await state.licenseManager.isUpdateCheckDue(
    autoUpdate as 'disabled' | 'on-activation' | 'daily' | 'manual'
  );

  if (shouldCheckUpdates && state.cloudClient) {
    // Check for updates in background
    checkAndDownloadUpdates().catch((err) => {
      log(`Update check failed: ${err.message}`);
    });
  }

  // Load packs
  log('[Packs] About to call loadPacks()...');
  await loadPacks();
  log('[Packs] loadPacks() returned');

  // Update license tree view
  await updateLicenseTree();
  log('[Packs] initializePacks() COMPLETED');
}

// ============================================================================
// License Tree Update
// ============================================================================

/**
 * Update the license tree view with current license and pack info.
 */
export async function updateLicenseTree(): Promise<void> {
  const state = getState();

  if (!state.licenseTreeProvider) {
    return;
  }

  // Get cloud and offline license info separately
  const cloudLicenseInfo = state.licenseManager
    ? await state.licenseManager.getCloudLicenseInfo()
    : null;
  const offlineLicenseInfo = state.licenseManager
    ? await state.licenseManager.getOfflineLicenseInfo()
    : null;

  // Check if license is revoked by server
  const isRevoked = state.licenseManager
    ? await state.licenseManager.isLicenseInvalidated()
    : false;

  // Build entitlement info from both licenses
  const entitlements: EntitlementInfo[] = [];
  const seenFeedIds = new Set<string>();

  // Get cache manifest for cached status
  const cacheManifest = state.cloudClient
    ? await state.cloudClient.loadCacheManifest()
    : null;

  // Add cloud license feeds (if not revoked)
  if (cloudLicenseInfo && !isRevoked) {
    for (const feedId of cloudLicenseInfo.payload.feeds) {
      if (seenFeedIds.has(feedId)) continue;
      seenFeedIds.add(feedId);

      const packInfo = state.encryptedPacksInfo.find((p) => p.feedId === feedId);
      const cacheEntry = cacheManifest?.entries[feedId];

      entitlements.push({
        feedId,
        name: packInfo?.name || feedId,
        source: 'cloud',
        loaded: packInfo?.loaded ?? false,
        cached: !!cacheEntry,
        version: packInfo?.version ?? cacheEntry?.version,
        ruleCount: packInfo?.ruleCount,
      });
    }
  }

  // Add offline license feeds
  if (offlineLicenseInfo && !offlineLicenseInfo.isExpired) {
    for (const feedId of offlineLicenseInfo.payload.feeds) {
      if (seenFeedIds.has(feedId)) continue;
      seenFeedIds.add(feedId);

      const packInfo = state.encryptedPacksInfo.find((p) => p.feedId === feedId);

      entitlements.push({
        feedId,
        name: packInfo?.name || feedId,
        source: 'offline',
        loaded: packInfo?.loaded ?? false,
        cached: false,
        version: packInfo?.version,
        ruleCount: packInfo?.ruleCount,
      });
    }
  }

  state.licenseTreeProvider.setCloudLicense(cloudLicenseInfo, isRevoked);
  state.licenseTreeProvider.setOfflineLicense(offlineLicenseInfo);
  state.licenseTreeProvider.setEncryptedPacks(state.encryptedPacksInfo);
  state.licenseTreeProvider.setEntitlements(entitlements);
}
