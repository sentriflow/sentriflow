/**
 * Suppression Helper Functions
 *
 * Pure utility functions for suppression management.
 * Extracted to allow unit testing without vscode dependency.
 */

// ============================================================================
// Constants
// ============================================================================

/** Maximum length for line preview text */
export const MAX_PREVIEW_LENGTH = 80;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Compute content hash for line tracking using djb2 algorithm.
 * This hash is used to identify specific line content across edits.
 *
 * @param line - Line text to hash
 * @returns Hash string in base36
 */
export function contentHash(line: string): string {
  const trimmed = line.trim();
  let hash = 5381;
  for (let i = 0; i < trimmed.length; i++) {
    hash = ((hash << 5) + hash) + trimmed.charCodeAt(i);
  }
  return (hash >>> 0).toString(36);
}

/**
 * Truncate line text for preview display.
 *
 * @param text - Full line text
 * @param maxLength - Maximum length (default 80)
 * @returns Truncated text with ellipsis if needed
 */
export function truncateForPreview(text: string, maxLength: number = MAX_PREVIEW_LENGTH): string {
  const trimmed = text.trim();
  if (trimmed.length <= maxLength) {
    return trimmed;
  }
  return trimmed.slice(0, maxLength - 3) + '...';
}
