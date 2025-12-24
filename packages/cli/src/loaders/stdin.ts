/**
 * Stdin loader for reading configuration content from stdin.
 * FR-017: Accept `-` as file argument to read from stdin.
 */
import { MAX_CONFIG_SIZE } from '@sentriflow/core';

/**
 * Result of reading from stdin
 */
export interface StdinReadResult {
  success: boolean;
  content?: string;
  error?: string;
}

/**
 * Reads configuration content from stdin.
 * FR-017: Accept `-` as file argument to read configuration from stdin.
 * FR-019: Display clear error when no data is piped.
 * FR-022: Apply same size limit as file input (MAX_CONFIG_SIZE).
 *
 * @returns Promise resolving to read result
 */
export async function readStdin(): Promise<StdinReadResult> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let sizeLimitExceeded = false;

    // Set encoding for proper character handling
    stdin.setEncoding('utf8');

    // Check if stdin is a TTY (no piped input)
    if (stdin.isTTY) {
      resolve({
        success: false,
        error: 'No input received from stdin',
      });
      return;
    }

    stdin.on('data', (chunk: string | Buffer) => {
      if (sizeLimitExceeded) return;

      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
      totalSize += buffer.length;

      // FR-022: Size limit check
      if (totalSize > MAX_CONFIG_SIZE) {
        sizeLimitExceeded = true;
        resolve({
          success: false,
          error: `Input exceeds maximum size (${totalSize} > ${MAX_CONFIG_SIZE} bytes)`,
        });
        // Stop reading more data
        stdin.destroy();
        return;
      }

      chunks.push(buffer);
    });

    stdin.on('end', () => {
      if (sizeLimitExceeded) return;

      const content = Buffer.concat(chunks).toString('utf8');

      // FR-019: Empty input check
      if (content.length === 0) {
        resolve({
          success: false,
          error: 'No input received from stdin',
        });
        return;
      }

      resolve({
        success: true,
        content,
      });
    });

    stdin.on('error', (err) => {
      resolve({
        success: false,
        error: `Failed to read from stdin: ${err.message}`,
      });
    });

    // Set a reasonable timeout for stdin reading
    const timeout = setTimeout(() => {
      if (chunks.length === 0 && !sizeLimitExceeded) {
        stdin.destroy();
        resolve({
          success: false,
          error: 'No input received from stdin (timeout)',
        });
      }
    }, 100); // Short timeout since we check isTTY first

    stdin.on('end', () => clearTimeout(timeout));
    stdin.on('error', () => clearTimeout(timeout));
  });
}

/**
 * Validates stdin argument usage.
 * FR-020: `-` cannot be combined with other files or directory mode.
 *
 * @param files - Array of file arguments
 * @param hasDirectory - Whether -D option is specified
 * @returns Validation result
 */
export function validateStdinArgument(
  files: string[],
  hasDirectory: boolean
): { valid: boolean; error?: string } {
  const hasStdin = files.includes('-');

  if (!hasStdin) {
    return { valid: true };
  }

  // FR-020: `-` cannot be combined with other files
  if (files.length > 1) {
    return {
      valid: false,
      error: 'Cannot combine stdin (-) with other file arguments',
    };
  }

  // FR-020: `-` cannot be combined with -D directory mode
  if (hasDirectory) {
    return {
      valid: false,
      error: 'Cannot combine stdin (-) with directory mode (-D)',
    };
  }

  return { valid: true };
}

/**
 * Checks if stdin input is requested.
 * @param files - Array of file arguments
 * @returns true if `-` is the only file argument
 */
export function isStdinRequested(files: string[]): boolean {
  return files.length === 1 && files[0] === '-';
}
