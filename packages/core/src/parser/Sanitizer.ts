// packages/core/src/parser/Sanitizer.ts

import { MAX_LINE_LENGTH } from '../constants';

/**
 * Control characters to remove (M-3 fix: Insufficient Input Sanitization).
 * Includes ASCII control characters except tab (\x09) which is valid whitespace.
 * - 0x00-0x08: NUL, SOH, STX, ETX, EOT, ENQ, ACK, BEL, BS
 * - 0x0B: VT (Vertical Tab)
 * - 0x0C: FF (Form Feed)
 * - 0x0E-0x1F: SO, SI, DLE, DC1-DC4, NAK, SYN, ETB, CAN, EM, SUB, ESC, FS, GS, RS, US
 * - 0x7F: DEL
 */
const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

/**
 * Unicode whitespace characters to normalize to ASCII space.
 * - \u00A0: No-Break Space
 * - \u2000-\u200A: Various width spaces (En Quad through Hair Space)
 * - \u202F: Narrow No-Break Space
 * - \u205F: Medium Mathematical Space
 * - \u3000: Ideographic Space
 */
const UNICODE_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

/**
 * Sanitizes input text by:
 * 1. Removing control characters (security hardening)
 * 2. Replacing Unicode space characters with standard ASCII space
 * 3. Trimming leading/trailing whitespace
 *
 * This function is crucial for ensuring consistent parsing of configuration files
 * that might contain non-standard characters, which could otherwise lead to
 * parsing errors, security issues, or inconsistent matching by regexes.
 *
 * @param text The input string potentially containing various control/whitespace characters.
 * @returns The sanitized string with uniform ASCII spaces and no leading/trailing whitespace.
 */
export function sanitizeText(text: string): string {
    if (typeof text !== 'string') {
        // Handle non-string input gracefully, though type-checking should prevent this.
        return String(text).trim();
    }

    return text
        .replace(CONTROL_CHARS, '')     // Remove control characters (M-3 fix)
        .replace(UNICODE_SPACES, ' ')   // Normalize Unicode spaces
        .trim();
}

/**
 * Parses a line into parameters, handling quoted strings properly.
 * This addresses M-3 where simple split(/\s+/) breaks on quoted passwords/descriptions.
 *
 * SEC-006: Added explicit length check to prevent DoS via very long strings.
 * While upstream MAX_LINE_LENGTH provides protection, direct calls could bypass it.
 *
 * @param line The sanitized line to parse into parameters.
 * @returns An array of parameter strings.
 */
export function parseParameters(line: string): string[] {
    // SEC-006: Explicit length check to prevent DoS on direct calls
    // that might bypass upstream line length validation
    if (line.length > MAX_LINE_LENGTH) {
        // Return truncated line as single parameter rather than processing
        return [line.slice(0, MAX_LINE_LENGTH)];
    }

    const params: string[] = [];
    let current = '';
    let inQuote = false;
    let quoteChar = '';

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (!char) continue;

        if (!inQuote && (char === '"' || char === "'")) {
            // Start of quoted string
            inQuote = true;
            quoteChar = char;
        } else if (inQuote && char === quoteChar) {
            // End of quoted string
            inQuote = false;
            quoteChar = '';
        } else if (!inQuote && /\s/.test(char)) {
            // Whitespace outside quotes - end of parameter
            if (current.length > 0) {
                params.push(current);
                current = '';
            }
        } else {
            // Regular character - add to current parameter
            current += char;
        }
    }

    // Don't forget the last parameter
    if (current.length > 0) {
        params.push(current);
    }

    return params;
}
