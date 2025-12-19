// packages/core/src/errors.ts

/**
 * Base error class for all SentriFlow errors.
 * Provides structured error handling with error codes.
 */
export class SentriflowError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'SentriflowError';
    // Maintains proper stack trace for where error was thrown (V8 only)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Returns a user-friendly error message without internal details.
   */
  toUserMessage(): string {
    return `[${this.code}] ${this.message}`;
  }

  /**
   * Returns a JSON representation for logging.
   */
  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
    };
  }
}

/**
 * Error thrown when configuration loading fails.
 */
export class SentriflowConfigError extends SentriflowError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('CONFIG_ERROR', message, details);
    this.name = 'SentriflowConfigError';
  }
}

/**
 * Error thrown when path validation fails.
 */
export class SentriflowPathError extends SentriflowError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('PATH_ERROR', message, details);
    this.name = 'SentriflowPathError';
  }
}

/**
 * Error thrown when parsing fails.
 */
export class SentriflowParseError extends SentriflowError {
  constructor(message: string, line?: number) {
    super('PARSE_ERROR', message, line !== undefined ? { line } : undefined);
    this.name = 'SentriflowParseError';
  }
}

/**
 * Error thrown when rule validation or execution fails.
 */
export class SentriflowRuleError extends SentriflowError {
  constructor(message: string, ruleId?: string) {
    super('RULE_ERROR', message, ruleId ? { ruleId } : undefined);
    this.name = 'SentriflowRuleError';
  }
}

/**
 * Error thrown when input size exceeds limits.
 */
export class SentriflowSizeLimitError extends SentriflowError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('SIZE_LIMIT_ERROR', message, details);
    this.name = 'SentriflowSizeLimitError';
  }
}
