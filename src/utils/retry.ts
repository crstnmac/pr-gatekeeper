interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  backoffFactor?: number;
  retryableErrors?: (error: unknown) => boolean;
}

interface RetryResult<T> {
  result: T;
  attempt: number;
  totalDelayMs: number;
}

/**
 * Retry an async function with exponential backoff
 */
export async function retry<T>(
  fn: (attempt: number) => Promise<T>,
  options: RetryOptions = {}
): Promise<RetryResult<T>> {
  const {
    maxAttempts = 3,
    baseDelayMs = 1000,
    maxDelayMs = 30000,
    backoffFactor = 2,
    retryableErrors = isRetryableError
  } = options;

  let lastError: unknown;
  let totalDelay = 0;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const result = await fn(attempt);
      return {
        result,
        attempt,
        totalDelayMs: totalDelay
      };
    } catch (error) {
      lastError = error;

      // Check if error is retryable
      if (!retryableErrors(error) || attempt === maxAttempts) {
        throw error;
      }

      // Calculate delay with exponential backoff
      const delay = Math.min(
        maxDelayMs,
        baseDelayMs * Math.pow(backoffFactor, attempt - 1)
      );

      totalDelay += delay;

      // Wait before retry
      await sleep(delay);
    }
  }

  // This should never be reached, but TypeScript needs it
  throw lastError;
}

/**
 * Check if an error is retryable
 */
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    // Network errors
    if (
      error.message.includes('ECONNRESET') ||
      error.message.includes('ECONNREFUSED') ||
      error.message.includes('ETIMEDOUT') ||
      error.message.includes('ENOTFOUND') ||
      error.message.includes('EAI_AGAIN')
    ) {
      return true;
    }

    // HTTP 5xx errors
    if (
      error.message.includes('502') ||
      error.message.includes('503') ||
      error.message.includes('504')
    ) {
      return true;
    }

    // GitHub API rate limit (403) or temporary (429)
    if (
      error.message.includes('403') ||
      error.message.includes('429') ||
      error.message.includes('rate limit')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create a retryable version of a function
 */
export function withRetry<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  options?: RetryOptions
): T {
  return ((...args: any[]) => retry(() => fn(...args), options)) as T;
}
