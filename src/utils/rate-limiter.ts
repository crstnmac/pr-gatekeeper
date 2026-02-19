interface RateLimitConfig {
  maxRequests?: number;
  windowMs?: number;
  queueTimeout?: number;
}

interface QueuedRequest<T> {
  resolve: (result: T) => void;
  reject: (error: Error) => void;
  timestamp: number;
}

export class RateLimiter {
  private config: Required<RateLimitConfig>;
  private requests: number[] = [];
  private queue: QueuedRequest<any>[] = [];
  private timer: NodeJS.Timeout | null = null;

  constructor(config: RateLimitConfig = {}) {
    this.config = {
      maxRequests: config.maxRequests || 5000, // GitHub default: 5000/hour
      windowMs: config.windowMs || 3600000, // 1 hour in ms
      queueTimeout: config.queueTimeout || 60000 // 60 seconds
    };
  }

  /**
   * Execute a request, respecting rate limits
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    // Check if we're within rate limits
    await this.waitForSlot();

    // Execute the request
    try {
      this.recordRequest();
      const result = await fn();
      return result;
    } catch (error) {
      // Check if it's a rate limit error (403/429)
      if (this.isRateLimitError(error)) {
        console.warn('⚠️  Rate limit hit, queuing request...');
        await this.queueRequest<T>(fn);
        return fn(); // Retry after waiting
      }
      throw error;
    }
  }

  /**
   * Wait for an available request slot
   */
  private async waitForSlot(): Promise<void> {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    // Clean old requests outside the window
    this.requests = this.requests.filter(t => t > windowStart);

    // Check if we have capacity
    if (this.requests.length < this.config.maxRequests) {
      return; // Ready to go
    }

    // Calculate wait time
    const oldestRequest = this.requests[0];
    const waitTime = windowStart + this.config.windowMs - oldestRequest;

    if (waitTime > 0) {
      console.log(`🕐 Rate limited, waiting ${waitTime}ms...`);
      await this.sleep(waitTime);
    }
  }

  /**
   * Queue a request to be executed later
   */
  private async queueRequest<T>(_request: () => Promise<T>): Promise<void> {
    return new Promise((resolve, reject) => {
      const queued: QueuedRequest<T> = {
        resolve: resolve as any,
        reject,
        timestamp: Date.now()
      };

      this.queue.push(queued);

      // Start queue processor if not running
      if (!this.timer) {
        this.processQueue();
      }
    });
  }

  /**
   * Process the queued requests
   */
  private async processQueue(): Promise<void> {
    if (this.queue.length === 0) {
      this.timer = null;
      return;
    }

    const now = Date.now();

    // Check for timed out requests
    for (const item of this.queue) {
      if (now - item.timestamp > this.config.queueTimeout) {
        item.reject(new Error('Request timed out in queue'));
        this.queue.shift(); // Remove from queue
      }
    }

    if (this.queue.length === 0) {
      this.timer = null;
      return;
    }

    // Execute next queued request
    const nextRequest = this.queue[0];
    try {
      await this.waitForSlot();
      this.recordRequest();
      // Note: We can't actually execute the original request here
      // The caller will retry
    } catch (error) {
      nextRequest.reject(error as Error);
    } finally {
      this.queue.shift();
    }

    // Process next item
    this.timer = setTimeout(() => this.processQueue(), 100) as unknown as NodeJS.Timeout;
  }

  /**
   * Record a request timestamp
   */
  private recordRequest(): void {
    this.requests.push(Date.now());
  }

  /**
   * Check if an error is a rate limit error
   */
  private isRateLimitError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return (
        message.includes('403') ||
        message.includes('429') ||
        message.includes('rate limit') ||
        message.includes('api rate limit exceeded')
      );
    }
    return false;
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current rate limit status
   */
  getStatus(): { used: number; remaining: number; resetAt: number } {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const used = this.requests.filter(t => t > windowStart).length;
    const remaining = this.config.maxRequests - used;
    const oldestRequest = this.requests[0];
    const resetAt = oldestRequest ? oldestRequest + this.config.windowMs : now + this.config.windowMs;

    return { used, remaining, resetAt };
  }

  /**
   * Reset the rate limiter
   */
  reset(): void {
    this.requests = [];
    this.queue = [];
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
