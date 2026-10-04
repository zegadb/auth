declare module '@zegadb/lib/client' {
  export class ZegaError extends Error {
    readonly code: string;
    readonly status: number;
    constructor(code: string, message: string, details?: { status?: number; serverCode?: string; retryAfter?: number; cause?: unknown });
  }
  export function connect(options: { url: string; key: string | (() => string | undefined | Promise<string | undefined>); schema?: string }): unknown;
}
