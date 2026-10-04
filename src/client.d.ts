export type User = { uid: string; email: string; emailVerified: boolean; isAnonymous: boolean; providers?: string[]; aal?: number };
export type Session = { access_token: string; refresh_token: string; expires_in: number; token_type: 'bearer'; user: User; expires_at?: number };
export type AuthEvent = 'SIGNED_IN' | 'SIGNED_OUT' | 'TOKEN_REFRESHED' | 'USER_UPDATED';
export interface Storage { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void }
export interface AuthConfig { url: string; publishableKey: string; storage?: Storage; fetch?: typeof fetch }
export class ZegaAuthError extends Error { readonly code: string; readonly status: number; readonly retryAfter?: number }
export function createAuth(config: AuthConfig): {
  signUp(options: { email: string; password: string; data?: Record<string, unknown>; redirectTo?: string }): Promise<{ user: User | null; session: Session | null }>;
  signInWithPassword(options: { email: string; password: string }): Promise<{ user: User; session: Session }>;
  signInWithOtp(options: { email: string; redirectTo?: string }): Promise<unknown>;
  verifyOtp(options: { email?: string; token?: string; code?: string; type?: 'email' | 'recovery' }): Promise<{ user: User; session: Session }>;
  signOut(options?: { scope?: 'local' | 'global' | 'others' }): Promise<void>;
  getUser(options?: { verify?: 'local' | 'server' }): Promise<User | null>;
  getSession(): Promise<Session | null>;
  refreshSession(): Promise<Session | null>;
  onAuthStateChange(callback: (event: AuthEvent, session: Session | null) => void): { data: { subscription: { unsubscribe(): void } } };
  resetPasswordForEmail(email: string, options?: { redirectTo?: string }): Promise<unknown>;
  updateUser(attributes: { password?: string; data?: Record<string, unknown> }): Promise<unknown>;
  graph(options?: { schema?: string }): Promise<unknown>;
  key(): Promise<string>;
};
