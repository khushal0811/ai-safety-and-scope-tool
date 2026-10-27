import { createClient, type SupabaseClient, type Session, type User } from '@supabase/supabase-js';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL || 'https://xiydkzcxbtpylsaugzzn.supabase.co';
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

export const isSupabaseConfigured = Boolean(
  SUPABASE_URL &&
  SUPABASE_ANON_KEY &&
  !SUPABASE_URL.includes('your-project-id') &&
  !SUPABASE_ANON_KEY.includes('your-anon-key')
);

export const supabase: SupabaseClient | null = isSupabaseConfigured
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null;

/**
 * Send an email OTP (one-time passcode) via Supabase Auth
 */
export async function sendEmailOtp(email: string): Promise<{ error: Error | null }> {
  if (!supabase) return { error: null }; // Mock fallback in offline mode
  try {
    const { error } = await supabase.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: true,
      },
    });
    return { error };
  } catch (err: any) {
    return { error: err };
  }
}

/**
 * Verify a 6-digit email OTP
 */
export async function verifyEmailOtp(email: string, token: string): Promise<{ session: Session | null; user: User | null; error: Error | null }> {
  if (!supabase) return { session: null, user: null, error: null };
  try {
    const { data, error } = await supabase.auth.verifyOtp({
      email,
      token,
      type: 'email',
    });
    return { session: data.session, user: data.user, error };
  } catch (err: any) {
    return { session: null, user: null, error: err };
  }
}

/**
 * Sign in using Google OAuth
 */
export async function signInWithGoogle(): Promise<{ error: Error | null }> {
  if (!supabase) return { error: null };
  try {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: window.location.origin,
      },
    });
    return { error };
  } catch (err: any) {
    return { error: err };
  }
}

/**
 * Sign in using email and password
 */
export async function signInWithEmailPassword(
  email: string,
  password: string
): Promise<{ session: Session | null; user: User | null; error: Error | null }> {
  if (!supabase) return { session: null, user: null, error: null };
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    return { session: data.session, user: data.user, error };
  } catch (err: any) {
    return { session: null, user: null, error: err };
  }
}

/**
 * Register a new user using email and password
 */
export async function signUpWithEmailPassword(
  email: string,
  password: string,
  fullName?: string
): Promise<{ session: Session | null; user: User | null; error: Error | null }> {
  if (!supabase) return { session: null, user: null, error: null };
  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: fullName || email.split('@')[0],
        },
      },
    });
    return { session: data.session, user: data.user, error };
  } catch (err: any) {
    return { session: null, user: null, error: err };
  }
}

/**
 * Sign out from active Supabase session
 */
export async function signOutSupabase(): Promise<void> {
  if (!supabase) return;
  try {
    await supabase.auth.signOut();
  } catch (err) {
    console.error('Failed to sign out from Supabase:', err);
  }
}

/**
 * Check active Supabase session
 */
export async function getSupabaseSession(): Promise<Session | null> {
  if (!supabase) return null;
  try {
    const { data } = await supabase.auth.getSession();
    return data.session;
  } catch {
    return null;
  }
}
