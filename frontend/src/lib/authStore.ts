import type { User } from '@supabase/supabase-js';
import type { UserProfile, UserRole } from '../types/user';
import { supabase, signOutSupabase } from './supabaseClient';

const STORAGE_KEY = 'sst.auth.user';

/**
 * Canonical super-admin email: Khushal Arora.
 * Invariant: Only this email can ever be assigned the 'admin' role.
 * All other authenticated users are assigned 'penetration_tester'.
 */
export const ADMIN_EMAILS = new Set([
  'arorakhushal1108@gmail.com',
  'arorak1108@gmail.com',
]);

export function resolveUserRole(email: string): UserRole {
  if (!email) return 'penetration_tester';
  return ADMIN_EMAILS.has(email.trim().toLowerCase())
    ? 'admin'
    : 'penetration_tester';
}

function clearStoredUser(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore storage errors
  }
}

function displayNameFromEmail(email: string): string {
  return email.split('@')[0] || email;
}

function profileFromAuthUser(u: User): UserProfile {
  const email = u.email || '';
  const name = (u.user_metadata?.full_name ||
    u.user_metadata?.name ||
    u.user_metadata?.user_name ||
    displayNameFromEmail(email)) as string;
  const avatarUrl = (u.user_metadata?.avatar_url ||
    `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`) as string;
  const rawProvider = u.app_metadata?.provider;
  const provider: 'google' | 'github' | 'email' =
    rawProvider === 'github' ? 'github' : rawProvider === 'google' ? 'google' : 'email';

  return {
    id: u.id,
    email,
    name,
    avatarUrl,
    provider,
    role: resolveUserRole(email),
    isVerified: Boolean(u.email_confirmed_at) || provider !== 'email',
    createdAt: u.created_at || new Date().toISOString(),
  };
}

/**
 * Validate the cached session against the Supabase auth server before trusting it.
 * The localStorage profile is only a UI cache; it must never be the sole proof of
 * authentication (see AUDIT_004 H1).
 */
export async function loadAuthenticatedUser(): Promise<UserProfile | null> {
  if (!supabase) {
    clearStoredUser();
    return null;
  }

  try {
    const { data, error } = await supabase.auth.getUser();
    const authUser = data.user;
    if (error || !authUser || !authUser.email) {
      clearStoredUser();
      return null;
    }

    const profile = profileFromAuthUser(authUser);
    if (!profile.isVerified) {
      clearStoredUser();
      return null;
    }

    saveUser(profile);
    return profile;
  } catch {
    clearStoredUser();
    return null;
  }
}

export function saveUser(user: UserProfile | null) {
  if (user) {
    user.role = resolveUserRole(user.email);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
  } else {
    clearStoredUser();
    signOutSupabase();
  }
}

export function createGoogleUser(email: string, name: string, id?: string): UserProfile {
  const generatedId = typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : '00000000-0000-4000-8000-' + Math.random().toString(16).slice(2, 14).padStart(12, '0');

  return {
    id: id || generatedId,
    name: name || displayNameFromEmail(email),
    email,
    avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`,
    provider: 'google',
    role: resolveUserRole(email),
    isVerified: true,
    createdAt: new Date().toISOString(),
  };
}

export function createGithubUser(email: string, name: string, id?: string): UserProfile {
  const generatedId = typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : '00000000-0000-4000-8000-' + Math.random().toString(16).slice(2, 14).padStart(12, '0');

  return {
    id: id || generatedId,
    name: name || displayNameFromEmail(email),
    email,
    avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`,
    provider: 'github',
    role: resolveUserRole(email),
    isVerified: true,
    createdAt: new Date().toISOString(),
  };
}

export function createEmailUser(email: string, name: string, isVerified = false, id?: string): UserProfile {
  const generatedId = typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : '00000000-0000-4000-8000-' + Math.random().toString(16).slice(2, 14).padStart(12, '0');

  return {
    id: id || generatedId,
    name: name || displayNameFromEmail(email),
    email,
    avatarUrl: `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`,
    provider: 'email',
    role: resolveUserRole(email),
    isVerified,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Listen to Supabase Auth state changes and return active user profile
 */
export function initSupabaseAuthListener(onUserChanged: (user: UserProfile | null) => void) {
  if (!supabase) return () => {};

  const { data: authListener } = supabase.auth.onAuthStateChange((_event, session) => {
    if (session?.user) {
      const profile = profileFromAuthUser(session.user);
      saveUser(profile);
      onUserChanged(profile);
    } else {
      clearStoredUser();
      onUserChanged(null);
    }
  });

  return () => {
    authListener.subscription.unsubscribe();
  };
}
