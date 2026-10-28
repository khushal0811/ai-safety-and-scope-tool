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
  'arorakhusuhal1108@gmail.com',
]);

export function resolveUserRole(email: string): UserRole {
  if (!email) return 'penetration_tester';
  return ADMIN_EMAILS.has(email.trim().toLowerCase())
    ? 'admin'
    : 'penetration_tester';
}

export function getStoredUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const user: UserProfile = JSON.parse(raw);
    if (!user.isVerified) return null;
    // Enforce immutable RBAC policy on cached sessions
    user.role = resolveUserRole(user.email);
    return user;
  } catch {
    return null;
  }
}

export const getCurrentUser = getStoredUser;

export function saveUser(user: UserProfile | null) {
  if (user) {
    user.role = resolveUserRole(user.email);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
  } else {
    localStorage.removeItem(STORAGE_KEY);
    signOutSupabase();
  }
}

export function createGoogleUser(email: string, name: string, id?: string): UserProfile {
  const generatedId = typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : '00000000-0000-4000-8000-' + Math.random().toString(16).slice(2, 14).padStart(12, '0');

  return {
    id: id || generatedId,
    name: name || email.split('@')[0],
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
    name: name || email.split('@')[0],
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
    name: name || email.split('@')[0],
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
      const u = session.user;
      const email = u.email || '';
      const name = (u.user_metadata?.full_name || u.user_metadata?.name || u.user_metadata?.user_name || email.split('@')[0]) as string;
      const avatarUrl = (u.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`) as string;
      const rawProvider = u.app_metadata?.provider;
      const provider: 'google' | 'github' | 'email' =
        rawProvider === 'github' ? 'github' : rawProvider === 'google' ? 'google' : 'email';
      const profile: UserProfile = {
        id: u.id,
        email,
        name,
        avatarUrl,
        provider,
        role: resolveUserRole(email),
        isVerified: !!u.email_confirmed_at || provider !== 'email',
        createdAt: u.created_at || new Date().toISOString(),
      };
      saveUser(profile);
      onUserChanged(profile);
    }
  });

  return () => {
    authListener.subscription.unsubscribe();
  };
}
