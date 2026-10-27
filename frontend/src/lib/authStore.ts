import type { UserProfile } from '../types/user';
import { supabase, signOutSupabase } from './supabaseClient';

const STORAGE_KEY = 'sst.auth.user';

export function getStoredUser(): UserProfile | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const user: UserProfile = JSON.parse(raw);
    return user.isVerified ? user : null;
  } catch {
    return null;
  }
}

export function saveUser(user: UserProfile | null) {
  if (user) {
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
      const email = u.email || 'user@pentest.local';
      const name = (u.user_metadata?.full_name || u.user_metadata?.name || email.split('@')[0]) as string;
      const avatarUrl = (u.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(email)}`) as string;
      const profile: UserProfile = {
        id: u.id,
        email,
        name,
        avatarUrl,
        provider: u.app_metadata?.provider === 'google' ? 'google' : 'email',
        isVerified: true,
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
