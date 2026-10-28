export type UserRole = 'admin' | 'penetration_tester';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  avatarUrl: string;
  provider: 'google' | 'github' | 'email';
  role: UserRole;
  isVerified: boolean;
  createdAt: string;
}
