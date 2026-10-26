export interface UserProfile {
  id: string;
  name: string;
  email: string;
  avatarUrl: string;
  provider: 'google' | 'email';
  isVerified: boolean;
  createdAt: string;
}
