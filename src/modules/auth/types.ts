export interface RegisterDTO {
  email: string;
  password: string;
  name?: string;
  phone?: string;
}

export interface LoginDTO {
  email: string;
  password: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface TokenPayload {
  userId: string;
  role: string;
  sessionId: string;
}

export interface UserResponse {
  id: string;
  email: string;
  name: string | null;
  phone: string | null;
  role: string;
  oauthProvider: string | null;
  createdAt: Date;
}
