import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../../config/database';
import redisClient from '../../config/redis';
import { env } from '../../config/env';
import { ValidationError, ConflictError, AuthenticationError } from '../../utils/errors';
import type { RegisterDTO, TokenPair, TokenPayload, UserResponse, LoginDTO } from './types';

class AuthService {
  /**
   * Login with email and password
   * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 10.1, 10.2, 10.4
   */
  async login(data: LoginDTO): Promise<{ user: UserResponse; tokens: TokenPair }> {
    const { email, password } = data;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || !user.password) {
      throw new AuthenticationError('Invalid credentials');
    }

    // Compare password with bcrypt
    const isPasswordValid = await this.comparePassword(password, user.password);

    if (!isPasswordValid) {
      throw new AuthenticationError('Invalid credentials');
    }

    // Generate Access Token (15 min) and Refresh Token (30 days)
    const tokens = await this.generateTokenPair(user.id, user.role);

    // Return user data (excluding password) and tokens
    const userResponse: UserResponse = {
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      role: user.role,
      oauthProvider: user.oauthProvider,
      createdAt: user.createdAt,
    };

    return {
      user: userResponse,
      tokens,
    };
  }

  async register(data: RegisterDTO): Promise<{ user: UserResponse; tokens: TokenPair }> {

    const { email, password, name, phone } = data;

    // Validate email format
    if (!this.isValidEmail(email)) {
      throw new ValidationError('Invalid email format');
    }

    // Validate password length
    if (password.length < 8) {
      throw new ValidationError('Password must be at least 8 characters long');
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictError('Email already in use');
    }

    // Hash password with bcrypt
    const hashedPassword = await this.hashPassword(password);

    // Create user in database with default role CLIENT
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name || null,
        phone: phone || null,
        role: 'CLIENT', // Default role
      },
    });

    // Generate tokens
    const tokens = await this.generateTokenPair(user.id, user.role);

    // Return user data (excluding password) and tokens
    const userResponse: UserResponse = {
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      role: user.role,
      oauthProvider: user.oauthProvider,
      createdAt: user.createdAt,
    };

    return {
      user: userResponse,
      tokens,
    };
  }

  /**
   * Hash password using bcrypt with cost factor 10
   */
  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }

  /**
   * Compare password with hash using bcrypt
   */
  private async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Generate Access Token and Refresh Token pair
   */
  private async generateTokenPair(userId: string, role: string): Promise<TokenPair> {
    const sessionId = uuidv4();

    // Generate Access Token (15 minutes)
    const accessTokenPayload: TokenPayload = {
      userId,
      role,
      sessionId,
    };

    const accessToken = jwt.sign(accessTokenPayload, env.JWT_SECRET, {
      expiresIn: '15m',
    });

    // Generate Refresh Token (30 days)
    const refreshTokenPayload = {
      userId,
      sessionId,
    };

    const refreshToken = jwt.sign(refreshTokenPayload, env.JWT_SECRET, {
      expiresIn: '30d',
    });

    // Store Refresh Token in Redis - Requirement 2.3
    await this.storeRefreshToken(userId, sessionId, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Store Refresh Token in Redis with TTL
   */
  private async storeRefreshToken(
    userId: string,
    sessionId: string,
    token: string
  ): Promise<void> {
    const key = `refresh:${userId}:${sessionId}`;
    const ttl = 30 * 24 * 60 * 60; // 30 days in seconds

    await redisClient.setEx(key, ttl, token);
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}

export default new AuthService();
