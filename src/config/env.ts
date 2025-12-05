import dotenv from 'dotenv';

dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'DATABASE_URL',
  'REDIS_URL',
  'JWT_SECRET',
  'JWT_ACCESS_EXPIRATION',
  'JWT_REFRESH_EXPIRATION',
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}

export const env = {
  PORT: parseInt(process.env.PORT || '3000', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Database
  DATABASE_URL: process.env.DATABASE_URL!,
  
  // Redis
  REDIS_URL: process.env.REDIS_URL!,
  
  // JWT
  JWT_SECRET: process.env.JWT_SECRET!,
  JWT_ACCESS_EXPIRATION: process.env.JWT_ACCESS_EXPIRATION!,
  JWT_REFRESH_EXPIRATION: process.env.JWT_REFRESH_EXPIRATION!,
  
  // OAuth Google
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
  
  // OAuth Apple
  APPLE_CLIENT_ID: process.env.APPLE_CLIENT_ID || '',
  APPLE_TEAM_ID: process.env.APPLE_TEAM_ID || '',
  APPLE_KEY_ID: process.env.APPLE_KEY_ID || '',
  APPLE_PRIVATE_KEY: process.env.APPLE_PRIVATE_KEY || '',
};
