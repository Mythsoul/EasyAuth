import fetch from 'node-fetch';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

const prisma = new PrismaClient();

export async function getOAuthTokens(provider, code) {
  try {
    const oauthConfig = {
      google: {
        tokenUrl: 'https://oauth2.googleapis.com/token',
        params: {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: `${process.env.SERVER_URL}/oauth/callback/google`,
          grant_type: 'authorization_code',
        },
      },
      github: {
        tokenUrl: 'https://github.com/login/oauth/access_token',
        params: {
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          redirect_uri: `${process.env.SERVER_URL}/oauth/callback/github`,
        },
      },
      facebook: {
        tokenUrl: 'https://graph.facebook.com/v9.0/oauth/access_token',
        params: {
          client_id: process.env.FACEBOOK_APP_ID,
          client_secret: process.env.FACEBOOK_APP_SECRET,
          redirect_uri: `${process.env.SERVER_URL}/oauth/callback/facebook`,
          grant_type: 'authorization_code',
        },
      },
    };

    const config = oauthConfig[provider];
    if (!config) throw new Error('Invalid provider');

    const response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ ...config.params, code }),
    });
    if (!response.ok) throw new Error('Token request failed');

    return await response.json();
  } catch (error) {
    throw new Error(`Error getting OAuth tokens: ${error.message}`);
  }
}

export async function fetchUserDataFromProvider(provider, tokens) {
  try {
    let userApiUrl;
    let headers = {};

    switch (provider) {
      case 'google':
        userApiUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
        headers = { Authorization: `Bearer ${tokens.access_token}` };
        break;
      case 'github':
        userApiUrl = 'https://api.github.com/user';
        headers = { Authorization: `Bearer ${tokens.access_token}` };
        break;
      case 'facebook':
        userApiUrl = `https://graph.facebook.com/me?fields=id,name,email&access_token=${tokens.access_token}`;
        break;
      default:
        throw new Error('Invalid provider');
    }

    const response = await fetch(userApiUrl, { headers });
    if (!response.ok) throw new Error('Failed to fetch user data');

    return await response.json();
  } catch (error) {
    throw new Error(`Error fetching user data from ${provider}: ${error.message}`);
  }
}

export async function createOrUpdateUserFromOAuth(provider, oauthData, applicationUrl) {
  try {
    const email = oauthData.email;
    const providerId = oauthData.id.toString();
    const username = oauthData.name || oauthData.login || oauthData.email?.split('@')[0];

    // Find existing user by email and applicationUrl
    let user = await prisma.user.findUnique({
      where: {
        email_applicationUrl: {
          email: email,
          applicationUrl: applicationUrl
        }
      },
      include: {
        oauthProviders: true
      }
    });

    if (!user) {
      // Create new user with OAuth provider
      user = await prisma.user.create({
        data: {
          email,
          username,
          applicationUrl,
          emailVerified: true, // OAuth users are pre-verified
          oauthProviders: {
            create: {
              provider,
              providerId
            }
          }
        },
        include: {
          oauthProviders: true
        }
      });
    } else {
      // Check if OAuth provider is already linked
      const existingProvider = user.oauthProviders.find(p => p.provider === provider);
      
      if (!existingProvider) {
        // Link new OAuth provider to existing user
        await prisma.oAuthProvider.create({
          data: {
            provider,
            providerId,
            userId: user.id
          }
        });
      }

      // Update user's last login time
      user = await prisma.user.update({
        where: { id: user.id },
        data: { lastLogin: new Date() },
        include: {
          oauthProviders: true
        }
      });
    }

    return user;
  } catch (error) {
    throw new Error(`Error creating/updating user: ${error.message}`);
  }
}

export function generateJwt(user) {
  return jwt.sign({
    userId: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
  }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
}

