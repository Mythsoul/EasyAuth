import fetch from 'node-fetch';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

const prisma = new PrismaClient();

export async function getOAuthTokens(provider, code) {
  try {
    if (provider === 'github') {
      const response = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'EasyAuth/1.0'
        },
        body: new URLSearchParams({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code: code,
          redirect_uri: `${process.env.SERVER_URL}/oauth/callback/github`
        })
      });

      if (!response.ok) {
        throw new Error('GitHub authentication failed');
      }

      const githubToken = await response.json();
      
      // Generate our own token format
      return {
        access_token: githubToken.access_token,
        token_type: 'Bearer',
        expires_in: parseInt(process.env.JWT_EXPIRES_IN) || 3600,
        provider: 'github',
        scope: githubToken.scope
      };
    }

    // Handle other providers
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
    
    if (!response.ok) throw new Error(`${provider} authentication failed`);

    const tokens = await response.json();
    tokens.provider = provider;
    return tokens;
  } catch (error) {
    throw new Error(`Error getting OAuth tokens: ${error.message}`);
  }
}

export async function fetchUserDataFromProvider(provider, tokens) {
  try {
    let userData;
    let headers = { Authorization: `Bearer ${tokens.access_token}` };

    switch (provider) {
      case 'google':
        const googleResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers });
        if (!googleResponse.ok) throw new Error('Failed to fetch Google user data');
        userData = await googleResponse.json();
        break;
        
      case 'github':
        // Fetch user profile
        const githubUserResponse = await fetch('https://api.github.com/user', { headers });
        if (!githubUserResponse.ok) throw new Error('Failed to fetch GitHub user data');
        const githubUser = await githubUserResponse.json();
        
        // If email is private, fetch from emails API
        if (!githubUser.email) {
          const emailsResponse = await fetch('https://api.github.com/user/emails', { headers });
          if (emailsResponse.ok) {
            const emails = await emailsResponse.json();
            const primaryEmail = emails.find(email => email.primary && email.verified);
            if (primaryEmail) {
              githubUser.email = primaryEmail.email;
            }
          }
        }
        
        userData = githubUser;
        break;
        
      case 'facebook':
        const facebookResponse = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${tokens.access_token}`);
        if (!facebookResponse.ok) throw new Error('Failed to fetch Facebook user data');
        userData = await facebookResponse.json();
        break;
        
      default:
        throw new Error('Invalid provider');
    }

    if (!userData.email) {
      throw new Error(`No email address available from ${provider}. Please ensure your ${provider} account has a verified email address.`);
    }

    return userData;
  } catch (error) {
    throw new Error(`Error fetching user data from ${provider}: ${error.message}`);
  }
}

export async function createOrUpdateUserFromOAuth(provider, oauthData, applicationUrl) {
  try {
    const email = oauthData.email;
    const providerId = oauthData.id.toString();
    const username = oauthData.name || oauthData.login || oauthData.email?.split('@')[0];

    // First check if this OAuth provider is already linked to a user for this specific application
    const existingOAuthProvider = await prisma.oAuthProvider.findFirst({
      where: {
        provider: provider,
        providerId: providerId,
        user: {
          applicationUrl: applicationUrl
        }
      },
      include: {
        user: true
      }
    });

    if (existingOAuthProvider) {
      // This OAuth account is already linked to a user for this application
      // Check if it's for the same email
      if (existingOAuthProvider.user.email === email) {
        // Same user, just update last login
        const user = await prisma.user.update({
          where: { id: existingOAuthProvider.user.id },
          data: { lastLogin: new Date() },
          include: {
            oauthProviders: true
          }
        });
        return user;
      } else {
        // Different user email but same OAuth account for this application - this shouldn't happen
        throw new Error(`USER_ALREADY_EXISTS:This ${provider} account is already linked to a different user in this application`);
      }
    }

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
          password : uuidv4(), 
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
      // Check if OAuth provider is already linked to this user
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
    throw error; // Re-throw to preserve the specific error
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

