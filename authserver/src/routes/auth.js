import express from "express"; 
import { login, register, logout, refreshToken, verifyEmail, resendVerificationEmail, verifyEmailPage, forgotPassword, resetPassword, resetPasswordPage, checkAuthStatus } from "../controllers/AuthController.js";
import { originValidator, strictOriginValidator } from "../middleware/originValidator.js";
import { authenticateToken } from "../middleware/authMiddleware.js";
import { validate, authSchemas } from "../middleware/validation.js";
import { authRateLimit, loginRateLimit } from "../middleware/rateLimiter.js";
import { getOAuthTokens, createOrUpdateUserFromOAuth, generateJwt, fetchUserDataFromProvider } from "../helpers/oauthHelper.js";
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const router = express.Router(); 

router.use('/auth/*', originValidator);

// Public routes
router.post('/auth/register', authRateLimit, strictOriginValidator, validate(authSchemas.register), register);
router.post('/auth/login', loginRateLimit, strictOriginValidator, validate(authSchemas.login), login);
router.post('/auth/refresh-token', authRateLimit, validate(authSchemas.refreshToken), refreshToken);

// Auth status check (public - doesn't require authentication)
router.get('/auth/status', authRateLimit, checkAuthStatus);

// Email verification routes
router.get('/verify-email', verifyEmailPage); 
router.post('/auth/verify-email', authRateLimit, strictOriginValidator, validate(authSchemas.verifyEmail), verifyEmail);
router.post('/auth/resend-verification-email', authRateLimit, strictOriginValidator, validate(authSchemas.resendVerification), resendVerificationEmail);

// Password reset routes
router.get('/reset-password', resetPasswordPage);
router.post('/auth/forgot-password', authRateLimit, strictOriginValidator, validate(authSchemas.forgotPassword), forgotPassword);
router.post('/auth/reset-password', authRateLimit, strictOriginValidator, validate(authSchemas.resetPassword), resetPassword);

// OAuth routes
router.get('/auth/oauth/:provider', authRateLimit, originValidator, (req, res) => {
  try {
    const { provider } = req.params;
    const { redirectUrl } = req.query;
    const applicationUrl = req.applicationUrl;
    
    if (!redirectUrl) {
      return res.status(400).json({
        success: false,
        error: 'REDIRECT_URL_REQUIRED',
        message: 'redirectUrl parameter is required'
      });
    }

    // Validate that redirectUrl belongs to the same origin as applicationUrl
    try {
      const appOrigin = new URL(applicationUrl).origin;
      const redirectOrigin = new URL(redirectUrl).origin;
      
      if (appOrigin !== redirectOrigin) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_REDIRECT_URL',
          message: 'Redirect URL must belong to the same origin as the requesting application'
        });
      }
    } catch (urlError) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_URL_FORMAT',
        message: 'Invalid URL format in redirectUrl parameter'
      });
    }

    const callbackUrl = `${process.env.SERVER_URL}/oauth/callback/${provider}`;
    const state = Buffer.from(JSON.stringify({ applicationUrl, redirectUrl })).toString('base64');

    let oauthUrl;

    switch (provider) {
      case 'google':
        oauthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&response_type=code&scope=email%20profile&access_type=offline&state=${encodeURIComponent(state)}`;
        break;
      case 'github':
        oauthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=user:email&state=${encodeURIComponent(state)}`;
        break;
      case 'facebook':
        oauthUrl = `https://www.facebook.com/v9.0/dialog/oauth?client_id=${process.env.FACEBOOK_APP_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=email&state=${encodeURIComponent(state)}`;
        break;
      default:
        return res.status(400).json({ 
          success: false, 
          error: 'UNSUPPORTED_PROVIDER',
          message: 'Unsupported OAuth provider. Supported providers: google, github, facebook' 
        });
    }

    res.redirect(oauthUrl);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'OAUTH_INITIATION_ERROR',
      message: 'Failed to initiate OAuth flow'
    });
  }
});

router.get('/oauth/callback/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state, error } = req.query;

    // Handle OAuth provider errors
    if (error) {
      const errorMessage = req.query.error_description || error;
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=${encodeURIComponent(errorMessage)}`);
    }

    if (!code || !state) {
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=Missing%20authorization%20code%20or%20state`);
    }

    // Decode state parameter
    let stateData;
    try {
      stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    } catch {
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=Invalid%20state%20parameter`);
    }

    const { applicationUrl, redirectUrl } = stateData;

    const tokens = await getOAuthTokens(provider, code);
    const oauthData = await fetchUserDataFromProvider(provider, tokens);
    const user = await createOrUpdateUserFromOAuth(provider, oauthData, applicationUrl);
    const jwtToken = generateJwt(user);

    // Redirect back to client application with token
    const separator = redirectUrl.includes('?') ? '&' : '?';
    res.redirect(`${redirectUrl}${separator}token=${jwtToken}&provider=${provider}`);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.redirect(`${process.env.SERVER_URL}/oauth/error?error=${encodeURIComponent(error.message)}`);
  }
});

// OAuth error page
router.get('/oauth/error', (req, res) => {
  const { error } = req.query;
  res.status(400).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Error</title>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .error { color: #e74c3c; }
        .button { display: inline-block; padding: 12px 24px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
      </style>
    </head>
    <body>
      <h1 class="error">🔒 OAuth Authentication Error</h1>
      <p>There was an error during the authentication process:</p>
      <p><strong>${error || 'Unknown error occurred'}</strong></p>
      <a href="#" class="button" onclick="window.close()">Close</a>
    </body>
    </html>
  `);
});

// Protected routes
router.get('/auth/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      userId: req.user.userId,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role
    }
  });
});

router.post('/auth/verify-token', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      userId: req.user.userId,
      email: req.user.email,
      username: req.user.username,
      role: req.user.role
    }
  });
});

router.post('/auth/logout', authenticateToken, logout);

// OAuth provider management routes
router.get('/auth/oauth-providers', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        oauthProviders: {
          select: {
            provider: true,
            providerId: true,
            id: true
          }
        }
      }
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        providers: user.oauthProviders,
        hasPassword: !!user.password
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Failed to fetch OAuth providers'
    });
  }
});

// Link additional OAuth provider to existing account
router.get('/auth/oauth/link/:provider', authRateLimit, authenticateToken, async (req, res) => {
  try {
    const { provider } = req.params;
    const { redirectUrl } = req.query;
    const userId = req.user.userId;
    
    if (!redirectUrl) {
      return res.status(400).json({
        success: false,
        error: 'REDIRECT_URL_REQUIRED',
        message: 'redirectUrl parameter is required'
      });
    }

    // Get user's application URL from database
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { applicationUrl: true }
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      });
    }

    const applicationUrl = user.applicationUrl;

    // Validate that redirectUrl belongs to the same origin as applicationUrl
    try {
      const appOrigin = new URL(applicationUrl).origin;
      const redirectOrigin = new URL(redirectUrl).origin;
      
      if (appOrigin !== redirectOrigin) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_REDIRECT_URL',
          message: 'Redirect URL must belong to the same origin as your application'
        });
      }
    } catch (urlError) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_URL_FORMAT',
        message: 'Invalid URL format in redirectUrl parameter'
      });
    }

    const callbackUrl = `${process.env.SERVER_URL}/oauth/callback/link/${provider}`;
    const state = Buffer.from(JSON.stringify({ 
      applicationUrl, 
      redirectUrl, 
      userId,
      linkMode: true 
    })).toString('base64');

    let oauthUrl;

    switch (provider) {
      case 'google':
        oauthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&response_type=code&scope=email%20profile&access_type=offline&state=${encodeURIComponent(state)}`;
        break;
      case 'github':
        oauthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=user:email&state=${encodeURIComponent(state)}`;
        break;
      case 'facebook':
        oauthUrl = `https://www.facebook.com/v9.0/dialog/oauth?client_id=${process.env.FACEBOOK_APP_ID}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=email&state=${encodeURIComponent(state)}`;
        break;
      default:
        return res.status(400).json({ 
          success: false, 
          error: 'UNSUPPORTED_PROVIDER',
          message: 'Unsupported OAuth provider. Supported providers: google, github, facebook' 
        });
    }

    res.redirect(oauthUrl);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'OAUTH_LINK_INITIATION_ERROR',
      message: 'Failed to initiate OAuth linking flow'
    });
  }
});

// OAuth linking callback
router.get('/oauth/callback/link/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { code, state, error } = req.query;

    // Handle OAuth provider errors
    if (error) {
      const errorMessage = req.query.error_description || error;
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=${encodeURIComponent(errorMessage)}`);
    }

    if (!code || !state) {
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=Missing%20authorization%20code%20or%20state`);
    }

    // Decode state parameter
    let stateData;
    try {
      stateData = JSON.parse(Buffer.from(state, 'base64').toString());
    } catch {
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=Invalid%20state%20parameter`);
    }

    const { applicationUrl, redirectUrl, userId, linkMode } = stateData;

    if (!linkMode || !userId) {
      return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=Invalid%20linking%20state`);
    }

    const tokens = await getOAuthTokens(provider, code);
    const oauthData = await fetchUserDataFromProvider(provider, tokens);
    const providerId = oauthData.id.toString();

    // Check if this OAuth account is already linked to another user
    const existingProvider = await prisma.oAuthProvider.findUnique({
      where: {
        provider_providerId: {
          provider,
          providerId
        }
      },
      include: {
        user: true
      }
    });

    if (existingProvider) {
      if (existingProvider.userId === userId) {
        // Already linked to this user
        const separator = redirectUrl.includes('?') ? '&' : '?';
        return res.redirect(`${redirectUrl}${separator}linked=already&provider=${provider}`);
      } else {
        // Linked to different user
        return res.redirect(`${process.env.SERVER_URL}/oauth/error?error=This%20${provider}%20account%20is%20already%20linked%20to%20another%20user`);
      }
    }

    // Link the OAuth provider to the user
    await prisma.oAuthProvider.create({
      data: {
        provider,
        providerId,
        userId
      }
    });

    // Redirect back to client application with success
    const separator = redirectUrl.includes('?') ? '&' : '?';
    res.redirect(`${redirectUrl}${separator}linked=success&provider=${provider}`);
  } catch (error) {
    console.error('OAuth linking callback error:', error);
    res.redirect(`${process.env.SERVER_URL}/oauth/error?error=${encodeURIComponent(error.message)}`);
  }
});

router.delete('/auth/oauth-providers/:providerId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { providerId } = req.params;
    
    // Check if user has password or other OAuth providers
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        oauthProviders: true
      }
    });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'USER_NOT_FOUND',
        message: 'User not found'
      });
    }
    
    // Prevent user from removing their only authentication method
    if (!user.password && user.oauthProviders.length <= 1) {
      return res.status(400).json({
        success: false,
        error: 'CANNOT_REMOVE_LAST_AUTH_METHOD',
        message: 'Cannot remove your only authentication method. Set a password first or link another OAuth provider.'
      });
    }
    
    // Find and remove the OAuth provider
    const oauthProvider = await prisma.oAuthProvider.findFirst({
      where: {
        id: providerId,
        userId: userId
      }
    });
    
    if (!oauthProvider) {
      return res.status(404).json({
        success: false,
        error: 'PROVIDER_NOT_FOUND',
        message: 'OAuth provider not found'
      });
    }
    
    await prisma.oAuthProvider.delete({
      where: { id: providerId }
    });
    
    res.json({
      success: true,
      message: `${oauthProvider.provider} provider unlinked successfully`
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: 'Failed to unlink OAuth provider'
    });
  }
});

export const authRoutes = router;
