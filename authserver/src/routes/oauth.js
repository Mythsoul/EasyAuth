import express from 'express';
import { 
  initiateOAuth, 
  handleOAuthCallback, 
  showOAuthError,
  getLinkedProviders,
  initiateLinkProvider,
  handleLinkCallback,
  unlinkProvider
} from '../controllers/OAuthController.js';
import { originValidator } from '../middleware/originValidator.js';
import { authenticateToken } from '../middleware/authMiddleware.js';
import { authRateLimit } from '../middleware/rateLimiter.js';

const router = express.Router();

// Public OAuth routes
router.get('/auth/oauth/:provider', authRateLimit, originValidator, initiateOAuth);
router.get('/oauth/callback/:provider', handleOAuthCallback);
router.get('/oauth/error', showOAuthError);

// Protected OAuth routes (require authentication)
router.get('/auth/oauth-providers', authenticateToken, getLinkedProviders);
router.get('/auth/oauth/link/:provider', authRateLimit, authenticateToken, initiateLinkProvider);
router.get('/oauth/callback/link/:provider', handleLinkCallback);
router.delete('/auth/oauth-providers/:providerId', authenticateToken, unlinkProvider);

export const oauthRoutes = router;
