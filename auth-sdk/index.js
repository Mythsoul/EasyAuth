
export { 
  signIn, 
  signUp, 
  signOut, 
  getSession, 
  verifyToken,
  resendVerificationEmail,
  forgotPassword,
  refreshToken,
  isAuthenticated,
  getStoredAccessToken,
  getStoredRefreshToken,
  debugTokens,
  
  // Configuration functions
  configure,
  getConfig,
  resetConfig,
  
  // OAuth functions
  signInWithOAuth,
  handleOAuthCallback,
  handleOAuthLinkCallback,
  getLinkedProviders,
  linkOAuthProvider,
  unlinkOAuthProvider,
 
  sessionManager,
  events
} from './src/index.js';

export { 
  login, 
  register, 
  logout, 
  me 
} from './src/index.js';

export { useSession, useAuth } from './src/hooks.js';
