import axios from "axios"; 
import { sessionManager } from './session.js';

// Default configuration for the EasyAuth server
const DEFAULT_CONFIG = {
  baseURL: 'https://easyauth-server.vercel.app/api/v1', // Default server 
  withCredentials: true,
  timeout: 10000, // 10 seconds
  tokenCookies: {
    access: 'easyauth_access_token',
    refresh: 'easyauth_refresh_token'
  },
  tokenExpiry: {
    access: 15 * 60, 
    refresh: 7 * 24 * 60 * 60 
  }
};

// Global configuration that can be customized
let config = { ...DEFAULT_CONFIG };
let client = null;

// Initialize the axios client with current config
function initializeClient() {
  client = axios.create({
    baseURL: config.baseURL,
    withCredentials: config.withCredentials,
    timeout: config.timeout
  });
  
  // Re-apply interceptors
  setupInterceptors();
}

// Configuration function to set custom server
export function configure(options = {}) {
  // Merge with existing config
  config = {
    ...config,
    ...options,
    tokenCookies: {
      ...config.tokenCookies,
      ...options.tokenCookies
    },
    tokenExpiry: {
      ...config.tokenExpiry,
      ...options.tokenExpiry
    }
  };
  
  // Reinitialize client with new config
  initializeClient();
  
  return {
    success: true,
    message: 'EasyAuth SDK configured successfully',
    config: {
      baseURL: config.baseURL,
      timeout: config.timeout,
      withCredentials: config.withCredentials
    }
  };
}

// Get current configuration
export function getConfig() {
  return {
    baseURL: config.baseURL,
    timeout: config.timeout,
    withCredentials: config.withCredentials,
    tokenCookies: { ...config.tokenCookies },
    tokenExpiry: { ...config.tokenExpiry }
  };
}

// Reset to default configuration
export function resetConfig() {
  config = { ...DEFAULT_CONFIG };
  initializeClient();
  
  return {
    success: true,
    message: 'EasyAuth SDK reset to default configuration'
  };
}

// Initialize with default config
initializeClient();

// Token storage helpers - using secure cookies
function getTokenCookieName() {
  return config.tokenCookies?.access || 'easyauth_access_token';
}

function getRefreshTokenCookieName() {
  return config.tokenCookies?.refresh || 'easyauth_refresh_token';
}

// Helper function to get cookie by name
function getCookie(name) {
  if (typeof document === 'undefined') return null;
  const cookies = document.cookie.split(';');
  for (let cookie of cookies) {
    const [cookieName, cookieValue] = cookie.trim().split('=');
    if (cookieName === name) {
      return decodeURIComponent(cookieValue);
    }
  }
  return null;
}

// Helper function to set cookie with security options
function setCookie(name, value, options = {}) {
  if (typeof document === 'undefined') return;
  
  const {
    expires = null,
    maxAge = null,
    path = '/',
    secure = window.location.protocol === 'https:',
    sameSite = 'lax' 
  } = options;
  
  let cookieString = `${name}=${encodeURIComponent(value)}`;
  
  if (expires) cookieString += `; expires=${expires.toUTCString()}`;
  if (maxAge) cookieString += `; max-age=${maxAge}`;
  if (path) cookieString += `; path=${path}`;
  if (secure) cookieString += `; secure`;
  if (sameSite) cookieString += `; samesite=${sameSite}`;
  
  document.cookie = cookieString;
}

// Helper function to delete cookie
function deleteCookie(name) {
  if (typeof document === 'undefined') return;
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
}

// Helper function to get access token from cookie
function getAccessToken() {
  return getCookie(getTokenCookieName());
}

// Helper function to get refresh token from cookie
function getRefreshToken() {
  return getCookie(getRefreshTokenCookieName());
}

// Helper function to set tokens in cookies
function setTokens(accessToken, refreshToken) {
  if (typeof window === 'undefined') return;
  
  // Use configured expiry times
  const accessMaxAge = config.tokenExpiry?.access || 15 * 60;
  const refreshMaxAge = config.tokenExpiry?.refresh || 7 * 24 * 60 * 60;
  
  // Set access token with configured expiration
  setCookie(getTokenCookieName(), accessToken, {
    maxAge: accessMaxAge,
    secure: window.location.protocol === 'https:',
    sameSite: 'lax'
  });
  
  if (refreshToken) {
    setCookie(getRefreshTokenCookieName(), refreshToken, {
      maxAge: refreshMaxAge,
      secure: window.location.protocol === 'https:',
      sameSite: 'lax'
    });
  }
}

// Helper function to clear tokens from cookies
function clearTokens() {
  if (typeof window === 'undefined') return;
  deleteCookie(getTokenCookieName());
  deleteCookie(getRefreshTokenCookieName());
}

// Helper function to refresh access token
async function refreshAccessToken() {
  try {
    const refreshToken = getRefreshToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    
    // Create a separate axios instance for refresh token to avoid interceptor loop
    const refreshClient = axios.create({
      baseURL: config.baseURL,
      withCredentials: false 
    });
    
    const response = await refreshClient.post('/auth/refresh-token', {
      refreshToken: refreshToken
    });

    if (response.data.success) {
      const { token } = response.data.data;
      setTokens(token, refreshToken);
      return token;
    } else {
      throw new Error(response.data.message || 'Token refresh failed');
    }
  } catch (error) {
    clearTokens();
    sessionManager.clearSession();
    throw error;
  }
}

// Setup interceptors function
function setupInterceptors() {
  if (!client) return;
  
  // Clear existing interceptors
  client.interceptors.request.clear();
  client.interceptors.response.clear();
  
  // Add request interceptor to include auth token
  client.interceptors.request.use(
    (config) => {
      const token = getAccessToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  // Add response interceptor to handle token refresh
  client.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;
      
      if (error.response?.status === 401 && !originalRequest._retry) {
        originalRequest._retry = true;
        
        try {
          const newToken = await refreshAccessToken();
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          return client(originalRequest);
        } catch (refreshError) {
          // Dispatch custom event for token refresh failure
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('token-refresh-failed', { detail: refreshError }));
          }
          return Promise.reject(refreshError);
        }
      }
      
      return Promise.reject(error);
    }
  );
}

// Login function 
export async function signIn(email, password, applicationUrl = '') {
  try {
    sessionManager.setLoading(true);
    
    const response = await client.post('/auth/login', { email, password, applicationUrl });
    
    if (response.data.success) {
      const { data } = response.data;
      
      // Store tokens in secure cookies
      if (data.token && data.refreshToken) {
        setTokens(data.token, data.refreshToken);
      }
      
      const session = {
        user: {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          role: data.user.role
        },
        expires: null
      };
      
      sessionManager.updateSession(session, 'authenticated');
      
      return {
        success: true,
        data: session,
        message: response.data.message
      };
    } else {
      sessionManager.setLoading(false);
      return {
        success: false,
        error: response.data.error || 'LOGIN_FAILED',
        message: response.data.message || 'Login failed'
      };
    }
  } catch (error) {
    sessionManager.setLoading(false);
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Login failed'
    };
  }
}

//  register function with optional email configuration
export async function signUp(email, password, username, applicationUrl = '', emailConfig = null) {
  try {
    const requestBody = { email, password, username, applicationUrl };
    if (emailConfig) {
      requestBody.emailConfig = emailConfig;
    }
    
    const response = await client.post('/auth/register', requestBody);
    
    if (response.data.success) {
      return {
        success: true,
        data: response.data.data,
        message: response.data.message
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'REGISTRATION_FAILED',
        message: response.data.message || 'Registration failed',
        details: response.data.details // Include validation details
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Registration failed',
      details: error.response?.data?.details // Include validation details
    };
  }
}

// Logout function 
export async function signOut() {
  try {
    sessionManager.setLoading(true);
    
    const response = await client.post('/auth/logout');
    
    // Clear tokens from cookies
    clearTokens();
    
    // Clear session
    sessionManager.clearSession();
    
    return {
      success: true,
      message: response.data.message || 'Logout successful'
    };
  } catch (error) {
    // Even if server request fails, clear local session
    clearTokens();
    sessionManager.clearSession();
    
    return {
      success: false,
      error: error.response?.data?.error || 'LOGOUT_ERROR',
      message: error.response?.data?.message || 'Logout failed'
    };
  }
}

// Get current session 
export async function getSession() {
  try {
    const token = getAccessToken();
    const refreshToken = getRefreshToken();
    
    // If no access token but refresh token exists, try to refresh first
    if (!token && refreshToken) {
      try {
        await refreshAccessToken();
        // Continue with the new token
      } catch (refreshError) {
        sessionManager.clearSession();
        return null;
      }
    } else if (!token && !refreshToken) {
      // No tokens at all
      sessionManager.clearSession();
      return null;
    }
    
    const response = await client.get('/auth/me');
    
    if (response.data.success) {
      const { data } = response.data;
      
      const session = {
        user: {
          id: data.userId,
          email: data.email,
          username: data.username,
          role: data.role
        },
        expires: null 
      };
      
      sessionManager.updateSession(session, 'authenticated');
      return session;
    } else {
      sessionManager.clearSession();
      clearTokens();
      return null;
    }
  } catch (error) {

    sessionManager.clearSession();
    clearTokens();
    return null;
  }
}

// Verify token function
export async function verifyToken() {
  try {
    const response = await client.post('/auth/verify-token');
    return response.data;
  } catch (error) {
    throw new Error(error.response?.data?.message || 'Token verification failed');
  }
}

// Manual token refresh function
export async function refreshToken() {
  try {
    const newToken = await refreshAccessToken();
    return {
      success: true,
      token: newToken,
      message: 'Token refreshed successfully'
    };
  } catch (error) {
    return {
      success: false,
      error: error.message || 'TOKEN_REFRESH_FAILED',
      message: 'Token refresh failed'
    };
  }
}

export function isAuthenticated() {
  const accessToken = getAccessToken();
  const refreshToken = getRefreshToken();
  
  return !!(accessToken || refreshToken);
}

// Get stored access token
export function getStoredAccessToken() {
  return getAccessToken();
}

// Get stored refresh token
export function getStoredRefreshToken() {
  return getRefreshToken();
}




export async function resendVerificationEmail(email, applicationUrl = '', emailConfig = null) {
  try {
    const requestBody = { email, applicationUrl };
    if (emailConfig) {
      requestBody.emailConfig = emailConfig;
    }
    
    const response = await client.post('/auth/resend-verification-email', requestBody);
    
    if (response.data.success) {
      return {
        success: true,
        message: response.data.message
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'RESEND_FAILED',
        message: response.data.message || 'Failed to resend verification email'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Failed to resend verification email'
    };
  }
}

// Email verification function
export async function verifyEmail(token) {
  try {
    const response = await client.post('/auth/verify-email', { token });
    
    if (response.data.success) {
      return {
        success: true,
        message: response.data.message
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'VERIFY_EMAIL_FAILED',
        message: response.data.message || 'Email verification failed'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Email verification failed'
    };
  }
}

// Forgot password function
export async function forgotPassword(email, applicationUrl = '') {
  try {
    const response = await client.post('/auth/forgot-password', { email, applicationUrl });
    
    if (response.data.success) {
      return {
        success: true,
        message: response.data.message
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'FORGOT_PASSWORD_FAILED',
        message: response.data.message || 'Failed to process forgot password request'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Failed to process forgot password request'
    };
  }
}


// Debug function to check token status
export function debugTokens() {
  const accessToken = getAccessToken();
  const refreshToken = getRefreshToken();
  const isAuth = !!(accessToken || refreshToken);
  
  console.log('Token Debug Info:');
  console.log('Access Token:', accessToken ? `${accessToken.substring(0, 20)}...` : 'Not found');
  console.log('Refresh Token:', refreshToken ? `${refreshToken.substring(0, 20)}...` : 'Not found');
  console.log('Is Authenticated:', isAuth);
  
  return {
    hasAccessToken: !!accessToken,
    hasRefreshToken: !!refreshToken,
    isAuthenticated: isAuth
  };
}

// OAuth authentication methods
export async function signInWithOAuth(provider, redirectPath = '', applicationUrl = '') {
  try {
    const finalApplicationUrl = applicationUrl || (typeof window !== 'undefined' ? window.location.origin : '');
    
    // Build OAuth URL with optional redirectPath
    let oauthUrl = `${config.baseURL}/auth/oauth/${provider}`;
    if (redirectPath) {
      // The server will handle relative paths automatically
      oauthUrl += `?redirectUrl=${encodeURIComponent(redirectPath)}`;
    }
    
    // For client-side usage, redirect to OAuth URL
    if (typeof window !== 'undefined') {
      window.location.href = oauthUrl;
      return {
        success: true,
        message: 'Redirecting to OAuth provider...'
      };
    } else {
      // For server-side usage, return the URL
      return {
        success: true,
        oauthUrl,
        message: 'OAuth URL generated successfully'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: 'OAUTH_INITIATION_ERROR',
      message: error.message || 'Failed to initiate OAuth flow'
    };
  }
}

// Handle OAuth callback (extract token from URL)
export function handleOAuthCallback() {
  if (typeof window === 'undefined') {
    return { success: false, error: 'NOT_BROWSER_ENVIRONMENT' };
  }
  
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const provider = urlParams.get('provider');
    const error = urlParams.get('error');
    
    if (error) {
      return {
        success: false,
        error: 'OAUTH_ERROR',
        message: decodeURIComponent(error)
      };
    }
    
    if (token) {
      // Store the token and create a session
      setTokens(token, null); // OAuth doesn't provide refresh token in callback
      
      // Clean up the URL
      const cleanUrl = window.location.origin + window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);
      
      return {
        success: true,
        provider,
        message: 'OAuth authentication successful'
      };
    }
    
    return {
      success: false,
      error: 'NO_TOKEN',
      message: 'No authentication token found in callback'
    };
  } catch (error) {
    return {
      success: false,
      error: 'CALLBACK_PARSE_ERROR',
      message: error.message || 'Failed to parse OAuth callback'
    };
  }
}

// Get linked OAuth providers
export async function getLinkedProviders() {
  try {
    const response = await client.get('/auth/oauth-providers');
    
    if (response.data.success) {
      return {
        success: true,
        data: response.data.data
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'FETCH_PROVIDERS_FAILED',
        message: response.data.message || 'Failed to fetch OAuth providers'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Failed to fetch OAuth providers'
    };
  }
}

// Link a new OAuth provider
export async function linkOAuthProvider(provider, redirectPath = '') {
  try {
    if (typeof window !== 'undefined') {
      let linkUrl = `${config.baseURL}/auth/oauth/link/${provider}`;
      if (redirectPath) {
        // The server will handle relative paths automatically
        linkUrl += `?redirectUrl=${encodeURIComponent(redirectPath)}`;
      }
      
      window.location.href = linkUrl;
      
      return {
        success: true,
        message: 'Redirecting to link OAuth provider...'
      };
    } else {
      return {
        success: false,
        error: 'NOT_BROWSER_ENVIRONMENT',
        message: 'OAuth linking requires browser environment'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: 'OAUTH_LINK_ERROR',
      message: error.message || 'Failed to initiate OAuth linking'
    };
  }
}

// Unlink an OAuth provider
export async function unlinkOAuthProvider(providerId) {
  try {
    const response = await client.delete(`/auth/oauth-providers/${providerId}`);
    
    if (response.data.success) {
      return {
        success: true,
        message: response.data.message
      };
    } else {
      return {
        success: false,
        error: response.data.error || 'UNLINK_FAILED',
        message: response.data.message || 'Failed to unlink OAuth provider'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Failed to unlink OAuth provider'
    };
  }
}

// Handle OAuth linking callback
export function handleOAuthLinkCallback() {
  if (typeof window === 'undefined') {
    return { success: false, error: 'NOT_BROWSER_ENVIRONMENT' };
  }
  
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const linked = urlParams.get('linked');
    const provider = urlParams.get('provider');
    const error = urlParams.get('error');
    
    if (error) {
      return {
        success: false,
        error: 'OAUTH_LINK_ERROR',
        message: decodeURIComponent(error)
      };
    }
    
    if (linked) {
      // Clean up the URL
      const cleanUrl = window.location.origin + window.location.pathname;
      window.history.replaceState({}, document.title, cleanUrl);
      
      return {
        success: true,
        linked: linked === 'success',
        already: linked === 'already',
        provider,
        message: linked === 'success' ? 'OAuth provider linked successfully' : 'OAuth provider was already linked'
      };
    }
    
    return {
      success: false,
      error: 'NO_LINK_STATUS',
      message: 'No linking status found in callback'
    };
  } catch (error) {
    return {
      success: false,
      error: 'CALLBACK_PARSE_ERROR',
      message: error.message || 'Failed to parse OAuth linking callback'
    };
  }
}

export const login = signIn;
export const register = signUp;
export const logout = signOut;
export const me = getSession;

// Session manager for external use
export { sessionManager };

export const events = {
  on: (event, callback) => {
    if (event === 'session') {
      return sessionManager.addListener(callback);
    }
  }
};
