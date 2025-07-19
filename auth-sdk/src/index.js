import axios from "axios"; 
import { sessionManager } from './session.js';

// Hardcoded configuration for the EasyAuth server
const config = {
  baseURL: 'https://easyauth-server.vercel.app/api/v1',
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

const client = axios.create({
  baseURL: config.baseURL,
  withCredentials: config.withCredentials,
  timeout: config.timeout
});

// Token storage helpers - using secure cookies
const TOKEN_COOKIE = 'easyauth_access_token';
const REFRESH_TOKEN_COOKIE = 'easyauth_refresh_token';

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
  return getCookie(TOKEN_COOKIE);
}

// Helper function to get refresh token from cookie
function getRefreshToken() {
  return getCookie(REFRESH_TOKEN_COOKIE);
}

// Helper function to set tokens in cookies
function setTokens(accessToken, refreshToken) {
  if (typeof window === 'undefined') return;
  
  // Set access token with 15 minute expiration
  setCookie(TOKEN_COOKIE, accessToken, {
    maxAge: 15 * 60, // 15 minutes
    secure: window.location.protocol === 'https:',
    sameSite: 'lax'
  });
  
  if (refreshToken) {
    setCookie(REFRESH_TOKEN_COOKIE, refreshToken, {
      maxAge: 7 * 24 * 60 * 60, 
      secure: window.location.protocol === 'https:',
      sameSite: 'lax'
    });
  }
}

// Helper function to clear tokens from cookies
function clearTokens() {
  if (typeof window === 'undefined') return;
  deleteCookie(TOKEN_COOKIE);
  deleteCookie(REFRESH_TOKEN_COOKIE);
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
