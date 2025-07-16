import axios from 'axios';
import { sessionManager } from './session.js';

const client = axios.create({
  baseURL: process.env.NODE_ENV === 'production' ? 'https://your-production-url.com/api' : 'http://localhost:3000/api/v1', 
    withCredentials: true, 
});

// Helper function to get token from cookies
function getTokenFromCookies() {
  if (typeof document === 'undefined') return null;
  const cookies = document.cookie.split(';');
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'token') return value;
  }
  return null;
}

// Helper function to set token in cookies
function setTokenInCookies(token) {
  if (typeof document === 'undefined') return;
  document.cookie = `token=${token}; path=/; secure; samesite=strict`;
}

// Helper function to clear token from cookies
function clearTokenFromCookies() {
  if (typeof document === 'undefined') return;
  document.cookie = 'token=; Max-Age=0; path=/;';
}

// Login function 
export async function signIn(email, password) {
  try {
    sessionManager.setLoading(true);
    
    const response = await client.post('/auth/login', { email, password });
    
    if (response.data.success) {
      const { data } = response.data;
      
      // Set token in cookies if provided
      if (data.token) {
        setTokenInCookies(data.token);
      }
      

      const session = {
        user: {
          id: data.userId,
          email: data.email,
          username: data.username,
          role: data.role
        },
        expires: data.expires || null
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

// Enhanced register function
export async function signUp(email, password, username) {
  try {
    const response = await client.post('/auth/register', { email, password, username });
    
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
        message: response.data.message || 'Registration failed'
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.error || 'NETWORK_ERROR',
      message: error.response?.data?.message || 'Registration failed'
    };
  }
}

// Logout function 
export async function signOut() {
  try {
    sessionManager.setLoading(true);
    
    const response = await client.post('/auth/logout');
    
    // Clear token from cookies
    clearTokenFromCookies();
    
    // Clear session
    sessionManager.clearSession();
    
    return {
      success: true,
      message: response.data.message || 'Logout successful'
    };
  } catch (error) {
    // Even if server request fails, clear local session
    clearTokenFromCookies();
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
    const token = getTokenFromCookies();
    
    if (!token) {
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
      clearTokenFromCookies();
      return null;
    }
  } catch (error) {
    sessionManager.clearSession();
    clearTokenFromCookies();
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
