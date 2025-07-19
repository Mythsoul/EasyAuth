import { logger } from './logger.js';

export const parseCookie = (req, cookieName) => {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;
  
  const cookies = cookieHeader.split(';');
  
  for (const cookie of cookies) {
    const trimmedCookie = cookie.trim();
    const equalIndex = trimmedCookie.indexOf('=');
    
    if (equalIndex > 0) {
      const name = trimmedCookie.substring(0, equalIndex).trim();
      const value = trimmedCookie.substring(equalIndex + 1).trim();
      
      if (name === cookieName) {
        try {
          return decodeURIComponent(value);
        } catch (error) {
          logger.warn('Cookie decoding failed', { cookieName, value, error: error.message });
          return value;
        }
      }
    }
  }
  return null;
};

export const parseAllCookies = (req) => {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return {};
  
  const cookies = {};
  const cookieArray = cookieHeader.split(';');
  
  for (const cookie of cookieArray) {
    const trimmedCookie = cookie.trim();
    const equalIndex = trimmedCookie.indexOf('=');
    
    if (equalIndex > 0) {
      const name = trimmedCookie.substring(0, equalIndex).trim();
      const value = trimmedCookie.substring(equalIndex + 1).trim();
      
      try {
        cookies[name] = decodeURIComponent(value);
      } catch {
        cookies[name] = value;
      }
    }
  }
  
  return cookies;
};

export const hasCookie = (req, cookieName) => {
  return parseCookie(req, cookieName) !== null;
};
