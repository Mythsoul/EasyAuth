import { useState, useEffect } from 'react';
import { sessionManager } from './session.js';
import { getSession } from './index.js';

// Hook for session management
export function useSession() {
  const [session, setSession] = useState(null);
  const [status, setStatus] = useState('loading');

  useEffect(() => {
    const initSession = async () => {
      try {
        const sessionData = await getSession();
        setSession(sessionData);
        setStatus(sessionData ? 'authenticated' : 'unauthenticated');
      } catch (error) {
        setSession(null);
        setStatus('unauthenticated');
      }
    };

    initSession();

    const unsubscribe = sessionManager.addListener((sessionData, sessionStatus) => {
      setSession(sessionData);
      setStatus(sessionStatus);
    });

    return unsubscribe;
  }, []);

  return {
    data: session,
    status,
    update: getSession
  };
}

// Hook for authentication status
export function useAuth() {
  const { data: session, status } = useSession();
  
  return {
    user: session?.user || null,
    isAuthenticated: status === 'authenticated',
    isLoading: status === 'loading',
    isUnauthenticated: status === 'unauthenticated'
  };
}
