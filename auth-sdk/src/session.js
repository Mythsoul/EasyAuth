// Session management utilities
export class SessionManager {
  constructor() {
    this.listeners = new Set();
    this.session = null;
    this.status = 'loading';
  }
  
  // Add listener for session changes
  addListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  // Notify all listeners of session changes
  notifyListeners() {
    this.listeners.forEach(callback => callback(this.session, this.status));
  }

  // Update session state
  updateSession(session, status = 'authenticated') {
    this.session = session;
    this.status = status;
    this.notifyListeners();
  }

  // Clear session
  clearSession() {
    this.session = null;
    this.status = 'unauthenticated';
    this.notifyListeners();
  }

  // Get current session
  getSession() {
    return {
      data: this.session,
      status: this.status
    };
  }

  // Set loading state
  setLoading(loading = true) {
    this.status = loading ? 'loading' : (this.session ? 'authenticated' : 'unauthenticated');
    this.notifyListeners();
  }
}

// Global session manager instance
export const sessionManager = new SessionManager();
