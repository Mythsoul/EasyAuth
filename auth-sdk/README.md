# EasyAuth SDK

A simple, powerful authentication SDK for developers.

## Features
- Uses EasyAuth server for authentication 
- 🔐 **Complete Authentication** - Login, register, logout with JWT tokens (Automatically stores and manages tokens)
- 🌐 **OAuth Integration** - Google, GitHub, and Facebook OAuth with provider linking
- 📧 **Email Verification** - Uses the EasyAuth server's email verification system
- 🔄 **Password Reset** - Server-handled forgot password functionality
- 🏢 **Multi-Tenant Support** - Same OAuth accounts across different applications
- 🔗 **Provider Linking** - Link multiple OAuth providers to a single account
- 🔒 **Production Ready** - Built with security and performance in mind
- 📦 **Easy Integration** - Just a few lines of code to get started
- ⚛️ **React Hooks** - Built-in hooks for easy React integration

## Installation

```bash
npm install easy.auth98
```

# Please Visit Our [Documentation](https://easyauth-three.vercel.app/sdk) for more details.

### Basic Authentication

```javascript
import { signIn, signUp, signOut, getSession } from 'easy.auth98';

// Simple registration (no email verification)
const registerResult = await signUp('user@example.com', 'password123', 'username');

// Registration with email verification
const registerWithVerification = await signUp(
  'user@example.com', 
  'password123', 
  'username',
  "emailconfig" : {
    sendVerificationEmail: true,
  }
);

// Sign in
const loginResult = await signIn('user@example.com', 'password123');

// Get current session
const session = await getSession();
if (session) {
  console.log('User:', session.user);
}

// Sign out
await signOut();
```

### Email Verification Workflow

When you enable email verification during registration, the server automatically:
1. Sends a verification email to the user
2. Blocks login until email is verified
3. Provides built-in verification pages

```javascript
import { resendVerificationEmail } from 'easy.auth98';

// User clicks verification link in email → Server handles verification automatically
// Link format: https://easyauth-server.vercel.app/api/v1/verify-email?token=abc123

// If user needs a new verification email:
await resendVerificationEmail('user@example.com');

// The server provides built-in verification pages:
// ✅ Valid token → Shows success page
// ❌ Invalid/expired token → Shows error page with instructions
```

**Note**: You typically don't need to call `verifyEmail()` directly since the server's built-in verification page handles the token verification when users click the email link.

### Password Reset

```javascript
import { forgotPassword, resetPassword } from 'easy.auth98';

// Send reset email
await forgotPassword('user@example.com');

// U just need to call the forgot password method the server automatically sends a reset email with its own reset page and then u can login afterwards 

### OAuth Authentication

EasyAuth supports OAuth authentication with Google, GitHub, and Facebook providers:

```javascript
import { 
  signInWithOAuth, 
  handleOAuthCallback, 
  linkOAuthProvider, 
  unlinkOAuthProvider, 
  getLinkedProviders,
  handleOAuthLinkCallback
} from 'easy.auth98';

// OAuth Sign In
const googleLogin = () => {
  // Redirects to Google OAuth - no return value needed
  signInWithOAuth('google', '/dashboard');
};

const githubLogin = () => {
  signInWithOAuth('github', '/profile');
};

const facebookLogin = () => {
  signInWithOAuth('facebook', '/home');
};

// Handle OAuth callback (in your callback page)
const result = handleOAuthCallback();
if (result.success) {
  console.log(`Authenticated with ${result.provider}`);
  // User is now logged in, redirect or update UI
} else {
  console.error('OAuth failed:', result.message);
}

// Link additional OAuth providers (for authenticated users)
const linkGoogle = () => {
  linkOAuthProvider('google', '/settings');
};

// Get user's linked providers
const { data } = await getLinkedProviders();
console.log('Linked providers:', data.providers);
console.log('Has password:', data.hasPassword);

// Unlink a provider
await unlinkOAuthProvider(providerId);
```

### OAuth in React

```jsx
import React, { useState, useEffect } from 'react';
import { 
  signInWithOAuth, 
  handleOAuthCallback, 
  getLinkedProviders, 
  linkOAuthProvider, 
  unlinkOAuthProvider 
} from 'easy.auth98';

function OAuthComponent() {
  const [providers, setProviders] = useState([]);

  useEffect(() => {
    // Handle OAuth callback if present
    const result = handleOAuthCallback();
    if (result.success) {
      console.log('OAuth login successful!');
    }

    // Load linked providers for authenticated users
    loadProviders();
  }, []);

  const loadProviders = async () => {
    const result = await getLinkedProviders();
    if (result.success) {
      setProviders(result.data.providers);
    }
  };

  const handleOAuthLogin = (provider) => {
    signInWithOAuth(provider, '/dashboard');
  };

  const handleLinkProvider = (provider) => {
    linkOAuthProvider(provider, '/settings');
  };

  const handleUnlinkProvider = async (providerId) => {
    await unlinkOAuthProvider(providerId);
    loadProviders(); // Refresh list
  };

  return (
    <div>
      {/* OAuth Login Buttons */}
      <div>
        <h3>Login with OAuth</h3>
        <button onClick={() => handleOAuthLogin('google')}>
          Login with Google
        </button>
        <button onClick={() => handleOAuthLogin('github')}>
          Login with GitHub
        </button>
        <button onClick={() => handleOAuthLogin('facebook')}>
          Login with Facebook
        </button>
      </div>

      {/* Linked Providers Management (for authenticated users) */}
      <div>
        <h3>Linked Accounts</h3>
        {providers.map(provider => (
          <div key={provider.id}>
            <span>{provider.provider.toUpperCase()}</span>
            <button onClick={() => handleUnlinkProvider(provider.id)}>
              Unlink
            </button>
          </div>
        ))}
        
        <h4>Link Additional Accounts</h4>
        <button onClick={() => handleLinkProvider('google')}>Link Google</button>
        <button onClick={() => handleLinkProvider('github')}>Link GitHub</button>
        <button onClick={() => handleLinkProvider('facebook')}>Link Facebook</button>
      </div>
    </div>
  );
}
```

### OAuth Configuration

```javascript
import { configure } from 'easy.auth98';

// Configure SDK with custom settings
configure({
  baseURL: 'https://your-auth-server.com/api/v1',
  timeout: 15000,
  tokenCookies: {
    access: 'custom_access_token',
    refresh: 'custom_refresh_token'
  },
  tokenExpiry: {
    access: 30 * 60, // 30 minutes
    refresh: 14 * 24 * 60 * 60 // 14 days
  }
});
```

### Multi-Tenant OAuth

The system supports multi-tenant OAuth, allowing the same OAuth account to be used across different applications:

```javascript
// App 1: todoapp.com
signInWithOAuth('google'); // Uses john@gmail.com

// App 2: blogapp.com  
signInWithOAuth('google'); // Same john@gmail.com, different user record
```

## React Integration

### Using Hooks

```jsx
import React from 'react';
import { useAuth, useSession } from 'easy.auth98';

function App() {
  const { user, isAuthenticated, isLoading } = useAuth();
  const { data: session, status } = useSession();

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      {isAuthenticated ? (
        <div>
          <h1>Welcome, {user.username}!</h1>
          <p>Email: {user.email}</p>
          <p>Role: {user.role}</p>
        </div>
      ) : (
        <div>
          <h1>Please log in</h1>
        </div>
      )}
    </div>
  );
}

export default App;
```

### Session Event Listener

```javascript
import { events } from 'easy.auth98';

// Listen for session changes
const unsubscribe = events.on('session', (session, status) => {
  console.log('Session changed:', { session, status });
});

// Clean up listener
unsubscribe();
```


### Configuration 

```javascript
// No configuration needed - uses hosted EasyAuth service
import { signIn, signUp } from 'easy.auth98';
```


### Authentication Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `signUp` | `email, password, username, emailConfig?` | `Promise<Result>` | Register a new user |
| `signIn` | `email, password` | `Promise<Result>` | Authenticate user |
| `signOut` | None | `Promise<Result>` | Log out current user |
| `getSession` | None | `Promise<Session \| null>` | Get current session |
| `verifyToken` | None | `Promise<Result>` | Verify current token |

### OAuth Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `signInWithOAuth` | `provider, redirectPath?, applicationUrl?` | `Promise<Result>` | Initiate OAuth login |
| `handleOAuthCallback` | None | `Result` | Handle OAuth callback |
| `linkOAuthProvider` | `provider, redirectPath?` | `Promise<Result>` | Link OAuth provider to account |
| `unlinkOAuthProvider` | `providerId` | `Promise<Result>` | Unlink OAuth provider |
| `getLinkedProviders` | None | `Promise<Result>` | Get user's linked providers |
| `handleOAuthLinkCallback` | None | `Result` | Handle OAuth linking callback |

### Email Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `resendVerificationEmail` | `email` | `Promise<Result>` | Resend verification email |
| `forgotPassword` | `email` | `Promise<Result>` | Send password reset email |

### Utility Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `isAuthenticated` | None | `boolean` | Check if user has valid tokens |
| `refreshToken` | None | `Promise<Result>` | Manually refresh access token |
| `getUser` | None | `User \| null` | Get current user details |
| `getConfig` | None | `Config` | Get current configuration |
| `debugTokens` | None | `TokenDebugInfo` | Get token debug information |

### React Hooks

| Hook | Returns | Description |
|------|---------|-------------|
| `useAuth` | `{ user, isAuthenticated, isLoading, isUnauthenticated }` | Authentication state |
| `useSession` | `{ data, status, update }` | Session management |

## Error Types

### Authentication Errors
- `LOGIN_FAILED` - Invalid credentials
- `REGISTRATION_FAILED` - Registration failed
- `VERIFICATION_FAILED` - Email verification failed
- `RESET_PASSWORD_FAILED` - Password reset failed
- `TOKEN_REFRESH_FAILED` - Token refresh failed
- `NETWORK_ERROR` - Network connection issues
- `VALIDATION_ERROR` - Input validation errors

### OAuth Errors
- `OAUTH_INITIATION_ERROR` - Failed to start OAuth flow
- `OAUTH_ERROR` - OAuth provider error
- `OAUTH_LINK_ERROR` - Failed to link OAuth provider
- `CALLBACK_PARSE_ERROR` - Failed to parse OAuth callback
- `NO_TOKEN` - No token in OAuth callback
- `NOT_BROWSER_ENVIRONMENT` - OAuth requires browser
- `FETCH_PROVIDERS_FAILED` - Failed to get linked providers
- `UNLINK_FAILED` - Failed to unlink provider
- `PROVIDER_NOT_FOUND` - OAuth provider not found
- `INVALID_REDIRECT_URL` - Invalid or unauthorized redirect URL



## Security Features

- 🔒 Secure HTTP-only cookies for token storage
- 🔄 Automatic token refresh
- 🛡️ CSRF protection via SameSite cookies
- ⏰ Configurable token expiration
- 🔐 Secure password validation
- 📧 Email domain validation
- 🚫 Disposable email blocking

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License.

## Support

For support, email easyauth98[@gmail.com](mailto:easyauth98@gmail.com) or create an issue on GitHub.
