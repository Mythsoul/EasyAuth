# EasyAuth SDK

A simple, powerful authentication SDK for JavaScript applications. Connect to any authentication server with just a few lines of code.

## Features

- 🔐 **Complete Authentication** - Login, register, logout with JWT tokens
- 📧 **Email Verification** - Built-in email verification system
- 🔄 **Password Reset** - Server-handled forgot password functionality  
- 🍪 **Secure Sessions** - HTTP-only cookie token storage
- ⚛️ **React Hooks** - Built-in hooks for React applications
- 🔄 **Auto Token Refresh** - Seamless token renewal
- 🌐 **Hosted Service** - Uses the official EasyAuth server (no configuration needed)
- 📱 **SSR Compatible** - Works with Next.js and other SSR frameworks

## Installation

```bash
npm install easy.auth98
```

## Quick Start

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

## Configuration

### Default (Recommended)
```javascript
// No configuration needed - uses hosted EasyAuth service
import { signIn, signUp } from 'easy.auth98';
```

### Custom Server
```javascript
import { configure } from 'easy.auth98';

// Use your own auth server
configure({
  baseURL: 'https://your-auth-server.com/api/v1'
});
```

> 📖 **Open Source**: You can host your own auth server using our [open source backend](https://github.com/Mythsoul/Easyauth/tree/main/authserver)

## API Reference

### Authentication Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `signUp` | `email, password, username, applicationUrl?, emailConfig?` | `Promise<Result>` | Register a new user |
| `signIn` | `email, password, applicationUrl?` | `Promise<Result>` | Authenticate user |
| `signOut` | None | `Promise<Result>` | Log out current user |
| `getSession` | None | `Promise<Session \| null>` | Get current session |
| `verifyToken` | None | `Promise<Result>` | Verify current token |

### Email Functions

| Function | Parameters | Returns | Description |
|----------|------------|---------|-------------|
| `resendVerificationEmail` | `email, applicationUrl?` | `Promise<Result>` | Resend verification email |
| `forgotPassword` | `email, applicationUrl?` | `Promise<Result>` | Send password reset email |

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

- `LOGIN_FAILED` - Invalid credentials
- `REGISTRATION_FAILED` - Registration failed
- `VERIFICATION_FAILED` - Email verification failed
- `RESET_PASSWORD_FAILED` - Password reset failed
- `TOKEN_REFRESH_FAILED` - Token refresh failed
- `NETWORK_ERROR` - Network connection issues
- `VALIDATION_ERROR` - Input validation errors



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
