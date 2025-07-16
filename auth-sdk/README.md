# Easy Auth SDK

A Next.js Auth-style authentication SDK with session management for your authentication server.

## Features

- 🔐 **Email/Password Authentication**
- 🎯 **Session Management** (like `next-auth`)
- ⚛️ **React Hooks** (`useSession`, `useAuth`)
- 🍪 **Cookie-based Token Storage**
- 🔄 **Real-time Session Updates**
- ✅ **TypeScript-like API**

## Installation

```bash
npm install easy.auth98
```

## Quick Start

### Basic Usage

```javascript
import { signIn, signUp, signOut, getSession } from 'easy.auth98';

// Register a new user
const result = await signUp('user@example.com', 'password123', 'username');

// Sign in
const session = await signIn('user@example.com', 'password123');

// Get current session
const currentSession = await getSession();

// Sign out
await signOut();
```

### React Hooks

```jsx
import { useSession, useAuth } from 'easy.auth98';

function MyComponent() {
  const { data: session, status } = useSession();
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) return <div>Loading...</div>;

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user.email}!</p>
        <button onClick={() => signOut()}>Sign Out</button>
      </div>
    );
  }

  return <div>Please sign in</div>;
}
```

## API Reference

### Authentication Functions

#### `signIn(email, password)`
Sign in with email and password.

```javascript
const result = await signIn('user@example.com', 'password123');
// Returns: { success: true, data: sessionData, message: "Login successful" }
```

#### `signUp(email, password, username)`
Register a new user.

```javascript
const result = await signUp('user@example.com', 'password123', 'username');
// Returns: { success: true, data: userData, message: "Registration successful" }
```

#### `signOut()`
Sign out the current user.

```javascript
const result = await signOut();
// Returns: { success: true, message: "Logout successful" }
```

#### `getSession()`
Get the current session.

```javascript
const session = await getSession();
// Returns: { user: { id, email, username, role }, expires: null } or null
```

#### `verifyToken()`
Verify the current token.

```javascript
const result = await verifyToken();
// Returns: { success: true, data: userData }
```

### React Hooks

#### `useSession()`
Hook for session management.

```javascript
const { data, status, update } = useSession();
// data: session object or null
// status: 'loading' | 'authenticated' | 'unauthenticated'
// update: function to manually update session
```

#### `useAuth()`
Hook for authentication status.

```javascript
const { user, isAuthenticated, isLoading, isUnauthenticated } = useAuth();
// user: user object or null
// isAuthenticated: boolean
// isLoading: boolean
// isUnauthenticated: boolean
```

### Session Management

#### `sessionManager`
Direct access to the session manager.

```javascript
import { sessionManager } from 'easy.auth98';

// Listen to session changes
const unsubscribe = sessionManager.addListener((session, status) => {
  console.log('Session changed:', session, status);
});

// Get current session
const { data, status } = sessionManager.getSession();
```

#### `events`
Event system for authentication events.

```javascript
import { events } from 'easy.auth98';

// Listen to session events
const unsubscribe = events.on('session', (session, status) => {
  console.log('Session event:', session, status);
});
```

## Session Object Structure

```javascript
{
  user: {
    id: "user_id",
    email: "user@example.com",
    username: "username",
    role: "user"
  },
  expires: null // or expiration date
}
```

## Status Values

- `'loading'` - Session is being fetched
- `'authenticated'` - User is signed in
- `'unauthenticated'` - User is not signed in

## Error Handling

All functions return structured error responses:

```javascript
{
  success: false,
  error: 'ERROR_CODE',
  message: 'Human readable error message'
}
```

## Legacy API (Backward Compatibility)

The SDK also supports the legacy API:

```javascript
import { login, register, logout, me } from 'easy.auth98';

// These are aliases for signIn, signUp, signOut, getSession
```

## Server Integration

This SDK is designed to work with your authentication server running on `http://localhost:3000/api`. Make sure your server has the following endpoints:

- `POST /auth/login`
- `POST /auth/register`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/verify-token`

## Contributing

Feel free to submit issues and enhancement requests!

## License

ISC
