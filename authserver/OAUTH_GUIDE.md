# OAuth Authentication Guide

This authentication server supports OAuth authentication with Google, GitHub, and Facebook. The implementation follows a Firebase/Auth0-style approach, suitable for multi-tenant applications.

## Setup

### 1. Environment Variables

Add the following OAuth configuration to your `.env` file:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Facebook OAuth
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
```

### 2. OAuth Provider Setup

#### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URI: `https://your-auth-server.com/oauth/callback/google`

#### GitHub OAuth Setup

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Create a new OAuth App
3. Set Authorization callback URL: `https://your-auth-server.com/oauth/callback/github`

#### Facebook OAuth Setup

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add Facebook Login product
4. Set Valid OAuth Redirect URIs: `https://your-auth-server.com/oauth/callback/facebook`

## Usage

### Initiating OAuth Flow

To start OAuth authentication, redirect users to:

```
GET /auth/oauth/{provider}?redirectUrl={your-client-app-callback-url}
```

**Supported providers:** `google`, `github`, `facebook`

**Example:**
```javascript
// Client-side JavaScript
const initiateOAuth = (provider) => {
  const redirectUrl = encodeURIComponent(`${window.location.origin}/auth/callback`);
  const oauthUrl = `https://your-auth-server.com/api/v1/auth/oauth/${provider}?redirectUrl=${redirectUrl}`;
  
  // Open in popup or redirect
  window.location.href = oauthUrl;
  // OR for popup: window.open(oauthUrl, 'oauth', 'width=500,height=600');
};

// Usage
initiateOAuth('google');
initiateOAuth('github');
initiateOAuth('facebook');
```

### Handling OAuth Callback

After successful OAuth authentication, users will be redirected to your specified `redirectUrl` with the JWT token:

```
https://your-client-app.com/auth/callback?token=JWT_TOKEN&provider=google
```

**Example client-side handler:**
```javascript
// Handle OAuth callback
const handleOAuthCallback = () => {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  const provider = urlParams.get('provider');
  
  if (token) {
    // Store token
    localStorage.setItem('authToken', token);
    
    // Verify token and get user info
    fetch('https://your-auth-server.com/api/v1/auth/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.json())
    .then(data => {
      console.log('User authenticated:', data);
      // Redirect to app dashboard
      window.location.href = '/dashboard';
    });
  }
};
```

## API Responses

### Successful OAuth Authentication

After successful OAuth authentication, the user will be redirected to your callback URL with:

```
https://your-app.com/callback?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...&provider=google
```

### User Information

Use the JWT token to get user information:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     https://your-auth-server.com/api/v1/auth/me
```

**Response:**
```json
{
  "success": true,
  "data": {
    "userId": "cuid_12345",
    "email": "user@example.com",
    "username": "John Doe",
    "role": "USER",
    "emailVerified": true
  }
}
```

## Error Handling

### OAuth Errors

If OAuth authentication fails, users will be redirected to an error page:

```
https://your-auth-server.com/oauth/error?error=Error+message
```

### Common Error Cases

1. **Invalid redirect URL**: Redirect URL must belong to the same origin as the requesting application
2. **Missing OAuth credentials**: Check environment variables are set correctly
3. **User denies permission**: User cancelled OAuth flow
4. **Invalid provider**: Only `google`, `github`, `facebook` are supported

## Security Features

### Multi-Tenant Support

- Each user is scoped to their `applicationUrl`
- Same email can exist across different applications
- OAuth tokens are application-specific

### State Parameter Security

- Uses base64-encoded JSON with `applicationUrl` and `redirectUrl`
- Prevents CSRF attacks
- Validates redirect URL matches requesting origin

### Token Security

- JWT tokens with configurable expiration
- Refresh token support
- Token blacklisting capability

## Integration Examples

### React Integration

```jsx
import React, { useEffect, useState } from 'react';

const OAuthLogin = () => {
  const [user, setUser] = useState(null);

  const handleOAuth = (provider) => {
    const redirectUrl = `${window.location.origin}/auth/callback`;
    const oauthUrl = `${process.env.REACT_APP_AUTH_SERVER}/api/v1/auth/oauth/${provider}?redirectUrl=${encodeURIComponent(redirectUrl)}`;
    window.location.href = oauthUrl;
  };

  useEffect(() => {
    // Handle OAuth callback
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
      localStorage.setItem('authToken', token);
      // Get user info and update state
      fetchUserInfo(token);
    }
  }, []);

  const fetchUserInfo = async (token) => {
    try {
      const response = await fetch(`${process.env.REACT_APP_AUTH_SERVER}/api/v1/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      if (data.success) {
        setUser(data.data);
      }
    } catch (error) {
      console.error('Failed to fetch user info:', error);
    }
  };

  return (
    <div>
      {user ? (
        <div>Welcome, {user.username}!</div>
      ) : (
        <div>
          <button onClick={() => handleOAuth('google')}>Login with Google</button>
          <button onClick={() => handleOAuth('github')}>Login with GitHub</button>
          <button onClick={() => handleOAuth('facebook')}>Login with Facebook</button>
        </div>
      )}
    </div>
  );
};
```

### Vue.js Integration

```vue
<template>
  <div>
    <div v-if="user">
      Welcome, {{ user.username }}!
    </div>
    <div v-else>
      <button @click="handleOAuth('google')">Login with Google</button>
      <button @click="handleOAuth('github')">Login with GitHub</button>
      <button @click="handleOAuth('facebook')">Login with Facebook</button>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      user: null
    };
  },
  methods: {
    handleOAuth(provider) {
      const redirectUrl = `${window.location.origin}/auth/callback`;
      const oauthUrl = `${process.env.VUE_APP_AUTH_SERVER}/api/v1/auth/oauth/${provider}?redirectUrl=${encodeURIComponent(redirectUrl)}`;
      window.location.href = oauthUrl;
    }
  },
  mounted() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
      localStorage.setItem('authToken', token);
      this.fetchUserInfo(token);
    }
  }
};
</script>
```

## Testing

You can test OAuth functionality using curl or Postman:

```bash
# Initiate OAuth (will redirect to provider)
curl -L "https://your-auth-server.com/api/v1/auth/oauth/google?redirectUrl=https://your-app.com/callback"

# Verify token (after receiving it from callback)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     https://your-auth-server.com/api/v1/auth/me
```

## Troubleshooting

### Common Issues

1. **Redirect URI mismatch**: Ensure OAuth provider settings match your server's callback URLs
2. **CORS errors**: Configure CORS properly for your client applications
3. **Token validation fails**: Check JWT_SECRET environment variable
4. **User creation fails**: Verify database connection and Prisma schema

### Debug Mode

Enable verbose logging in development:

```env
NODE_ENV=development
LOG_LEVEL=debug
VERBOSE_LOGS=true
```

This will provide detailed logs for OAuth flows and help identify issues.
