# OAuth Quick Start Guide

## 🚀 Quick Setup

### 1. Install Dependencies
The OAuth functionality is already included. No additional dependencies needed.

### 2. Environment Variables
Add to your `.env` file:
```env
# Google OAuth (Get from Google Cloud Console)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth (Get from GitHub Developer Settings)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Facebook OAuth (Get from Facebook Developers)
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
```

### 3. Set Redirect URIs in OAuth Providers

#### Google Cloud Console
- Redirect URI: `https://your-server.com/oauth/callback/google`
- Link URI: `https://your-server.com/oauth/callback/link/google`

#### GitHub Developer Settings  
- Authorization callback URL: `https://your-server.com/oauth/callback/github`
- Link callback URL: `https://your-server.com/oauth/callback/link/github`

#### Facebook Developers
- Valid OAuth Redirect URIs:
  - `https://your-server.com/oauth/callback/facebook`
  - `https://your-server.com/oauth/callback/link/facebook`

## 🔧 Client Integration

### Basic OAuth Login
```javascript
// Redirect user to OAuth
const loginWithOAuth = (provider) => {
  const redirectUrl = `${window.location.origin}/auth/callback`;
  const oauthUrl = `https://your-server.com/api/v1/auth/oauth/${provider}?redirectUrl=${encodeURIComponent(redirectUrl)}`;
  window.location.href = oauthUrl;
};

// Handle callback
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');
if (token) {
  localStorage.setItem('authToken', token);
  // User is now authenticated!
}
```

### Link Additional Provider (Authenticated Users)
```javascript
// Link additional OAuth provider
const linkProvider = (provider) => {
  const redirectUrl = `${window.location.origin}/settings`;
  const linkUrl = `https://your-server.com/api/v1/auth/oauth/link/${provider}?redirectUrl=${encodeURIComponent(redirectUrl)}`;
  
  fetch(linkUrl, {
    headers: { 'Authorization': `Bearer ${authToken}` }
  }).then(response => {
    if (response.redirected) {
      window.location.href = response.url;
    }
  });
};
```

### Manage OAuth Providers
```javascript
// Get linked providers
const getProviders = async () => {
  const response = await fetch('https://your-server.com/api/v1/auth/oauth-providers', {
    headers: { 'Authorization': `Bearer ${authToken}` }
  });
  const data = await response.json();
  return data.data.providers;
};

// Unlink provider
const unlinkProvider = async (providerId) => {
  const response = await fetch(`https://your-server.com/api/v1/auth/oauth-providers/${providerId}`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${authToken}` }
  });
  return await response.json();
};
```

## 📊 API Endpoints

### Public OAuth Routes
- `GET /auth/oauth/:provider` - Initiate OAuth flow
- `GET /oauth/callback/:provider` - OAuth callback handler

### Protected OAuth Routes  
- `GET /auth/oauth-providers` - List linked providers
- `GET /auth/oauth/link/:provider` - Link additional provider
- `DELETE /auth/oauth-providers/:id` - Unlink provider

## 🔍 Testing

Test OAuth integration:
```bash
# Initiate Google OAuth (will redirect)
curl -L "https://your-server.com/api/v1/auth/oauth/google?redirectUrl=https://your-app.com/callback"

# Get user's linked providers (need auth token)
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://your-server.com/api/v1/auth/oauth-providers
```

## 🛠️ Supported Providers

| Provider | Status | Features |
|----------|--------|----------|
| Google | ✅ | Email, Profile, Private email support |
| GitHub | ✅ | Email, Profile, Private email API |
| Facebook | ✅ | Email, Profile |

## 📝 Next Steps

1. **Set up OAuth applications** with each provider
2. **Configure environment variables**
3. **Update redirect URIs** in provider settings
4. **Test OAuth flows** with your application
5. **Read full documentation** in `OAUTH_GUIDE.md`

## 🆘 Need Help?

- Check `OAUTH_GUIDE.md` for detailed documentation
- Review error messages in the OAuth error page
- Enable debug logging with `LOG_LEVEL=debug`
- Ensure all environment variables are set correctly

Happy authenticating! 🎉
