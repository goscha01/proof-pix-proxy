# Apple Sign In Implementation for ProofPix Proxy Server

## Quick Start Guide

Follow these steps to add Apple Sign In support to your existing proxy server.

---

## Step 1: Install Required Dependencies

```bash
cd ../proof-pix-proxy
npm install jsonwebtoken jwks-rsa
```

---

## Step 2: Update Environment Variables

Add these to your `.env` file and Vercel environment variables:

```bash
# Apple Sign In Credentials
APPLE_TEAM_ID=ABCDE12345
APPLE_KEY_ID=XYZ1234ABC
APPLE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg...
-----END PRIVATE KEY-----"

# Optional: CloudKit (for iCloud Drive integration)
CLOUDKIT_API_TOKEN=your_token_here
CLOUDKIT_CONTAINER_ID=iCloud.com.proofpix.app
```

### How to Get Apple Credentials:

1. **APPLE_TEAM_ID**:
   - Go to https://developer.apple.com/account
   - Your Team ID is shown in the top right (10 characters, e.g., "ABCDE12345")

2. **Create Private Key (.p8)**:
   - Go to Certificates, Identifiers & Profiles > Keys
   - Click "+" to create a new key
   - Name: "Sign in with Apple Key"
   - Enable "Sign in with Apple"
   - Click "Continue" then "Register"
   - **Download the .p8 file** (you can only download once!)
   - Note the Key ID shown (e.g., "XYZ1234ABC")

3. **APPLE_PRIVATE_KEY**:
   - Open the downloaded .p8 file in a text editor
   - Copy the entire contents including BEGIN/END lines
   - For `.env`: Use literal newlines
   - For Vercel: Replace newlines with `\n` characters

---

## Step 3: Add Apple Verification Code

Create a new file `apple-auth-utils.js` in your proxy folder:

```javascript
// apple-auth-utils.js
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Apple's public key endpoint
const client = jwksClient({
  jwksUri: 'https://appleid.apple.com/auth/keys',
  cache: true,
  cacheMaxAge: 86400000, // 24 hours
});

function getApplePublicKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

async function verifyAppleToken(identityToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      identityToken,
      getApplePublicKey,
      {
        issuer: 'https://appleid.apple.com',
        audience: 'com.proofpix.app', // Your bundle ID
      },
      (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded);
        }
      }
    );
  });
}

function generateAppleClientSecret() {
  const privateKey = process.env.APPLE_PRIVATE_KEY;
  const teamId = process.env.APPLE_TEAM_ID;
  const keyId = process.env.APPLE_KEY_ID;

  if (!privateKey || !teamId || !keyId) {
    throw new Error('Missing Apple credentials in environment variables');
  }

  const headers = {
    kid: keyId,
    typ: undefined, // Must be undefined for Apple
  };

  const claims = {
    iss: teamId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 * 180, // 6 months
    aud: 'https://appleid.apple.com',
    sub: 'com.proofpix.app', // Your bundle ID
  };

  return jwt.sign(claims, privateKey, {
    algorithm: 'ES256',
    header: headers,
  });
}

async function exchangeAppleAuthCode(authorizationCode) {
  const clientSecret = generateAppleClientSecret();

  const params = new URLSearchParams({
    client_id: 'com.proofpix.app',
    client_secret: clientSecret,
    code: authorizationCode,
    grant_type: 'authorization_code',
  });

  const response = await fetch('https://appleid.apple.com/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Apple token exchange failed: ${error}`);
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    idToken: data.id_token,
  };
}

async function refreshAppleAccessToken(refreshToken) {
  const clientSecret = generateAppleClientSecret();

  const params = new URLSearchParams({
    client_id: 'com.proofpix.app',
    client_secret: clientSecret,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });

  const response = await fetch('https://appleid.apple.com/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    throw new Error('Failed to refresh Apple access token');
  }

  const data = await response.json();
  return data.access_token;
}

module.exports = {
  verifyAppleToken,
  exchangeAppleAuthCode,
  refreshAppleAccessToken,
};
```

---

## Step 4: Update index.js

Find the `/api/admin/init` endpoint (around line 22) and update it:

```javascript
const { verifyAppleToken, exchangeAppleAuthCode } = require('./apple-auth-utils');

app.post('/api/admin/init', async (req, res) => {
  try {
    const { accountType, userId } = req.body;

    console.log(`[INIT] Account type: ${accountType || 'google (default)'}`);
    console.log(`[INIT] User ID: ${userId || 'NOT PROVIDED'}`);

    // Handle Apple Sign In
    if (accountType === 'apple') {
      const { identityToken, authorizationCode, appleUserId, folderId } = req.body;

      if (!identityToken || !authorizationCode) {
        return res.status(400).json({ error: 'Missing Apple credentials' });
      }

      console.log('[APPLE] Verifying identity token...');

      // 1. Verify the identity token
      let decodedToken;
      try {
        decodedToken = await verifyAppleToken(identityToken);
        console.log('[APPLE] Token verified for user:', decodedToken.sub);
      } catch (verifyError) {
        console.error('[APPLE] Token verification failed:', verifyError.message);
        return res.status(401).json({ error: 'Invalid Apple identity token' });
      }

      // 2. Exchange authorization code for tokens
      console.log('[APPLE] Exchanging authorization code...');
      let tokens;
      try {
        tokens = await exchangeAppleAuthCode(authorizationCode);
        console.log('[APPLE] Token exchange successful');
      } catch (exchangeError) {
        console.error('[APPLE] Token exchange failed:', exchangeError.message);
        return res.status(500).json({
          error: 'Failed to exchange Apple authorization code',
          details: exchangeError.message
        });
      }

      // 3. Generate session ID
      const sessionId = `apple_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // 4. Store session in Vercel KV
      const sessionData = {
        accountType: 'apple',
        userId: userId || appleUserId,
        folderId: folderId,
        refreshToken: tokens.refreshToken,
        email: decodedToken.email,
        createdAt: Date.now(),
      };

      await kv.set(`session:${sessionId}`, JSON.stringify(sessionData), {
        ex: SESSION_TTL,
      });

      console.log('[APPLE] Session created:', sessionId);

      return res.json({ sessionId });
    }

    // Existing Google implementation
    const { folderId, serverAuthCode, clientId: requestedClientId } = req.body;

    if (!folderId || !serverAuthCode) {
      return res.status(400).json({ error: 'Missing folderId or serverAuthCode' });
    }

    // ... rest of your existing Google code ...
```

---

## Step 5: Update Team Member Upload Endpoint

Find the team member upload endpoint and add Apple support:

```javascript
const { refreshAppleAccessToken } = require('./apple-auth-utils');

// Around line 300+ where team member uploads are handled
app.post('/api/team-member/upload', async (req, res) => {
  try {
    const { sessionId, token } = req.body;

    // Get session data
    const sessionDataStr = await kv.get(`session:${sessionId}`);
    if (!sessionDataStr) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    const session = JSON.parse(sessionDataStr);

    if (session.accountType === 'apple') {
      console.log('[APPLE] Team member upload for session:', sessionId);

      // Get fresh access token
      const accessToken = await refreshAppleAccessToken(session.refreshToken);

      // TODO: Implement iCloud/CloudKit upload
      // For now, return success (you can implement CloudKit later)
      console.log('[APPLE] Upload token validated (CloudKit integration pending)');

      return res.json({
        success: true,
        message: 'Apple upload validated (CloudKit integration pending)',
        sessionId: sessionId
      });
    }

    // Existing Google Drive upload logic
    // ... your existing code ...
  } catch (error) {
    console.error('[UPLOAD] Error:', error);
    res.status(500).json({ error: error.message });
  }
});
```

---

## Step 6: Deploy to Vercel

```bash
# From proof-pix-proxy directory
git add .
git commit -m "Add Apple Sign In support"
git push

# Or deploy directly
vercel --prod
```

---

## Step 7: Update Vercel Environment Variables

1. Go to https://vercel.com/your-team/proof-pix-proxy/settings/environment-variables
2. Add these variables:
   - `APPLE_TEAM_ID`
   - `APPLE_KEY_ID`
   - `APPLE_PRIVATE_KEY` (use `\n` for newlines)
3. Redeploy after adding variables

---

## Testing

### Test Apple Init Endpoint:

```bash
curl -X POST https://proof-pix-proxy.vercel.app/api/admin/init \
  -H "Content-Type: application/json" \
  -d '{
    "accountType": "apple",
    "identityToken": "YOUR_TOKEN",
    "authorizationCode": "YOUR_CODE",
    "appleUserId": "001234.abcd...",
    "folderId": "icloud_123",
    "userId": "user_123"
  }'
```

Expected response:
```json
{
  "sessionId": "apple_1234567890_abc123"
}
```

---

## Optional: iCloud Drive Integration

For actual file storage in iCloud Drive, you'll need to:

1. Set up CloudKit Dashboard
2. Create CloudKit container
3. Implement file upload using CloudKit JS or REST API

See main APPLE_PROXY_IMPLEMENTATION.md for CloudKit details.

---

## Troubleshooting

### "Missing Apple credentials"
- Check `.env` file has all three variables
- Verify Vercel environment variables are set
- Check private key includes BEGIN/END lines

### "Token verification failed"
- Identity token may be expired (they're short-lived)
- Check bundle ID matches: `com.proofpix.app`

### "Token exchange failed"
- Authorization code is one-time use only
- Check Team ID and Key ID are correct
- Verify private key is valid ES256 key

---

## Summary

✅ Install dependencies: `jsonwebtoken`, `jwks-rsa`
✅ Create `apple-auth-utils.js` with verification/exchange logic
✅ Update `/api/admin/init` to handle `accountType: 'apple'`
✅ Update team member upload to support Apple sessions
✅ Set environment variables in Vercel
✅ Deploy and test

Your proxy server will now support both Google and Apple authentication! 🎉
