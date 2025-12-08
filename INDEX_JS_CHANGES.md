# Exact Code Changes for index.js

## Change 1: Add Import at Top of File

**Location**: After line 5 (after `require('dotenv').config();`)

**Add this line**:
```javascript
const { verifyAppleToken, exchangeAppleAuthCode, refreshAppleAccessToken } = require('./apple-auth-utils');
```

---

## Change 2: Update /api/admin/init Endpoint

**Location**: Around line 22, **before** the existing Google code

**Replace**:
```javascript
app.post('/api/admin/init', async (req, res) => {
  try {
    const { folderId, serverAuthCode, clientId: requestedClientId, userId } = req.body;
```

**With**:
```javascript
app.post('/api/admin/init', async (req, res) => {
  try {
    const { accountType, userId } = req.body;

    console.log(`[INIT] Account type: ${accountType || 'google (default)'}`);
    console.log(`[INIT] User ID: ${userId || 'NOT PROVIDED'}`);

    // ========== APPLE SIGN IN ==========
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

    // ========== GOOGLE SIGN IN (existing code) ==========
    const { folderId, serverAuthCode, clientId: requestedClientId } = req.body;
```

**Keep all your existing Google code after this!**

---

## Change 3: Update Team Member Upload Endpoint

**Location**: Find the team member upload endpoint (search for `/api/team-member/upload`)

**After getting the session**, add this code **before** your existing Google Drive upload logic:

```javascript
app.post('/api/team-member/upload', async (req, res) => {
  try {
    const { sessionId, token } = req.body;

    // Get session data
    const sessionDataStr = await kv.get(`session:${sessionId}`);
    if (!sessionDataStr) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    const session = JSON.parse(sessionDataStr);

    // ========== APPLE UPLOAD HANDLING ==========
    if (session.accountType === 'apple') {
      console.log('[APPLE] Team member upload for session:', sessionId);

      // Validate refresh token by getting new access token
      try {
        const accessToken = await refreshAppleAccessToken(session.refreshToken);
        console.log('[APPLE] Access token refreshed successfully');
      } catch (refreshError) {
        console.error('[APPLE] Failed to refresh access token:', refreshError.message);
        return res.status(401).json({ error: 'Apple session expired. Admin needs to reconnect.' });
      }

      // TODO: Implement actual CloudKit/iCloud upload
      // For now, just validate the session is active
      console.log('[APPLE] Upload token validated (CloudKit integration pending)');

      return res.json({
        success: true,
        message: 'Apple upload validated. CloudKit integration coming soon.',
        sessionId: sessionId,
        // When you implement CloudKit, return the actual upload result
      });
    }

    // ========== GOOGLE DRIVE UPLOAD (your existing code) ==========
    // ... keep all your existing Google Drive code here ...
```

---

## Summary of Changes

1. **Import Apple utilities** at the top
2. **Check for `accountType: 'apple'`** at the start of `/api/admin/init`
3. **Handle Apple authentication** and return `sessionId`
4. **Keep all Google code** working as before
5. **Add Apple upload handling** in team member endpoint

---

## Testing After Changes

1. Install dependencies:
   ```bash
   cd ../proof-pix-proxy
   npm install
   ```

2. Update `.env` with Apple credentials

3. Test locally:
   ```bash
   npm start
   ```

4. Deploy to Vercel:
   ```bash
   git add .
   git commit -m "Add Apple Sign In support"
   git push
   ```

5. Update Vercel environment variables with Apple credentials

---

## Expected Behavior

### Apple Init Request:
```json
POST /api/admin/init
{
  "accountType": "apple",
  "identityToken": "eyJraWQi...",
  "authorizationCode": "c1a2b3...",
  "appleUserId": "001234.abcd...",
  "folderId": "icloud_123",
  "userId": "user_123"
}
```

### Apple Init Response:
```json
{
  "sessionId": "apple_1733686400000_x7k3m9p2q"
}
```

### Google Still Works:
```json
POST /api/admin/init
{
  "folderId": "abc123",
  "serverAuthCode": "4/...",
  "clientId": "your-client-id"
}
```

Both authentication methods work side-by-side! 🎉
