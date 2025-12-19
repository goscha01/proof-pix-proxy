const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const { Readable } = require('stream');
const { kv } = require('@vercel/kv');
const { verifyAppleToken, exchangeAppleAuthCode, refreshAppleAccessToken } = require('./apple-auth-utils');
const multer = require('multer'); // Middleware for handling multipart/form-data
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for memory storage (files are processed in memory, not saved to disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB file size limit
    fieldSize: 10 * 1024 * 1024 // 10MB field size limit
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// TTL for sessions in seconds (7 days)
const SESSION_TTL = 7 * 24 * 60 * 60;

/**
 * Admin endpoint: Initialize a new session by exchanging a serverAuthCode for a refresh token.
 * POST /api/admin/init
 * Body: { folderId, serverAuthCode }
 */
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

    if (!folderId || !serverAuthCode) {
      return res.status(400).json({ error: 'Missing folderId or serverAuthCode' });
    }

    console.log(`[INIT] User ID for global team tracking: ${userId || 'NOT PROVIDED'}`);

    // IMPORTANT: Use the client ID sent by the mobile app
    // This allows platform-specific client IDs (Android Client ID for Android, Web Client ID for iOS)
    // The serverAuthCode must be exchanged using the same client ID that generated it
    const clientId = requestedClientId ||
                     process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID ||
                     process.env.GOOGLE_WEB_CLIENT_ID ||
                     process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    console.log(`[INIT] Using client ID for server-side token exchange: ${clientId ? clientId.substring(0, 20) + '...' : 'MISSING'}`);
    console.log(`[INIT] Client ID source: ${requestedClientId ? 'from mobile app (platform-specific)' : 'from environment variable (fallback)'}`);
    
    console.log('Environment check:', {
      hasClientId: !!clientId,
      hasClientSecret: !!clientSecret,
      clientIdLength: clientId?.length || 0,
      clientSecretLength: clientSecret?.length || 0,
      allEnvKeys: Object.keys(process.env).filter(k => k.includes('GOOGLE') || k.includes('CLIENT'))
    });
    
    if (!clientId || !clientSecret) {
      console.error('Missing OAuth credentials:', { 
        hasClientId: !!clientId, 
        hasClientSecret: !!clientSecret,
        availableKeys: Object.keys(process.env).filter(k => k.includes('GOOGLE') || k.includes('CLIENT'))
      });
      return res.status(500).json({ 
        error: 'Server configuration error: Missing OAuth credentials. Please check Vercel environment variables.',
        hint: 'Required: EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID and GOOGLE_CLIENT_SECRET'
      });
    }

    console.log('Exchanging serverAuthCode for tokens...');
    console.log('Client ID being used:', clientId.substring(0, 20) + '...');
    console.log('Full Client ID:', clientId);
    console.log('ServerAuthCode length:', serverAuthCode?.length || 0);

    // Exchange serverAuthCode for tokens
    // Use the proxy server URL as the redirect URI
    // This must match one of the authorized redirect URIs in Google Cloud Console
    const redirectUri = process.env.PROXY_SERVER_URL || 'https://proof-pix-proxy.vercel.app';

    const oauth2Client = new google.auth.OAuth2(
      clientId,
      clientSecret,
      redirectUri
    );

    console.log(`[INIT] Using redirect URI: ${redirectUri}`);

    let tokens;
    try {
      const tokenResponse = await oauth2Client.getToken(serverAuthCode);
      tokens = tokenResponse.tokens;
      console.log('[INIT] Token exchange successful. Token keys:', Object.keys(tokens));
    } catch (tokenError) {
      console.error('Token exchange error:', {
        message: tokenError.message,
        code: tokenError.code,
        response: tokenError.response?.data
      });

      // Log full error details for redirect_uri_mismatch to help debug
      if (tokenError.response?.data?.error === 'redirect_uri_mismatch') {
        console.error('REDIRECT URI MISMATCH DETAILS:');
        console.error('- This means the serverAuthCode was generated with a specific redirect URI');
        console.error('- You need to add that redirect URI to Google Cloud Console');
        console.error('- For iOS apps, the redirect URI is usually: com.googleusercontent.apps.IOS_CLIENT_ID:/oauth2redirect');
        console.error('- Full error:', JSON.stringify(tokenError.response?.data, null, 2));
      }
      
      // Provide more specific error messages
      if (tokenError.response?.data?.error === 'invalid_grant') {
        return res.status(400).json({ 
          error: 'The authorization code has expired or already been used. Please sign in again to get a new code.' 
        });
      }
      
      if (tokenError.response?.data?.error === 'invalid_client') {
        return res.status(400).json({
          error: 'Invalid client. Please check that the Client ID and Secret are correct in Vercel environment variables.',
          details: tokenError.response.data
        });
      }
      
      if (tokenError.response?.data?.error === 'invalid_request') {
        return res.status(400).json({ 
          error: 'Invalid request. Please check that the client ID and secret are correct in Vercel environment variables.',
          details: tokenError.response.data
        });
      }
      
      if (tokenError.response?.data?.error === 'redirect_uri_mismatch') {
        return res.status(400).json({
          error: 'Redirect URI mismatch. This usually means the serverAuthCode was generated with a different Client ID than the one being used for token exchange. Make sure both the mobile app and server use the same OAuth project.',
          details: tokenError.response.data,
          hint: 'The serverAuthCode from mobile contains embedded redirect URI info. Ensure the Web Client ID and iOS Client ID are in the same Google Cloud project.'
        });
      }
      
      throw tokenError;
    }

    const refreshToken = tokens.refresh_token;

    if (!refreshToken) {
      console.error('Failed to obtain refresh token from Google.');
      console.error('Tokens received:', Object.keys(tokens));
      console.error('This can happen if:');
      console.error('1. offlineAccess is not set to true in Google Sign-In config');
      console.error('2. The user previously granted access and Google is reusing the same session');
      console.error('3. The serverAuthCode was already used or has expired');
      console.error('Solution: Have the admin sign out completely and sign in again from Settings');
      return res.status(400).json({
        error: 'Failed to obtain refresh token. Please sign out completely in Settings and sign in again. If testing on the same device, this is expected - the refresh token is only issued once per account.',
        hint: 'If you are the admin testing as a team member on the same device, the refresh token may have already been issued. Try using a different Google account or device for testing.'
      });
    }

    console.log(`[INIT] ✅ Got refresh token! Length: ${refreshToken.length}`);
    console.log(`[INIT] Refresh token preview: ${refreshToken.substring(0, 30)}...`);
    console.log(`[INIT] Testing refresh token immediately...`);

    // TEST: Try to use the refresh token immediately to verify it works
    try {
      const testClient = new google.auth.OAuth2(clientId, clientSecret);
      testClient.setCredentials({ refresh_token: refreshToken });
      const { credentials: testCreds } = await testClient.refreshAccessToken();
      console.log(`[INIT] ✅ Refresh token test PASSED! Got access token with length: ${testCreds.access_token.length}`);
    } catch (testError) {
      console.error(`[INIT] ❌ Refresh token test FAILED immediately after exchange!`);
      console.error(`[INIT] This means the refresh token Google gave us is already invalid`);
      console.error(`[INIT] Error:`, {
        message: testError.message,
        code: testError.code,
        error: testError.response?.data?.error
      });
      return res.status(500).json({
        error: 'The refresh token obtained from Google is invalid. This may be a Google OAuth configuration issue.',
        details: testError.response?.data
      });
    }

    // Generate admin session ID
    const sessionId = generateSessionId();

    // Fetch admin user info from Google
    let adminUserInfo = null;
    try {
      const oauth2Client = new google.auth.OAuth2(clientId, clientSecret);
      oauth2Client.setCredentials({ refresh_token: refreshToken });
      const { credentials } = await oauth2Client.refreshAccessToken();
      oauth2Client.setCredentials(credentials);
      
      const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
      const userInfo = await oauth2.userinfo.get();
      adminUserInfo = {
        name: userInfo.data.name || null,
        email: userInfo.data.email || null,
        picture: userInfo.data.picture || null
      };
      console.log(`[INIT] Fetched admin user info: ${adminUserInfo.name} (${adminUserInfo.email})`);
    } catch (userInfoError) {
      console.warn(`[INIT] Failed to fetch admin user info:`, userInfoError.message);
      // Continue without user info - it's not critical
    }

    // Store the folderId, refreshToken, clientId used, admin user info, invite tokens, and team members list for this session
    // This ensures we use the correct Client ID/Secret when refreshing tokens
    const sessionData = {
      folderId,
      refreshToken,
      clientId, // Store which client ID was used for this session
      adminUserInfo, // Store admin's Google account info
      userId, // Store user ID for global team tracking across accounts
      inviteTokens: [],
      teamMembers: [], // Track team members: [{ token, name, status: 'pending'|'joined'|'declined', joinedAt, lastUploadAt }]
    };
    
    console.log(`[INIT] Storing session with refresh token (length: ${refreshToken.length})`);
    console.log(`[INIT] Storing Client ID with session: ${clientId.substring(0, 20)}...`);
    await kv.set(`session:${sessionId}`, sessionData, { ex: SESSION_TTL });
    
    // Verify the token was stored correctly by reading it back
    const verifySession = await kv.get(`session:${sessionId}`);
    if (verifySession && verifySession.refreshToken) {
      console.log(`[INIT] Verified refresh token stored correctly (length: ${verifySession.refreshToken.length})`);
      if (verifySession.refreshToken !== refreshToken) {
        console.error(`[INIT] WARNING: Refresh token mismatch! Original length: ${refreshToken.length}, Stored length: ${verifySession.refreshToken.length}`);
      }
    } else {
      console.error(`[INIT] ERROR: Refresh token not found in stored session!`);
    }

    console.log(`Admin session created in KV with refresh token: ${sessionId}`);

    res.json({
      success: true,
      sessionId,
      message: 'Admin session initialized',
    });
  } catch (error) {
    console.error('Error initializing admin session:', {
      message: error.message,
      code: error.code,
      response: error.response?.data,
      stack: error.stack
    });
    
    const errorMessage = error.response?.data?.error || error.message || 'Unknown error';
    res.status(500).json({ 
      error: errorMessage,
      details: error.response?.data
    });
  }
});


/**
 * Admin endpoint: Add an invite token
 * POST /api/admin/:sessionId/tokens
 * Body: { token }
 */
app.post('/api/admin/:sessionId/tokens', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { token } = req.body;

    const session = await kv.get(`session:${sessionId}`);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    const inviteTokens = new Set(session.inviteTokens || []);
    inviteTokens.add(token);
    session.inviteTokens = Array.from(inviteTokens);

    await kv.set(`session:${sessionId}`, session, { ex: SESSION_TTL });

    // Add to global team member registry immediately when invite is created
    if (session.userId) {
      const globalTeamKey = `team:${session.userId}:members`;
      let globalTeamMembers = await kv.get(globalTeamKey) || [];

      // Ensure it's an array
      if (!Array.isArray(globalTeamMembers)) {
        globalTeamMembers = [];
      }

      // Convert to Set for deduplication, add token, convert back to array
      const memberSet = new Set(globalTeamMembers);
      memberSet.add(token);

      // Save global team members as array
      await kv.set(globalTeamKey, Array.from(memberSet), { ex: SESSION_TTL });
      console.log(`[TOKEN_ADD] Added invite token to global registry for userId ${session.userId}. Total count: ${memberSet.size}`);
    }

    console.log(`Token added to session ${sessionId}`);

    res.json({ success: true });
  } catch (error) {
    console.error('Error adding token:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Admin endpoint: Remove an invite token
 * DELETE /api/admin/:sessionId/tokens/:token
 */
app.delete('/api/admin/:sessionId/tokens/:token', async (req, res) => {
  try {
    const { sessionId, token } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Remove the invite token
    const inviteTokens = new Set(session.inviteTokens);
    inviteTokens.delete(token);
    session.inviteTokens = Array.from(inviteTokens);

    // Also remove the team member associated with this token
    if (session.teamMembers) {
      session.teamMembers = session.teamMembers.filter(member => member.token !== token);
      console.log(`Team member with token ${token} removed from session ${sessionId}`);
    }

    await kv.set(`session:${sessionId}`, session, { ex: SESSION_TTL });

    // Remove from global team member registry (tracked by userId)
    if (session.userId) {
      const globalTeamKey = `team:${session.userId}:members`;
      let globalTeamMembers = await kv.get(globalTeamKey) || [];

      // Ensure it's an array
      if (!Array.isArray(globalTeamMembers)) {
        globalTeamMembers = [];
      }

      // Convert to Set for easier manipulation
      const memberSet = new Set(globalTeamMembers);
      const sizeBefore = memberSet.size;
      memberSet.delete(token);
      const sizeAfter = memberSet.size;

      // Save updated global team members
      await kv.set(globalTeamKey, Array.from(memberSet), { ex: SESSION_TTL });
      console.log(`[TOKEN_REMOVE] Removed token from global registry for userId ${session.userId}. Count: ${sizeBefore} -> ${sizeAfter}`);
    }

    console.log(`Token removed from session ${sessionId}`);

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing token:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Helper function to find or create a folder in Google Drive
 * This function checks for existing folders and only creates if none exist
 */
async function findOrCreateFolder(drive, parentFolderId, folderName) {
  try {
    // Escape single quotes in folder name for the query
    const escapedFolderName = folderName.replace(/'/g, "\\'");
    
    // Search for existing folder - be very specific to avoid duplicates
    const response = await drive.files.list({
      q: `mimeType='application/vnd.google-apps.folder' and name='${escapedFolderName}' and '${parentFolderId}' in parents and trashed=false`,
      fields: 'files(id, name)',
      spaces: 'drive',
      pageSize: 10, // Limit results
      orderBy: 'createdTime desc', // Prefer most recently created folder if duplicates exist
    });

    // If folder exists, return the first one (most recent if duplicates)
    if (response.data.files && response.data.files.length > 0) {
      const existingFolderId = response.data.files[0].id;
      console.log(`Found existing folder: ${folderName} (${existingFolderId}) in parent ${parentFolderId}`);
      
      // If multiple folders with same name exist, log a warning and use the most recent
      if (response.data.files.length > 1) {
        console.warn(`WARNING: Multiple folders named "${folderName}" found in parent ${parentFolderId}. Using most recent: ${existingFolderId}`);
        console.warn(`All duplicate folder IDs: ${response.data.files.map(f => f.id).join(', ')}`);
      }
      
      return existingFolderId;
    }

    // Folder doesn't exist, create it
    console.log(`Creating new folder: ${folderName} in parent ${parentFolderId}`);
    const folderResponse = await drive.files.create({
      requestBody: {
        name: folderName,
        mimeType: 'application/vnd.google-apps.folder',
        parents: [parentFolderId],
      },
      fields: 'id, name',
    });

    console.log(`Created folder: ${folderName} (${folderResponse.data.id})`);
    return folderResponse.data.id;
  } catch (error) {
    // If error is "duplicate" or "already exists", try to find it again
    if (error.message && (error.message.includes('duplicate') || error.message.includes('already exists'))) {
      console.log(`Folder creation returned duplicate error, searching again for: ${folderName}`);
      try {
        const retryResponse = await drive.files.list({
          q: `mimeType='application/vnd.google-apps.folder' and name='${folderName.replace(/'/g, "\\'")}' and '${parentFolderId}' in parents and trashed=false`,
          fields: 'files(id, name)',
          spaces: 'drive',
          orderBy: 'createdTime desc',
        });
        if (retryResponse.data.files && retryResponse.data.files.length > 0) {
          console.log(`Found folder after retry: ${folderName} (${retryResponse.data.files[0].id})`);
          return retryResponse.data.files[0].id;
        }
      } catch (retryError) {
        console.error(`Retry search failed for ${folderName}:`, retryError);
      }
    }
    console.error(`Error finding/creating folder ${folderName}:`, error);
    throw error;
  }
}

/**
 * Prepare upload endpoint: Create album folder structure before parallel uploads
 * POST /api/prepare/:sessionId
 * Body: { albumName }
 */
app.post('/api/prepare/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { albumName } = req.body;

    if (!albumName) {
      return res.status(400).json({ error: 'Missing albumName' });
    }

    // Get admin session from Vercel KV
    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Skip folder preparation for Apple/iCloud uploads (simulated for now)
    if (session.accountType === 'apple') {
      console.log('[APPLE] Album folder preparation skipped (iCloud simulated)');
      return res.json({ 
        success: true, 
        message: 'iCloud folder ready (simulated)',
        albumName: albumName,
        folderId: session.folderId 
      });
    }

    if (!session.refreshToken) {
      return res.status(400).json({ error: 'Admin session is missing the required refresh token. Please have the admin re-authenticate.' });
    }

    // Get the client ID that was used for this session
    const sessionClientId = session.clientId || process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
    const sessionClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    
    console.log(`[PREPARE] Using Client ID for session: ${sessionClientId.substring(0, 20)}...`);
    
    // Initialize Google OAuth2 client with the correct Client ID for this session
    const oauth2Client = new google.auth.OAuth2(
      sessionClientId,
      sessionClientSecret
    );
    oauth2Client.setCredentials({
      refresh_token: session.refreshToken,
    });
    
    // Explicitly refresh the access token before using Drive API
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      oauth2Client.setCredentials(credentials);
      
      // If a new refresh token was provided, update it in the session
      if (credentials.refresh_token && credentials.refresh_token !== session.refreshToken) {
        console.log('New refresh token received, updating session');
        await kv.set(`session:${sessionId}`, {
          ...session,
          refreshToken: credentials.refresh_token
        });
      }
    } catch (refreshError) {
      console.error('Failed to refresh access token:', {
        message: refreshError.message,
        code: refreshError.code,
        response: refreshError.response?.data
      });
      
      if (refreshError.response?.data?.error === 'invalid_grant') {
        return res.status(500).json({ 
          error: 'invalid_grant',
          message: 'The admin\'s Google account session has expired. Please have the admin re-authenticate in Settings.'
        });
      }
      
      throw refreshError;
    }

    const drive = google.drive({ version: 'v3', auth: oauth2Client });

    // Create or find album folder
    console.log(`[PREPARE] Creating/finding album folder: ${albumName}`);
    const albumFolderId = await findOrCreateFolder(drive, session.folderId, albumName);
    console.log(`[PREPARE] Album folder ready: ${albumName} (${albumFolderId})`);

    // Cache it in KV for parallel uploads
    const albumCacheKey = `album:${sessionId}:${albumName}`;
    await kv.set(albumCacheKey, albumFolderId, { ex: 3600 }); // 1 hour TTL
    console.log(`[PREPARE] Cached album folder ID: ${albumFolderId}`);

    res.json({
      success: true,
      albumFolderId,
      albumName,
      message: 'Album folder structure prepared'
    });
  } catch (error) {
    console.error('[PREPARE] Error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Upload endpoint: Upload a photo (supports both admin and team member uploads)
 * POST /api/upload/:sessionId
 * Supports JSON body (legacy) and multipart/form-data (new standard)
 */
app.post('/api/upload/:sessionId', upload.single('photo'), async (req, res) => {
  try {
    const { sessionId } = req.params;
    let { 
      token, 
      filename, 
      contentBase64,
      albumName,
      room,
      type,
      format = 'default',
      location,
      cleanerName,
      flat = false
    } = req.body;

    // Handle multipart/form-data upload (raw binary)
    // req.file contains the file buffer if uploaded via multipart
    let fileBuffer;
    let mimeType = 'image/jpeg';

    if (req.file) {
      console.log(`[UPLOAD] Received multipart file upload: ${req.file.originalname} (${req.file.size} bytes)`);
      fileBuffer = req.file.buffer;
      filename = filename || req.file.originalname; // Use uploaded filename if not provided in body
      mimeType = req.file.mimetype || mimeType;
      
      // Convert string 'true'/'false' to boolean for flat
      if (typeof flat === 'string') {
        flat = flat === 'true';
      }
    } else if (contentBase64) {
      // Legacy Base64 handling
      console.log(`[UPLOAD] Received Base64 upload: ${filename} (${contentBase64.length} chars)`);
      fileBuffer = Buffer.from(contentBase64, 'base64');
    } else {
      return res.status(400).json({ error: 'Missing file content (req.file or contentBase64)' });
    }

    // Validate required inputs
    if (!filename) {
      return res.status(400).json({ error: 'Missing filename' });
    }

    // Get admin session from Vercel KV
    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      console.error(`[UPLOAD] Session not found: ${sessionId}`);
      return res.status(404).json({ error: 'Session not found' });
    }

    if (!session.refreshToken) {
      console.error(`[UPLOAD] Session missing refresh token: ${sessionId}`, { sessionKeys: Object.keys(session) });
      return res.status(400).json({ error: 'Admin session is missing the required refresh token. Please have the admin re-authenticate.' });
    }
    
    console.log(`[UPLOAD] Session found for ${sessionId}, refresh token length: ${session.refreshToken?.length || 0}`);
    console.log(`[UPLOAD] Session account type: ${session.accountType || 'google'}`);
    
    // ========== APPLE / iCLOUD UPLOAD HANDLING ==========
    if (session.accountType === 'apple') {
      console.log('[APPLE] Upload request for Apple/iCloud session');
      
      // Validate Apple refresh token by attempting to get new access token
      try {
        const { refreshAppleAccessToken } = require('./apple-auth-utils');
        const accessToken = await refreshAppleAccessToken(session.refreshToken);
        console.log('[APPLE] Access token refreshed successfully');
      } catch (refreshError) {
        console.error('[APPLE] Failed to refresh access token:', refreshError.message);
        return res.status(401).json({ 
          success: false,
          error: 'Apple session expired. Please reconnect your Apple account in Settings.' 
        });
      }
      
      // TODO: Implement actual CloudKit/iCloud Drive upload
      // For now, we'll simulate a successful upload
      // In the future, this would use CloudKit JS or CloudKit REST API
      console.log('[APPLE] iCloud upload simulated successfully:', {
        filename,
        albumName,
        room,
        type,
        format,
        flat
      });
      
      // Return success response that matches Google Drive upload format
      const folderPath = flat 
        ? albumName 
        : `${albumName}/${type === 'mix' || type === 'combined' ? 'combined' : type}${format !== 'default' ? `/formats/${format}/` : '/'}`;
      
      return res.json({
        success: true,
        fileId: `icloud_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        fileName: filename,
        albumName: albumName || null,
        room: room || 'general',
        type: type || null,
        format: format || 'default',
        location: location || null,
        cleanerName: cleanerName || null,
        folderPath: folderPath,
        flatMode: !!flat,
        message: 'Photo uploaded successfully to iCloud (simulated - CloudKit integration pending)'
      });
    }
    
    // ========== GOOGLE DRIVE UPLOAD (existing code) ==========
    // If token is provided, validate it (for team member uploads)
    // If token is not provided, assume it's an admin upload
    if (token) {
      const sessionTokens = new Set(session.inviteTokens || []);
      if (!sessionTokens.has(token)) {
        console.log(`Unauthorized token attempt: ${token}`);
        return res.status(403).json({ error: 'Invalid invite token' });
      }
      
      // Mark team member as "joined" when they upload (if they haven't been marked yet)
      if (!session.teamMembers) {
        session.teamMembers = [];
      }
      const memberIndex = session.teamMembers.findIndex(m => m.token === token);
      const now = new Date().toISOString();

      if (memberIndex >= 0) {
        // Update existing member - mark as joined and update last upload time
        session.teamMembers[memberIndex] = {
          ...session.teamMembers[memberIndex],
          status: 'joined',
          lastUploadAt: now,
          lastSeenAt: now
        };
      } else if (cleanerName) {
        // If member doesn't exist yet but we have their name, create entry
        session.teamMembers.push({
          token,
          name: cleanerName,
          status: 'joined',
          joinedAt: now,
          lastSeenAt: now,
          lastUploadAt: now
        });
      }

      // Save updated session with team member info
      await kv.set(`session:${sessionId}`, session, { ex: SESSION_TTL });

      // Update global team member registry (for cross-account tracking by userId)
      if (session.userId) {
        const globalTeamKey = `team:${session.userId}:members`;
        let globalTeamMembers = await kv.get(globalTeamKey) || [];

        // Ensure it's an array
        if (!Array.isArray(globalTeamMembers)) {
          globalTeamMembers = [];
        }

        // Convert to Set for deduplication, add token, convert back to array
        const memberSet = new Set(globalTeamMembers);
        memberSet.add(token);

        // Save global team members as array
        await kv.set(globalTeamKey, Array.from(memberSet), { ex: SESSION_TTL });
        console.log(`[UPLOAD] Added token to global registry for userId ${session.userId}. Total count: ${memberSet.size}`);
      }
    }
    
    // Get the client ID and secret that were used for this session
    // If not stored, fall back to Web Client ID (for backward compatibility)
    const sessionClientId = session.clientId || process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
    const sessionClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    
    console.log(`[UPLOAD] Session Client ID: ${sessionClientId ? sessionClientId.substring(0, 20) + '...' : 'MISSING'}`);
    console.log(`[UPLOAD] Session has clientId stored: ${!!session.clientId}`);
    console.log(`[UPLOAD] Full stored Client ID: ${session.clientId || 'NOT STORED'}`);
    console.log(`[UPLOAD] Refresh token length: ${session.refreshToken?.length || 0}`);
    console.log(`[UPLOAD] Refresh token preview: ${session.refreshToken ? session.refreshToken.substring(0, 20) + '...' : 'MISSING'}`);
    
    // Initialize Google OAuth2 client with the correct Client ID for this session
    const oauth2Client = new google.auth.OAuth2(
      sessionClientId,
      sessionClientSecret
    );
    oauth2Client.setCredentials({
      refresh_token: session.refreshToken,
    });
    
    // Explicitly refresh the access token before using Drive API
    // This ensures we have a valid access token and catches refresh errors early
    console.log(`[UPLOAD] Attempting to refresh access token with refresh token length: ${session.refreshToken?.length || 0}`);
    try {
      const { credentials } = await oauth2Client.refreshAccessToken();
      oauth2Client.setCredentials(credentials);
      console.log(`[UPLOAD] Successfully refreshed access token`);
      
      // If a new refresh token was provided, update it in the session
      if (credentials.refresh_token && credentials.refresh_token !== session.refreshToken) {
        console.log('[UPLOAD] New refresh token received, updating session');
        await kv.set(`session:${sessionId}`, {
          ...session,
          refreshToken: credentials.refresh_token
        });
      }
    } catch (refreshError) {
      console.error('[UPLOAD] Failed to refresh access token:', {
        message: refreshError.message,
        code: refreshError.code,
        response: refreshError.response?.data,
        refreshTokenLength: session.refreshToken?.length || 0,
        refreshTokenPreview: session.refreshToken ? session.refreshToken.substring(0, 20) + '...' : 'MISSING'
      });
      
      if (refreshError.response?.data?.error === 'invalid_grant') {
        // Check if the refresh token in the session matches what we're trying to use
        const verifySession = await kv.get(`session:${sessionId}`);
        if (verifySession && verifySession.refreshToken !== session.refreshToken) {
          console.error('[UPLOAD] Refresh token mismatch detected! Session may have been corrupted.');
        }
        
        return res.status(500).json({ 
          success: false,
          error: 'invalid_grant',
          message: 'Upload failed: The admin\'s Google account session has expired. Please have the admin re-authenticate in Settings.'
        });
      }
      
      throw refreshError;
    }
    
    const drive = google.drive({ version: 'v3', auth: oauth2Client });

    // Determine target folder ID based on upload parameters
    let targetFolderId = session.folderId;

    // If albumName is provided, create folder structure
    if (albumName) {
      console.log(`[FOLDER STRUCTURE] Creating folder structure for album: ${albumName}, type: ${type}, format: ${format}, flat: ${flat}`);
      
      // Use a separate KV key for album folder mapping to ensure atomicity across parallel uploads
      // This ensures all uploads in the same batch use the same album folder, even when running in parallel
      const albumCacheKey = `album:${sessionId}:${albumName}`;
      const albumLockKey = `lock:album:${sessionId}:${albumName}`;
      let albumFolderId = await kv.get(albumCacheKey);

      if (!albumFolderId) {
        // Try to acquire a lock to prevent race conditions when creating folders
        // Use SET NX (only set if not exists) with a short TTL
        const lockAcquired = await kv.set(albumLockKey, 'locked', { ex: 30, nx: true });

        if (lockAcquired) {
          // We got the lock, create the folder
          try {
            // Double-check cache in case another request just finished
            albumFolderId = await kv.get(albumCacheKey);
            if (!albumFolderId) {
              // Create or find album folder (findOrCreateFolder handles duplicates by using the most recent)
              albumFolderId = await findOrCreateFolder(drive, session.folderId, albumName);
              console.log(`[FOLDER STRUCTURE] Album folder: ${albumName} (${albumFolderId})`);

              // Cache it in KV with a shorter TTL (1 hour) - just for this upload session
              await kv.set(albumCacheKey, albumFolderId, { ex: 3600 }); // 1 hour TTL
              console.log(`[FOLDER STRUCTURE] Cached album folder ID for ${albumName}: ${albumFolderId}`);
            } else {
              console.log(`[FOLDER STRUCTURE] Another request created the folder: ${albumName} (${albumFolderId})`);
            }
          } finally {
            // Release the lock
            await kv.del(albumLockKey);
          }
        } else {
          // Another request has the lock, wait for it to finish
          console.log(`[FOLDER STRUCTURE] Waiting for another request to create album folder: ${albumName}`);
          // Poll for the cached folder ID (up to 10 seconds)
          for (let i = 0; i < 20; i++) {
            await new Promise(resolve => setTimeout(resolve, 500)); // Wait 500ms
            albumFolderId = await kv.get(albumCacheKey);
            if (albumFolderId) {
              console.log(`[FOLDER STRUCTURE] Got cached album folder after waiting: ${albumName} (${albumFolderId})`);
              break;
            }
          }

          // If still no folder ID, create it ourselves (lock may have expired)
          if (!albumFolderId) {
            console.log(`[FOLDER STRUCTURE] Lock expired, creating folder ourselves: ${albumName}`);
            albumFolderId = await findOrCreateFolder(drive, session.folderId, albumName);
            await kv.set(albumCacheKey, albumFolderId, { ex: 3600 });
            console.log(`[FOLDER STRUCTURE] Created album folder after lock timeout: ${albumName} (${albumFolderId})`);
          }
        }
      } else {
        console.log(`[FOLDER STRUCTURE] Using cached album folder: ${albumName} (${albumFolderId})`);
      }
      
      targetFolderId = albumFolderId;

      // If not flat mode, create subfolder structure
      // Organize by type first (before/after/combined), then by format if needed
      if (!flat) {
        // Always create type folder first (before/after/combined)
        const folderName = type === 'mix' || type === 'combined' ? 'combined' : (type || 'general');
        console.log(`[FOLDER STRUCTURE] Looking for type folder: ${folderName} in album ${albumName}`);
        const typeFolderId = await findOrCreateFolder(drive, albumFolderId, folderName);
        console.log(`[FOLDER STRUCTURE] Type folder: ${folderName} (${typeFolderId})`);
        
        // If format is not default, create formats subfolder within type folder
        if (format !== 'default') {
          console.log(`[FOLDER STRUCTURE] Format is not default (${format}), creating formats subfolder in ${folderName}`);
          const formatsFolderId = await findOrCreateFolder(drive, typeFolderId, 'formats');
          console.log(`[FOLDER STRUCTURE] Formats folder in ${folderName}: formats (${formatsFolderId})`);
          targetFolderId = await findOrCreateFolder(drive, formatsFolderId, format);
          console.log(`[FOLDER STRUCTURE] Final target folder: ${folderName}/formats/${format} (${targetFolderId})`);
        } else {
          // Default format goes directly in type folder
          targetFolderId = typeFolderId;
          console.log(`[FOLDER STRUCTURE] Default format, using type folder directly: ${folderName} (${targetFolderId})`);
        }
      } else {
        console.log(`[FOLDER STRUCTURE] Flat mode enabled, uploading directly to album folder`);
      }
    }
    
    console.log(`[FOLDER STRUCTURE] Final upload target: ${targetFolderId}`);

    // Create readable stream from buffer (works for both multipart and base64 sources)
    const stream = Readable.from(fileBuffer);

    // Upload to Google Drive
    let response;
    try {
      response = await drive.files.create({
        requestBody: {
          name: filename,
          parents: [targetFolderId]
        },
        media: {
          mimeType: mimeType,
          body: stream
        }
      });
    } catch (uploadError) {
      console.error('Drive API upload error:', {
        message: uploadError.message,
        code: uploadError.code,
        response: uploadError.response?.data
      });
      
      // Handle token refresh errors
      if (uploadError.message?.includes('invalid_grant') || 
          uploadError.response?.data?.error === 'invalid_grant' ||
          uploadError.code === 401) {
        // Try to get a fresh access token explicitly
        try {
          const { credentials } = await oauth2Client.refreshAccessToken();
          oauth2Client.setCredentials(credentials);
          
          // Retry the upload with refreshed token
          response = await drive.files.create({
            requestBody: {
              name: filename,
              parents: [targetFolderId]
            },
            media: {
              mimeType: mimeType,
              body: Readable.from(fileBuffer) // Create new stream for retry
            }
          });
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError.message);
          return res.status(500).json({ 
            success: false,
            error: 'invalid_grant',
            message: 'Upload failed: The admin\'s Google account session has expired. Please have the admin re-authenticate in Settings.'
          });
        }
      } else {
        // Re-throw other errors
        throw uploadError;
      }
    }

    console.log(`File uploaded successfully: ${filename} (${response.data.id}) to folder ${targetFolderId}`);

    // Build folder path for response
    let folderPath = '';
    if (albumName) {
      if (flat) {
        folderPath = albumName;
      } else {
        const folderName = type === 'mix' || type === 'combined' ? 'combined' : (type || 'general');
        if (format !== 'default') {
          folderPath = `${albumName}/${folderName}/formats/${format}/`;
        } else {
          folderPath = `${albumName}/${folderName}/`;
        }
      }
    }

    res.json({
      success: true,
      fileId: response.data.id,
      fileName: filename,
      albumName: albumName || null,
      room: room || 'general',
      type: type || null,
      format: format || 'default',
      location: location || null,
      cleanerName: cleanerName || null,
      folderPath: folderPath,
      flatMode: !!flat,
      message: 'Photo uploaded successfully'
    });
  } catch (error) {
    console.error('Error uploading file:', error.response ? error.response.data : error.message);
    res.status(500).json({ 
      success: false,
      error: error.message,
      message: `Upload failed: ${error.message}`
    });
  }
});

/**
 * Team member join endpoint: Register a team member joining
 * POST /api/team/:sessionId/join
 * Body: { token, memberName }
 */
app.post('/api/team/:sessionId/join', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { token, memberName } = req.body;

    if (!token || !memberName) {
      return res.status(400).json({ error: 'Missing token or memberName' });
    }

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Validate token
    const sessionTokens = new Set(session.inviteTokens || []);
    if (!sessionTokens.has(token)) {
      return res.status(403).json({ error: 'Invalid invite token' });
    }

    // Initialize teamMembers array if it doesn't exist
    if (!session.teamMembers) {
      session.teamMembers = [];
    }

    // Check if team member already exists for this token
    const existingMemberIndex = session.teamMembers.findIndex(m => m.token === token);
    const now = new Date().toISOString();

    if (existingMemberIndex >= 0) {
      // Update existing member
      session.teamMembers[existingMemberIndex] = {
        ...session.teamMembers[existingMemberIndex],
        name: memberName,
        status: 'joined', // If they're joining again, mark as joined
        joinedAt: session.teamMembers[existingMemberIndex].joinedAt || now,
        lastSeenAt: now
      };
    } else {
      // Add new team member
      session.teamMembers.push({
        token,
        name: memberName,
        status: 'pending', // Initially pending until first upload
        joinedAt: now,
        lastSeenAt: now,
        lastUploadAt: null
      });
    }

    await kv.set(`session:${sessionId}`, session, { ex: SESSION_TTL });

    // Update global team member registry (for cross-account tracking by userId)
    if (session.userId) {
      const globalTeamKey = `team:${session.userId}:members`;
      let globalTeamMembers = await kv.get(globalTeamKey) || [];

      // Ensure it's an array
      if (!Array.isArray(globalTeamMembers)) {
        globalTeamMembers = [];
      }

      // Convert to Set for deduplication, add token, convert back to array
      const memberSet = new Set(globalTeamMembers);
      memberSet.add(token);

      // Save global team members as array
      await kv.set(globalTeamKey, Array.from(memberSet), { ex: SESSION_TTL });
      console.log(`[TEAM_JOIN] Added token to global registry for userId ${session.userId}. Total count: ${memberSet.size}`);
    }

    res.json({
      success: true,
      message: 'Team member registered'
    });
  } catch (error) {
    console.error('Error registering team member:', error);
    res.status(500).json({
      error: error.message
    });
  }
});

/**
 * Get session info (including admin user info)
 * GET /api/admin/:sessionId/info
 */
app.get('/api/admin/:sessionId/info', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // If adminUserInfo is not stored, fetch it from Google
    let adminUserInfo = session.adminUserInfo;
    if (!adminUserInfo && session.refreshToken) {
      try {
        const sessionClientId = session.clientId || process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
        const sessionClientSecret = process.env.GOOGLE_CLIENT_SECRET;
        
        const oauth2Client = new google.auth.OAuth2(sessionClientId, sessionClientSecret);
        oauth2Client.setCredentials({ refresh_token: session.refreshToken });
        const { credentials } = await oauth2Client.refreshAccessToken();
        oauth2Client.setCredentials(credentials);
        
        const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
        const userInfo = await oauth2.userinfo.get();
        adminUserInfo = {
          name: userInfo.data.name || null,
          email: userInfo.data.email || null,
          picture: userInfo.data.picture || null
        };
        
        // Update session with admin user info for future requests
        await kv.set(`session:${sessionId}`, {
          ...session,
          adminUserInfo
        }, { ex: SESSION_TTL });
        
        console.log(`[INFO] Fetched and stored admin user info: ${adminUserInfo.name} (${adminUserInfo.email})`);
      } catch (userInfoError) {
        console.warn(`[INFO] Failed to fetch admin user info:`, userInfoError.message);
        // Continue without user info - it's not critical
      }
    }

    res.json({
      success: true,
      adminUserInfo: adminUserInfo || null,
      folderId: session.folderId || null
    });
  } catch (error) {
    console.error('Error getting session info:', error);
    res.status(500).json({
      error: error.message
    });
  }
});

/**
 * Get team members list for admin
 * GET /api/admin/:sessionId/team-members
 */
app.get('/api/admin/:sessionId/team-members', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    const teamMembers = session.teamMembers || [];

    res.json({
      success: true,
      teamMembers: teamMembers.map(m => ({
        token: m.token,
        name: m.name,
        status: m.status || 'pending',
        joinedAt: m.joinedAt,
        lastSeenAt: m.lastSeenAt,
        lastUploadAt: m.lastUploadAt
      }))
    });
  } catch (error) {
    console.error('Error getting team members:', error);
    res.status(500).json({
      error: error.message
    });
  }
});

/**
 * Get global team member count across all accounts for the same user (by userId)
 * GET /api/admin/:sessionId/global-team-count
 */
app.get('/api/admin/:sessionId/global-team-count', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (!session.userId) {
      console.warn(`[GLOBAL_COUNT] Session ${sessionId} does not have userId, falling back to local count`);
      // Fallback: return local count if no userId
      return res.json({
        success: true,
        globalCount: (session.teamMembers || []).length,
        userId: null,
        fallback: true
      });
    }

    // Get global team member count from the global registry (by userId)
    const globalTeamKey = `team:${session.userId}:members`;
    let globalTeamMembers = await kv.get(globalTeamKey) || [];

    // Ensure it's an array
    if (!Array.isArray(globalTeamMembers)) {
      globalTeamMembers = [];
    }

    console.log(`[GLOBAL_COUNT] User ${session.userId} has ${globalTeamMembers.length} total team members across all accounts`);

    res.json({
      success: true,
      globalCount: globalTeamMembers.length,
      userId: session.userId
    });
  } catch (error) {
    console.error('Error getting global team count:', error);
    res.status(500).json({
      error: error.message
    });
  }
});

/**
 * Reset global team member registry for this user (by userId).
 * This is used when the admin explicitly clears all team members in the app,
 * so both local state and server-side global tracking are reset together.
 *
 * DELETE /api/admin/:sessionId/global-team-count
 */
app.delete('/api/admin/:sessionId/global-team-count', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    if (!session.userId) {
      console.warn(`[GLOBAL_COUNT_RESET] Session ${sessionId} does not have userId, nothing to reset`);
      return res.json({
        success: true,
        userId: null,
        previousCount: (session.teamMembers || []).length || 0,
        remainingCount: (session.teamMembers || []).length || 0,
        fallback: true
      });
    }

    const globalTeamKey = `team:${session.userId}:members`;
    let globalTeamMembers = await kv.get(globalTeamKey) || [];

    if (!Array.isArray(globalTeamMembers)) {
      globalTeamMembers = [];
    }

    const previousCount = globalTeamMembers.length;

    // Clear the global registry for this user
    await kv.del(globalTeamKey);

    console.log(`[GLOBAL_COUNT_RESET] Cleared global team registry for user ${session.userId}. Count: ${previousCount} -> 0`);

    res.json({
      success: true,
      userId: session.userId,
      previousCount,
      remainingCount: 0
    });
  } catch (error) {
    console.error('Error resetting global team count:', error);
    res.status(500).json({
      error: error.message
    });
  }
});

/**
 * Validate session endpoint: Check if a session exists and is valid
 * GET /api/admin/:sessionId/validate
 */
app.get('/api/admin/:sessionId/validate', async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await kv.get(`session:${sessionId}`);
    if (!session) {
      return res.status(404).json({
        valid: false,
        error: 'Session not found'
      });
    }

    if (!session.refreshToken) {
      return res.status(400).json({
        valid: false,
        error: 'Session exists but missing refresh token'
      });
    }

    // Try to refresh the access token to verify the session is still valid
    const sessionClientId = session.clientId || process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID;
    const sessionClientSecret = process.env.GOOGLE_CLIENT_SECRET;

    const oauth2Client = new google.auth.OAuth2(
      sessionClientId,
      sessionClientSecret
    );
    oauth2Client.setCredentials({
      refresh_token: session.refreshToken,
    });

    try {
      const { credentials } = await oauth2Client.refreshAccessToken();

      // If we got here, the session is valid!
      // Update the refresh token if a new one was provided
      if (credentials.refresh_token && credentials.refresh_token !== session.refreshToken) {
        await kv.set(`session:${sessionId}`, {
          ...session,
          refreshToken: credentials.refresh_token
        }, { ex: SESSION_TTL });
      }

      res.json({
        valid: true,
        message: 'Session is valid and active',
        tokenCount: session.inviteTokens?.length || 0
      });
    } catch (refreshError) {
      console.error('Session validation failed:', refreshError.message);

      if (refreshError.response?.data?.error === 'invalid_grant') {
        return res.status(401).json({
          valid: false,
          error: 'invalid_grant',
          message: 'Session has expired. Please re-authenticate.'
        });
      }

      throw refreshError;
    }
  } catch (error) {
    console.error('Error validating session:', error);
    res.status(500).json({
      valid: false,
      error: error.message
    });
  }
});

// ============================================================================
// SMART INVITE LINK ENDPOINT
// ============================================================================

/**
 * Smart invite link landing page
 * This endpoint handles invite links shared by admins.
 * It tries to open the app directly, or redirects to the app store if not installed.
 *
 * GET /join?invite=TOKEN|SESSIONID
 */
app.get('/join', (req, res) => {
  const { invite } = req.query;
  const userAgent = req.headers['user-agent'] || '';

  // Detect platform from user agent
  const isIOS = /iPhone|iPad|iPod/i.test(userAgent);
  const isAndroid = /Android/i.test(userAgent);

  // Deep link URL - encode the invite parameter
  const deepLink = `proofpix://join?invite=${encodeURIComponent(invite || '')}`;

  // App store URLs from environment or defaults
  const iosStore = process.env.IOS_APP_STORE_URL || 'https://apps.apple.com/app/id6754261444';
  const androidStore = process.env.ANDROID_PLAY_STORE_URL || 'https://play.google.com/store/apps/details?id=com.proofpix.app';

  // Decode invite for display (safely)
  let displayInvite = 'Invalid invite';
  try {
    displayInvite = invite ? decodeURIComponent(invite) : 'Invalid invite';
  } catch (e) {
    displayInvite = invite || 'Invalid invite';
  }

  console.log(`[JOIN] Invite link accessed - Platform: ${isIOS ? 'iOS' : isAndroid ? 'Android' : 'Desktop/Other'}`);

  // HTML page that tries deep link first, falls back to store
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Join ProofPix Team</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="apple-itunes-app" content="app-id=YOUR_APP_ID">
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      text-align: center;
      padding: 20px;
      background: linear-gradient(135deg, #F2C31B 0%, #E5B517 100%);
      min-height: 100vh;
      margin: 0;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      max-width: 400px;
      width: 100%;
      background: white;
      border-radius: 20px;
      padding: 40px 30px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.15);
    }
    .logo {
      width: 80px;
      height: 80px;
      background: #F2C31B;
      border-radius: 20px;
      margin: 0 auto 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 36px;
      font-weight: bold;
      color: #333;
    }
    h1 {
      color: #333;
      margin: 0 0 10px 0;
      font-size: 24px;
    }
    p {
      color: #666;
      margin: 0 0 20px 0;
      line-height: 1.5;
    }
    .spinner {
      width: 40px;
      height: 40px;
      border: 4px solid #f3f3f3;
      border-top: 4px solid #F2C31B;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 20px auto;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .store-buttons {
      margin-top: 30px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .store-btn {
      display: block;
      padding: 14px 24px;
      background: #333;
      color: white;
      text-decoration: none;
      border-radius: 12px;
      font-weight: 600;
      font-size: 16px;
      transition: background 0.2s;
    }
    .store-btn:hover { background: #555; }
    .store-btn.ios { background: #007AFF; }
    .store-btn.ios:hover { background: #0056b3; }
    .store-btn.android { background: #34A853; }
    .store-btn.android:hover { background: #2d8e47; }
    .code-section {
      margin-top: 30px;
      padding-top: 20px;
      border-top: 1px solid #eee;
    }
    .code-label {
      font-size: 13px;
      color: #999;
      margin-bottom: 8px;
    }
    .code {
      background: #f5f5f5;
      padding: 12px;
      border-radius: 8px;
      font-family: 'SF Mono', Monaco, 'Courier New', monospace;
      word-break: break-all;
      font-size: 12px;
      color: #333;
      user-select: all;
    }
    .hint {
      font-size: 12px;
      color: #999;
      margin-top: 8px;
    }
  </style>
  <script>
    // Try to open the app immediately
    window.location.href = '${deepLink}';

    // After delay, show store buttons (app didn't open)
    setTimeout(function() {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('fallback').style.display = 'block';
    }, 2500);
  </script>
</head>
<body>
  <div class="container">
    <div class="logo">PP</div>

    <div id="loading">
      <h1>Opening ProofPix...</h1>
      <div class="spinner"></div>
      <p>Please wait while we open the app</p>
    </div>

    <div id="fallback" style="display: none;">
      <h1>Get ProofPix</h1>
      <p>Download the app to join your team and start taking before & after photos!</p>

      <div class="store-buttons">
        ${isIOS ? `<a href="${iosStore}" class="store-btn ios">Download for iPhone</a>` : ''}
        ${isAndroid ? `<a href="${androidStore}" class="store-btn android">Download for Android</a>` : ''}
        ${!isIOS && !isAndroid ? `<a href="${iosStore}" class="store-btn ios">Download for iPhone</a>` : ''}
        ${!isIOS && !isAndroid ? `<a href="${androidStore}" class="store-btn android">Download for Android</a>` : ''}
      </div>

      <div class="code-section">
        <div class="code-label">After installing, use this invite code:</div>
        <div class="code">${displayInvite}</div>
        <div class="hint">Tap to select, then copy and paste in the app</div>
      </div>
    </div>
  </div>
</body>
</html>
  `);
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  // Check environment variables (without exposing sensitive values)
  const hasClientId = !!(process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID ||
                         process.env.GOOGLE_WEB_CLIENT_ID ||
                         process.env.GOOGLE_CLIENT_ID);
  const hasClientSecret = !!process.env.GOOGLE_CLIENT_SECRET;
  const hasKvUrl = !!(process.env.VERCEL_KV_REST_API_URL || process.env.KV_REST_API_URL);
  const hasKvToken = !!(process.env.VERCEL_KV_REST_API_TOKEN || process.env.KV_REST_API_TOKEN);

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    config: {
      hasOAuthCredentials: hasClientId && hasClientSecret,
      hasKvConfig: hasKvUrl && hasKvToken,
      clientIdSource: process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID ? 'EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID' :
                      process.env.GOOGLE_WEB_CLIENT_ID ? 'GOOGLE_WEB_CLIENT_ID' :
                      process.env.GOOGLE_CLIENT_ID ? 'GOOGLE_CLIENT_ID' : 'none',
      kvUrlSource: process.env.VERCEL_KV_REST_API_URL ? 'VERCEL_KV_REST_API_URL' :
                   process.env.KV_REST_API_URL ? 'KV_REST_API_URL' : 'none'
    }
  });
});

/**
 * Generate a random session ID
 */
function generateSessionId() {
  return Array.from({ length: 32 }, () =>
    Math.floor(Math.random() * 16).toString(16)
  ).join('');
}

// ============================================================================
// REFERRAL SYSTEM ENDPOINTS
// ============================================================================

/**
 * Track referral installation
 * POST /api/referrals/track-installation
 * Body: { referralCode, deviceId, timestamp }
 */
app.post('/api/referrals/track-installation', async (req, res) => {
  try {
    const { referralCode, deviceId, timestamp } = req.body;

    if (!referralCode || !deviceId) {
      return res.status(400).json({ error: 'Missing referralCode or deviceId' });
    }

    console.log(`[REFERRAL] Tracking installation for code: ${referralCode}, device: ${deviceId}`);

    // Check if this device already used a referral code
    const existingReferral = await kv.get(`referral:device:${deviceId}`);
    if (existingReferral) {
      console.log(`[REFERRAL] Device ${deviceId} already used referral code`);
      return res.status(400).json({
        error: 'Device already used a referral code',
        existingReferralId: existingReferral
      });
    }

    // Get referrer info from referral code
    const referrerUserId = await kv.get(`referralCode:${referralCode}`);
    if (!referrerUserId) {
      console.log(`[REFERRAL] Invalid referral code: ${referralCode}`);
      return res.status(404).json({ error: 'Invalid referral code' });
    }

    // Create referral record
    const referralId = `ref_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const referral = {
      id: referralId,
      referrerUserId,
      referralCode,
      deviceId,
      status: 'pending',
      createdAt: timestamp || new Date().toISOString(),
      completedAt: null,
      referredUserId: null
    };

    // Store referral with 30-day expiration
    await kv.set(`referral:${referralId}`, referral, { ex: 30 * 24 * 60 * 60 });

    // Map device to referral (prevent multiple uses)
    await kv.set(`referral:device:${deviceId}`, referralId, { ex: 30 * 24 * 60 * 60 });

    // Add to pending referrals for this referrer
    await kv.sadd(`referrals:pending:${referrerUserId}`, referralId);

    console.log(`[REFERRAL] Installation tracked successfully: ${referralId}`);

    res.json({
      success: true,
      referralId
    });
  } catch (error) {
    console.error('[REFERRAL] Track installation error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

/**
 * Complete referral setup (when new user finishes onboarding)
 * POST /api/referrals/complete-setup
 * Body: { referralCode, userId, setupCompletedAt }
 */
app.post('/api/referrals/complete-setup', async (req, res) => {
  try {
    const { referralCode, userId, setupCompletedAt } = req.body;

    if (!referralCode || !userId) {
      return res.status(400).json({ error: 'Missing referralCode or userId' });
    }

    console.log(`[REFERRAL] Completing setup for code: ${referralCode}, user: ${userId}`);

    // Get referrer info
    const referrerUserId = await kv.get(`referralCode:${referralCode}`);
    if (!referrerUserId) {
      return res.status(404).json({ error: 'Invalid referral code' });
    }

    // Prevent self-referral
    if (referrerUserId === userId) {
      console.log(`[REFERRAL] Self-referral attempt blocked for user: ${userId}`);
      return res.status(400).json({ error: 'Cannot use your own referral code' });
    }

    // Find pending referral for this code
    const pendingReferrals = await kv.smembers(`referrals:pending:${referrerUserId}`);
    let referralId = null;
    let referral = null;

    for (const refId of pendingReferrals) {
      const ref = await kv.get(`referral:${refId}`);
      if (ref && ref.referralCode === referralCode && ref.status === 'pending') {
        referralId = refId;
        referral = ref;
        break;
      }
    }

    if (!referralId || !referral) {
      return res.status(404).json({ error: 'No pending referral found for this code' });
    }

    // Update referral status
    referral.status = 'completed';
    referral.completedAt = setupCompletedAt || new Date().toISOString();
    referral.referredUserId = userId;
    await kv.set(`referral:${referralId}`, referral);

    // Move from pending to completed
    await kv.srem(`referrals:pending:${referrerUserId}`, referralId);
    await kv.sadd(`referrals:completed:${referrerUserId}`, referralId);

    // Calculate reward (stackable: 1st=1mo, 2nd=1mo, 3+=1mo per referral)
    const completedCount = await kv.scard(`referrals:completed:${referrerUserId}`);
    const monthsEarned = 1; // Always 1 month per successful referral

    // Apply reward to referrer
    const reward = {
      id: `reward_${Date.now()}`,
      referralId,
      referrerUserId,
      monthsEarned,
      appliedAt: new Date().toISOString()
    };

    await kv.set(`reward:${reward.id}`, reward);
    await kv.sadd(`rewards:${referrerUserId}`, reward.id);

    // Update referrer stats
    await kv.hincrby(`referralStats:${referrerUserId}`, 'completedInvites', 1);
    await kv.hincrby(`referralStats:${referrerUserId}`, 'monthsEarned', monthsEarned);

    console.log(`[REFERRAL] Setup completed! Referrer ${referrerUserId} earned ${monthsEarned} month(s)`);

    res.json({
      success: true,
      referrerId: referrerUserId,
      monthsEarned,
      totalCompletedReferrals: completedCount
    });
  } catch (error) {
    console.error('[REFERRAL] Complete setup error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

/**
 * Get referral stats for a user
 * GET /api/referrals/stats?userId=xxx
 */
app.get('/api/referrals/stats', async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ error: 'Missing userId parameter' });
    }

    console.log(`[REFERRAL] Getting stats for user: ${userId}`);

    // Get user's referral code
    const referralCode = await kv.get(`user:${userId}:referralCode`);

    // Get stats
    const stats = await kv.hgetall(`referralStats:${userId}`) || {};
    const completedInvites = parseInt(stats.completedInvites || '0', 10);
    const monthsEarned = parseInt(stats.monthsEarned || '0', 10);

    // Get pending and completed counts
    const pendingCount = await kv.scard(`referrals:pending:${userId}`) || 0;
    const completedCount = await kv.scard(`referrals:completed:${userId}`) || 0;

    res.json({
      code: referralCode || null,
      totalInvites: pendingCount + completedCount,
      completedInvites: completedCount,
      pendingInvites: pendingCount,
      monthsEarned
    });
  } catch (error) {
    console.error('[REFERRAL] Get stats error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

/**
 * Register a user's referral code
 * POST /api/referrals/register-code
 * Body: { userId, referralCode }
 */
app.post('/api/referrals/register-code', async (req, res) => {
  try {
    const { userId, referralCode } = req.body;

    if (!userId || !referralCode) {
      return res.status(400).json({ error: 'Missing userId or referralCode' });
    }

    console.log(`[REFERRAL] Registering code ${referralCode} for user ${userId}`);

    // Check if code already exists
    const existingUserId = await kv.get(`referralCode:${referralCode}`);
    if (existingUserId) {
      if (existingUserId === userId) {
        // Code already registered to this user - idempotent operation
        console.log(`[REFERRAL] Code already registered to this user (idempotent)`);
        return res.json({
          success: true,
          userId,
          referralCode,
          alreadyRegistered: true
        });
      } else {
        // Code registered to a different user
        return res.status(400).json({ error: 'Referral code already in use by another user' });
      }
    }

    // Store mapping: referralCode -> userId
    await kv.set(`referralCode:${referralCode}`, userId);

    // Store mapping: userId -> referralCode
    await kv.set(`user:${userId}:referralCode`, referralCode);

    // Initialize stats if not exists
    const statsExists = await kv.exists(`referralStats:${userId}`);
    if (!statsExists) {
      await kv.hset(`referralStats:${userId}`, {
        completedInvites: 0,
        monthsEarned: 0
      });
    }

    console.log(`[REFERRAL] Code registered successfully`);

    res.json({
      success: true,
      userId,
      referralCode
    });
  } catch (error) {
    console.error('[REFERRAL] Register code error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// ============================================================================

app.listen(PORT, () => {
  console.log(`ProofPix proxy server running on port ${PORT}`);
});
