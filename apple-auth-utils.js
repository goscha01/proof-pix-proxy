/**
 * Apple Sign In Authentication Utilities
 * Handles verification, token exchange, and refresh for Apple Sign In
 */

const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

// Apple's public key endpoint for token verification
const client = jwksClient({
  jwksUri: 'https://appleid.apple.com/auth/keys',
  cache: true,
  cacheMaxAge: 86400000, // 24 hours
});

/**
 * Get Apple's public key for JWT verification
 * @private
 */
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

/**
 * Verify Apple identity token (JWT)
 * @param {string} identityToken - JWT from Apple Sign In
 * @returns {Promise<object>} Decoded token payload
 */
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

/**
 * Generate Apple client secret (JWT signed with private key)
 * @returns {string} Client secret JWT
 */
function generateAppleClientSecret() {
  let privateKey = process.env.APPLE_PRIVATE_KEY;
  const teamId = process.env.APPLE_TEAM_ID;
  const keyId = process.env.APPLE_KEY_ID;

  if (!privateKey || !teamId || !keyId) {
    throw new Error('Missing Apple credentials in environment variables. Required: APPLE_PRIVATE_KEY, APPLE_TEAM_ID, APPLE_KEY_ID');
  }

  // Handle private key formatting
  // If the key is on a single line (from Vercel), format it properly
  if (!privateKey.includes('\n')) {
    console.log('[APPLE] Private key is on single line, reformatting...');
    // Split the key into proper PEM format
    privateKey = privateKey
      .replace('-----BEGIN PRIVATE KEY-----', '-----BEGIN PRIVATE KEY-----\n')
      .replace('-----END PRIVATE KEY-----', '\n-----END PRIVATE KEY-----');
    
    // Insert newlines every 64 characters in the key body
    const beginMarker = '-----BEGIN PRIVATE KEY-----\n';
    const endMarker = '\n-----END PRIVATE KEY-----';
    const keyBody = privateKey.replace(beginMarker, '').replace(endMarker, '');
    const formattedBody = keyBody.match(/.{1,64}/g)?.join('\n') || keyBody;
    privateKey = beginMarker + formattedBody + endMarker;
    
    console.log('[APPLE] Private key reformatted successfully');
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

/**
 * Exchange Apple authorization code for tokens
 * @param {string} authorizationCode - One-time authorization code from Apple
 * @returns {Promise<{accessToken, refreshToken, expiresIn, idToken}>}
 */
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

/**
 * Refresh Apple access token using refresh token
 * @param {string} refreshToken - Apple refresh token
 * @returns {Promise<string>} New access token
 */
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
    const errorText = await response.text();
    throw new Error(`Failed to refresh Apple access token: ${errorText}`);
  }

  const data = await response.json();
  return data.access_token;
}

module.exports = {
  verifyAppleToken,
  exchangeAppleAuthCode,
  refreshAppleAccessToken,
};
