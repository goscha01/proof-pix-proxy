# ProofPix Proxy Server

This is a simple proxy server that allows team members to upload photos without requiring Google sign-in.

## How It Works

1. **Admin initializes a session** with their Google Drive credentials
2. **Admin adds invite tokens** for team members
3. **Team members upload photos** using their invite token
4. **Proxy validates tokens** and uploads to admin's Google Drive

## Deployment Options

### Option 1: Deploy to Vercel (Recommended - Free)

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Deploy:
   ```bash
   cd proxy-server
   vercel
   ```

3. Copy the deployment URL (e.g., `https://proofpix-proxy.vercel.app`)

### Option 2: Deploy to Railway (Free tier available)

1. Visit https://railway.app
2. Create a new project
3. Connect your GitHub repo or deploy from CLI
4. Set environment variables if needed
5. Copy the deployment URL

### Option 3: Deploy to Render (Free tier available)

1. Visit https://render.com
2. Create a new Web Service
3. Connect your GitHub repo
4. Set build command: `npm install`
5. Set start command: `npm start`
6. Copy the deployment URL

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create `.env` file:
   ```bash
   cp .env.example .env
   ```

3. Start server:
   ```bash
   npm run dev
   ```

## API Endpoints

### Admin: Initialize Session
```
POST /api/admin/init
Body: {
  "folderId": "google-drive-folder-id",
  "accessToken": "google-access-token",
  "refreshToken": "google-refresh-token"
}
Response: { "success": true, "sessionId": "..." }
```

### Admin: Add Token
```
POST /api/admin/:sessionId/tokens
Body: { "token": "invite-token" }
Response: { "success": true }
```

### Team Member: Upload
```
POST /api/upload/:sessionId
Body: {
  "token": "invite-token",
  "filename": "photo.jpg",
  "contentBase64": "base64-encoded-image"
}
Response: { "success": true, "fileId": "..." }
```
