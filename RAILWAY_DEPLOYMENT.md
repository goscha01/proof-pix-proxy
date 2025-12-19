# Railway Deployment Guide for ProofPix Proxy

## Why Railway?
- **No 4.5MB body size limit** (Vercel has a hard 4.5MB limit on all tiers)
- **Simple pricing**: Pay only for what you use
- **Better for file uploads**: Designed to handle large payloads

## Prerequisites
1. Railway account (sign up at https://railway.app)
2. Railway CLI installed: `npm install -g @railway/cli`

## Deployment Steps

### Step 1: Install Railway CLI
```bash
npm install -g @railway/cli
```

### Step 2: Login to Railway
```bash
railway login
```

### Step 3: Initialize Railway Project
Navigate to the proxy directory and create a new Railway project:
```bash
cd c:\Users\HP\Desktop\Projects\Active\Running\ProofPix\proof-pix-proxy
railway init
```

Follow the prompts:
- Create a new project or select existing
- Name it: `proofpix-proxy`

### Step 4: Set Environment Variables
You need to set all the environment variables from your `.env` file:

```bash
# Copy these from your .env file
railway variables set APPLE_PRIVATE_KEY="<your-value>"
railway variables set APPLE_KEY_ID="<your-value>"
railway variables set APPLE_TEAM_ID="<your-value>"
railway variables set GOOGLE_CLIENT_SECRET="<your-value>"
railway variables set EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID="<your-value>"
railway variables set KV_URL="<your-value>"
railway variables set KV_REST_API_READ_ONLY_TOKEN="<your-value>"
railway variables set REDIS_URL="<your-value>"
railway variables set KV_REST_API_TOKEN="<your-value>"
railway variables set KV_REST_API_URL="<your-value>"
```

**OR** set them in the Railway dashboard:
1. Go to https://railway.app/dashboard
2. Select your project
3. Click "Variables" tab
4. Add each variable from your `.env` file

### Step 5: Deploy
```bash
railway up
```

This will:
1. Build your application
2. Deploy to Railway
3. Give you a deployment URL

### Step 6: Get Your Railway URL
```bash
railway domain
```

Or go to your Railway dashboard → Select project → Click "Settings" → "Domains" → "Generate Domain"

Your Railway URL will be something like: `https://proofpix-proxy-production.up.railway.app`

### Step 7: Update React Native App
Update the proxy URL in your React Native app to point to the new Railway URL.

Find and replace in your codebase:
- Old: `https://proof-pix-proxy.vercel.app`
- New: `https://proofpix-proxy-production.up.railway.app` (or your actual Railway domain)

Files to update:
- `src/services/proxyService.js`
- Any other files that reference the Vercel URL

### Step 8: Test Upload
Test uploading a large photo (>4.5MB) to verify it works without 413 errors.

## Railway Configuration Details

### Port Configuration
Railway automatically sets the `PORT` environment variable. Your `index.js` already handles this:
```javascript
const PORT = process.env.PORT || 3000;
```

### Health Checks
Railway will automatically detect your Express server is running on the PORT.

### Logs
View logs in real-time:
```bash
railway logs
```

Or in the Railway dashboard → Select project → "Deployments" → Click deployment → "View Logs"

## Cost Estimation
Railway pricing (as of 2025):
- **Free tier**: $5 credit per month
- **Usage-based**: ~$0.000463 per GB-hour of RAM + $0.000231 per vCPU-hour

For a typical proxy server with moderate traffic:
- Expected cost: **$5-20/month** depending on usage
- Much cheaper than Vercel Pro at $20/month with the 4.5MB limitation

## Rollback Plan
If you need to rollback to Vercel:
1. Keep the Vercel deployment active
2. Switch the proxy URL back in the React Native app
3. Railway deployment can stay as backup

## Common Issues

### Issue: "Build failed"
**Solution**: Check logs with `railway logs` and ensure all dependencies are in `package.json`

### Issue: "Environment variable not found"
**Solution**: Verify all variables are set with `railway variables`

### Issue: "Port binding error"
**Solution**: Ensure your `index.js` uses `process.env.PORT`

## Support
- Railway docs: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- ProofPix issues: https://github.com/anthropics/claude-code/issues
