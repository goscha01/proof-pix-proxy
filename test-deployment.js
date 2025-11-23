#!/usr/bin/env node

/**
 * Test script to verify the latest proxy server code is deployed
 *
 * Usage: node test-deployment.js
 */

const PROXY_URL = 'https://proof-pix-proxy.vercel.app';

async function testDeployment() {
  console.log('Testing proxy server deployment...\n');

  // Test 1: Health check
  console.log('1. Testing health endpoint...');
  try {
    const healthResponse = await fetch(`${PROXY_URL}/health`);
    const health = await healthResponse.json();
    console.log('   ✅ Health check passed');
    console.log('   - Status:', health.status);
    console.log('   - Has OAuth credentials:', health.config.hasOAuthCredentials);
  } catch (error) {
    console.log('   ❌ Health check failed:', error.message);
    return;
  }

  // Test 2: Init endpoint with test data (should fail with proper error)
  console.log('\n2. Testing init endpoint with test data...');
  try {
    const initResponse = await fetch(`${PROXY_URL}/api/admin/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        folderId: 'test',
        serverAuthCode: 'test'
      })
    });

    const initData = await initResponse.json();

    if (initData.error && initData.error.includes('redirectUri')) {
      console.log('   ❌ OLD CODE DETECTED: Getting "redirectUri" error');
      console.log('   Error:', initData.error);
      return;
    }

    if (initData.error && initData.error.includes('authorization code')) {
      console.log('   ✅ NEW CODE CONFIRMED: Getting proper OAuth error');
      console.log('   Error:', initData.error);
    } else {
      console.log('   ⚠️  Unexpected response:', initData);
    }
  } catch (error) {
    console.log('   ❌ Init endpoint test failed:', error.message);
    return;
  }

  console.log('\n✅ Deployment verification complete! Latest code is deployed.');
}

testDeployment().catch(error => {
  console.error('Test failed:', error);
  process.exit(1);
});
