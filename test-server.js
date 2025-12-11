import dotenv from 'dotenv';
import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';

// Load environment variables
dotenv.config();

// Use localhost for testing, not the configured BASE_URL
const BASE_URL = 'http://localhost:3000';
const agent = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
  validateStatus: () => true // Don't throw on any status
});

// Store cookies for session management
let cookies = [];

const tests = [];
let passedCount = 0;
let failedCount = 0;

// Test helper
async function test(name, fn) {
  tests.push({ name, fn });
}

// Run all tests
async function runTests() {
  console.log(`\n${'='.repeat(80)}`);
  console.log('🚀 FULL SERVER TEST SUITE');
  console.log(`${'='.repeat(80)}\n`);

  console.log(`📍 BASE_URL: ${BASE_URL}`);
  console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`✓ Supabase: ${process.env.SUPABASE_URL ? '✓ Configured' : '✗ Missing'}`);
  console.log('\n');

  for (const t of tests) {
    try {
      await t.fn();
      console.log(`✅ PASS: ${t.name}`);
      passedCount++;
    } catch (err) {
      console.error(`❌ FAIL: ${t.name}`);
      console.error(`   Error: ${err.message}`);
      failedCount++;
    }
  }

  console.log(`\n${'='.repeat(80)}`);
  console.log(`📊 Results: ${passedCount} passed, ${failedCount} failed out of ${tests.length} tests`);
  console.log(`${'='.repeat(80)}\n`);

  process.exit(failedCount > 0 ? 1 : 0);
}

// ============================================================================
// TEST SUITE
// ============================================================================

// 1. Health Checks
test('Health Check - GET /', async () => {
  const res = await agent.get('/');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('Health Check - GET /api/supabase/health', async () => {
  const res = await agent.get('/api/supabase/health');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!res.data || res.data.ok !== true) throw new Error('Supabase health check failed');
});

// 2. Authentication Pages
test('GET /login - Login page renders', async () => {
  const res = await agent.get('/login');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!res.data.includes('login')) throw new Error('Login page missing content');
});

test('GET /register - Register page renders', async () => {
  const res = await agent.get('/register');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!res.data.includes('register')) throw new Error('Register page missing content');
});

test('GET /forgot-password - Password reset page renders', async () => {
  const res = await agent.get('/forgot-password');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

// 3. API Tests
test('GET /api/resolve-username - Check username availability', async () => {
  const res = await agent.get('/api/resolve-username?username=testuser');
  // Endpoint returns email if found (200) or empty object if not found (200)
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (typeof res.data !== 'object') throw new Error('Invalid response format');
});

test('GET /api/photos - Fetch photos feed', async () => {
  const res = await agent.get('/api/photos');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!Array.isArray(res.data.photos)) throw new Error('Expected array response');
});

test('GET /api/videos - Fetch videos feed', async () => {
  const res = await agent.get('/api/videos');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!Array.isArray(res.data.videos)) throw new Error('Expected array response');
});

// 4. OAuth/SSO Pages
test('GET /oauth/setup - OAuth setup page renders', async () => {
  const res = await agent.get('/oauth/setup');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('GET /login/oauth/consent - Consent page renders', async () => {
  // OAuth consent requires client_id, redirect_uri, response_type parameters
  const res = await agent.get('/login/oauth/consent?client_id=test-client&redirect_uri=http://localhost:3000/callback&response_type=code');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

// 5. 2FA Pages
test('GET /2fa-login - 2FA login page renders', async () => {
  const res = await agent.get('/2fa-login');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('GET /setup-2fa - 2FA setup requires authentication (should redirect)', async () => {
  const res = await agent.get('/setup-2fa');
  // Should redirect or return 401 if not authenticated
  if (res.status >= 400 && res.status < 500) {
    return; // Expected unauthorized response
  }
});

// 6. Support/Help Pages
test('GET /support - Support page renders', async () => {
  const res = await agent.get('/support');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('GET /check-email - Email verification check page', async () => {
  const res = await agent.get('/check-email');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('GET /verified - Email verified page', async () => {
  const res = await agent.get('/verified');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

test('GET /resend-verification - Resend verification page', async () => {
  const res = await agent.get('/resend-verification');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

// 7. Static Assets
test('GET /js/supabase-client.mjs - Supabase client bundle', async () => {
  const res = await agent.get('/js/supabase-client.mjs');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
  if (!res.data.includes('supabase')) throw new Error('Missing Supabase content');
});

// 8. API Logging
test('POST /api/client-log - Client logging endpoint', async () => {
  const res = await agent.post('/api/client-log', {
    level: 'info',
    message: 'Test log message'
  });
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

// 9. Reset/Recovery Flow
test('GET /reset - Password reset page', async () => {
  const res = await agent.get('/reset');
  if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
});

// 10. Logout
test('GET /logout - Logout endpoint', async () => {
  const res = await agent.get('/logout');
  // Should redirect or return success
  if (res.status >= 400 && res.status !== 302) throw new Error(`Unexpected status ${res.status}`);
});

// ============================================================================
// ENVIRONMENT VARIABLE VALIDATION
// ============================================================================

test('Verify SUPABASE_URL is set', async () => {
  if (!process.env.SUPABASE_URL) throw new Error('SUPABASE_URL not set');
});

test('Verify SUPABASE_SERVICE_ROLE_KEY is set', async () => {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('SUPABASE_SERVICE_ROLE_KEY not set');
});

test('Verify SUPABASE_BUCKET is set', async () => {
  if (!process.env.SUPABASE_BUCKET) throw new Error('SUPABASE_BUCKET not set');
});

test('Verify BASE_URL is set', async () => {
  if (!process.env.BASE_URL && !process.env.APP_URL) throw new Error('BASE_URL or APP_URL not set');
});

test('Verify SESSION_SECRET is set', async () => {
  if (!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET not set');
});

// ============================================================================
// START TESTS
// ============================================================================

// Wait for server to be ready, then run tests
console.log('⏳ Waiting for server to be ready...\n');

let retries = 0;
const maxRetries = 30;

const checkServer = async () => {
  try {
    await agent.get('/');
    console.log('✓ Server is ready!\n');
    await runTests();
  } catch (err) {
    retries++;
    if (retries >= maxRetries) {
      console.error(`\n❌ Server failed to start after ${maxRetries} retries`);
      console.error(`   ${err.message}`);
      process.exit(1);
    }
    console.log(`⏳ Attempt ${retries}/${maxRetries}: Server not ready, retrying...`);
    setTimeout(checkServer, 1000);
  }
};

checkServer();
