import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

// Ensure env vars are loaded
dotenv.config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

console.log('[SUPABASE-SERVER] Checking credentials...');
console.log('[SUPABASE-SERVER] SUPABASE_URL:', SUPABASE_URL ? '✓ SET' : '✗ MISSING');
console.log('[SUPABASE-SERVER] SUPABASE_SERVICE_ROLE_KEY:', SUPABASE_SERVICE_ROLE_KEY ? `✓ SET (${SUPABASE_SERVICE_ROLE_KEY.substring(0, 20)}...)` : '✗ MISSING');

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  // Keep this safe — service role key must only live server-side
  console.warn('[SUPABASE-SERVER] ⚠️  Missing Supabase credentials. Server client disabled.');
}

const supabaseAdmin = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false }
    })
  : null;

if (supabaseAdmin) {
  console.log('[SUPABASE-SERVER] ✓ Supabase admin client initialized successfully');
} else {
  console.log('[SUPABASE-SERVER] ✗ Supabase admin client is NULL');
}

export default supabaseAdmin;
