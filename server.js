import express from 'express';
import session from 'express-session';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

// Load environment variables FIRST before importing anything that depends on process.env
dotenv.config();

// Now safely import modules that depend on env vars
// Passport removed - using Supabase auth and server-side sessions instead
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import supabaseDb from './lib/supabaseDb.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import Mailjet from 'node-mailjet';
import fs from 'fs';

// Import supabase AFTER dotenv.config() is called
const supabaseAdminModule = await import('./lib/supabaseServer.js');
const supabaseAdmin = supabaseAdminModule.default;

const supabaseClientModule = await import('./lib/supabaseClient.js');
const supabase = supabaseClientModule.default;

console.log('[SERVER] Supabase admin client:', supabaseAdmin ? '✓ Loaded' : '✗ NULL');

// Mailjet integration (will create a Nodemailer-compatible transporter wrapper)
let mailjetTransporter;

// Require a canonical public base URL — do not fall back to localhost in Codespaces
if (!process.env.BASE_URL && !process.env.APP_URL) {
  console.error('ERROR: BASE_URL or APP_URL must be set in your .env (no localhost fallbacks).');
  process.exit(1);
}

// Enforce or provide sensible defaults for critical configuration
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET && process.env.NODE_ENV === 'production') {
  console.error('ERROR: SESSION_SECRET must be set in production.');
  process.exit(1);
}
const sessionSecret = SESSION_SECRET || 'dev-session-secret';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize app first
const app = express();
app.set('trust proxy', 1);

// ====================
// Middleware Setup
// ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));
// Security headers middleware (CSP, X-Frame-Options, Referrer-Policy, etc.)
app.use((req, res, next) => {
  const baseUrl = app.locals.BASE_URL || '';
  const supabaseUrl = process.env.SUPABASE_URL || '';
  const connectSrc = ["'self'", 'https://cdn.jsdelivr.net'];
  if (baseUrl) connectSrc.push(baseUrl);
  if (supabaseUrl) connectSrc.push(supabaseUrl);

  // Restrictive but pragmatic CSP allowing local scripts/styles, jsdelivr CDN and Supabase origins
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net ${supabaseUrl ? supabaseUrl : ''}`.trim(),
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "img-src 'self' data: blob:",
    `connect-src ${connectSrc.join(' ')}`,
    "font-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'"
  ].join('; ');

  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Prevent caching of sensitive endpoints by default
  res.setHeader('Pragma', 'no-cache');
  next();
});
// No local /uploads route - all files served from Supabase storage

// Expose whether Supabase is configured for views/clients
app.locals.SUPABASE_ENABLED = !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.SUPABASE_BUCKET);
app.locals.SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || null;
app.locals.SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || null;

console.log('[SERVER] Supabase configuration:', {
  SUPABASE_URL: process.env.SUPABASE_URL ? '✓ Set' : '✗ Missing',
  SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY ? '✓ Set' : '✗ Missing',
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY ? '✓ Set' : '✗ Missing',
  SUPABASE_BUCKET: process.env.SUPABASE_BUCKET ? '✓ Set' : '✗ Missing'
});

// Session middleware
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

// Make the current user available in all templates and provide session helpers.
app.use((req, res, next) => {
  // Attach simple session-based auth helpers (compatible with existing uses of req.logIn/req.logOut/req.isAuthenticated)
  req.isAuthenticated = () => !!(req.session && req.session.userId);
  req.logIn = (user, cb) => {
    if (req.session) {
      req.session.userId = user.id;
      // IMPORTANT: Save session synchronously before callback to ensure cookie is set
      req.session.save((err) => {
        if (err && cb) return cb(err);
        req.user = user;
        res.locals.user = user;
        console.log('[MIDDLEWARE] logIn: Session saved for user', user.id, 'sessionID:', req.sessionID);
        if (cb) cb(null);
      });
    } else {
      req.user = user;
      res.locals.user = user;
      if (cb) cb(null);
    }
  };
  req.logOut = (cb) => {
    if (req.session) delete req.session.userId;
    delete req.user;
    res.locals.user = null;
    if (cb) cb && cb(null);
  };

  // Make auth flags available to templates
  res.locals.GOOGLE_OAUTH = app.locals.GOOGLE_OAUTH;
  res.locals.ENTRA_OAUTH = app.locals.ENTRA_OAUTH;
  res.locals.SUPABASE_ENABLED = app.locals.SUPABASE_ENABLED;
  res.locals.user = req.user || null;
  next();
});

// ====================
// Multer Setup
// ====================
// Memory storage only - all files go to Supabase storage
const uploadMemory = multer({ 
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = file.mimetype.startsWith('video/');
    if (isImage || isVideo) cb(null, true);
    else cb(new Error('Only image and video files allowed'));
  }
});

// Support form uploader (allow broader file types, store in uploads)
const supportUpload = multer({ dest: join(__dirname, 'uploads') });

// ====================
// View Setup
// ====================
app.set('views', join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Make important env-driven defaults available to all views
app.locals.SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'akunknow3124@gmail.com';
app.locals.LEGAL_EMAIL = process.env.LEGAL_EMAIL || 'kinville134@gmail.com';
app.locals.BASE_URL = process.env.BASE_URL || process.env.APP_URL;

// Feature flags for templatescd
// Always show OAuth buttons (override env flags)
app.locals.GOOGLE_OAUTH = true;
app.locals.ENTRA_OAUTH = true;
app.locals.NODE_ENV = process.env.NODE_ENV || 'development';

// Passport configuration removed — Supabase handles authentication in production.

// ====================
// Helper Functions
// ====================
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  // For API requests, return 401
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.redirect('/login');
};

// Use ONLY Supabase - no local database fallback
console.log('[SERVER] Checking Supabase configuration...');
console.log('[SERVER] supabaseAdmin:', supabaseAdmin ? 'NOT NULL' : 'IS NULL');
console.log('[SERVER] SUPABASE_URL:', process.env.SUPABASE_URL ? '✓' : '✗');
console.log('[SERVER] SUPABASE_SERVICE_ROLE_KEY:', process.env.SUPABASE_SERVICE_ROLE_KEY ? '✓' : '✗');

if (!supabaseAdmin) {
  console.error('ERROR: Supabase is required but not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env');
  process.exit(1);
}
console.log('[SERVER] ✓ Supabase is configured correctly');
// Keep `store` alias for compatibility while we migrate all references to `supabaseDb`.
const store = supabaseDb;

// If a session has a userId, load the full user from the chosen store and attach to req/res.locals
app.use(async (req, res, next) => {
  try {
    if (req.session && req.session.userId && !req.user) {
      const u = await supabaseDb.users.findById(req.session.userId);
      if (u) {
        req.user = u;
        res.locals.user = u;
      } else {
        // cleanup invalid session
        delete req.session.userId;
        res.locals.user = null;
      }
    }
  } catch (e) {
    console.error('Failed to hydrate session user:', e && e.message);
  }
  next();
});

let smtpTransporter;
let consoleTransporter = {
  sendMail: async (opts) => {
    console.log('--- Email (logged) ---');
    console.log('To:', opts.to);
    console.log('Subject:', opts.subject);
    console.log('Text:', opts.text);
    console.log('HTML:', opts.html);
    if (opts.attachments) console.log('Attachments:', opts.attachments.map(a => a.filename || a.path));
  }
};

// Prefer Mailjet, then SMTP, then console
const getMailer = () => mailjetTransporter || smtpTransporter || consoleTransporter;
const sendMail = async (opts) => {
  const t = getMailer();
  try {
    return await t.sendMail(opts);
  } catch (err) {
    console.error('Mail send error, falling back to console:', err && err.message);
    return consoleTransporter.sendMail(opts);
  }
};

// ====================
// Routes
// ====================

// Client-side console logging - captures browser console logs and displays them in terminal
app.post('/api/client-log', express.json(), (req, res) => {
  const { level, messages, url, timestamp } = req.body || {};
  const levelEmoji = {
    'log': '📝',
    'warn': '⚠️ ',
    'error': '❌',
    'info': 'ℹ️ ',
    'debug': '🐛',
    'group': '📦'
  }[level] || '📝';
  
  const timeStr = new Date(timestamp).toLocaleTimeString();
  const msgStr = (messages || []).map(m => {
    if (typeof m === 'object') {
      try { return JSON.stringify(m, null, 2); } catch (e) { return String(m); }
    }
    return String(m);
  }).join(' ');
  
  console.log(`[CLIENT ${timeStr}] ${levelEmoji} ${level.toUpperCase()}: ${msgStr}`);
  res.json({ received: true });
});

// Serve Supabase client as a module
// This expects window.supabase to be loaded globally via a script tag in the views
// and provides a simple re-export for module imports
app.get('/js/supabase-client.mjs', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  
  // Export the createClient function from the global window.supabase object
  const code = `
// Supabase Client Module - Browser ES Module
// Re-exports from window.supabase which is loaded globally

export const createClient = (supabaseUrl, supabaseKey, options) => {
  if (typeof window === 'undefined' || !window.supabase || !window.supabase.createClient) {
    throw new Error('[SUPABASE-MODULE] Supabase library not loaded. Make sure the script tag is loaded before this module.');
  }
  return window.supabase.createClient(supabaseUrl, supabaseKey, options);
};
`;
    res.send(code);
});

// Proxy route to serve files from Supabase Storage
// This allows the client to request /uploads/filename and we serve it from Supabase Storage
app.get(/^\/uploads\/(.+)$/, async (req, res) => {
  try {
    const filename = req.params[0];  // Captured group from regex
    console.log('[UPLOADS] GET /uploads/' + filename);
    
    if (!filename) {
      console.log('[UPLOADS] No filename provided');
      return res.status(400).json({ error: 'Filename required' });
    }

    const bucket = process.env.SUPABASE_BUCKET;
    console.log('[UPLOADS] Bucket:', bucket);
    
    if (!bucket) {
      console.log('[UPLOADS] Bucket not configured');
      return res.status(500).json({ error: 'Supabase bucket not configured' });
    }

    // Download the file from Supabase Storage
    console.log('[UPLOADS] Downloading from Supabase...');
    const { data, error } = await supabaseAdmin.storage.from(bucket).download(filename);
    if (error) {
      console.error('[UPLOADS] Download error:', error);
      return res.status(404).json({ error: 'File not found: ' + error.message });
    }

    // Convert Blob to Buffer if needed
    const buffer = Buffer.from(await data.arrayBuffer());
    console.log('[UPLOADS] File size:', buffer.length, 'bytes');
    
    // Set appropriate content type based on file extension
    const ext = filename.split('.').pop().toLowerCase();
    const contentTypes = {
      'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif',
      'mp4': 'video/mp4', 'webm': 'video/webm', 'mov': 'video/quicktime'
    };
    const contentType = contentTypes[ext] || 'application/octet-stream';
    console.log('[UPLOADS] Content-Type:', contentType);
    
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', buffer.length);
    res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year cache
    res.send(buffer);
    console.log('[UPLOADS] Successfully served:', filename);
  } catch (err) {
    console.error('[UPLOADS] Error:', err.message);
    res.status(500).json({ error: 'Failed to load file: ' + err.message });
  }
});

// Quick Supabase health check (requires SUPABASE_SERVICE_ROLE_KEY)
app.get('/api/supabase/health', async (req, res) => {
  try {
    if (!supabaseAdmin) return res.status(503).json({ ok: false, error: 'Supabase server client not configured' });
    // Try a lightweight query - depends on schema existence
    const { data, error } = await supabaseAdmin.from('profiles').select('id').limit(1);
    if (error) return res.status(500).json({ ok: false, error: error.message || error });
    return res.json({ ok: true, sample: data || [] });
  } catch (err) {
    console.error('Supabase health error:', err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// Bridge for client-side Supabase auth -> server session
// This endpoint ensures the user exists in Supabase, creates profile if needed, and establishes server session
app.post('/auth/supabase/session', async (req, res) => {
  try {
    // Ensure CORS headers are set
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    const { access_token, userId } = req.body || {};
    console.log('\n[AUTH] ===== Supabase Session Request Start =====');
    console.log('[AUTH] Body:', { access_token: access_token ? `(${access_token.length} chars)` : 'missing', userId });
    console.log('[AUTH] Headers:', { 
      origin: req.headers.origin, 
      contentType: req.headers['content-type'],
      cookie: req.headers.cookie ? `(${req.headers.cookie.length} chars)` : 'missing'
    });
    console.log('[AUTH] Request method:', req.method, 'URL:', req.originalUrl);

    // If we have an access token and supabase server is available, try to verify and fetch user
    let supaUser = null;
    if (supabaseAdmin && access_token) {
      try {
        console.log('[AUTH] 🔍 Attempting to verify access token with multiple strategies...');
        let resp = null;
        
        // Try 1: getUser with direct token
        try {
          console.log('[AUTH]   Trying getUser(access_token)...');
          resp = await supabaseAdmin.auth.getUser(access_token);
          supaUser = (resp && (resp.data && resp.data.user)) || resp.user || null;
          if (supaUser) console.log('[AUTH]   ✓ getUser(access_token) success');
        } catch (e1) {
          console.log('[AUTH]   ⚠️  getUser(access_token) failed:', e1?.message);
          
          // Try 2: getUser with object shape
          try {
            console.log('[AUTH]   Trying getUser({ access_token })...');
            resp = await supabaseAdmin.auth.getUser({ access_token });
            supaUser = (resp && (resp.data && resp.data.user)) || resp.user || null;
            if (supaUser) console.log('[AUTH]   ✓ getUser({ access_token }) success');
          } catch (e2) {
            console.log('[AUTH]   ⚠️  getUser({ access_token }) failed:', e2?.message);
            
            // Try 3: admin.getUserById if we have userId
            if (userId) {
              try {
                console.log('[AUTH]   Trying admin.getUserById(userId)...');
                resp = await supabaseAdmin.auth.admin.getUserById(userId);
                supaUser = (resp && (resp.user || resp.data)) || resp;
                if (supaUser) console.log('[AUTH]   ✓ admin.getUserById success');
              } catch (e3) {
                console.log('[AUTH]   ⚠️  admin.getUserById failed:', e3?.message);
              }
            }
          }
        }
        
        console.log('[AUTH] Token verification result:', supaUser ? `✓ Found (${supaUser.id})` : '✗ Not found');
      } catch (e) {
        console.warn('[AUTH] ⚠️  Unexpected error during token verification:', e && e.message);
      }
    }

    // Determine target user ID
    const targetId = (supaUser && supaUser.id) || userId;
    console.log('[AUTH] Target ID:', targetId ? targetId.substring(0, 8) + '...' : '❌ MISSING');

    if (!targetId) {
      console.error('[AUTH] ❌ Missing both access_token and userId');
      return res.status(400).json({ error: 'Missing supabase access token or userId' });
    }

    // Check if user exists locally
    console.log('[AUTH] 🔍 Looking up user in local database...');
    let localUser = await supabaseDb.users.findById(targetId);
    console.log('[AUTH] Local user lookup:', localUser ? `✓ Found (${localUser.username})` : '✗ Not found');

    // If user does not exist and an access_token was provided (OAuth flow), pause and ask user to pick username/display name
    if (!localUser && req.body && req.body.access_token) {
      try {
        console.log('[AUTH] 🔔 OAuth user not mapped locally — deferring to profile setup page');
        let existingProfile = null;
        if (supabaseAdmin && targetId) {
          try {
            const { data: pData } = await supabaseAdmin.from('profiles').select('*').eq('id', targetId).limit(1).maybeSingle(); // maybeSingle: profile creation can lag behind auth user creation due to DB trigger timing
            if (pData) existingProfile = pData;
          } catch (e) {
            console.log('[AUTH] ⚠️  Could not fetch existing profile for setup:', e?.message);
          }
        }

        // Store pending OAuth details in session so the setup form can complete creation server-side
        req.session.pendingOAuth = {
          access_token: req.body.access_token,
          userId: targetId,
          profile: existingProfile
        };
        await new Promise((r) => req.session.save(r));
        return res.json({ needs_setup: true, redirect: '/oauth/setup' });
      } catch (e) {
        console.error('[AUTH] Error preparing OAuth setup:', e && e.message);
      }
    }

    // If not found locally, fetch from Supabase and create mapping
    if (!localUser && supabaseAdmin) {
      try {
        console.log('[AUTH] 🆕 User not found locally, fetching from Supabase...');
        
        let supaAuthUser = null;
        let supaProfile = null;

        // Try to get auth user details via multiple methods
        if (!supaUser && targetId) {
          try {
            console.log('[AUTH]   Fetching Supabase auth user via admin.getUserById...');
            const adminResp = await supabaseAdmin.auth.admin.getUserById(targetId);
            supaUser = (adminResp && (adminResp.user || adminResp.data)) || adminResp;
            if (supaUser) console.log('[AUTH]   ✓ Got auth user');
          } catch (e) {
            console.log('[AUTH]   ⚠️  Could not fetch auth user:', e?.message);
          }
        }

        // Try to get profile from profiles table
        try {
          console.log('[AUTH]   Fetching user profile from Supabase profiles table...');
          const { data: pData } = await supabaseAdmin
            .from('profiles')
            .select('*')
            .eq('id', targetId)
            .limit(1)
            .maybeSingle(); // maybeSingle: profile creation can lag behind auth user creation due to DB trigger timing
          
          if (pData) {
            supaProfile = pData;
            console.log('[AUTH]   ✓ Got profile:', supaProfile.username);
          } else {
            console.log('[AUTH]   ⚠️  Profile not found yet (may be created shortly by auth trigger)');
          }
        } catch (e) {
          console.log('[AUTH]   ⚠️  Profile fetch exception:', e?.message);
        }

        // Build local user from collected data
        if (supaUser || supaProfile) {
          const email = (supaUser && supaUser.email) || (supaProfile && supaProfile.email) || 'unknown@oauth.local';
          const username = (supaProfile && supaProfile.username) || 
                          (supaUser && supaUser.user_metadata && supaUser.user_metadata.username) ||
                          `oauth-${targetId.slice(0, 8)}`;
          const displayName = (supaProfile && supaProfile.display_name) ||
                            (supaUser && supaUser.user_metadata && supaUser.user_metadata.displayName) ||
                            username;

          localUser = {
            id: targetId,
            uid: targetId,
            username: username,
            email: email,
            displayName: displayName,
            authProvider: 'supabase',
            verified: 1  // OAuth users are verified
          };

          console.log('[AUTH] 📝 Creating local user mapping:', localUser.username, '(', email, ')');
          try { 
            await supabaseDb.users.create(localUser); 
            console.log('[AUTH] ✓ Local user mapping created successfully');
          } catch (createErr) { 
            console.log('[AUTH] ⚠️  Local user creation error (may already exist):', createErr?.message);
            // Try to fetch again in case it was created concurrently
            const retryUser = await supabaseDb.users.findById(targetId);
            if (retryUser) {
              localUser = retryUser;
              console.log('[AUTH] ✓ Retrieved user after creation attempt');
            }
          }
        } else {
          console.log('[AUTH] ❌ Could not fetch user details from Supabase');
        }

        // If still no user, create profile in Supabase if service role available
        if (!localUser && supabaseAdmin) {
          try {
            // Profiles must be created by Supabase auth triggers; do not insert into profiles table from the server to avoid FK violations.
        console.log('[AUTH] ℹ️ Profile creation skipped on server; expecting Supabase auth trigger to create the profile');
          } catch (e) {
            console.log('[AUTH] ⚠️  Error creating Supabase profile:', e?.message);
          }
        }
      } catch (e) {
        console.error('[AUTH] ❌ Error during Supabase fetch and mapping:', e && e.message, e);
      }
    }

    if (!localUser) {
      console.error('[AUTH] ❌ Could not create or retrieve user for ID:', targetId);
      console.log('[AUTH] ===== Supabase Session Request END (FAILED - NO USER) =====\n');
      return res.status(404).json({ error: 'Could not create or find user' });
    }

    console.log('[AUTH] ✓ User ready, establishing session...');
    // Check if 2FA is enabled for this user
    if (localUser.is2FAEnabled && localUser.is2FAEnabled !== 'none') {
      console.log('[AUTH] 🔐 2FA enabled for user:', localUser.is2FAEnabled);
      // Set up 2FA session instead of logging in
      const twoFactor = {
        userId: localUser.id,
        method: localUser.is2FAEnabled,
        email: localUser.is2FAEnabled === 'email' ? localUser.email2FAEmail : localUser.magicLinkEmail
      };

      if (localUser.is2FAEnabled === 'email') {
        // Generate and send email code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        twoFactor.code = code;
        twoFactor.expiresAt = Date.now() + 1000 * 60 * 10; // 10 minutes
        req.session.twoFactor = twoFactor;

        // Send email with code
        try {
          const email = localUser.email2FAEmail;
          const subject = 'Your VibeNest login code';
          const text = `Your login code is: ${code}\n\nThis code will expire in 10 minutes.`;
          const html = `<p>Your login code is: <strong>${code}</strong></p><p>This code will expire in 10 minutes.</p>`;
          
          await sendMail({ to: email, subject, text, html });
          console.log('[AUTH] 📧 Sent 2FA code to:', email);
        } catch (emailErr) {
          console.error('[AUTH] ❌ Failed to send 2FA email:', emailErr);
          twoFactor.emailDeliveryFailed = true;
          req.session.twoFactor = twoFactor;
        }
      } else if (localUser.is2FAEnabled === 'magic_link') {
        // For magic link, just set the session - the 2FA page will send the link
        req.session.twoFactor = twoFactor;
      } else if (localUser.is2FAEnabled === 'authenticator') {
        // For authenticator, just set the session
        req.session.twoFactor = twoFactor;
      }

      console.log('[AUTH] ===== Supabase Session Request END (2FA REQUIRED) =====\n');
      return res.json({ needs_2fa: true, method: localUser.is2FAEnabled });
    }

    // No 2FA - complete login
    req.logIn(localUser, (err) => {
      if (err) {
        console.error('[AUTH] ❌ Failed to create session:', err.message);
        console.log('[AUTH] ===== Supabase Session Request END (FAILED - SESSION ERROR) =====\n');
        return res.status(500).json({ error: 'Failed to create session: ' + err.message });
      }
      console.log('[AUTH] ✓ Successfully logged in user:', localUser.username, 'sessionID:', req.sessionID);
      console.log('[AUTH] ===== Supabase Session Request END (SUCCESS) =====\n');
      return res.json({ ok: true, user: { id: localUser.id, username: localUser.username, email: localUser.email } });
    });
  } catch (err) {
    console.error('[AUTH] ❌ Session bridge error:', err && err.message, err);
    console.log('[AUTH] ===== Supabase Session Request END (ERROR) =====\n');
    return res.status(500).json({ error: 'Internal error: ' + (err?.message || 'unknown') });
  }
});

// Resolve usernames (frontend can query to turn username -> email for supabase sign-in)
app.get('/api/resolve-username', async (req, res) => {
  try {
    console.log('[RESOLVE] incoming', req.method, req.originalUrl, req.query);
    const username = req.query.username;
    if (!username) return res.status(400).json({ error: 'Missing username' });

    // Try local DB first
    const local = await supabaseDb.users.findByUsername(username);
    if (local && local.email) return res.json({ email: local.email });

    // Next, if Supabase admin client is available, look up the profile and attempt to fetch auth user
    if (supabaseAdmin) {
      try {
        const { data: profileData } = await supabaseAdmin.from('profiles').select('id').eq('username', username).limit(1).maybeSingle(); // maybeSingle: profile row may not exist immediately after auth creation due to trigger timing
        if (profileData && profileData.id) {
          // Try to fetch auth.user by id using admin API
          try {
            const adminResp = await supabaseAdmin.auth.admin.getUserById(profileData.id);
            const fetchedUser = (adminResp && (adminResp.user || adminResp.data)) || adminResp;
            if (fetchedUser && fetchedUser.email) return res.json({ email: fetchedUser.email });
          } catch (e) {
            console.warn('Could not fetch auth user by id (admin.getUserById not supported?):', e && e.message);
          }
        }
      } catch (e) {
        console.warn('Error resolving username via Supabase:', e && e.message);
      }
    }

    // Not found - return 200 with empty object for client-friendly response
    return res.json({});
  } catch (err) {
    console.error('resolve-username error:', err && err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }

// Invite user via Supabase Admin (server-side) - expects JSON { email }
app.post('/api/invite-user', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Missing email' });
    if (!supabaseAdmin) return res.status(500).json({ error: 'Supabase admin client not configured' });

    const { data, error } = await supabaseAdmin.auth.admin.inviteUserByEmail(email);
    if (error) {
      console.error('[INVITE] Error inviting user:', error);
      return res.status(500).json({ error: error.message || 'Invite failed' });
    }
    return res.json({ ok: true, data });
  } catch (err) {
    console.error('[INVITE] Unexpected error:', err && err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
});

// Home / Feed
app.get('/', async (req, res) => {
  try {
    // If user is not authenticated, send them to the login page instead
    if (!req.isAuthenticated()) return res.redirect('/login');
    const allPhotos = await supabaseDb.photos.getAll();
    const allVideos = await supabaseDb.videos.getAll();
    
    // Combine photos and videos, adding type field
    const allPhotosWithType = allPhotos.map(p => ({ ...p, type: 'photo' }));
    const allVideosWithType = allVideos.map(v => ({ ...v, type: 'video' }));
    const combined = [...allPhotosWithType, ...allVideosWithType]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    res.render('feed', { user: req.user, posts: combined });
  } catch (err) {
    console.error(err);
    res.render('error', { error: err.message });
  }
});

// ----- Password reset request form -----
app.get('/reset', (req, res) => {
  res.render('reset_request', { message: req.query.message });
});

// Handle reset request (submit email)
app.post('/reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.render('reset_request', { message: 'Please provide your email' });

    const user = await supabaseDb.users.findByEmail(email);
    if (!user) {
      // Do not reveal whether the email exists — show success message anyway
      return res.render('reset_sent');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hour
    await supabaseDb.passwordResets.create(token, user.id, expiresAt);

    const base = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const resetUrl = `${base}/reset/${token}`;

    // Send using Supabase email template
    try {
      await supabaseAdmin.auth.admin.sendRawEmail({
        email: user.email,
        template: 'reset',
        data: {
          displayName: user.displayName || user.username,
          resetUrl: resetUrl
        }
      }).catch(async (err) => {
        // Fallback to sendMail if template fails
        console.warn('Supabase template send failed, using fallback:', err?.message);
        const mailOpts = {
          to: user.email,
          subject: 'VibeNest password reset',
          text: `You requested a password reset. Visit: ${resetUrl}`,
          html: `<p>Hi ${user.displayName || user.username},</p>
                 <p>You requested a password reset. Click the link below to set a new password (valid for 1 hour):</p>
                 <p><a href="${resetUrl}">${resetUrl}</a></p>
                 <p>If you didn't request this, ignore this email.</p>`
        };
        return sendMail(mailOpts);
      });
    } catch (templateErr) {
      console.error('Password reset email error:', templateErr?.message);
      // Fallback to sendMail
      const mailOpts = {
        to: user.email,
        subject: 'VibeNest password reset',
        text: `You requested a password reset. Visit: ${resetUrl}`,
        html: `<p>Hi ${user.displayName || user.username},</p>
               <p>You requested a password reset. Click the link below to set a new password (valid for 1 hour):</p>
               <p><a href="${resetUrl}">${resetUrl}</a></p>
               <p>If you didn't request this, ignore this email.</p>`
      };
      await sendMail(mailOpts);
    }

    res.render('reset_sent');
  } catch (err) {
    console.error(err);
    res.render('reset_request', { message: 'Error processing reset request' });
  }
});

// Token link -> show password entry form
app.get('/reset/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const record = await supabaseDb.passwordResets.findByToken(token);
    if (!record) return res.render('reset_request', { message: 'Invalid or expired token' });
    if (new Date(record.expiresAt) < new Date()) {
      await supabaseDb.passwordResets.deleteByToken(token);
      return res.render('reset_request', { message: 'Token expired' });
    }
    res.render('reset', { token, error: null });
  } catch (err) {
    console.error(err);
    res.render('reset_request', { message: 'Error validating token' });
  }
});

// Handle new password submission
app.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.render('reset', { token, error: 'Missing token or password' });
    const record = await supabaseDb.passwordResets.findByToken(token);
    if (!record) return res.render('reset', { token: null, error: 'Invalid or expired token' });
    if (new Date(record.expiresAt) < new Date()) {
      await supabaseDb.passwordResets.deleteByToken(token);
      return res.render('reset', { token: null, error: 'Token expired' });
    }

    // Update user's password
    const hashed = bcrypt.hashSync(newPassword, 10);
    await supabaseDb.users.update(record.userId, { password: hashed });
    await supabaseDb.passwordResets.deleteByToken(token);

    res.redirect('/login?message=Password%20updated%20successfully');
  } catch (err) {
    console.error(err);
    res.render('reset', { token: req.body.token, error: 'Error updating password' });
  }
});

// Login page
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  // Debug: log whether server has a supabase client and anon key available
  console.log('[LOGIN] Rendering login page - supabase client:', supabase ? 'initialized' : 'NULL', 'anonKeyPresent:', !!app.locals.SUPABASE_ANON_KEY);

  res.render('login', {
    message: req.query.message,
    GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
    ENTRA_OAUTH: app.locals.ENTRA_OAUTH,
    SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY,
    user: req.user
  });
});

// OAuth redirect routes - redirect to Supabase's OAuth endpoints
app.get('/auth/google', (req, res) => {
  const baseUrl = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
  const callbackUrl = `${baseUrl}/auth/callback`;
  const redirectTo = encodeURIComponent(callbackUrl);
  const supabaseUrl = process.env.SUPABASE_URL;
  console.log('[OAUTH] 🔐 Google OAuth initiated');
  console.log('[OAUTH] Callback URL:', callbackUrl);
  console.log('[OAUTH] Redirect to Supabase:', `${supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${redirectTo}`);
  res.redirect(`${supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${redirectTo}`);
});

app.get('/auth/entra', (req, res) => {
  const baseUrl = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
  const callbackUrl = `${baseUrl}/auth/callback`;
  const redirectTo = encodeURIComponent(callbackUrl);
  const supabaseUrl = process.env.SUPABASE_URL;
  console.log('[OAUTH] 🔐 Entra (Azure) OAuth initiated');
  console.log('[OAUTH] Callback URL:', callbackUrl);
  console.log('[OAUTH] Redirect to Supabase:', `${supabaseUrl}/auth/v1/authorize?provider=azure&redirect_to=${redirectTo}`);
  res.redirect(`${supabaseUrl}/auth/v1/authorize?provider=azure&redirect_to=${redirectTo}`);
});

// OAuth callback handler - Supabase redirects here with session tokens in URL fragments
app.get('/auth/callback', (req, res) => {
  console.log('[OAUTH] 📍 Callback received');
  console.log('[OAUTH] URL:', req.originalUrl);
  console.log('[OAUTH] Query:', req.query);
  
  // The tokens are in URL fragments (#), not query params
  // Browser will handle this client-side via supabase-auth.js
  // Just render a page that will process the fragments
  res.render('oauth-callback', { 
    SUPABASE_URL: process.env.SUPABASE_URL || '', 
    SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY || '' 
  });
});


// OAuth setup page - lets user choose a username and display name before completing account creation
app.get('/oauth/setup', (req, res) => {
  try {
    const pending = req.session && req.session.pendingOAuth;
    if (!pending) return res.redirect('/login?message=' + encodeURIComponent('No pending OAuth signup found'));

    const pre = pending.profile || {};
    res.render('oauth-setup', {
      suggestedUsername: pre.username || '',
      suggestedDisplayName: pre.display_name || '',
      error: null
    });
  } catch (e) {
    console.error('Error rendering oauth setup page:', e && e.message);
    res.redirect('/login?message=Error');
  }
});

// Handle OAuth setup submission
app.post('/oauth/setup', async (req, res) => {
  try {
    const pending = req.session && req.session.pendingOAuth;
    if (!pending) return res.redirect('/login?message=' + encodeURIComponent('No pending OAuth signup found'));

    const { username, displayName } = req.body || {};
    if (!username || !/^[a-zA-Z0-9_\-]{3,30}$/.test(username)) {
      return res.render('oauth-setup', { suggestedUsername: username || '', suggestedDisplayName: displayName || '', error: 'Invalid username. Use 3-30 letters, numbers, hyphen or underscore.' });
    }

    // Ensure username unique (check profiles table first, then local mapping)
    if (supabaseAdmin) {
      const { data: existing } = await supabaseAdmin.from('profiles').select('id').eq('username', username).limit(1).maybeSingle(); // maybeSingle: avoid treating missing profile as error during signup/OAuth due to trigger timing
      if (existing && existing.id) {
        return res.render('oauth-setup', { suggestedUsername: username, suggestedDisplayName: displayName || '', error: 'Username already taken' });
      }
    }

    const existingLocal = await supabaseDb.users.findByUsername(username).catch(() => null);
    if (existingLocal && existingLocal.id) {
      return res.render('oauth-setup', { suggestedUsername: username, suggestedDisplayName: displayName || '', error: 'Username already taken' });
    }

    const userId = pending.userId;

    // Create profile in Supabase (service role)
    if (supabaseAdmin) {
      try {
        // Profiles are managed by Supabase auth triggers; avoid manual insert to profiles table.
        console.log('[OAUTH-SETUP] Skipping manual profiles insert; profile creation should be handled by Supabase auth trigger.');
      } catch (e) {
        console.warn('[OAUTH-SETUP] Error creating Supabase profile:', e && e.message);
      }
    }

    // Create local mapping
    const localUser = {
      id: userId,
      uid: userId,
      username: username,
      email: (pending.profile && pending.profile.email) || `${username}@oauth.local`,
      displayName: displayName || username,
      authProvider: 'supabase',
      verified: 1
    };

    try {
      await supabaseDb.users.create(localUser);
      console.log('[OAUTH-SETUP] Local mapping created for', username);
    } catch (e) {
      console.warn('[OAUTH-SETUP] Local mapping creation failed:', e && e.message);
    }

    // Complete login
    req.logIn(localUser, (err) => {
      if (err) {
        console.error('[OAUTH-SETUP] Failed to create session after setup:', err && err.message);
        return res.redirect('/login?message=' + encodeURIComponent('Failed to create session'));
      }
      // Clean pending data
      delete req.session.pendingOAuth;
      req.session.save(() => {
        return res.redirect('/');
      });
    });

  } catch (err) {
    console.error('[OAUTH-SETUP] Error handling setup submission:', err && err.message);
    res.render('oauth-setup', { suggestedUsername: req.body.username || '', suggestedDisplayName: req.body.displayName || '', error: 'Internal error' });
  }
});

// In-memory authorization code store (dev-only, short-lived)
const oauthAuthCodes = new Map(); // code -> { client_id, redirect_uri, userId, scope, expiresAt }
const generateAuthCode = () => crypto.randomBytes(24).toString('hex');
// Cleanup expired codes every minute
setInterval(() => {
  const now = Date.now();
  for (const [code, meta] of oauthAuthCodes.entries()) {
    if (meta.expiresAt <= now) oauthAuthCodes.delete(code);
  }
}, 60 * 1000);

// OAuth consent page (used when Supabase OAuth Server is configured to preview the consent UI)
app.get('/login/oauth/consent', (req, res) => {
  const { client_id, redirect_uri, response_type, state, scope } = req.query;
  if (!client_id || !redirect_uri || !response_type) {
    return res.status(400).send('Missing required OAuth parameters');
  }

  // Render a simple consent screen. In production you should look up the client by client_id
  // and display its registered name, logo, and exact redirect URIs.
  res.render('oauth-consent', {
    client_id,
    redirect_uri,
    response_type,
    state,
    scope: scope || ''
  });
});

// Handle consent form submission
app.post('/login/oauth/consent', async (req, res) => {
  try {
    const { client_id, redirect_uri, response_type, state, scope, action } = req.body;
    // Ensure the user is authenticated before issuing a code
    if (!req.isAuthenticated()) {
      // Save the original query in session and redirect to login
      req.session.oauthReturnTo = req.originalUrl || req.url;
      return res.redirect('/login');
    }

    if (action !== 'approve') {
      const url = new URL(redirect_uri);
      url.searchParams.set('error', 'access_denied');
      if (state) url.searchParams.set('state', state);
      return res.redirect(url.toString());
    }

    // Approve: create an authorization code and redirect back
    const code = generateAuthCode();
    const expiresAt = Date.now() + 1000 * 60 * 5; // 5 minutes
    oauthAuthCodes.set(code, { client_id, redirect_uri, userId: req.user.id, scope: scope || '', expiresAt });

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
  } catch (err) {
    console.error('OAuth consent error:', err && err.message);
    return res.status(500).send('Internal error');
  }
});

// Register page
app.get('/register', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('register', {
    message: req.query.message,
    GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
    ENTRA_OAUTH: app.locals.ENTRA_OAUTH,
    SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY,
    user: req.user
  });
});

// Forgot password page (alias to reset request)
app.get('/forgot-password', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.render('forogt-password', { error: req.query.error || null, user: req.user });
});

// Handle forgot-password form (mirror /reset behavior)
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.render('forogt-password', { error: 'Please provide your email' });

    const user = await supabaseDb.users.findByEmail(email);
    if (!user) {
      return res.render('reset_sent');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hour
    await supabaseDb.passwordResets.create(token, user.id, expiresAt);

    const base = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const resetUrl = `${base}/reset/${token}`;

    // Send using Supabase email template
    try {
      await supabaseAdmin.auth.admin.sendRawEmail({
        email: user.email,
        template: 'reset',
        data: {
          displayName: user.displayName || user.username,
          resetUrl: resetUrl
        }
      }).catch(async (err) => {
        // Fallback to sendMail if template fails
        console.warn('Supabase template send failed, using fallback:', err?.message);
        const mailOpts = {
          to: user.email,
          subject: 'VibeNest password reset',
          text: `You requested a password reset. Visit: ${resetUrl}`,
          html: `<p>Hi ${user.displayName || user.username},</p>
                 <p>You requested a password reset. Click the link below to set a new password (valid for 1 hour):</p>
                 <p><a href="${resetUrl}">${resetUrl}</a></p>
                 <p>If you didn't request this, ignore this email.</p>`
        };
        return sendMail(mailOpts);
      });
    } catch (templateErr) {
      console.error('Password reset email error:', templateErr?.message);
      // Fallback to sendMail
      const mailOpts = {
        to: user.email,
        subject: 'VibeNest password reset',
        text: `You requested a password reset. Visit: ${resetUrl}`,
        html: `<p>Hi ${user.displayName || user.username},</p>
               <p>You requested a password reset. Click the link below to set a new password (valid for 1 hour):</p>
               <p><a href="${resetUrl}">${resetUrl}</a></p>
               <p>If you didn't request this, ignore this email.</p>`
      };
      await sendMail(mailOpts);
    }

    res.render('reset_sent');
  } catch (err) {
    console.error(err);
    res.render('forogt-password', { error: 'Error processing reset request' });
  }
});

// Registration is handled by Supabase Auth in production. Allow local registrations in development/testing.
app.post('/register', async (req, res) => {
  try {
    const { displayName, username, email, password, confirmPassword } = req.body || {};
    // Basic validation
    if (!username || !email || !password) {
      return res.render('register', { message: 'Please provide username, email and password', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }
    if (password !== confirmPassword) {
      return res.render('register', { message: 'Passwords do not match', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    console.log('[REGISTER] Attempting Supabase signUp for email:', email);
    if (!supabase) {
      console.error('[REGISTER] Supabase client is null');
      return res.render('register', { message: 'Supabase not configured', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    const baseUrl = process.env.BASE_URL || process.env.APP_URL;
    if (!baseUrl) {
      console.error('[REGISTER] BASE_URL or APP_URL not set');
      return res.render('register', { message: 'Server configuration error', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          username,
          display_name: displayName || username
        },
        emailRedirectTo: `${baseUrl}/auth/callback`
      }
    });

    console.log('[REGISTER] signUp result:', { data: data ? 'success' : null, error: error ? error.message : null });

    if (error) {
      // Check if the error is related to email confirmation sending
      const errorMsg = error.message.toLowerCase();
      const isEmailError = errorMsg.includes('email') || errorMsg.includes('confirmation') || errorMsg.includes('send') || errorMsg.includes('mail');
      
      if (isEmailError) {
        console.warn('[REGISTER] Email confirmation error detected, but proceeding with signup:', error.message);
        // Treat as success and redirect to check email
        return res.redirect(`/check-email?email=${encodeURIComponent(email)}`);
      } else {
        // Fatal error, show to user
        return res.render('register', {
          message: error.message,
          GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
          ENTRA_OAUTH: app.locals.ENTRA_OAUTH,
          SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY,
          user: req.user
        });
      }
    }

    // Success: redirect to check email
    return res.redirect(`/check-email?email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error('Registration error:', err && err.message);
    res.status(500).render('register', { message: 'Error creating account', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
  }
});

// Client-side Supabase signup will handle account creation
// This endpoint is called AFTER successful Supabase signup to confirm the profile exists
app.post('/api/register-profile', async (req, res) => {
  try {
    const { userId, username, displayName, email } = req.body || {};
    console.log('[REGISTER] 📝 Profile check request:', { userId: userId?.substring(0, 8), username, displayName, email });

    if (!userId || !username) {
      return res.status(400).json({ error: 'userId and username required' });
    }

    // If profile already exists return it
    console.log('[REGISTER] 🔍 Checking if profile already exists...');
    const existing = await supabaseDb.users.findById(userId).catch(() => null);
    if (existing) {
      console.log('[REGISTER] ✓ Profile already exists for', existing.username);
      return res.json({ ok: true, user: existing });
    }

    // Wait for profiles row to be created by auth.users trigger (avoid manual inserts that can cause FK violations)
    if (!supabaseAdmin) return res.status(500).json({ error: 'Supabase admin client not configured' });

    const maxAttempts = 10;
    let attempt = 0;
    let profile = null;
    while (attempt < maxAttempts) {
      attempt += 1;
      const { data: pData } = await supabaseAdmin.from('profiles').select('*').eq('id', userId).limit(1).maybeSingle();
      if (pData) {
        profile = pData;
        break;
      }
      console.log('[REGISTER] Profile not found yet, retrying (' + attempt + '/' + maxAttempts + ')...');
      await new Promise(r => setTimeout(r, 500));
    }

    if (profile) {
      const mapped = { id: profile.id, username: profile.username, email: email || null, displayName: profile.display_name };
      console.log('[REGISTER] ✓ Found profile after wait:', mapped.username);
      return res.json({ ok: true, user: mapped });
    }

    console.warn('[REGISTER] Profile still not found after waiting; client should retry or complete setup.');
    return res.status(202).json({ ok: false, message: 'Profile not yet created. Please retry shortly or complete setup.' });
  } catch (err) {
    console.error('[REGISTER] Error:', err?.message);
    return res.status(500).json({ error: err?.message || 'Internal error' });
  }
});

// Local login disabled — use Supabase Auth for user authentication in production
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.render('login', { message: 'Username and password required', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    // Resolve identifier (email | username | display name) to a concrete email address
    let email = null;
    const identifier = String(username).trim();
    try {
      // If user supplied an email-like identifier, use it directly
      if (identifier.includes('@')) {
        email = identifier.toLowerCase();
      } else {
        // Try high-level helper to find by username (may also consult auth metadata)
        try {
          const found = await supabaseDb.users.findByUsername(identifier).catch(() => null);
          if (found && found.email) {
            email = found.email;
          }
        } catch (e) {
          console.warn('[LOGIN] findByUsername error:', e && e.message);
        }

        // If still not found, try matching display_name in profiles (case-insensitive)
        if (!email && supabaseAdmin) {
          try {
            const { data: profileByDisplay } = await supabaseAdmin.from('profiles')
              .select('id, display_name')
              .ilike('display_name', identifier)
              .limit(1)
              .maybeSingle();
            if (profileByDisplay && profileByDisplay.id) {
              const adminResp = await supabaseAdmin.auth.admin.getUserById(profileByDisplay.id).catch(() => null);
              const fetchedUser = (adminResp && (adminResp.user || adminResp.data)) || adminResp;
              if (fetchedUser && fetchedUser.email) email = fetchedUser.email;
            }
          } catch (e) {
            console.warn('[LOGIN] display_name lookup error:', e && e.message);
          }
        }
      }
    } catch (e) {
      console.warn('[LOGIN] Identifier resolution error:', e && e.message);
    }

    if (!email) {
      console.log('[LOGIN] Username lookup failed for', username);
      // Fallback: attempt to resolve username via supabaseDb helper (searches auth users)
      try {
        const found = await supabaseDb.users.findByUsername(username);
        if (found && found.email) {
          console.log('[LOGIN] Fallback found email via supabaseDb.users.findByUsername for', username, '->', found.email.substring(0,6) + '...');
          email = found.email;
        }
      } catch (fbErr) {
        console.warn('[LOGIN] Fallback username lookup error:', fbErr && fbErr.message);
      }

      if (!email) {
        return res.render('login', { message: 'Invalid username or password', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
      }
    }

    // Attempt login with Supabase
    if (!supabase) {
      console.error('[LOGIN] Supabase client not initialized; cannot sign in');
      return res.render('login', { message: 'Authentication service not available', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    console.log('[LOGIN] Attempting signInWithPassword for email:', email.substring(0,6) + '...');
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      console.log('Login error:', error.message, 'status:', error.status || 'N/A');
      return res.render('login', { message: 'Invalid username or password', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
    }

    // Login successful - redirect to callback to handle session
    res.redirect('/auth/callback');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { message: 'Login failed', GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH, ENTRA_OAUTH: app.locals.ENTRA_OAUTH, SUPABASE_ANON_KEY: app.locals.SUPABASE_ANON_KEY, user: req.user });
  }
});

// 2FA Login Form
app.get('/2fa-login', (req, res) => {
  const twoFactor = req.session.twoFactor;
  if (!twoFactor) return res.redirect('/login');
  // Pass a debugCode for local development (helps when no mailer is configured)
  const debugCode = twoFactor.debug ? twoFactor.code : null;
  const emailDeliveryFailed = !!twoFactor.emailDeliveryFailed;
  res.render('2fa-login', { error: null, twoFactorMethod: twoFactor.method, debugCode, emailDeliveryFailed, userId: twoFactor.userId });
});

// Verify 2FA via authenticator token (not implemented) or email
app.post('/2fa-login', async (req, res) => {
  try {
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.redirect('/login');
    // Authenticator (TOTP) verification
    if (twoFactor.method === 'authenticator') {
      const { token, backupCode } = req.body;
      if (!token && !backupCode) return res.render('2fa-login', { error: 'Code or backup code required', twoFactorMethod: 'authenticator' });
      const user = await supabaseDb.users.findById(twoFactor.userId);
      if (!user || !user.twoFactorSecret) return res.render('2fa-login', { error: 'User or secret not found', twoFactorMethod: 'authenticator' });
      authenticator.options = { window: 1 };
      const valid = authenticator.check(String(token).trim(), user.twoFactorSecret);
      if (!valid) {
        // If token isn't valid, check backup codes if provided
        if (backupCode && String(backupCode).trim()) {
          // lookup unused codes for user
          const rows = await supabaseDb.backupCodes.findValidByUserAndCode(user.id, null);
          let match = null;
          for (const r of rows) {
            try {
              if (bcrypt.compareSync(String(backupCode).trim(), r.code)) { match = r; break; }
            } catch (e) {}
          }
          if (match) {
            // mark used and log user in
            await supabaseDb.backupCodes.markUsed(match.id);
            await new Promise((resolve, reject) => {
              req.logIn(user, (err) => (err ? reject(err) : resolve()));
            });
            delete req.session.twoFactor;
            return res.redirect('/');
          }
        }
        return res.render('2fa-login', { error: 'Invalid code', twoFactorMethod: 'authenticator' });
      }
      // Valid — log in the user
      await new Promise((resolve, reject) => {
        req.logIn(user, (err) => (err ? reject(err) : resolve()));
      });
      delete req.session.twoFactor;
      return res.redirect('/');
    }
    // If it's not authenticator, fallback to login page
    return res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.render('2fa-login', { error: 'Error validating code', twoFactorMethod: 'email' });
  }
});

// Verify email 2FA code (includes magic link verification)
app.post('/2fa-verify-email', async (req, res) => {
  try {
    const { emailToken } = req.body;
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.render('2fa-login', { error: 'No login in progress', twoFactorMethod: 'email' });
    
    // Handle magic link token (from /verify-magic-link/:token)
    if (twoFactor.method === 'magic_link') {
      // Token already verified in /verify-magic-link/:token route, just log in
      const user = await supabaseDb.users.findById(twoFactor.userId);
      if (!user) return res.render('2fa-login', { error: 'User not found', twoFactorMethod: 'magic_link' });
      await new Promise((resolve, reject) => {
        req.logIn(user, (err) => (err ? reject(err) : resolve()));
      });
      delete req.session.twoFactor;
      return res.redirect('/');
    }
    
    // Handle email OTP code
    if (twoFactor.method !== 'email') return res.render('2fa-login', { error: 'Email 2FA not active', twoFactorMethod: twoFactor.method });
    if (Date.now() > twoFactor.expiresAt) return res.render('2fa-login', { error: 'Code expired', twoFactorMethod: 'email' });
    if (String(emailToken).trim() !== String(twoFactor.code)) return res.render('2fa-login', { error: 'Invalid code', twoFactorMethod: 'email' });
    
    const user = await supabaseDb.users.findById(twoFactor.userId);
    if (!user) return res.render('2fa-login', { error: 'User not found', twoFactorMethod: 'email' });
    await new Promise((resolve, reject) => {
      req.logIn(user, (err) => (err ? reject(err) : resolve()));
    });
    delete req.session.twoFactor;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.render('2fa-login', { error: 'Error verifying code', twoFactorMethod: 'email' });
  }
});

// Send magic link for 2FA (only for users with magic link 2FA enabled)
app.post('/api/2fa/send-magic-link', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    const user = await supabaseDb.users.findById(userId);
    if (!user || user.is2FAEnabled !== 'magic_link' || !user.magicLinkEmail) {
      return res.status(400).json({ error: 'Magic link 2FA not enabled for this user' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 15).toISOString(); // 15 minutes
    await supabaseDb.magicLinks.create(token, userId, expiresAt);

    const base = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const magicUrl = `${base}/verify-magic-link/${token}`;

    // Send using Supabase email template
    try {
      await supabaseAdmin.auth.admin.sendRawEmail({
        email: user.magicLinkEmail,
        template: 'magic_link',
        data: {
          displayName: user.displayName || user.username,
          magicUrl: magicUrl
        }
      }).catch(async (err) => {
        // Fallback to sendMail if template fails
        console.warn('Supabase template send failed, using fallback:', err?.message);
        return sendMail({
          to: user.magicLinkEmail,
          subject: 'Your VibeNest login link',
          text: `Click to verify: ${magicUrl}`,
          html: `<p>Hi ${user.displayName || user.username},</p><p>Click <a href="${magicUrl}">here</a> to verify and log in.</p>`
        });
      });
    } catch (templateErr) {
      console.error('Magic link email error:', templateErr?.message);
      // Fallback to sendMail
      await sendMail({
        to: user.magicLinkEmail,
        subject: 'Your VibeNest login link',
        text: `Click to verify: ${magicUrl}`,
        html: `<p>Hi ${user.displayName || user.username},</p><p>Click <a href="${magicUrl}">here</a> to verify and log in.</p>`
      });
    }

    res.json({ success: true, message: 'Magic link sent to ' + user.magicLinkEmail });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send magic link' });
  }
});

// Verify magic link token
app.get('/verify-magic-link/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const record = await supabaseDb.magicLinks.findByToken(token);
    if (!record) return res.render('verify', { success: false, message: 'Invalid or expired magic link.' });
    if (new Date(record.expiresAt) < new Date()) {
      await supabaseDb.magicLinks.deleteByToken(token);
      return res.render('verify', { success: false, message: 'Magic link expired.' });
    }

    const user = await supabaseDb.users.findById(record.userId);
    if (!user) return res.render('verify', { success: false, message: 'User not found.' });

    // Mark token as used
    await supabaseDb.magicLinks.deleteByToken(token);

    // Log user in
    await new Promise((resolve, reject) => {
      req.logIn(user, (err) => (err ? reject(err) : resolve()));
    });

    res.render('verify', { success: true, message: 'You have been logged in successfully.' });
  } catch (err) {
    console.error(err);
    res.render('verify', { success: false, message: 'Error processing magic link.' });
  }
});
app.post('/2fa-resend', async (req, res) => {
  try {
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.status(400).json({ error: 'No login pending' });
    const user = await supabaseDb.users.findById(twoFactor.userId);
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (twoFactor.method !== 'email') return res.status(400).json({ error: 'Only email 2FA supported' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    twoFactor.code = code;
    twoFactor.expiresAt = Date.now() + 1000 * 60 * 10;
    req.session.twoFactor = twoFactor;
    
    // Send using Supabase email template
    try {
      await supabaseAdmin.auth.admin.sendRawEmail({
        email: user.email,
        template: '2fa',
        data: {
          displayName: user.displayName || user.username,
          code: code
        }
      }).catch(async (err) => {
        // Fallback to sendMail if template fails
        console.warn('Supabase template send failed, using fallback:', err?.message);
        return sendMail({
          to: user.email,
          subject: 'Your VibeNest login code (resend)',
          text: `Your login code: ${code}`,
          html: `<p>Your login code: <strong>${code}</strong></p>`
        });
      });
    } catch (templateErr) {
      console.error('2FA email error:', templateErr?.message);
      // Fallback to sendMail
      await sendMail({
        to: user.email,
        subject: 'Your VibeNest login code (resend)',
        text: `Your login code: ${code}`,
        html: `<p>Your login code: <strong>${code}</strong></p>`
      });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to resend code' });
  }
});

// Regenerate backup recovery codes (server-side, authenticated)
app.post('/api/2fa/backup-codes/regenerate', isAuthenticated, async (req, res) => {
  try {
    if (!supabaseAdmin) return res.status(500).json({ error: 'Supabase service client not configured' });

    const userId = req.user.id;
    // Remove existing codes for user
    await supabaseAdmin.from('backup_codes').delete().eq('user_id', userId);

    // Generate 10 single-use codes
    const codes = [];
    const codeHashes = [];
    for (let i = 0; i < 10; i++) {
      // 8-char alphanumeric code
      const code = Math.random().toString(36).slice(2, 10).toUpperCase();
      codes.push(code);
      const hash = bcrypt.hashSync(code, 10);
      codeHashes.push({ user_id: userId, code_hash: hash });
    }

    // Insert hashed codes into Supabase
    const { error } = await supabaseAdmin.from('backup_codes').insert(codeHashes);
    if (error) return res.status(500).json({ error: error.message || error });

    // Return plaintext codes once for the user to copy/save — these are single-shot
    res.json({ success: true, codes });
  } catch (err) {
    console.error('Regenerate backup-codes error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Verify a backup code during an in-progress 2FA login flow (uses session.twoFactor.userId)
app.post('/2fa-verify-backup', async (req, res) => {
  try {
    const { backupCode } = req.body;
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.status(400).render('2fa-login', { error: 'No login in progress', twoFactorMethod: 'authenticator' });
    const targetUserId = twoFactor.userId;

    if (!backupCode) return res.render('2fa-login', { error: 'Backup code required', twoFactorMethod: twoFactor.method || 'authenticator' });

    if (!supabaseAdmin) return res.render('2fa-login', { error: 'Server not configured for backup codes', twoFactorMethod: twoFactor.method || 'authenticator' });

    // fetch unused codes for user
    const { data, error } = await supabaseAdmin.from('backup_codes').select('*').eq('user_id', targetUserId).eq('used', false).limit(100);
    if (error) return res.render('2fa-login', { error: 'Error checking backup codes', twoFactorMethod: twoFactor.method || 'authenticator' });

    let matched = null;
    for (const row of data || []) {
      if (bcrypt.compareSync(String(backupCode).trim(), row.code_hash)) {
        matched = row;
        break;
      }
    }

    if (!matched) return res.render('2fa-login', { error: 'Invalid backup code', twoFactorMethod: twoFactor.method || 'authenticator' });

    // Mark the used code as used
    await supabaseAdmin.from('backup_codes').update({ used: true }).eq('id', matched.id);

    // Log in the user and complete the 2FA flow
    const user = await supabaseDb.users.findById(targetUserId);
    if (!user) return res.render('2fa-login', { error: 'User not found', twoFactorMethod: twoFactor.method || 'authenticator' });

    await new Promise((resolve, reject) => {
      req.logIn(user, err => (err ? reject(err) : resolve()));
    });
    delete req.session.twoFactor;
    return res.redirect('/');
  } catch (err) {
    console.error('2fa backup verify error:', err);
    res.render('2fa-login', { error: 'Error verifying backup code', twoFactorMethod: 'authenticator' });
  }
});

// GET backup codes status (unused count)
app.get('/api/2fa/backup-codes', isAuthenticated, async (req, res) => {
  try {
    const user = await supabaseDb.users.findById(req.user.id);
    if (!user || user.is2FAEnabled !== 'authenticator') return res.status(400).json({ error: 'Authenticator 2FA not enabled' });
    const rows = await supabaseDb.backupCodes.getUnusedByUser(req.user.id);
    res.json({ success: true, unused: rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load backup codes status' });
  }
});

// Regenerate backup codes (delete old, create new) — returns the plain codes to present once
app.post('/api/2fa/backup-codes/regenerate', isAuthenticated, async (req, res) => {
  try {
    const user = await supabaseDb.users.findById(req.user.id);
    if (!user || user.is2FAEnabled !== 'authenticator') return res.status(400).json({ error: 'Authenticator 2FA not enabled' });

    await supabaseDb.backupCodes.deleteByUser(req.user.id);
    const count = 10;
    const plainCodes = [];
    for (let i = 0; i < count; i++) {
      const token = crypto.randomBytes(4).toString('hex').toUpperCase();
      const code = `${token.slice(0,4)}-${token.slice(4,8)}`;
      const id = uuidv4();
      const hashed = bcrypt.hashSync(code, 10);
      if (supabaseAdmin && supabaseDb.backupCodes && supabaseDb.backupCodes.insertMany) {
        await supabaseDb.backupCodes.insertMany([{ id, user_id: req.user.id, code_hash: hashed }]);
      } else {
        await backupCodes.create(id, req.user.id, hashed);
      }
      plainCodes.push(code);
    }

    res.json({ success: true, codes: plainCodes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to regenerate codes' });
  }
});

// OAuth routes previously handled by local Passport strategies have been removed.
// In production Supabase Auth handles OAuth and the client should perform sign-in there.

// Logout
app.get('/logout', (req, res) => {
  req.logOut(() => {
    res.redirect('/login');
  });
});

// Support page
app.get('/support', (req, res) => {
  res.render('support', { user: req.user, flash: null });
});

// Handle support form (accept an optional attachment)
app.post('/support', supportUpload.single('attachment'), async (req, res) => {
  try {
    const { name, email, category, subject, message } = req.body;
    const attachment = req.file;

    const mailOpts = {
      to: process.env.SUPPORT_EMAIL || 'akunknow3124@gmail.com',
      subject: `[Support] ${subject} (${category})`,
      text: `From: ${name} <${email}>\n\n${message}`,
      html: `<p><strong>From:</strong> ${name} &lt;${email}&gt;</p><p><strong>Category:</strong> ${category}</p><p>${message.replace(/\n/g, '<br/>')}</p>`,
    };

    if (attachment && attachment.path) {
      mailOpts.attachments = [{ filename: attachment.originalname || attachment.filename, path: attachment.path }];
    }

    // Support form should use Mailjet, then SMTP, then console.
    try {
      await sendMail(mailOpts);
    } catch (e) {
      console.error('Error sending support email:', e);
      console.log('Support request (logged):', mailOpts);
    }

    res.render('support', { user: req.user, flash: { success: 'Support request sent — we will respond within 48 hours.' } });
  } catch (err) {
    console.error(err);
    res.render('support', { user: req.user, flash: { error: 'Failed to submit support request' } });
  }
});

// Resend verification page
app.get('/resend-verification', (req, res) => {
  res.render('resend-verifacation', { message: req.query.message || null });
});

// Handle resend verification
app.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    // For privacy, always render check-email even if user not found
    const user = email ? await supabaseDb.users.findByEmail(email) : null;
    if (user) {
      // create a new verification token and send link
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24 hours
      await supabaseDb.verifications.create(token, user.id, expiresAt);
      const base = app.locals.BASE_URL;
      const verifyUrl = `${base}/verify/${token}`;
      
      // Send using Supabase email template
      try {
        await supabaseAdmin.auth.admin.sendRawEmail({
          email: user.email,
          template: 'verify',
          data: {
            displayName: user.displayName || user.username,
            verifyUrl: verifyUrl
          }
        }).catch(async (err) => {
          // Fallback to sendMail if template fails
          console.warn('Supabase template send failed, using fallback:', err?.message);
          return sendMail({
            to: user.email,
            subject: 'Verify your VibeNest account',
            text: `Verify your VibeNest account: ${verifyUrl}`,
            html: `<p>Hi ${user.displayName || user.username},</p><p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
          });
        });
      } catch (templateErr) {
        console.error('Verification email error:', templateErr?.message);
        // Fallback to sendMail
        await sendMail({
          to: user.email,
          subject: 'Verify your VibeNest account',
          text: `Verify your VibeNest account: ${verifyUrl}`,
          html: `<p>Hi ${user.displayName || user.username},</p><p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
        });
      }
    }

    res.render('check-email', { email: email || '', under13: false });
  } catch (err) {
    console.error(err);
    res.render('resend-verifacation', { message: 'Error resending verification' });
  }
});

// --- Admin: Resend verification (admin-only UI) ---
app.get('/admin/resend-verification', isAuthenticated, (req, res) => {
  const user = req.user;
  if (!user || !user.isAdmin) return res.status(403).send('Forbidden');
  res.render('resend-verification-admin', { user, message: null });
});

app.post('/admin/resend-verification', isAuthenticated, async (req, res) => {
  const user = req.user;
  if (!user || !user.isAdmin) return res.status(403).send('Forbidden');

  try {
    const { email } = req.body;
    if (!email) return res.render('resend-verification-admin', { user, message: 'Email required' });

    const target = await supabaseDb.users.findByEmail(email);
    if (!target) return res.render('resend-verification-admin', { user, message: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24 hours
    await supabaseDb.verifications.create(token, target.id, expiresAt);

    const base = app.locals.BASE_URL;
    const verifyUrl = `${base.replace(/\/$/, '')}/verify/${token}`;

    // Send using Supabase email template
    try {
      await supabaseAdmin.auth.admin.sendRawEmail({
        email: target.email,
        template: 'verify',
        data: {
          displayName: target.displayName || target.username,
          verifyUrl: verifyUrl
        }
      }).catch(async (err) => {
        // Fallback to sendMail if template fails
        console.warn('Supabase template send failed, using fallback:', err?.message);
        return sendMail({
          to: target.email,
          subject: 'Verify your VibeNest account',
          text: `Please verify your VibeNest account by visiting: ${verifyUrl}`,
          html: `<p>Hi ${target.displayName || target.username},</p><p>Please verify your VibeNest account by clicking the link below (valid for 24 hours):</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
        });
      });
    } catch (templateErr) {
      console.error('Verification email error:', templateErr?.message);
      // Fallback to sendMail
      await sendMail({
        to: target.email,
        subject: 'Verify your VibeNest account',
        text: `Please verify your VibeNest account by visiting: ${verifyUrl}`,
        html: `<p>Hi ${target.displayName || target.username},</p><p>Please verify your VibeNest account by clicking the link below (valid for 24 hours):</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
      });
    }

    res.render('resend-verification-admin', { user, message: `Verification sent to ${target.email}` });
  } catch (err) {
    console.error('Admin resend error:', err);
    res.render('resend-verification-admin', { user, message: 'Error sending verification' });
  }
});

// Settings page
app.get('/settings', isAuthenticated, (req, res) => {
  res.render('settings', { user: req.user });
});

// Update user settings via API
app.post('/api/settings', isAuthenticated, async (req, res) => {
  try {
    const { displayName, bio } = req.body;
    const updates = {};
    if (displayName) updates.displayName = displayName;
    if (typeof bio !== 'undefined') updates.bio = bio;
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No updates provided' });
    await supabaseDb.users.update(req.user.id, updates);
    const updated = await supabaseDb.users.findById(req.user.id);
    res.json({ success: true, user: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Upload page — render upload form
app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload', { user: req.user });
});

// Upload API — redirect to Supabase upload
app.post('/api/upload', isAuthenticated, (req, res) => {
  res.status(403).json({ error: 'Local uploads disabled. Use /api/upload-supabase' });
});

// New: upload to Supabase Storage and create a record in Supabase `photos` or `videos` tables
app.post('/api/upload-supabase', isAuthenticated, uploadMemory.single('photo'), async (req, res) => {
  try {
    if (!supabaseAdmin) return res.status(500).json({ error: 'Supabase not configured for uploads' });
    const file = req.file;
    const { caption } = req.body;
    if (!file) return res.status(400).json({ error: 'File is required' });

    const isVideo = file.mimetype && file.mimetype.startsWith('video/');
    const ext = file.originalname.substring(file.originalname.lastIndexOf('.')) || '';
    const bucket = process.env.SUPABASE_BUCKET;
    if (!bucket) return res.status(500).json({ error: 'SUPABASE_BUCKET not configured in .env' });

    // filepath: userId/YYYYMMDD/uuid.ext
    const filename = `${req.user.id}/${Date.now()}-${uuidv4()}${ext}`;

    const { data: uploadData, error: uploadErr } = await supabaseAdmin.storage.from(bucket).upload(filename, file.buffer, {
      contentType: file.mimetype,
      upsert: false
    });

    if (uploadErr) {
      console.error('Supabase upload error', uploadErr);
      return res.status(500).json({ error: uploadErr.message || 'Failed to upload' });
    }

    // Insert into Supabase photos or videos table
    const table = isVideo ? 'videos' : 'photos';
    const record = {
      id: uuidv4(),
      user_id: req.user.id,
      filename: filename,
      caption: caption || ''
    };

    const { error: insertErr } = await supabaseAdmin.from(table).insert(record);
    if (insertErr) {
      console.error('Supabase DB insert error', insertErr);
      return res.status(500).json({ error: insertErr.message || 'Failed to save metadata' });
    }

    return res.json({ success: true, storagePath: filename, record });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Setup 2FA page - show options
app.get('/setup-2fa', isAuthenticated, async (req, res) => {
  try {
    const user = await supabaseDb.users.findById(req.user.id);
    // If user already has an authenticator secret, show it. Otherwise generate a temporary secret
    let secret = user.twoFactorSecret || null;
    let qrCodeImage = null;

    if (!secret) {
      // Generate a temporary secret and keep it in session until verified
      secret = authenticator.generateSecret();
      req.session.pendingTwoFactorSecret = secret;
    }

    try {
      const otpauth = authenticator.keyuri(user.email || (user.username + '@vibenest.local'), 'VibeNest', secret);
      qrCodeImage = await QRCode.toDataURL(otpauth);
    } catch (e) {
      console.error('QR generation error:', e && e.message);
    }

    res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: null, plainCodes: null, magicLinkEmail: user.magicLinkEmail || '' });
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Error loading 2FA setup', plainCodes: null, magicLinkEmail: '', message: null });
  }
});

// Setup magic link 2FA
app.post('/setup-magic-link-2fa', isAuthenticated, async (req, res) => {
  try {
    const { magicLinkEmail } = req.body;
    if (!magicLinkEmail || !magicLinkEmail.includes('@')) {
      return res.json({ success: false, error: 'Valid email required' });
    }

    await supabaseDb.users.update(req.user.id, { is2FAEnabled: 'magic_link', magicLinkEmail: magicLinkEmail });
    res.json({ success: true, message: 'Magic link 2FA enabled', magicLinkEmail });
  } catch (err) {
    console.error(err);
    res.json({ success: false, error: 'Failed to setup magic link 2FA' });
  }
});

// Enable email 2FA (sends code to type in)
app.post('/enable-email-2fa', isAuthenticated, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Email address required', plainCodes: null, message: null });

    // Update user with email 2FA enabled and the email address
    await supabaseDb.users.update(req.user.id, { is2FAEnabled: 'email', email2FAEmail: email });
    const updatedUser = await supabaseDb.users.findById(req.user.id);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: null, message: 'Email code 2FA enabled', plainCodes: null, email2FAEmail: updatedUser.email2FAEmail || '' });
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Failed to enable email code 2FA', plainCodes: null, message: null });
  }
});

// Fallback GET route for 2FA setup (in case of redirect issues)
app.get('/enable-email-2fa', isAuthenticated, (req, res) => {
  res.redirect('/setup-2fa');
});

// Enable magic link 2FA (sends link to click)
app.post('/enable-magic-link-2fa', isAuthenticated, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Email address required', plainCodes: null, message: null });

    // Update user with magic link 2FA enabled and the email address
    await supabaseDb.users.update(req.user.id, { is2FAEnabled: 'magic_link', magicLinkEmail: email });
    const updatedUser = await supabaseDb.users.findById(req.user.id);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: null, message: 'Magic link 2FA enabled', plainCodes: null, magicLinkEmail: updatedUser.magicLinkEmail || '' });
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Failed to enable magic link 2FA', plainCodes: null, message: null, magicLinkEmail: '' });
  }
});

// Fallback GET route for magic link 2FA setup
app.get('/enable-magic-link-2fa', isAuthenticated, (req, res) => {
  res.redirect('/setup-2fa');
});

// Setup authenticator 2FA (simplified) — stores a random secret and marks authenticator as enabled
app.post('/setup-2fa', isAuthenticated, async (req, res) => {
  try {
    const { token } = req.body;
    // Prefer the pending secret in session (generated on GET) otherwise fall back to stored secret
    const pending = req.session.pendingTwoFactorSecret;
    const user = await supabaseDb.users.findById(req.user.id);
    const secret = pending || user.twoFactorSecret;
    if (!secret) return res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'No secret available to verify', message: null });

    // Allow a small time-window tolerance
    authenticator.options = { window: 1 };
    const valid = authenticator.check(String(token || '').trim(), secret);
    if (!valid) {
      // Re-generate QR so user can retry (if pending secret exists)
      let qrCodeImage = null;
      try {
        const otpauth = authenticator.keyuri(user.email || (user.username + '@vibenest.local'), 'VibeNest', secret);
        qrCodeImage = await QRCode.toDataURL(otpauth);
      } catch (e) {}
      return res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: 'Invalid code, please try again', message: null, plainCodes: null });
    }

    // Valid token: store secret permanently and mark authenticator 2FA enabled
    await supabaseDb.users.update(req.user.id, { twoFactorSecret: secret, is2FAEnabled: 'authenticator' });
    delete req.session.pendingTwoFactorSecret;

    // Show success and the secret/QR (so user can keep a backup)
    let qrCodeImage = null;
    try {
      const otpauth = authenticator.keyuri(user.email || (user.username + '@vibenest.local'), 'VibeNest', secret);
      qrCodeImage = await QRCode.toDataURL(otpauth);
    } catch (e) {}

    // Generate backup codes for the user and present them once
    try {
      // remove old codes
      await supabaseDb.backupCodes.deleteByUser(req.user.id);
      const count = 10;
      const plainCodes = [];
      for (let i = 0; i < count; i++) {
        // formatted code like AAAA-BBBB
        const token = crypto.randomBytes(4).toString('hex').toUpperCase();
        const code = `${token.slice(0,4)}-${token.slice(4,8)}`;
        const id = uuidv4();
        const hashed = bcrypt.hashSync(code, 10);
        if (supabaseAdmin && supabaseDb.backupCodes && supabaseDb.backupCodes.insertMany) {
          await supabaseDb.backupCodes.insertMany([{ id, user_id: req.user.id, code_hash: hashed }]);
        } else {
          await backupCodes.create(id, req.user.id, hashed);
        }
        plainCodes.push(code);
      }
      res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: 'Two-factor authentication enabled (Authenticator app)', plainCodes });
    } catch (e) {
      console.error('Backup codes generation error:', e && e.message);
      res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: 'Two-factor authentication enabled (Authenticator app)', plainCodes: null });
    }
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Failed to setup 2FA', plainCodes: null, message: null });
  }
});

// Disable 2FA (authenticator or email)
app.post('/disable-2fa', isAuthenticated, async (req, res) => {
  try {
    await supabaseDb.users.update(req.user.id, { is2FAEnabled: 'none', twoFactorSecret: null });
    res.redirect('/settings');
  } catch (err) {
    console.error('Disable 2FA error:', err);
    res.redirect('/settings');
  }
});

// Support page - handled earlier to allow flash messages

// Check email page (generic)
app.get('/check-email', (req, res) => {
  res.render('check-email', { email: req.query.email || '', under13: req.query.under13 === '1' });
});

// Verify email token route
app.get('/verify/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const record = await supabaseDb.verifications.findByToken(token);
    if (!record) return res.render('verify', { success: false, message: 'Invalid or expired verification token.' });
    if (new Date(record.expiresAt) < new Date()) {
      await supabaseDb.verifications.deleteByToken(token);
      return res.render('verify', { success: false, message: 'Verification token expired.' });
    }
    // mark user verified
    await supabaseDb.users.update(record.userId, { verified: 1 });
    await supabaseDb.verifications.deleteByToken(token);
    res.render('verify', { success: true, message: 'Your email has been verified. You can now use your account.' });
  } catch (err) {
    console.error(err);
    res.render('verify', { success: false, message: 'Error processing verification.' });
  }
});

// Simple verified page (backward compatibility with older templates)
app.get('/verified', (req, res) => {
  res.render('verified', { message: 'Your account has been successfully verified. You can now log in.' });
});

// (Resend verification handled earlier) — this block removed to avoid duplicate handlers

// ...existing code...

// Get all photos
app.get('/api/photos', async (req, res) => {
  try {
    const allPhotos = await supabaseDb.photos.getAll();
    res.json({ photos: allPhotos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get all videos
app.get('/api/videos', async (req, res) => {
  try {
    const allVideos = await supabaseDb.videos.getAll();
    res.json({ videos: allVideos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get user's photos
app.get('/api/user/:userId/photos', async (req, res) => {
  try {
    const userPhotos = await supabaseDb.photos.getByUserId(req.params.userId);
    res.json({ photos: userPhotos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get user's videos
app.get('/api/user/:userId/videos', async (req, res) => {
  try {
    const userVideos = await supabaseDb.videos.getByUserId(req.params.userId);
    res.json({ videos: userVideos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Like a photo
app.post('/api/photos/:photoId/like', isAuthenticated, async (req, res) => {
  try {
    console.log('[LIKE] User:', req.user?.id || 'NOT AUTH', 'Photo:', req.params.photoId);
    const photo = await supabaseDb.photos.findById(req.params.photoId);
    if (!photo) {
      console.log('[LIKE] Photo not found:', req.params.photoId);
      return res.status(404).json({ error: 'Photo not found' });
    }

    const existingLike = await supabaseDb.likes.findByPhotoAndUser(req.params.photoId, req.user.id);
    if (existingLike) {
      console.log('[LIKE] Removing like');
      await supabaseDb.likes.remove(req.params.photoId, req.user.id);
      const count = await supabaseDb.likes.countByPhoto(req.params.photoId);
      res.json({ success: true, liked: false, likes: count });
    } else {
      console.log('[LIKE] Adding like');
      await supabaseDb.likes.create({
        id: uuidv4(),
        photoId: req.params.photoId,
        userId: req.user.id
      });
      const count = await supabaseDb.likes.countByPhoto(req.params.photoId);
      res.json({ success: true, liked: true, likes: count });
    }
  } catch (err) {
    console.error('[LIKE] Error:', err.message, err);
    res.status(500).json({ error: err.message });
  }
});

// Like a video
app.post('/api/videos/:videoId/like', isAuthenticated, async (req, res) => {
  try {
    const video = await supabaseDb.videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const existingLike = await supabaseDb.videoLikes.findByVideoAndUser(req.params.videoId, req.user.id);
    if (existingLike) {
      await supabaseDb.videoLikes.remove(req.params.videoId, req.user.id);
      const count = await supabaseDb.videoLikes.countByVideo(req.params.videoId);
      res.json({ success: true, liked: false, likes: count });
    } else {
      await supabaseDb.videoLikes.create({
        id: uuidv4(),
        videoId: req.params.videoId,
        userId: req.user.id
      });
      const count = await supabaseDb.videoLikes.countByVideo(req.params.videoId);
      res.json({ success: true, liked: true, likes: count });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Comment on a photo
app.post('/api/photos/:photoId/comment', isAuthenticated, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Comment text required' });
    }

    const photo = await supabaseDb.photos.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    const comment = {
      id: uuidv4(),
      photoId: req.params.photoId,
      userId: req.user.id,
      text
    };

    await supabaseDb.comments.create(comment);
    const newComment = {
      ...comment,
      username: req.user.username,
      displayName: req.user.displayName,
      profilePic: req.user.profilePic
    };

    res.json({ success: true, comment: newComment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Comment on a video
app.post('/api/videos/:videoId/comment', isAuthenticated, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Comment text required' });
    }

    const video = await supabaseDb.videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const comment = {
      id: uuidv4(),
      videoId: req.params.videoId,
      userId: req.user.id,
      text
    };

    await supabaseDb.videoComments.create(comment);
    const newComment = {
      ...comment,
      username: req.user.username,
      displayName: req.user.displayName,
      profilePic: req.user.profilePic
    };

    res.json({ success: true, comment: newComment });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get comments for a photo
app.get('/api/photos/:photoId/comments', async (req, res) => {
  try {
    const photoComments = await supabaseDb.comments.getByPhoto(req.params.photoId);
    res.json({ comments: photoComments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get comments for a video
app.get('/api/videos/:videoId/comments', async (req, res) => {
  try {
    const vComments = await supabaseDb.videoComments.getByVideo(req.params.videoId);
    res.json({ comments: vComments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a photo (only owner)
app.delete('/api/photos/:photoId', isAuthenticated, async (req, res) => {
  try {
    const photo = await supabaseDb.photos.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }
    if (photo.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete from Supabase storage if filename exists
    if (photo.filename && supabaseAdmin) {
      const bucket = process.env.SUPABASE_BUCKET;
      if (bucket) {
        const { error: storageErr } = await supabaseAdmin.storage.from(bucket).remove([photo.filename]);
        if (storageErr) console.error('Storage delete error:', storageErr);
      }
    }

    await supabaseDb.photos.delete(req.params.photoId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a video (only owner)
app.delete('/api/videos/:videoId', isAuthenticated, async (req, res) => {
  try {
    const video = await supabaseDb.videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    if (video.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Delete from Supabase storage if filename exists
    if (video.filename && supabaseAdmin) {
      const bucket = process.env.SUPABASE_BUCKET;
      if (bucket) {
        const { error: storageErr } = await supabaseAdmin.storage.from(bucket).remove([video.filename]);
        if (storageErr) console.error('Storage delete error:', storageErr);
      }
    }

    await supabaseDb.videos.delete(req.params.videoId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a comment (only owner)
app.delete('/api/comments/:commentId', isAuthenticated, async (req, res) => {
  try {
    const comment = await supabaseDb.comments.findById(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    if (comment.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await supabaseDb.comments.delete(req.params.commentId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a video comment (only owner)
app.delete('/api/video-comments/:videoCommentId', isAuthenticated, async (req, res) => {
  try {
    const comment = await supabaseDb.videoComments.findById(req.params.videoCommentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    if (comment.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await supabaseDb.videoComments.delete(req.params.videoCommentId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
// ====================
// Error Handling
// ====================

// 404 handler (catch undefined routes)
app.use((req, res, next) => {
  res.status(404).render('error', { error: 'Page not found', user: req.user || null });
});

// Error handler (must come after 404 handler)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { error: err.message || 'Something went wrong', user: req.user || null });
});

// Auto-logout unverified users on every request
app.use((req, res, next) => {
  if (req.isAuthenticated() && req.user && !req.user.verified) {
    req.logOut(() => {});
    return res.redirect('/login?message=Please%20verify%20your%20email%20before%20using%20your%20account');
  }
  next();
});

// ====================
// Start Server
// ====================
(async () => {
  // Setup mail transporter (if SMTP env vars provided). Otherwise fall back to console.
  
  // Configure Mailjet (API client preferred). Support both MAILJET_USER/PASS and MAILJET_API_KEY/SECRET.
  const mjUser = process.env.MAILJET_USER || process.env.MAILJET_API_KEY;
  const mjPass = process.env.MAILJET_PASS || process.env.MAILJET_API_SECRET;
  if (mjUser && mjPass) {
    const mailjet = Mailjet.apiConnect(mjUser, mjPass);
    // Provide a Nodemailer-compatible `sendMail(opts)` wrapper so existing code can call sendMail()
    mailjetTransporter = {
      sendMail: async (opts) => {
        const fromEmail = process.env.MAILJET_SENDER_EMAIL || process.env.SUPPORT_EMAIL || 'no-reply@example.com';
        const fromName = process.env.MAILJET_SENDER_NAME || 'VibeNest';

        // Normalize recipients into Mailjet's expected array of { Email, Name }
        const toArr = [];
        try {
          if (!opts.to) {
            throw new Error('No recipient specified');
          }
          if (typeof opts.to === 'string') {
            // handle formats like 'Name <email@domain>' or just 'email@domain'
            const m = opts.to.match(/^(.*)<([^>]+)>$/);
            if (m) {
              toArr.push({ Email: m[2].trim(), Name: m[1].trim() });
            } else {
              toArr.push({ Email: opts.to.trim() });
            }
          } else if (Array.isArray(opts.to)) {
            for (const t of opts.to) {
              if (typeof t === 'string') {
                const m = t.match(/^(.*)<([^>]+)>$/);
                if (m) toArr.push({ Email: m[2].trim(), Name: m[1].trim() });
                else toArr.push({ Email: t.trim() });
              } else if (t && t.address) {
                toArr.push({ Email: t.address, Name: t.name || undefined });
              }
            }
          } else if (opts.to && opts.to.address) {
            toArr.push({ Email: opts.to.address, Name: opts.to.name || undefined });
          }
        } catch (e) {
          return Promise.reject(e);
        }

        const message = {
          From: { Email: fromEmail, Name: fromName },
          To: toArr,
          Subject: opts.subject || opts.subject || '(no subject)',
          TextPart: opts.text || undefined,
          HTMLPart: opts.html || undefined,
        };

        // Attachments: Mailjet v3.1 expects Base64 content with Filename and ContentType
        if (opts.attachments && Array.isArray(opts.attachments) && opts.attachments.length) {
          message.Attachments = [];
          for (const a of opts.attachments) {
            try {
              let filename = a.filename || a.path || (a.filename && a.filename.toString()) || 'attachment';
              let contentType = a.contentType || a.mimetype || 'application/octet-stream';
              let dataBuffer = null;
              if (a.content) {
                // nodemailer allows Buffer in `content`
                dataBuffer = Buffer.isBuffer(a.content) ? a.content : Buffer.from(a.content);
              } else if (a.path) {
                dataBuffer = fs.readFileSync(a.path);
              }
              if (dataBuffer) {
                message.Attachments.push({
                  ContentType: contentType,
                  Filename: filename,
                  Base64Content: dataBuffer.toString('base64')
                });
              }
            } catch (attachErr) {
              // If an attachment fails, log and continue without it
              console.error('Mailjet attachment error:', attachErr && attachErr.message);
            }
          }
        }

        const payload = { Messages: [message] };
        const res = await mailjet.post('send', { version: 'v3.1' }).request(payload);
        return res;
      }
    };
  }

  // Configure SMTP transporter (fallback)
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    smtpTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  // Console fallback transporter
  consoleTransporter = {
    sendMail: async (opts) => {
      console.log('--- Email (logged) ---');
      console.log('To:', opts.to);
      console.log('Subject:', opts.subject);
      console.log('Text:', opts.text);
      console.log('HTML:', opts.html);
      if (opts.attachments) console.log('Attachments:', opts.attachments.map(a => a.filename || a.path));
    }
  };
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✨ VibeNest running on http://localhost:${PORT}`);
    console.log(`Make sure to set your OAuth credentials in .env`);
  });
})();
