import express from 'express';
import session from 'express-session';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import GoogleStrategy from 'passport-google-oauth20';
import MicrosoftStrategy from 'passport-microsoft';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import dotenv from 'dotenv';
import { initializeDb, users, photos, likes, comments, videos, videoLikes, videoComments, passwordResets, verifications, backupCodes } from './db.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import Mailjet from 'node-mailjet';
import fs from 'fs';
// Mailjet integration (will create a Nodemailer-compatible transporter wrapper)
let mailjetTransporter;

dotenv.config();

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
app.use('/uploads', express.static(join(__dirname, 'uploads')));

// Session middleware
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Make the current user available in all templates (prevents undefined 'user' errors)
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  // Ensure auth flags are visible too
  res.locals.GOOGLE_OAUTH = app.locals.GOOGLE_OAUTH;
  res.locals.ENTRA_OAUTH = app.locals.ENTRA_OAUTH;
  // Debug: log the user presence
  // console.log('[debug] locals.user:', !!res.locals.user, res.locals.user && res.locals.user.username);
  next();
});

// ====================
// Multer Setup
// ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, join(__dirname, 'uploads'));
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${file.originalname.substring(file.originalname.lastIndexOf('.'))}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = file.mimetype.startsWith('video/');
    if (isImage || isVideo) {
      cb(null, true);
    } else {
      cb(new Error('Only image and video files allowed'));
    }
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

// ====================
// Passport Configuration
// ====================

// Local Strategy
passport.use(new LocalStrategy.Strategy(async (username, password, done) => {
  try {
    // Support login by username OR email
    let user = await users.findByUsername(username);
    if (!user) user = await users.findByEmail(username);
    if (!user) return done(null, false, { message: 'Invalid credentials' });

    // When user registered via OAuth there may be no password
    if (!user.password) return done(null, false, { message: 'Invalid credentials' });

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return done(null, false, { message: 'Invalid credentials' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Google Strategy
passport.use(new GoogleStrategy.Strategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID || 'your-google-client-id',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'your-google-client-secret',
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await users.findByEmail(profile.emails[0].value);
      if (!user) {
        user = {
          id: uuidv4(),
          username: profile.displayName.replace(/\s+/g, '').toLowerCase() + uuidv4().slice(0, 4),
          email: profile.emails[0].value,
          displayName: profile.displayName,
          profilePic: profile.photos[0]?.value,
          authProvider: 'google',
          verified: 1 // OAuth users are trusted — mark verified
        };
        await users.create(user);
      } else if (!user.verified) {
        // Ensure existing OAuth users are marked verified
        await users.update(user.id, { verified: 1 });
        user.verified = 1;
      }
      return done(null, user);
    } catch (err) {
      done(err);
    }
  }
));

// Microsoft/Entra ID Strategy
passport.use(new MicrosoftStrategy.Strategy(
  {
    clientID: process.env.ENTRA_CLIENT_ID || 'your-entra-client-id',
    clientSecret: process.env.ENTRA_CLIENT_SECRET || 'your-entra-client-secret',
    callbackURL: process.env.ENTRA_CALLBACK_URL || 'http://localhost:3000/auth/entra/callback',
    scope: ['user.read']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Extract email safely - Entra may provide it in different ways
      const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || 
                    profile.mail || 
                    profile.userPrincipalName ||
                    `${profile.displayName.replace(/\s+/g, '').toLowerCase()}@entra.local`;
      
      let user = await users.findByEmail(email);
      if (!user) {
        user = {
          id: uuidv4(),
          username: profile.displayName.replace(/\s+/g, '').toLowerCase() + uuidv4().slice(0, 4),
          email: email,
          displayName: profile.displayName,
          authProvider: 'entra',
          verified: 1 // OAuth users are trusted — mark verified
        };
        await users.create(user);
      } else if (!user.verified) {
        await users.update(user.id, { verified: 1 });
        user.verified = 1;
      }
      return done(null, user);
    } catch (err) {
      done(err);
    }
  }
));

// Serialize/Deserialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await users.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ====================
// Helper Functions
// ====================
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

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

// Home / Feed
app.get('/', async (req, res) => {
  try {
    // If user is not authenticated, send them to the login page instead
    if (!req.isAuthenticated()) return res.redirect('/login');
    const allPhotos = await photos.getAll();
    const allVideos = await videos.getAll();
    
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

    const user = await users.findByEmail(email);
    if (!user) {
      // Do not reveal whether the email exists — show success message anyway
      return res.render('reset_sent');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hour
    await passwordResets.create(token, user.id, expiresAt);

    const base = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const resetUrl = `${base}/reset/${token}`;

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
    const record = await passwordResets.findByToken(token);
    if (!record) return res.render('reset_request', { message: 'Invalid or expired token' });
    if (new Date(record.expiresAt) < new Date()) {
      await passwordResets.deleteByToken(token);
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
    const record = await passwordResets.findByToken(token);
    if (!record) return res.render('reset', { token: null, error: 'Invalid or expired token' });
    if (new Date(record.expiresAt) < new Date()) {
      await passwordResets.deleteByToken(token);
      return res.render('reset', { token: null, error: 'Token expired' });
    }

    // Update user's password
    const hashed = bcrypt.hashSync(newPassword, 10);
    await users.update(record.userId, { password: hashed });
    await passwordResets.deleteByToken(token);

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
  res.render('login', {
    message: req.query.message,
    GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
    ENTRA_OAUTH: app.locals.ENTRA_OAUTH,
    user: req.user
  });
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

    const user = await users.findByEmail(email);
    if (!user) {
      return res.render('reset_sent');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString(); // 1 hour
    await passwordResets.create(token, user.id, expiresAt);

    const base = process.env.BASE_URL || process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const resetUrl = `${base}/reset/${token}`;

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
    res.render('reset_sent');
  } catch (err) {
    console.error(err);
    res.render('forogt-password', { error: 'Error processing reset request' });
  }
});

// Handle local registration
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, displayName } = req.body;

    if (password !== confirmPassword) {
      return res.render('register', {
        message: 'Passwords do not match',
        GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
        ENTRA_OAUTH: app.locals.ENTRA_OAUTH
      });
    }

    if (await users.findByUsername(username)) {
      return res.render('register', {
        message: 'Username already taken',
        GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
        ENTRA_OAUTH: app.locals.ENTRA_OAUTH
      });
    }

    if (await users.findByEmail(email)) {
      return res.render('register', {
        message: 'Email already registered',
        GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
        ENTRA_OAUTH: app.locals.ENTRA_OAUTH
      });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      displayName: displayName || username,
      authProvider: 'local'
    };

    await users.create(user);
    // Create an email verification token and send verification email (if mail configured)
    try {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24 hours
      await verifications.create(token, user.id, expiresAt);
      const base = app.locals.BASE_URL;
      const verifyUrl = `${base}/verify/${token}`;
      const mailOpts = {
        to: user.email,
        subject: 'Verify your VibeNest account',
        text: `Please verify your VibeNest account by visiting: ${verifyUrl}`,
        html: `<p>Hi ${user.displayName || user.username},</p>
               <p>Welcome to VibeNest! Click the link below to verify your email address (valid for 24 hours):</p>
               <p><a href="${verifyUrl}">${verifyUrl}</a></p>
               <p>If you didn't create an account, ignore this email.</p>`
      };
      await sendMail(mailOpts);
    } catch (e) {
      console.error('Error sending verification email:', e && e.message);
    }

    req.logIn(user, (err) => {
      if (err) return res.redirect('/register');
      res.redirect('/');
    });
  } catch (err) {
    console.error(err);
    res.render('register', {
      message: 'Registration error',
      GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
      ENTRA_OAUTH: app.locals.ENTRA_OAUTH
    });
  }
});

// Handle local login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.render('login', {
        message: 'Invalid credentials',
        GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
        ENTRA_OAUTH: app.locals.ENTRA_OAUTH
      });
    }
    // Check if user is verified
    if (!user.verified) {
      req.logOut(() => {});
      return res.render('login', {
        message: 'Please verify your email before logging in',
        GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
        ENTRA_OAUTH: app.locals.ENTRA_OAUTH
      });
    }
    // If the user has 2FA enabled, start the 2FA flow instead of logging in directly
    if (user.is2FAEnabled && user.is2FAEnabled !== 'none') {
      try {
        // Generate a short 6-digit code for email 2FA (if configured)
            if (user.is2FAEnabled === 'email') {
              const code = Math.floor(100000 + Math.random() * 900000).toString();
              const expiresAt = Date.now() + 1000 * 60 * 10; // 10 minutes
              // Attach debug code for development if mailer isn't configured or in development mode
              const debug = (process.env.NODE_ENV !== 'production');
              req.session.twoFactor = { userId: user.id, method: 'email', code, expiresAt, debug };
              try {
                await sendMail({
                  to: user.email,
                  subject: 'Your VibeNest login code',
                  text: `Your VibeNest login code: ${code}`,
                  html: `<p>Your VibeNest login code: <strong>${code}</strong></p>`
                });
                // mark success
                req.session.twoFactor = { ...req.session.twoFactor, emailDeliveryFailed: false };
              } catch (e) {
                console.error('2FA email send error:', e && e.message);
                // mark delivery failure so the /2fa-login view can show a notice
                req.session.twoFactor = { ...req.session.twoFactor, emailDeliveryFailed: true };
              }
              return res.redirect('/2fa-login');
            }
        // Support authenticator (TOTP) 2FA
        if (user.is2FAEnabled === 'authenticator') {
          // Prepare a 2FA session marker and redirect to the 2FA form
          const expiresAt = Date.now() + 1000 * 60 * 10; // 10 minutes
          req.session.twoFactor = { userId: user.id, method: 'authenticator', expiresAt };
          return res.redirect('/2fa-login');
        }
      } catch (e) {
        console.error('2FA email send error:', e && e.message);
        // continue to login if the 2FA step fails to send
      }
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.render('login', {
          message: 'Login error',
          GOOGLE_OAUTH: app.locals.GOOGLE_OAUTH,
          ENTRA_OAUTH: app.locals.ENTRA_OAUTH
        });
      }
      return res.redirect('/');
    });
  })(req, res, next);
});

// 2FA Login Form
app.get('/2fa-login', (req, res) => {
  const twoFactor = req.session.twoFactor;
  if (!twoFactor) return res.redirect('/login');
  // Pass a debugCode for local development (helps when no mailer is configured)
  const debugCode = twoFactor.debug ? twoFactor.code : null;
  const emailDeliveryFailed = !!twoFactor.emailDeliveryFailed;
  res.render('2fa-login', { error: null, twoFactorMethod: twoFactor.method, debugCode, emailDeliveryFailed });
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
      const user = await users.findById(twoFactor.userId);
      if (!user || !user.twoFactorSecret) return res.render('2fa-login', { error: 'User or secret not found', twoFactorMethod: 'authenticator' });
      authenticator.options = { window: 1 };
      const valid = authenticator.check(String(token).trim(), user.twoFactorSecret);
      if (!valid) {
        // If token isn't valid, check backup codes if provided
        if (backupCode && String(backupCode).trim()) {
          // lookup unused codes for user
          const rows = await backupCodes.findValidByUserAndCode(user.id, null);
          let match = null;
          for (const r of rows) {
            try {
              if (bcrypt.compareSync(String(backupCode).trim(), r.code)) { match = r; break; }
            } catch (e) {}
          }
          if (match) {
            // mark used and log user in
            await backupCodes.markUsed(match.id);
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

// Verify email 2FA code
app.post('/2fa-verify-email', async (req, res) => {
  try {
    const { emailToken } = req.body;
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.render('2fa-login', { error: 'No login in progress', twoFactorMethod: 'email' });
    if (twoFactor.method !== 'email') return res.render('2fa-login', { error: 'Email 2FA not active', twoFactorMethod: twoFactor.method });
    if (Date.now() > twoFactor.expiresAt) return res.render('2fa-login', { error: 'Code expired', twoFactorMethod: 'email' });
    if (String(emailToken).trim() !== String(twoFactor.code)) return res.render('2fa-login', { error: 'Invalid code', twoFactorMethod: 'email' });
    // Valid — log in the user
    const user = await users.findById(twoFactor.userId);
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

// 2FA resend endpoint
app.post('/2fa-resend', async (req, res) => {
  try {
    const twoFactor = req.session.twoFactor;
    if (!twoFactor) return res.status(400).json({ error: 'No login pending' });
    const user = await users.findById(twoFactor.userId);
    if (!user) return res.status(400).json({ error: 'User not found' });
    if (twoFactor.method !== 'email') return res.status(400).json({ error: 'Only email 2FA supported' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    twoFactor.code = code;
    twoFactor.expiresAt = Date.now() + 1000 * 60 * 10;
    req.session.twoFactor = twoFactor;
    await sendMail({
      to: user.email,
      subject: 'Your VibeNest login code (resend)',
      text: `Your login code: ${code}`,
      html: `<p>Your login code: <strong>${code}</strong></p>`
    });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to resend code' });
  }
});

// GET backup codes status (unused count)
app.get('/api/2fa/backup-codes', isAuthenticated, async (req, res) => {
  try {
    const user = await users.findById(req.user.id);
    if (!user || user.is2FAEnabled !== 'authenticator') return res.status(400).json({ error: 'Authenticator 2FA not enabled' });
    const rows = await backupCodes.getUnusedByUser(req.user.id);
    res.json({ success: true, unused: rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load backup codes status' });
  }
});

// Regenerate backup codes (delete old, create new) — returns the plain codes to present once
app.post('/api/2fa/backup-codes/regenerate', isAuthenticated, async (req, res) => {
  try {
    const user = await users.findById(req.user.id);
    if (!user || user.is2FAEnabled !== 'authenticator') return res.status(400).json({ error: 'Authenticator 2FA not enabled' });

    await backupCodes.deleteByUser(req.user.id);
    const count = 10;
    const plainCodes = [];
    for (let i = 0; i < count; i++) {
      const token = crypto.randomBytes(4).toString('hex').toUpperCase();
      const code = `${token.slice(0,4)}-${token.slice(4,8)}`;
      const id = uuidv4();
      const hashed = bcrypt.hashSync(code, 10);
      await backupCodes.create(id, req.user.id, hashed);
      plainCodes.push(code);
    }

    res.json({ success: true, codes: plainCodes });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to regenerate codes' });
  }
});

// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', async (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login');
    // If user has 2FA enabled, start 2FA flow
    if (user.is2FAEnabled && user.is2FAEnabled !== 'none') {
      if (user.is2FAEnabled === 'email') {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        req.session.twoFactor = { userId: user.id, method: 'email', code, expiresAt: Date.now() + 1000 * 60 * 10 };
        try {
          await sendMail({
            to: user.email,
            subject: 'Your login code',
            text: `Your login code: ${code}`,
            html: `<p>Your login code: <strong>${code}</strong></p>`
          });
          req.session.twoFactor = { ...req.session.twoFactor, emailDeliveryFailed: false };
        } catch (e) {
          console.error('2FA send error (google):', e && e.message);
          req.session.twoFactor = { ...req.session.twoFactor, emailDeliveryFailed: true };
        }
        return res.redirect('/2fa-login');
      }
      if (user.is2FAEnabled === 'authenticator') {
        req.session.twoFactor = { userId: user.id, method: 'authenticator', expiresAt: Date.now() + 1000 * 60 * 10 };
        return res.redirect('/2fa-login');
      }
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

// Entra ID OAuth
app.get('/auth/entra', passport.authenticate('microsoft', { scope: ['user.read'] }));
app.get('/auth/entra/callback', (req, res, next) => {
  passport.authenticate('microsoft', async (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login');
    if (user.is2FAEnabled && user.is2FAEnabled !== 'none') {
      if (user.is2FAEnabled === 'email') {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        req.session.twoFactor = { userId: user.id, method: 'email', code, expiresAt: Date.now() + 1000 * 60 * 10 };
        try {
          await sendMail({
            to: user.email,
            subject: 'Your VibeNest login code',
            text: `Your login code: ${code}`,
            html: `<p>Your login code: <strong>${code}</strong></p>`
          });
        } catch (e) {
          console.error('2FA send error (entra):', e && e.message);
        }
        return res.redirect('/2fa-login');
      }
      if (user.is2FAEnabled === 'authenticator') {
        req.session.twoFactor = { userId: user.id, method: 'authenticator', expiresAt: Date.now() + 1000 * 60 * 10 };
        return res.redirect('/2fa-login');
      }
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

// Logout
app.get('/logout', (req, res) => {
  req.logOut((err) => {
    if (err) return res.status(500).send('Logout failed');
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
    const user = email ? await users.findByEmail(email) : null;
    if (user) {
      // create a new verification token and send link
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24 hours
      await verifications.create(token, user.id, expiresAt);
      const base = app.locals.BASE_URL;
      const verifyUrl = `${base}/verify/${token}`;
      await sendMail({
        to: user.email,
        subject: 'Verify your VibeNest account',
        text: `Verify your VibeNest account: ${verifyUrl}`,
        html: `<p>Hi ${user.displayName || user.username},</p><p>Click <a href="${verifyUrl}">here</a> to verify your account.</p>`
      });
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

    const target = await users.findByEmail(email);
    if (!target) return res.render('resend-verification-admin', { user, message: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24 hours
    await verifications.create(token, target.id, expiresAt);

    const base = app.locals.BASE_URL;
    const verifyUrl = `${base.replace(/\/$/, '')}/verify/${token}`;

    await sendMail({
      to: target.email,
      subject: 'Verify your VibeNest account',
      text: `Please verify your VibeNest account by visiting: ${verifyUrl}`,
      html: `<p>Hi ${target.displayName || target.username},</p><p>Please verify your VibeNest account by clicking the link below (valid for 24 hours):</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
    });

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
    await users.update(req.user.id, updates);
    const updated = await users.findById(req.user.id);
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

// Upload API — handle media uploads
app.post('/api/upload', isAuthenticated, upload.single('photo'), async (req, res) => {
  try {
    const file = req.file;
    const { caption } = req.body;
    if (!file) return res.status(400).json({ error: 'File is required' });
    const isVideo = file.mimetype && file.mimetype.startsWith('video/');
    if (isVideo) {
      await videos.create({ id: uuidv4(), userId: req.user.id, filename: file.filename, caption });
    } else {
      await photos.create({ id: uuidv4(), userId: req.user.id, filename: file.filename, caption });
    }
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Setup 2FA page - show options
app.get('/setup-2fa', isAuthenticated, async (req, res) => {
  try {
    const user = await users.findById(req.user.id);
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

    res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: null, plainCodes: null });
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Error loading 2FA setup', plainCodes: null });
  }
});

// Enable email 2FA
app.post('/enable-email-2fa', isAuthenticated, async (req, res) => {
  try {
    await users.update(req.user.id, { is2FAEnabled: 'email' });
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: null, message: 'Email 2FA enabled', plainCodes: null });
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Failed to enable email 2FA', plainCodes: null });
  }
});

// Setup authenticator 2FA (simplified) — stores a random secret and marks authenticator as enabled
app.post('/setup-2fa', isAuthenticated, async (req, res) => {
  try {
    const { token } = req.body;
    // Prefer the pending secret in session (generated on GET) otherwise fall back to stored secret
    const pending = req.session.pendingTwoFactorSecret;
    const user = await users.findById(req.user.id);
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
    await users.update(req.user.id, { twoFactorSecret: secret, is2FAEnabled: 'authenticator' });
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
      await backupCodes.deleteByUser(req.user.id);
      const count = 10;
      const plainCodes = [];
      for (let i = 0; i < count; i++) {
        // formatted code like AAAA-BBBB
        const token = crypto.randomBytes(4).toString('hex').toUpperCase();
        const code = `${token.slice(0,4)}-${token.slice(4,8)}`;
        const id = uuidv4();
        const hashed = bcrypt.hashSync(code, 10);
        await backupCodes.create(id, req.user.id, hashed);
        plainCodes.push(code);
      }
      res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: 'Two-factor authentication enabled (Authenticator app)', plainCodes });
    } catch (e) {
      console.error('Backup codes generation error:', e && e.message);
      res.render('setup-2fa', { user: req.user, qrCodeImage, secret, error: null, message: 'Two-factor authentication enabled (Authenticator app)', plainCodes: null });
    }
  } catch (err) {
    console.error(err);
    res.render('setup-2fa', { user: req.user, qrCodeImage: null, secret: null, error: 'Failed to setup 2FA', plainCodes: null });
  }
});

// Disable 2FA (authenticator or email)
app.post('/disable-2fa', isAuthenticated, async (req, res) => {
  try {
    await users.update(req.user.id, { is2FAEnabled: 'none', twoFactorSecret: null });
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
    const record = await verifications.findByToken(token);
    if (!record) return res.render('verify', { success: false, message: 'Invalid or expired verification token.' });
    if (new Date(record.expiresAt) < new Date()) {
      await verifications.deleteByToken(token);
      return res.render('verify', { success: false, message: 'Verification token expired.' });
    }
    // mark user verified
    await users.update(record.userId, { verified: 1 });
    await verifications.deleteByToken(token);
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
    const allPhotos = await photos.getAll();
    res.json({ photos: allPhotos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get all videos
app.get('/api/videos', async (req, res) => {
  try {
    const allVideos = await videos.getAll();
    res.json({ videos: allVideos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get user's photos
app.get('/api/user/:userId/photos', async (req, res) => {
  try {
    const userPhotos = await photos.getByUserId(req.params.userId);
    res.json({ photos: userPhotos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get user's videos
app.get('/api/user/:userId/videos', async (req, res) => {
  try {
    const userVideos = await videos.getByUserId(req.params.userId);
    res.json({ videos: userVideos });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Like a photo
app.post('/api/photos/:photoId/like', isAuthenticated, async (req, res) => {
  try {
    const photo = await photos.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    const existingLike = await likes.findByPhotoAndUser(req.params.photoId, req.user.id);
    if (existingLike) {
      await likes.remove(req.params.photoId, req.user.id);
      const count = await likes.countByPhoto(req.params.photoId);
      res.json({ success: true, liked: false, likes: count });
    } else {
      await likes.create({
        id: uuidv4(),
        photoId: req.params.photoId,
        userId: req.user.id
      });
      const count = await likes.countByPhoto(req.params.photoId);
      res.json({ success: true, liked: true, likes: count });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Like a video
app.post('/api/videos/:videoId/like', isAuthenticated, async (req, res) => {
  try {
    const video = await videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const existingLike = await videoLikes.findByVideoAndUser(req.params.videoId, req.user.id);
    if (existingLike) {
      await videoLikes.remove(req.params.videoId, req.user.id);
      const count = await videoLikes.countByVideo(req.params.videoId);
      res.json({ success: true, liked: false, likes: count });
    } else {
      await videoLikes.create({
        id: uuidv4(),
        videoId: req.params.videoId,
        userId: req.user.id
      });
      const count = await videoLikes.countByVideo(req.params.videoId);
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

    const photo = await photos.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    const comment = {
      id: uuidv4(),
      photoId: req.params.photoId,
      userId: req.user.id,
      text
    };

    await comments.create(comment);
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

    const video = await videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const comment = {
      id: uuidv4(),
      videoId: req.params.videoId,
      userId: req.user.id,
      text
    };

    await videoComments.create(comment);
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
    const photoComments = await comments.getByPhoto(req.params.photoId);
    res.json({ comments: photoComments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get comments for a video
app.get('/api/videos/:videoId/comments', async (req, res) => {
  try {
    const vComments = await videoComments.getByVideo(req.params.videoId);
    res.json({ comments: vComments });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a photo (only owner)
app.delete('/api/photos/:photoId', isAuthenticated, async (req, res) => {
  try {
    const photo = await photos.findById(req.params.photoId);
    if (!photo) {
      return res.status(404).json({ error: 'Photo not found' });
    }
    if (photo.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await photos.delete(req.params.photoId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a video (only owner)
app.delete('/api/videos/:videoId', isAuthenticated, async (req, res) => {
  try {
    const video = await videos.findById(req.params.videoId);
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    if (video.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await videos.delete(req.params.videoId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a comment (only owner)
app.delete('/api/comments/:commentId', isAuthenticated, async (req, res) => {
  try {
    const comment = await comments.findById(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    if (comment.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await comments.delete(req.params.commentId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete a video comment (only owner)
app.delete('/api/video-comments/:videoCommentId', isAuthenticated, async (req, res) => {
  try {
    const comment = await videoComments.findById(req.params.videoCommentId);
    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }
    if (comment.userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await videoComments.delete(req.params.videoCommentId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ====================
// Error Handling
// ====================
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
  await initializeDb();
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
