import sqlite3 from 'sqlite3';
import { promisify } from 'util';
import dotenv from 'dotenv';
import Mailjet from 'node-mailjet';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

// Load env
dotenv.config({ path: path.join(process.cwd(), '.env') });

const DB_PATH = path.join(process.cwd(), 'vibenest.db');

async function main() {
  const rawDb = new sqlite3.Database(DB_PATH);
  const db = {
    run: promisify(rawDb.run.bind(rawDb)),
    get: promisify(rawDb.get.bind(rawDb)),
    all: promisify(rawDb.all.bind(rawDb)),
    exec: promisify(rawDb.exec.bind(rawDb)),
  };

  // Ensure verifications table exists (safe create)
  await db.exec(`CREATE TABLE IF NOT EXISTS verifications (
    token TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    expiresAt DATETIME NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // 1) Mark OAuth users as verified
  const users = await db.all('SELECT id, username, email, authProvider, uid, password, verified FROM users');
  const oauthCount = { marked: 0 };
  for (const u of users) {
    const isOauth = (u.authProvider && u.authProvider !== 'local') || (u.uid && u.uid !== '') || !u.password;
    if (isOauth && !u.verified) {
      await db.run('UPDATE users SET verified = 1 WHERE id = ?', [u.id]);
      oauthCount.marked++;
      console.log(`Marked verified: ${u.username} (${u.email})`);
    }
  }

  // 2) For local users who are not verified, send verification email via Mailjet
  const mailjetUser = process.env.MAILJET_USER;
  const mailjetPass = process.env.MAILJET_PASS;
  if (!mailjetUser || !mailjetPass) {
    console.warn('Mailjet credentials not found in .env — skipping sending emails.');
    console.log(`OAuth users marked verified: ${oauthCount.marked}`);
    return;
  }

  console.warn('WARNING: This script is deprecated. The website handles verifications. Exiting.');
  process.exit(0);

  const localUnverified = await db.all("SELECT id, username, email FROM users WHERE (authProvider IS NULL OR authProvider = 'local') AND (verified IS NULL OR verified = 0)");

  console.log(`Found ${localUnverified.length} local unverified users.`);
  for (const u of localUnverified) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(); // 24h

    try {
      await db.run('INSERT INTO verifications (token, userId, expiresAt) VALUES (?, ?, ?)', [token, u.id, expiresAt]);
    } catch (e) {
      console.error('Failed to insert verification token for', u.username, e.message);
      continue;
    }

    const verifyUrl = `${base.replace(/\/$/, '')}/verify/${token}`;

    const payload = {
      Messages: [
        {
          From: { Email: sender, Name: 'VibeNest' },
          To: [{ Email: u.email, Name: u.username }],
          Subject: 'Verify your VibeNest account',
          TextPart: `Please verify your account by visiting: ${verifyUrl}`,
          HTMLPart: `<p>Hi ${u.username},</p><p>Please verify your VibeNest account by clicking the link below (valid for 24 hours):</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
        }
      ]
    };

    try {
      const res = await mailjet.post('send', { version: 'v3.1' }).request(payload);
      console.log(`Sent verification to ${u.email} — status: ${res.response && res.response.status}`);
    } catch (err) {
      console.error('Mailjet send error for', u.email, err && err.response && err.response.body ? err.response.body : err.message);
    }
  }

  console.log('Migration & sending complete.');
}

main().catch(err => {
  console.error('Script failed:', err && err.message);
  process.exit(1);
});
