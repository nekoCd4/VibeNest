# VibeNest

A small social app for photos and short videos.

## Quick start

1. Copy `.env.example` to `.env` and fill the values you need (do NOT commit `.env`).

2. Install dependencies:

```bash
npm install
```

3. Run the app (development):

```bash
node server.js
# or
npm start
```

The app defaults to `PORT=3000` unless you set `PORT` in `.env`.

## Environment variables
See `.env.example` for all recommended variables. Important ones:

- `SESSION_SECRET` — set this in production.
- `SUPPORT_EMAIL`, `LEGAL_EMAIL` — emails used in support pages.
- `MAILJET_API_KEY`, `MAILJET_API_SECRET` — Mailjet API credentials for email sending.
- `MAILJET_SMTP_HOST` (default: `in-v3.mailjet.com`), `MAILJET_SMTP_PORT` (default: `587`), `MAILJET_SMTP_SECURE` (default: `false`) — Mailjet SMTP config.
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` — optional fallback SMTP config.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` — optional Google OAuth.
- `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` — optional Microsoft/Entra OAuth.

- `BASE_URL` — REQUIRED in Codespaces/production: set to your public URL (e.g. `https://<your-codespace>.app.github.dev`). The app will refuse to start without `BASE_URL` or `APP_URL` to avoid generating localhost links.

## Features implemented
- Local registration/login
- Password reset via email (token)
- Email verification (token sent at registration and via resend)
- Photo/video upload and feed
- Support form (logs email to console when no transporter configured)
- **Full Mailjet integration for all email sending**

## Two-Factor Authentication (2FA)

This project supports two 2FA methods:

- Email 2FA: receive a one-time 6-digit code via email during login.
- Authenticator App (TOTP): use an authenticator app (Google Authenticator, Authy, etc.) by scanning a QR code.

How to test 2FA locally

1. Install dependencies and start the app:

```bash
npm install
npm start
```

2. Register a local account via `/register` and log in.

3. Open the Settings page (`/settings`) and click `Manage 2FA`.

4. For Authenticator App (recommended):
  - Scan the QR code with your authenticator app or copy the secret key.
  - Enter the 6-digit code from your app and submit to enable 2FA.

5. To test login with Authenticator App enabled:
  - Log out, then log in with your username/password.
  - After successful password verification, if your account has Authenticator 2FA enabled, you should be prompted to enter a 2FA code (via `/2fa-login` flows).

6. For Email 2FA: enable it from the same page. The app will send a 6-digit code to your account's email when logging in.

Notes

- Emails are sent via Mailjet when `MAILJET_API_KEY` and `MAILJET_API_SECRET` are set in `.env`. If Mailjet is not configured, the app will fall back to SMTP (if provided) or log emails to the console for development.
- The server stores the TOTP secret encrypted in the database only if you successfully verify the code during setup. A temporary secret is used in the session until verification completes.

### Quick local testing checklist (UI & 2FA)

- Start the app locally:

```bash
npm install
npm run dev
```

- Open the app at http://localhost:3000 and register a new user via the Register page.
- To test Authenticator (TOTP):
  - Visit Settings → Manage 2FA → Authenticator App.
  - Scan the QR code with your authenticator (Google Authenticator, Authy, etc.) or copy the secret key.
  - Enter the 6-digit code from your app and click Enable 2FA.
  - Log out, log back in — after the password step you will be prompted for the TOTP code at /2fa-login.

- To test Email 2FA (if you don't have Mailjet/SMTP configured):
  - Enable Email 2FA from the same Settings → Manage 2FA screen.
  - Try logging in; the 6-digit code will be logged to the server console if mail transport is not configured.

- UI & navigation to check:
  - The top navigation header is centralized in `views/partials/header.ejs`. Verify the dropdown under Settings contains: Account settings, Two-factor (2FA), Resend verification, Support, and (if admin) Admin → Resend verification.
  - Core pages (Feed, Upload, Settings, Login, Register, 2FA pages and recovery pages) were modernized to use a shared theme in `public/css/theme.css` and updated button styles.

### Backup / recovery codes (Auth app)

- After enabling Authenticator (TOTP) 2FA you will be shown a set of single-use backup codes (10 by default). These are shown only once — copy them or download them immediately and store them securely.
- If you lose access to your authenticator, use one backup code at the `/2fa-login` prompt. Each code can only be used once. You can regenerate the entire set from Settings → Manage 2FA which invalidates old codes and gives you a fresh batch.

If you want me to add automated tests or provide a small demo script that exercises these flows automatically, I can add that next.

## Supabase schema & quick setup

I added a starter SQL schema for VibeNest under `scripts/supabase_schema.sql` — it creates core tables (profiles, photos, videos, likes, comments, backup_codes).

How to apply the schema:

- In the Supabase dashboard, open your project → SQL Editor → click "New query" → paste the contents of `scripts/supabase_schema.sql` and run it.
- Create a Storage bucket (Settings → Storage → Buckets) called `vibenest-uploads` or any name you prefer, then use that name as `SUPABASE_BUCKET` in `.env`.

Security / RLS guidance:
- For production you should enable Row Level Security (RLS) on your tables and add policies so that users can only read/write their own rows when using the public anon key.
- Use the `SUPABASE_SERVICE_ROLE_KEY` on the server to perform admin operations and bypass RLS when required (only server-side code should have this key).

For a simple dev flow the SQL editor + anon key is enough to start testing, then later install the service role key in `.env` for server integrations.

### Backup / recovery codes API (Supabase)

I added server endpoints to manage single-use backup codes that are stored in Supabase (hashed) so they are secure and single-use.

- POST /api/2fa/backup-codes/regenerate (authenticated): generates 10 new codes, stores hashed values in `backup_codes` table and returns the plaintext codes in the response (shown once to the user).
- POST /2fa-verify-backup: verifies a single-use code during an in-progress 2FA login (uses `req.session.twoFactor.userId`) and consumes it if valid.

These endpoints use the `SUPABASE_SERVICE_ROLE_KEY` (server-only) to write/read the `backup_codes` table; add it to `.env` before testing.

## Mailjet integration
- The app uses Mailjet for all email sending (verification, password reset, support).
- If Mailjet credentials are not provided, it will fall back to SMTP or log emails to the console for development.
- To enable Mailjet, set the following in your `.env`:
  - `MAILJET_API_KEY=your-mailjet-api-key`
  - `MAILJET_API_SECRET=your-mailjet-api-secret`
  - Optionally: `MAILJET_SMTP_HOST`, `MAILJET_SMTP_PORT`, `MAILJET_SMTP_SECURE`

Admin tools

- There is an admin-only UI to re-send verification emails at `/admin/resend-verification`. The admin user must have `isAdmin` set in the database. Use that page to reissue verification links for specific users.

## Security notes
- **Mailjet and its dependencies may be affected by SSRF vulnerabilities.** See: https://github.com/advisories/GHSA-2p57-rm9w-gvfp
- If you do not provide Mailjet or SMTP credentials, mail is logged to the console for development safety.
- In production, ensure `SESSION_SECRET` is a secure random value.

## Vulnerabilities
- As of November 2025, the SSRF vulnerability in the `ip` package (used by Mailjet and its dependencies) may affect your app. Review advisories and keep dependencies up to date.

If you'd like, I can add unit tests or Dockerfile next.

## Local Testing / Quick Validation (Upload, 2FA, Settings)

1. Start the application:

```bash
cp .env.example .env
npm install
npm start
```

2. Register a user via web UI or curl (without email verification — see step 4):

```bash
curl -i -c cookies.txt -L -X POST \
  -d "username=testuser" \
  -d "email=test@example.com" \
  -d "password=supersecret" \
  -d "confirmPassword=supersecret" \
  -d "displayName=Tester" \
  http://localhost:3000/register

# Notes
- Leading `@` characters in display names are stripped at registration time (so the stored `display_name` will not start with `@`).
- Login accepts display name handles with or without a leading `@` (the server will try both forms for compatibility).
```

3. Login (keep cookies) and visit the upload page:

```bash
# Login by username
curl -i -L -c cookies.txt -b cookies.txt -X POST -d "username=testuser" -d "password=supersecret" http://localhost:3000/login

# Login by display name (handles are supported). Both of the following should work if the user has display name "test4":
# Without @
curl -i -L -c cookies.txt -b cookies.txt -X POST -d "username=test4" -d "password=supersecret" http://localhost:3000/login
# With @
curl -i -L -c cookies.txt -b cookies.txt -X POST -d "username=@test4" -d "password=supersecret" http://localhost:3000/login

curl -i -b cookies.txt http://localhost:3000/upload
```

4. If verification emails are enabled and required in production, either use the email delivery configured in `.env` (Mailjet/SMTP) or set the user as verified directly in the DB for development:

```bash
sqlite3 vibenest.db "UPDATE users SET verified = 1 WHERE username = 'testuser';"
```

5. Upload a file to `/api/upload` (with session cookies):
```bash
curl -i -b cookies.txt -F "photo=@/path/to/image.jpg;type=image/jpeg" -F "caption=Test upload" http://localhost:3000/api/upload
```

6. Enable email 2FA or Authenticator 2FA at `/setup-2fa` (UI); verify the authenticator token, or for email check the server console for the code when SMTP/Mailjet isn't configured.

7. To test the 2FA login flow after enabling email 2FA, login again and you'll be redirected to `/2fa-login` where you need to enter the code emailed to the user or logged in server stdout.

Manual test for display-name handles:

```bash
# Register a test user (displayName with @)
curl -i -L -X POST \
  -d "username=testhandle" \
  -d "email=testhandle@example.com" \
  -d "password=supersecret" \
  -d "confirmPassword=supersecret" \
  -d "displayName=@test4" \
  http://localhost:3000/register

# Attempt login using '@test4' (should work)
curl -i -L -c cookies.txt -b cookies.txt -X POST -d "username=@test4" -d "password=supersecret" http://localhost:3000/login

# Attempt login using 'test4' (should also work)
curl -i -L -c cookies.txt -b cookies.txt -X POST -d "username=test4" -d "password=supersecret" http://localhost:3000/login
```

Migration: normalize existing display names

```bash
# Dry-run (shows what would change, writes a backup JSON)
node scripts/normalize_display_names.js

# Apply changes (writes backup JSON and updates profiles)
node scripts/normalize_display_names.js --apply

# Or use npm script
npm run migrate:normalize-display-names
```

Notes:
- The script writes a backup file at `scripts/normalize_display_names.backup.json` and a results file `scripts/normalize_display_names.results.TIMESTAMP.json` so you can review/rollback manually.
- If a stripping operation would result in a conflicting display name, the script appends `-<shortid>` (first 6 chars of user id) to make it unique and logs the change.


8. To generate backup codes for authenticator 2FA (single use), use the button on `/setup-2fa` or POST to `/api/2fa/backup-codes/regenerate`.

Notes:
- All pages use the central `public/css/theme.css` for theming and include a shared header partial `views/partials/header.ejs`.
- If the header throws an error about `user` not being defined, ensure sessions are set up or restart the server — the app now sets `res.locals.user` for every request.
