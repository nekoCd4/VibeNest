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
