import Mailjet from 'node-mailjet';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config({ path: './.env' });

async function main() {
  const user = process.env.MAILJET_USER;
  const pass = process.env.MAILJET_PASS;
  const sender = process.env.MAILJET_SENDER_EMAIL || 'no-reply@example.com';
  if (!user || !pass) {
    console.error('Missing MAILJET_USER or MAILJET_PASS in environment');
    process.exit(1);
  }

  const mailjet = Mailjet.apiConnect(user, pass);

  const token = crypto.randomBytes(24).toString('hex');
  const base = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
  const resetUrl = `${base}/reset/${token}`;

  const payload = {
    Messages: [
      {
        From: { Email: sender, Name: 'VibeNest' },
        To: [{ Email: 'kinvilleadam@maltaschools.org', Name: 'Kinville Adam' }],
        Subject: 'VibeNest password reset',
        TextPart: `You requested a password reset. Visit: ${resetUrl}`,
        HTMLPart: `<p>Hi,</p><p>You requested a password reset for your VibeNest account. Click the link below to reset your password (this is a test email):</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you didn't request this, ignore this email.</p>`
      }
    ]
  };

  try {
    const res = await mailjet.post('send', { version: 'v3.1' }).request(payload);
    console.log('Mailjet send response status:', res.response.status);
    console.log('Message ID (if available):', res.body && res.body.Messages && res.body.Messages[0] && res.body.Messages[0].Status);
    console.log('Sent reset link:', resetUrl);
  } catch (err) {
    console.error('Mailjet send error:', err && err.message ? err.message : err);
    if (err && err.response && err.response.body) console.error('Mailjet response body:', err.response.body);
    process.exit(1);
  }
}

main();
