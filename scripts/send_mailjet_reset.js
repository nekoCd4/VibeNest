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

    console.warn('Deprecated script. Use the website flows instead. Exiting.');
    process.exit(0);
}

main();
