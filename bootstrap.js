// Bootstrap file to load env vars before importing the main app
import dotenv from 'dotenv';
dotenv.config();

// Now import and start the server
import('./server.js').catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
