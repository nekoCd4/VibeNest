import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new sqlite3.Database(path.join(__dirname, 'vibenest.db'));

// Enable foreign keys and promisify basic operations
db.run('PRAGMA foreign_keys = ON');

// Helper function to promisify db.run
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

// Helper function to promisify db.get
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Helper function to promisify db.all
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
}

// Initialize database schema
export async function initializeDb() {
  const createTables = [
    `
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      displayName TEXT NOT NULL,
      profilePic TEXT,
      bio TEXT,
      authProvider TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS photos (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      filename TEXT NOT NULL,
      caption TEXT,
      likes INTEGER DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS likes (
      id TEXT PRIMARY KEY,
      photoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(photoId, userId),
      FOREIGN KEY (photoId) REFERENCES photos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      photoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      text TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (photoId) REFERENCES photos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS videos (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      filename TEXT NOT NULL,
      caption TEXT,
      likes INTEGER DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS video_likes (
      id TEXT PRIMARY KEY,
      videoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(videoId, userId),
      FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS video_comments (
      id TEXT PRIMARY KEY,
      videoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      text TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
    `
  ];

  // Add password reset table
  createTables.push(`
    CREATE TABLE IF NOT EXISTS password_resets (
      token TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      expiresAt DATETIME NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  for (const sql of createTables) {
    try {
      await dbRun(sql);
    } catch (err) {
      console.error('Error creating table:', err);
    }
  }

  // Ensure users table has a `verified` column (0/1). If it already exists, ignore error.
  try {
    await dbRun('ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0');
  } catch (e) {
    // ignore - column likely exists
  }

  // Create verifications table for account verification tokens
  try {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS verifications (
        token TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        expiresAt DATETIME NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
  } catch (err) {
    console.error('Error creating verifications table:', err);
  }
}

// User operations
export const users = {
  create: async (user) => {
    const sql = `
      INSERT INTO users (id, username, email, password, displayName, authProvider)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    await dbRun(sql, [user.id, user.username, user.email, user.password || null, user.displayName, user.authProvider || 'local']);
    return user;
  },

  findById: async (id) => {
    return await dbGet('SELECT * FROM users WHERE id = ?', [id]);
  },

  findByUsername: async (username) => {
    return await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  },

  findByEmail: async (email) => {
    return await dbGet('SELECT * FROM users WHERE email = ?', [email]);
  },

  update: async (id, updates) => {
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);
    const sql = `UPDATE users SET ${fields} WHERE id = ?`;
    await dbRun(sql, [...values, id]);
  },
};

// Photo operations
export const photos = {
  create: async (photo) => {
    const sql = `
      INSERT INTO photos (id, userId, filename, caption)
      VALUES (?, ?, ?, ?)
    `;
    await dbRun(sql, [photo.id, photo.userId, photo.filename, photo.caption || '']);
    return photo;
  },

  findById: async (id) => {
    return await dbGet('SELECT * FROM photos WHERE id = ?', [id]);
  },

  getAll: async () => {
    return await dbAll(`
      SELECT p.*, u.username, u.displayName, u.profilePic,
      (SELECT COUNT(*) FROM likes WHERE photoId = p.id) as likes
      FROM photos p
      JOIN users u ON p.userId = u.id
      ORDER BY p.createdAt DESC
    `);
  },

  getByUserId: async (userId) => {
    return await dbAll(`
      SELECT p.*, u.username, u.displayName,
      (SELECT COUNT(*) FROM likes WHERE photoId = p.id) as likes
      FROM photos p
      JOIN users u ON p.userId = u.id
      WHERE p.userId = ?
      ORDER BY p.createdAt DESC
    `, [userId]);
  },

  delete: async (id) => {
    await dbRun('DELETE FROM photos WHERE id = ?', [id]);
  },
};

// Like operations
export const likes = {
  create: async (likeData) => {
    const sql = `
      INSERT INTO likes (id, photoId, userId)
      VALUES (?, ?, ?)
    `;
    await dbRun(sql, [likeData.id, likeData.photoId, likeData.userId]);
  },

  remove: async (photoId, userId) => {
    await dbRun('DELETE FROM likes WHERE photoId = ? AND userId = ?', [photoId, userId]);
  },

  findByPhotoAndUser: async (photoId, userId) => {
    return await dbGet('SELECT * FROM likes WHERE photoId = ? AND userId = ?', [photoId, userId]);
  },

  countByPhoto: async (photoId) => {
    const result = await dbGet('SELECT COUNT(*) as count FROM likes WHERE photoId = ?', [photoId]);
    return result.count;
  },
};

// Comment operations
export const comments = {
  create: async (comment) => {
    const sql = `
      INSERT INTO comments (id, photoId, userId, text)
      VALUES (?, ?, ?, ?)
    `;
    await dbRun(sql, [comment.id, comment.photoId, comment.userId, comment.text]);
    return comment;
  },

  getByPhoto: async (photoId) => {
    return await dbAll(`
      SELECT c.*, u.username, u.displayName, u.profilePic
      FROM comments c
      JOIN users u ON c.userId = u.id
      WHERE c.photoId = ?
      ORDER BY c.createdAt ASC
    `, [photoId]);
  },

  // Find comment by id
  findById: async (id) => {
    return await dbGet('SELECT * FROM comments WHERE id = ?', [id]);
  },

  delete: async (id) => {
    await dbRun('DELETE FROM comments WHERE id = ?', [id]);
  },
};

// Video operations
export const videos = {
  create: async (video) => {
    const sql = `
      INSERT INTO videos (id, userId, filename, caption)
      VALUES (?, ?, ?, ?)
    `;
    await dbRun(sql, [video.id, video.userId, video.filename, video.caption || '']);
    return video;
  },

  findById: async (id) => {
    return await dbGet('SELECT * FROM videos WHERE id = ?', [id]);
  },

  getAll: async () => {
    return await dbAll(`
      SELECT v.*, u.username, u.displayName, u.profilePic,
      (SELECT COUNT(*) FROM video_likes WHERE videoId = v.id) as likes
      FROM videos v
      JOIN users u ON v.userId = u.id
      ORDER BY v.createdAt DESC
    `);
  },

  getByUserId: async (userId) => {
    return await dbAll(`
      SELECT v.*, u.username, u.displayName,
      (SELECT COUNT(*) FROM video_likes WHERE videoId = v.id) as likes
      FROM videos v
      JOIN users u ON v.userId = u.id
      WHERE v.userId = ?
      ORDER BY v.createdAt DESC
    `, [userId]);
  },

  delete: async (id) => {
    await dbRun('DELETE FROM videos WHERE id = ?', [id]);
  },
};

// Video likes operations
export const videoLikes = {
  create: async (likeData) => {
    const sql = `
      INSERT INTO video_likes (id, videoId, userId)
      VALUES (?, ?, ?)
    `;
    await dbRun(sql, [likeData.id, likeData.videoId, likeData.userId]);
  },

  remove: async (videoId, userId) => {
    await dbRun('DELETE FROM video_likes WHERE videoId = ? AND userId = ?', [videoId, userId]);
  },

  findByVideoAndUser: async (videoId, userId) => {
    return await dbGet('SELECT * FROM video_likes WHERE videoId = ? AND userId = ?', [videoId, userId]);
  },

  countByVideo: async (videoId) => {
    const result = await dbGet('SELECT COUNT(*) as count FROM video_likes WHERE videoId = ?', [videoId]);
    return result.count;
  },
};

// Video comments operations
export const videoComments = {
  create: async (comment) => {
    const sql = `
      INSERT INTO video_comments (id, videoId, userId, text)
      VALUES (?, ?, ?, ?)
    `;
    await dbRun(sql, [comment.id, comment.videoId, comment.userId, comment.text]);
    return comment;
  },

  getByVideo: async (videoId) => {
    return await dbAll(`
      SELECT c.*, u.username, u.displayName, u.profilePic
      FROM video_comments c
      JOIN users u ON c.userId = u.id
      WHERE c.videoId = ?
      ORDER BY c.createdAt ASC
    `, [videoId]);
  },

  // Find video comment by id
  findById: async (id) => {
    return await dbGet('SELECT * FROM video_comments WHERE id = ?', [id]);
  },

  delete: async (id) => {
    await dbRun('DELETE FROM video_comments WHERE id = ?', [id]);
  },
};

// Password reset operations
export const passwordResets = {
  create: async (token, userId, expiresAt) => {
    const sql = `
      INSERT INTO password_resets (token, userId, expiresAt)
      VALUES (?, ?, ?)
    `;
    await dbRun(sql, [token, userId, expiresAt]);
  },

  findByToken: async (token) => {
    return await dbGet(`
      SELECT pr.*, u.email, u.username, u.displayName
      FROM password_resets pr
      JOIN users u ON pr.userId = u.id
      WHERE pr.token = ?
    `, [token]);
  },

  deleteByToken: async (token) => {
    await dbRun('DELETE FROM password_resets WHERE token = ?', [token]);
  },

  deleteByUserId: async (userId) => {
    await dbRun('DELETE FROM password_resets WHERE userId = ?', [userId]);
  }
};

// Verification tokens (for email verification)
export const verifications = {
  create: async (token, userId, expiresAt) => {
    const sql = `
      INSERT INTO verifications (token, userId, expiresAt)
      VALUES (?, ?, ?)
    `;
    await dbRun(sql, [token, userId, expiresAt]);
  },

  findByToken: async (token) => {
    return await dbGet(`
      SELECT v.*, u.email, u.username, u.displayName
      FROM verifications v
      JOIN users u ON v.userId = u.id
      WHERE v.token = ?
    `, [token]);
  },

  deleteByToken: async (token) => {
    await dbRun('DELETE FROM verifications WHERE token = ?', [token]);
  },

  deleteByUserId: async (userId) => {
    await dbRun('DELETE FROM verifications WHERE userId = ?', [userId]);
  }
};
