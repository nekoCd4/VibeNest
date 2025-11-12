import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const db = new Database(path.join(__dirname, 'vibenest.db'));

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Initialize database schema
export function initializeDb() {
  // Users table
  db.exec(`
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
  `);

  // Photos table
  db.exec(`
    CREATE TABLE IF NOT EXISTS photos (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      filename TEXT NOT NULL,
      caption TEXT,
      likes INTEGER DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Likes table
  db.exec(`
    CREATE TABLE IF NOT EXISTS likes (
      id TEXT PRIMARY KEY,
      photoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(photoId, userId),
      FOREIGN KEY (photoId) REFERENCES photos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Comments table
  db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id TEXT PRIMARY KEY,
      photoId TEXT NOT NULL,
      userId TEXT NOT NULL,
      text TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (photoId) REFERENCES photos(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

// User operations
export const users = {
  create: (user) => {
    const stmt = db.prepare(`
      INSERT INTO users (id, username, email, password, displayName, authProvider)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(user.id, user.username, user.email, user.password || null, user.displayName, user.authProvider || 'local');
    return user;
  },

  findById: (id) => {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  },

  findByUsername: (username) => {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  },

  findByEmail: (email) => {
    return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  },

  update: (id, updates) => {
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);
    const stmt = db.prepare(`UPDATE users SET ${fields} WHERE id = ?`);
    stmt.run(...values, id);
  },
};

// Photo operations
export const photos = {
  create: (photo) => {
    const stmt = db.prepare(`
      INSERT INTO photos (id, userId, filename, caption)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(photo.id, photo.userId, photo.filename, photo.caption || '');
    return photo;
  },

  findById: (id) => {
    return db.prepare('SELECT * FROM photos WHERE id = ?').get(id);
  },

  getAll: () => {
    return db.prepare(`
      SELECT p.*, u.username, u.displayName, u.profilePic,
      (SELECT COUNT(*) FROM likes WHERE photoId = p.id) as likes
      FROM photos p
      JOIN users u ON p.userId = u.id
      ORDER BY p.createdAt DESC
    `).all();
  },

  getByUserId: (userId) => {
    return db.prepare(`
      SELECT p.*, u.username, u.displayName,
      (SELECT COUNT(*) FROM likes WHERE photoId = p.id) as likes
      FROM photos p
      JOIN users u ON p.userId = u.id
      WHERE p.userId = ?
      ORDER BY p.createdAt DESC
    `).all(userId);
  },

  delete: (id) => {
    db.prepare('DELETE FROM photos WHERE id = ?').run(id);
  },
};

// Like operations
export const likes = {
  create: (likeData) => {
    const stmt = db.prepare(`
      INSERT INTO likes (id, photoId, userId)
      VALUES (?, ?, ?)
    `);
    stmt.run(likeData.id, likeData.photoId, likeData.userId);
  },

  remove: (photoId, userId) => {
    db.prepare('DELETE FROM likes WHERE photoId = ? AND userId = ?').run(photoId, userId);
  },

  findByPhotoAndUser: (photoId, userId) => {
    return db.prepare('SELECT * FROM likes WHERE photoId = ? AND userId = ?').get(photoId, userId);
  },

  countByPhoto: (photoId) => {
    const result = db.prepare('SELECT COUNT(*) as count FROM likes WHERE photoId = ?').get(photoId);
    return result.count;
  },
};

// Comment operations
export const comments = {
  create: (comment) => {
    const stmt = db.prepare(`
      INSERT INTO comments (id, photoId, userId, text)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(comment.id, comment.photoId, comment.userId, comment.text);
    return comment;
  },

  getByPhoto: (photoId) => {
    return db.prepare(`
      SELECT c.*, u.username, u.displayName, u.profilePic
      FROM comments c
      JOIN users u ON c.userId = u.id
      WHERE c.photoId = ?
      ORDER BY c.createdAt ASC
    `).all(photoId);
  },

  delete: (id) => {
    db.prepare('DELETE FROM comments WHERE id = ?').run(id);
  },
};
