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
import dotenv from 'dotenv';
import { initializeDb, users, photos, likes, comments } from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize database
initializeDb();

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
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

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
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files allowed'));
    }
  }
});

// ====================
// View Setup
// ====================
app.set('views', join(__dirname, 'views'));
app.set('view engine', 'ejs');

// ====================
// Passport Configuration
// ====================

// Local Strategy
passport.use(new LocalStrategy.Strategy(
  {
    usernameField: 'username',
    passwordField: 'password'
  },
  (username, password, done) => {
    const user = users.findByUsername(username);
    if (!user) {
      return done(null, false, { message: 'Username not found' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
      return done(null, false, { message: 'Password incorrect' });
    }
    return done(null, user);
  }
));

// Google Strategy
passport.use(new GoogleStrategy.Strategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID || 'your-google-client-id',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'your-google-client-secret',
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    let user = users.findByEmail(profile.emails[0].value);
    if (!user) {
      user = {
        id: uuidv4(),
        username: profile.displayName.replace(/\s+/g, '').toLowerCase() + uuidv4().slice(0, 4),
        email: profile.emails[0].value,
        displayName: profile.displayName,
        profilePic: profile.photos[0]?.value,
        authProvider: 'google'
      };
      users.create(user);
    }
    return done(null, user);
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
  (accessToken, refreshToken, profile, done) => {
    // Extract email safely - Entra may provide it in different ways
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || 
                  profile.mail || 
                  profile.userPrincipalName ||
                  `${profile.displayName.replace(/\s+/g, '').toLowerCase()}@entra.local`;
    
    let user = users.findByEmail(email);
    if (!user) {
      user = {
        id: uuidv4(),
        username: profile.displayName.replace(/\s+/g, '').toLowerCase() + uuidv4().slice(0, 4),
        email: email,
        displayName: profile.displayName,
        authProvider: 'entra'
      };
      users.create(user);
    }
    return done(null, user);
  }
));

// Serialize/Deserialize
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.findById(id);
  done(null, user);
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

// ====================
// Routes
// ====================

// Home / Feed
app.get('/', (req, res) => {
  const allPhotos = photos.getAll();
  res.render('feed', { user: req.user, photos: allPhotos });
});

// Login page
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('login', { message: req.query.message });
});

// Register page
app.get('/register', (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.render('register', { message: req.query.message });
});

// Handle local registration
app.post('/register', (req, res) => {
  const { username, email, password, confirmPassword, displayName } = req.body;

  if (password !== confirmPassword) {
    return res.render('register', { message: 'Passwords do not match' });
  }

  if (users.findByUsername(username)) {
    return res.render('register', { message: 'Username already taken' });
  }

  if (users.findByEmail(email)) {
    return res.render('register', { message: 'Email already registered' });
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

  users.create(user);
  req.logIn(user, (err) => {
    if (err) return res.redirect('/register');
    res.redirect('/');
  });
});

// Handle local login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login?message=Invalid%20credentials',
  failureMessage: true
}));

// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

// Entra ID OAuth
app.get('/auth/entra', passport.authenticate('microsoft', { scope: ['user.read'] }));
app.get('/auth/entra/callback', passport.authenticate('microsoft', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

// Logout
app.get('/logout', (req, res) => {
  req.logOut((err) => {
    if (err) return res.status(500).send('Logout failed');
    res.redirect('/login');
  });
});

// Settings page
app.get('/settings', isAuthenticated, (req, res) => {
  res.render('settings', { user: req.user });
});

// Update settings
app.post('/api/settings', isAuthenticated, (req, res) => {
  const { displayName, bio } = req.body;
  users.update(req.user.id, { displayName, bio });
  req.user.displayName = displayName;
  req.user.bio = bio;
  res.json({ success: true });
});

// Upload page
app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload', { user: req.user });
});

// Handle photo upload
app.post('/api/upload', isAuthenticated, upload.single('photo'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const photo = {
    id: uuidv4(),
    userId: req.user.id,
    filename: req.file.filename,
    caption: req.body.caption || ''
  };

  photos.create(photo);
  res.json({ success: true, photo });
});

// Get all photos
app.get('/api/photos', (req, res) => {
  const allPhotos = photos.getAll();
  res.json({ photos: allPhotos });
});

// Get user's photos
app.get('/api/user/:userId/photos', (req, res) => {
  const userPhotos = photos.getByUserId(req.params.userId);
  res.json({ photos: userPhotos });
});

// Like a photo
app.post('/api/photos/:photoId/like', isAuthenticated, (req, res) => {
  const photo = photos.findById(req.params.photoId);
  if (!photo) {
    return res.status(404).json({ error: 'Photo not found' });
  }

  const existingLike = likes.findByPhotoAndUser(req.params.photoId, req.user.id);
  if (existingLike) {
    likes.remove(req.params.photoId, req.user.id);
    res.json({ success: true, liked: false, likes: likes.countByPhoto(req.params.photoId) });
  } else {
    likes.create({
      id: uuidv4(),
      photoId: req.params.photoId,
      userId: req.user.id
    });
    res.json({ success: true, liked: true, likes: likes.countByPhoto(req.params.photoId) });
  }
});

// Comment on a photo
app.post('/api/photos/:photoId/comment', isAuthenticated, (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ error: 'Comment text required' });
  }

  const photo = photos.findById(req.params.photoId);
  if (!photo) {
    return res.status(404).json({ error: 'Photo not found' });
  }

  const comment = {
    id: uuidv4(),
    photoId: req.params.photoId,
    userId: req.user.id,
    text
  };

  comments.create(comment);
  const newComment = {
    ...comment,
    username: req.user.username,
    displayName: req.user.displayName,
    profilePic: req.user.profilePic
  };

  res.json({ success: true, comment: newComment });
});

// Get comments for a photo
app.get('/api/photos/:photoId/comments', (req, res) => {
  const photoComments = comments.getByPhoto(req.params.photoId);
  res.json({ comments: photoComments });
});

// Delete a photo (only owner)
app.delete('/api/photos/:photoId', isAuthenticated, (req, res) => {
  const photo = photos.findById(req.params.photoId);
  if (!photo) {
    return res.status(404).json({ error: 'Photo not found' });
  }
  if (photo.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  photos.delete(req.params.photoId);
  res.json({ success: true });
});

// Delete a comment (only owner)
app.delete('/api/comments/:commentId', isAuthenticated, (req, res) => {
  const comment = comments.getByPhoto(req.params.commentId);
  if (!comment) {
    return res.status(404).json({ error: 'Comment not found' });
  }
  if (comment.userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  comments.delete(req.params.commentId);
  res.json({ success: true });
});

// ====================
// Error Handling
// ====================
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { error: err.message || 'Something went wrong' });
});

// ====================
// Start Server
// ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✨ VibeNest running on http://localhost:${PORT}`);
  console.log(`Make sure to set your OAuth credentials in .env`);
});
