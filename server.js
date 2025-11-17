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
import { initializeDb, users, photos, likes, comments, videos, videoLikes, videoComments } from './db.js';

dotenv.config();

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
    const isImage = file.mimetype.startsWith('image/');
    const isVideo = file.mimetype.startsWith('video/');
    if (isImage || isVideo) {
      cb(null, true);
    } else {
      cb(new Error('Only image and video files allowed'));
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
  async (username, password, done) => {
    try {
      const user = await users.findByUsername(username);
      if (!user) {
        return done(null, false, { message: 'Username not found' });
      }
      if (!bcrypt.compareSync(password, user.password)) {
        return done(null, false, { message: 'Password incorrect' });
      }
      return done(null, user);
    } catch (err) {
      done(err);
    }
  }
));

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
          authProvider: 'google'
        };
        await users.create(user);
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
          authProvider: 'entra'
        };
        await users.create(user);
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

// ====================
// Routes
// ====================

// Home / Feed
app.get('/', async (req, res) => {
  try {
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
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, displayName } = req.body;

    if (password !== confirmPassword) {
      return res.render('register', { message: 'Passwords do not match' });
    }

    if (await users.findByUsername(username)) {
      return res.render('register', { message: 'Username already taken' });
    }

    if (await users.findByEmail(email)) {
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

    await users.create(user);
    req.logIn(user, (err) => {
      if (err) return res.redirect('/register');
      res.redirect('/');
    });
  } catch (err) {
    console.error(err);
    res.render('register', { message: 'Registration error' });
  }
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
app.post('/api/settings', isAuthenticated, async (req, res) => {
  try {
    const { displayName, bio } = req.body;
    await users.update(req.user.id, { displayName, bio });
    req.user.displayName = displayName;
    req.user.bio = bio;
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Upload page
app.get('/upload', isAuthenticated, (req, res) => {
  res.render('upload', { user: req.user });
});

// Handle photo/video upload
app.post('/api/upload', isAuthenticated, upload.single('media'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const isImage = req.file.mimetype.startsWith('image/');
    const isVideo = req.file.mimetype.startsWith('video/');

    if (isImage) {
      const photo = {
        id: uuidv4(),
        userId: req.user.id,
        filename: req.file.filename,
        caption: req.body.caption || ''
      };
      await photos.create(photo);
      res.json({ success: true, type: 'photo', media: photo });
    } else if (isVideo) {
      const video = {
        id: uuidv4(),
        userId: req.user.id,
        filename: req.file.filename,
        caption: req.body.caption || ''
      };
      await videos.create(video);
      res.json({ success: true, type: 'video', media: video });
    } else {
      return res.status(400).json({ error: 'Invalid file type' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

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
    const videoComments = await videoComments.getByVideo(req.params.videoId);
    res.json({ comments: videoComments });
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
    const comment = await comments.getByPhoto(req.params.commentId);
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
    const comment = await videoComments.getByVideo(req.params.videoCommentId);
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
  res.status(500).render('error', { error: err.message || 'Something went wrong' });
});

// ====================
// Start Server
// ====================
(async () => {
  await initializeDb();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✨ VibeNest running on http://localhost:${PORT}`);
    console.log(`Make sure to set your OAuth credentials in .env`);
  });
})();
