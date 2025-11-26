import supabaseAdmin from './supabaseServer.js';
import { v4 as uuidv4 } from 'uuid';
import * as localDb from '../db.js';

const enabled = !!supabaseAdmin;

// Users
const users = {
  create: async (user) => {
    if (!enabled) return await localDb.users.create(user);
    const payload = {
      id: user.id,
      username: user.username,
      display_name: user.displayName || user.username,
      profile_pic: user.profilePic || null,
      bio: user.bio || null,
      is2fa_enabled: user.is2FAEnabled || 'none',
      is_admin: user.isAdmin ? true : false
    };
    const { data, error } = await supabaseAdmin.from('profiles').insert(payload).select().single();
    if (error) throw error;
    // ensure local mapping exists too for backwards compatibility
    try { await localDb.users.create({ id: data.id, username: data.username, email: user.email || '', password: null, displayName: data.display_name, authProvider: 'supabase' }); } catch (e) { /* ignore */ }
    return { id: data.id, username: data.username, email: user.email || null, displayName: data.display_name };
  },

  findById: async (id) => {
    if (!enabled) return await localDb.users.findById(id);
    const { data: profile, error: pErr } = await supabaseAdmin.from('profiles').select('*').eq('id', id).limit(1).maybeSingle();
    let email = null;
    if (!pErr && profile) {
      // attempt to fetch auth user email
      try {
        const resp = await supabaseAdmin.auth.admin.getUserById(id).catch(() => null);
        if (resp && resp.user) email = resp.user.email;
      } catch (e) {}
      return { id: profile.id, username: profile.username, email: email, displayName: profile.display_name, profilePic: profile.profile_pic, is2FAEnabled: profile.is2fa_enabled || 'none', isAdmin: profile.is_admin };
    }
    return await localDb.users.findById(id);
  },

  findByUsername: async (username) => {
    if (!enabled) return await localDb.users.findByUsername(username);
    const { data: profile, error } = await supabaseAdmin.from('profiles').select('*').eq('username', username).limit(1).maybeSingle();
    if (error) throw error;
    if (!profile) return null;
    let email = null;
    try {
      const resp = await supabaseAdmin.auth.admin.listUsers({ search: username }).catch(() => null);
      if (resp && resp.users) {
        const found = resp.users.find(u => u.user_metadata?.username === username || u.email?.toLowerCase() === username.toLowerCase());
        if (found) email = found.email;
      }
    } catch (e) {}
    return { id: profile.id, username: profile.username, email: email, displayName: profile.display_name, profilePic: profile.profile_pic };
  },

  findByEmail: async (email) => {
    if (!enabled) return await localDb.users.findByEmail(email);
    try {
      const resp = await supabaseAdmin.auth.admin.listUsers({ search: email });
      if (resp && resp.users && resp.users.length) {
        const u = resp.users.find(x => x.email && x.email.toLowerCase() === email.toLowerCase());
        if (u) {
          const { data: profile } = await supabaseAdmin.from('profiles').select('*').eq('id', u.id).limit(1).maybeSingle();
          return { id: u.id, username: profile?.username || u.user_metadata?.username || `supa-${u.id.slice(0,6)}`, email: u.email, displayName: profile?.display_name || u.user_metadata?.displayName || u.user_metadata?.display_name || '' };
        }
      }
    } catch (e) {}
    return await localDb.users.findByEmail(email);
  },

  update: async (id, updates) => {
    if (!enabled) return await localDb.users.update(id, updates);
    const payload = {};
    if (updates.displayName || updates.display_name) payload.display_name = updates.displayName || updates.display_name;
    if (updates.profilePic || updates.profile_pic) payload.profile_pic = updates.profilePic || updates.profile_pic;
    if ('is2FAEnabled' in updates) payload.is2fa_enabled = updates.is2FAEnabled;
    if ('twoFactorSecret' in updates) payload.two_factor_secret = updates.twoFactorSecret;
    if ('isAdmin' in updates) payload.is_admin = updates.isAdmin ? true : false;
    if (Object.keys(payload).length) {
      const { error } = await supabaseAdmin.from('profiles').update(payload).eq('id', id);
      if (error) throw error;
    }
    try { await localDb.users.update(id, updates); } catch (e) { /* ignore */ }
  }
};

// Photos
const photos = {
  create: async (photo) => {
    if (!enabled) return await localDb.photos.create(photo);
    const payload = { id: photo.id, user_id: photo.userId, filename: photo.filename, caption: photo.caption || '' };
    const { data, error } = await supabaseAdmin.from('photos').insert(payload).select().single();
    if (error) throw error;
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at };
  },

  findById: async (id) => {
    if (!enabled) return await localDb.photos.findById(id);
    const { data, error } = await supabaseAdmin.from('photos').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('id', id).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const profile = data.profiles || null;
    const { count } = await supabaseAdmin.from('photo_likes').select('id', { count: 'exact', head: true }).eq('photo_id', id);
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
  },

  getAll: async () => {
    if (!enabled) return await localDb.photos.getAll();
    const { data, error } = await supabaseAdmin.from('photos').select('*, profiles:profiles(id, username, display_name, profile_pic)').order('created_at', { ascending: false });
    if (error) throw error;
    const results = await Promise.all((data || []).map(async (p) => {
      const { count } = await supabaseAdmin.from('photo_likes').select('id', { count: 'exact', head: true }).eq('photo_id', p.id);
      const profile = p.profiles || null;
      return { id: p.id, userId: p.user_id, filename: p.filename, caption: p.caption, createdAt: p.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
    }));
    return results;
  },

  getByUserId: async (userId) => {
    if (!enabled) return await localDb.photos.getByUserId(userId);
    const { data, error } = await supabaseAdmin.from('photos').select('*, profiles:profiles(id, username, display_name)').eq('user_id', userId).order('created_at', { ascending: false });
    if (error) throw error;
    return (data || []).map(p => ({ id: p.id, userId: p.user_id, filename: p.filename, caption: p.caption, createdAt: p.created_at, username: p.profiles?.username, displayName: p.profiles?.display_name }));
  },

  delete: async (id) => {
    if (!enabled) return await localDb.photos.delete(id);
    const { error } = await supabaseAdmin.from('photos').delete().eq('id', id);
    if (error) throw error;
  }
};

// Likes
const likes = {
  create: async ({ id, photoId, userId }) => {
    if (!enabled) return await localDb.likes.create({ id, photoId, userId });
    const payload = { id, photo_id: photoId, user_id: userId };
    const { error } = await supabaseAdmin.from('photo_likes').insert(payload);
    if (error) throw error;
  },

  remove: async (photoId, userId) => {
    if (!enabled) return await localDb.likes.remove(photoId, userId);
    const { error } = await supabaseAdmin.from('photo_likes').delete().eq('photo_id', photoId).eq('user_id', userId);
    if (error) throw error;
  },

  findByPhotoAndUser: async (photoId, userId) => {
    if (!enabled) return await localDb.likes.findByPhotoAndUser(photoId, userId);
    const { data } = await supabaseAdmin.from('photo_likes').select('*').eq('photo_id', photoId).eq('user_id', userId).limit(1).maybeSingle();
    return data || null;
  },

  countByPhoto: async (photoId) => {
    if (!enabled) return await localDb.likes.countByPhoto(photoId);
    const { count } = await supabaseAdmin.from('photo_likes').select('id', { count: 'exact', head: true }).eq('photo_id', photoId);
    return count || 0;
  }
};

// Comments
const comments = {
  create: async (comment) => {
    if (!enabled) return await localDb.comments.create(comment);
    const payload = { id: comment.id, photo_id: comment.photoId, user_id: comment.userId, text: comment.text };
    const { data, error } = await supabaseAdmin.from('photo_comments').insert(payload).select().single();
    if (error) throw error;
    const p = await supabaseAdmin.from('profiles').select('username, display_name, profile_pic').eq('id', comment.userId).limit(1).maybeSingle();
    return { id: data.id, photoId: data.photo_id, userId: data.user_id, text: data.text, username: p.data?.username, displayName: p.data?.display_name };
  },

  getByPhoto: async (photoId) => {
    if (!enabled) return await localDb.comments.getByPhoto(photoId);
    const { data, error } = await supabaseAdmin.from('photo_comments').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('photo_id', photoId).order('created_at', { ascending: true });
    if (error) throw error;
    return (data || []).map(c => ({ id: c.id, photoId: c.photo_id, userId: c.user_id, text: c.text, username: c.profiles?.username, displayName: c.profiles?.display_name, profilePic: c.profiles?.profile_pic }));
  },

  findById: async (id) => {
    if (!enabled) return await localDb.comments.findById(id);
    const { data } = await supabaseAdmin.from('photo_comments').select('*').eq('id', id).limit(1).maybeSingle();
    return data || null;
  },

  delete: async (id) => {
    if (!enabled) return await localDb.comments.delete(id);
    const { error } = await supabaseAdmin.from('photo_comments').delete().eq('id', id);
    if (error) throw error;
  }
};

// Videos
const videos = {
  create: async (video) => {
    if (!enabled) return await localDb.videos.create(video);
    const payload = { id: video.id, user_id: video.userId, filename: video.filename, caption: video.caption || '' };
    const { data, error } = await supabaseAdmin.from('videos').insert(payload).select().single();
    if (error) throw error;
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at };
  },

  findById: async (id) => {
    if (!enabled) return await localDb.videos.findById(id);
    const { data, error } = await supabaseAdmin.from('videos').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('id', id).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const profile = data.profiles || null;
    const { count } = await supabaseAdmin.from('video_likes').select('id', { count: 'exact', head: true }).eq('video_id', id);
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
  },

  getAll: async () => {
    if (!enabled) return await localDb.videos.getAll();
    const { data, error } = await supabaseAdmin.from('videos').select('*, profiles:profiles(id, username, display_name, profile_pic)').order('created_at', { ascending: false });
    if (error) throw error;
    const results = await Promise.all((data || []).map(async (v) => {
      const { count } = await supabaseAdmin.from('video_likes').select('id', { count: 'exact', head: true }).eq('video_id', v.id);
      const profile = v.profiles || null;
      return { id: v.id, userId: v.user_id, filename: v.filename, caption: v.caption, createdAt: v.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
    }));
    return results;
  },

  getByUserId: async (userId) => {
    if (!enabled) return await localDb.videos.getByUserId(userId);
    const { data, error } = await supabaseAdmin.from('videos').select('*, profiles:profiles(id, username, display_name)').eq('user_id', userId).order('created_at', { ascending: false });
    if (error) throw error;
    return (data || []).map(v => ({ id: v.id, userId: v.user_id, filename: v.filename, caption: v.caption, createdAt: v.created_at, username: v.profiles?.username, displayName: v.profiles?.display_name }));
  },

  delete: async (id) => {
    if (!enabled) return await localDb.videos.delete(id);
    const { error } = await supabaseAdmin.from('videos').delete().eq('id', id);
    if (error) throw error;
  }
};

// Video likes
const videoLikes = {
  create: async (likeData) => {
    if (!enabled) return await localDb.videoLikes.create(likeData);
    const payload = { id: likeData.id, video_id: likeData.videoId, user_id: likeData.userId };
    const { error } = await supabaseAdmin.from('video_likes').insert(payload);
    if (error) throw error;
  },

  remove: async (videoId, userId) => {
    if (!enabled) return await localDb.videoLikes.remove(videoId, userId);
    const { error } = await supabaseAdmin.from('video_likes').delete().eq('video_id', videoId).eq('user_id', userId);
    if (error) throw error;
  },

  findByVideoAndUser: async (videoId, userId) => {
    if (!enabled) return await localDb.videoLikes.findByVideoAndUser(videoId, userId);
    const { data } = await supabaseAdmin.from('video_likes').select('*').eq('video_id', videoId).eq('user_id', userId).limit(1).maybeSingle();
    return data || null;
  },

  countByVideo: async (videoId) => {
    if (!enabled) return await localDb.videoLikes.countByVideo(videoId);
    const { count } = await supabaseAdmin.from('video_likes').select('id', { count: 'exact', head: true }).eq('video_id', videoId);
    return count || 0;
  }
};

// Video comments
const videoComments = {
  create: async (comment) => {
    if (!enabled) return await localDb.videoComments.create(comment);
    const payload = { id: comment.id, video_id: comment.videoId, user_id: comment.userId, text: comment.text };
    const { data, error } = await supabaseAdmin.from('video_comments').insert(payload).select().single();
    if (error) throw error;
    const p = await supabaseAdmin.from('profiles').select('username, display_name, profile_pic').eq('id', comment.userId).limit(1).maybeSingle();
    return { id: data.id, videoId: data.video_id, userId: data.user_id, text: data.text, username: p.data?.username, displayName: p.data?.display_name };
  },

  getByVideo: async (videoId) => {
    if (!enabled) return await localDb.videoComments.getByVideo(videoId);
    const { data, error } = await supabaseAdmin.from('video_comments').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('video_id', videoId).order('created_at', { ascending: true });
    if (error) throw error;
    return (data || []).map(c => ({ id: c.id, videoId: c.video_id, userId: c.user_id, text: c.text, username: c.profiles?.username, displayName: c.profiles?.display_name, profilePic: c.profiles?.profile_pic }));
  },

  findById: async (id) => {
    if (!enabled) return await localDb.videoComments.findById(id);
    const { data } = await supabaseAdmin.from('video_comments').select('*').eq('id', id).limit(1).maybeSingle();
    return data || null;
  },

  delete: async (id) => {
    if (!enabled) return await localDb.videoComments.delete(id);
    const { error } = await supabaseAdmin.from('video_comments').delete().eq('id', id);
    if (error) throw error;
  }
};

// Password resets & verifications & backup codes
const passwordResets = {
  create: async (token, userId, expiresAt) => {
    if (!enabled) return await localDb.passwordResets.create(token, userId, expiresAt);
    const { error } = await supabaseAdmin.from('password_resets').insert({ token, user_id: userId, expires_at: expiresAt });
    if (error) throw error;
  },

  findByToken: async (token) => {
    if (!enabled) return await localDb.passwordResets.findByToken(token);
    const { data, error } = await supabaseAdmin.from('password_resets').select('*').eq('token', token).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    let email = null;
    try {
      const resp = await supabaseAdmin.auth.admin.getUserById(data.user_id).catch(() => null);
      if (resp && resp.user) email = resp.user.email;
    } catch (e) {}
    return { token: data.token, userId: data.user_id, expiresAt: data.expires_at, email };
  },

  deleteByToken: async (token) => {
    if (!enabled) return await localDb.passwordResets.deleteByToken(token);
    const { error } = await supabaseAdmin.from('password_resets').delete().eq('token', token);
    if (error) throw error;
  },

  deleteByUserId: async (userId) => {
    if (!enabled) return await localDb.passwordResets.deleteByUserId(userId);
    const { error } = await supabaseAdmin.from('password_resets').delete().eq('user_id', userId);
    if (error) throw error;
  }
};

const verifications = {
  create: async (token, userId, expiresAt) => {
    if (!enabled) return await localDb.verifications.create(token, userId, expiresAt);
    const { error } = await supabaseAdmin.from('verifications').insert({ token, user_id: userId, expires_at: expiresAt });
    if (error) throw error;
  },

  findByToken: async (token) => {
    if (!enabled) return await localDb.verifications.findByToken(token);
    const { data, error } = await supabaseAdmin.from('verifications').select('*').eq('token', token).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    let email = null;
    try {
      const resp = await supabaseAdmin.auth.admin.getUserById(data.user_id).catch(() => null);
      if (resp && resp.user) email = resp.user.email;
    } catch (e) {}
    return { token: data.token, userId: data.user_id, expiresAt: data.expires_at, email };
  },

  deleteByToken: async (token) => {
    if (!enabled) return await localDb.verifications.deleteByToken(token);
    const { error } = await supabaseAdmin.from('verifications').delete().eq('token', token);
    if (error) throw error;
  },

  deleteByUserId: async (userId) => {
    if (!enabled) return await localDb.verifications.deleteByUserId(userId);
    const { error } = await supabaseAdmin.from('verifications').delete().eq('user_id', userId);
    if (error) throw error;
  }
};

const backupCodes = {
  deleteByUser: async (userId) => {
    if (!enabled) return await localDb.backupCodes.deleteByUser(userId);
    const { error } = await supabaseAdmin.from('backup_codes').delete().eq('user_id', userId);
    if (error) throw error;
  },

  insertMany: async (codeHashes) => {
    if (!enabled) return null;
    const { error } = await supabaseAdmin.from('backup_codes').insert(codeHashes);
    if (error) throw error;
    return true;
  },

  getUnusedByUser: async (userId) => {
    if (!enabled) return await localDb.backupCodes.getUnusedByUser(userId);
    const { data, error } = await supabaseAdmin.from('backup_codes').select('*').eq('user_id', userId).eq('used', false).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    return data || [];
  },

  markUsed: async (id) => {
    if (!enabled) return await localDb.backupCodes.markUsed(id);
    const { error } = await supabaseAdmin.from('backup_codes').update({ used: true }).eq('id', id);
    if (error) throw error;
  },

  findValidByUserAndCode: async (userId) => {
    if (!enabled) return await localDb.backupCodes.findValidByUserAndCode(userId);
    const { data, error } = await supabaseAdmin.from('backup_codes').select('*').eq('user_id', userId).eq('used', false).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    return data || [];
  }
};

export default { users, photos, likes, comments, videos, videoLikes, videoComments, passwordResets, verifications, backupCodes };
