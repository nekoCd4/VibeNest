import supabaseAdmin from './supabaseServer.js';
import { v4 as uuidv4 } from 'uuid';

// Users
const users = {
  create: async (user) => {
    // Profiles are created automatically by Supabase auth triggers.
    // Do not manually insert into the profiles table to avoid FK violations.
    return { id: user.id, username: user.username, email: user.email || null, displayName: user.displayName || user.username };
  },

  findById: async (id) => {
    const { data: profile, error: pErr } = await supabaseAdmin.from('profiles').select('*').eq('id', id).limit(1).maybeSingle();
    let email = null;
    if (!pErr && profile) {
      // attempt to fetch auth user email
      try {
        const resp = await supabaseAdmin.auth.admin.getUserById(id).catch(() => null);
        if (resp && resp.user) email = resp.user.email;
      } catch (e) {}
      return { id: profile.id, username: profile.username, email: email, displayName: profile.display_name, profilePic: profile.profile_pic, is2FAEnabled: profile.is2fa_enabled || 'none', isAdmin: profile.is_admin, magicLinkEmail: profile.magic_link_email };
    }
    if (pErr) throw pErr;
    return null;
  },

  findByUsername: async (username) => {
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
    return null;
  },

  update: async (id, updates) => {
    const payload = {};
    if (updates.displayName || updates.display_name) payload.display_name = updates.displayName || updates.display_name;
    if (updates.profilePic || updates.profile_pic) payload.profile_pic = updates.profilePic || updates.profile_pic;
    if ('is2FAEnabled' in updates) payload.is2fa_enabled = updates.is2FAEnabled;
    if ('twoFactorSecret' in updates) payload.two_factor_secret = updates.twoFactorSecret;
    if ('magicLinkEmail' in updates) payload.magic_link_email = updates.magicLinkEmail;
    if ('isAdmin' in updates) payload.is_admin = updates.isAdmin ? true : false;
    if (Object.keys(payload).length) {
      const { error } = await supabaseAdmin.from('profiles').update(payload).eq('id', id);
      if (error) throw error;
    }
  }
};

// Photos
const photos = {
  create: async (photo) => {
    const payload = { id: photo.id, user_id: photo.userId, filename: photo.filename, caption: photo.caption || '' };
    const { data, error } = await supabaseAdmin.from('photos').insert(payload).select().single();
    if (error) throw error;
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at };
  },

  findById: async (id) => {
    const { data, error } = await supabaseAdmin.from('photos').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('id', id).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const profile = data.profiles || null;
    const { count } = await supabaseAdmin.from('photo_likes').select('id', { count: 'exact', head: true }).eq('photo_id', id);
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
  },

  getAll: async () => {
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
    const { data, error } = await supabaseAdmin.from('photos').select('*, profiles:profiles(id, username, display_name)').eq('user_id', userId).order('created_at', { ascending: false });
    if (error) throw error;
    return (data || []).map(p => ({ id: p.id, userId: p.user_id, filename: p.filename, caption: p.caption, createdAt: p.created_at, username: p.profiles?.username, displayName: p.profiles?.display_name }));
  },

  delete: async (id) => {
    const { error } = await supabaseAdmin.from('photos').delete().eq('id', id);
    if (error) throw error;
  }
};

// Likes
const likes = {
  create: async ({ id, photoId, userId }) => {
    const payload = { id, photo_id: photoId, user_id: userId };
    const { error } = await supabaseAdmin.from('photo_likes').insert(payload);
    if (error) throw error;
  },

  remove: async (photoId, userId) => {
    const { error } = await supabaseAdmin.from('photo_likes').delete().eq('photo_id', photoId).eq('user_id', userId);
    if (error) throw error;
  },

  findByPhotoAndUser: async (photoId, userId) => {
    const { data } = await supabaseAdmin.from('photo_likes').select('*').eq('photo_id', photoId).eq('user_id', userId).limit(1).maybeSingle();
    return data || null;
  },

  countByPhoto: async (photoId) => {
    const { count } = await supabaseAdmin.from('photo_likes').select('id', { count: 'exact', head: true }).eq('photo_id', photoId);
    return count || 0;
  }
};

// Comments
const comments = {
  create: async (comment) => {
    const payload = { id: comment.id, photo_id: comment.photoId, user_id: comment.userId, text: comment.text };
    const { data, error } = await supabaseAdmin.from('photo_comments').insert(payload).select().single();
    if (error) throw error;
    const p = await supabaseAdmin.from('profiles').select('username, display_name, profile_pic').eq('id', comment.userId).limit(1).maybeSingle();
    return { id: data.id, photoId: data.photo_id, userId: data.user_id, text: data.text, username: p.data?.username, displayName: p.data?.display_name };
  },

  getByPhoto: async (photoId) => {
    const { data, error } = await supabaseAdmin.from('photo_comments').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('photo_id', photoId).order('created_at', { ascending: true });
    if (error) throw error;
    return (data || []).map(c => ({ id: c.id, photoId: c.photo_id, userId: c.user_id, text: c.text, username: c.profiles?.username, displayName: c.profiles?.display_name, profilePic: c.profiles?.profile_pic }));
  },

  findById: async (id) => {
    const { data } = await supabaseAdmin.from('photo_comments').select('*').eq('id', id).limit(1).maybeSingle();
    return data || null;
  },

  delete: async (id) => {
    const { error } = await supabaseAdmin.from('photo_comments').delete().eq('id', id);
    if (error) throw error;
  }
};

// Videos
const videos = {
  create: async (video) => {
    if (!supabaseAdmin) throw new Error('Supabase admin client is not initialized');
    const payload = { id: video.id, user_id: video.userId, filename: video.filename, caption: video.caption || '' };
    const { data, error } = await supabaseAdmin.from('videos').insert(payload).select().single();
    if (error) throw error;
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at };
  },

  findById: async (id) => {
    if (!supabaseAdmin) return null;
    const { data, error } = await supabaseAdmin.from('videos').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('id', id).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const profile = data.profiles || null;
    const { count } = await supabaseAdmin.from('video_likes').select('id', { count: 'exact', head: true }).eq('video_id', id);
    return { id: data.id, userId: data.user_id, filename: data.filename, caption: data.caption, createdAt: data.created_at, username: profile?.username, displayName: profile?.display_name, profilePic: profile?.profile_pic, likes: count || 0 };
  },

  getAll: async () => {
    if (!supabaseAdmin) return [];
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
    const { data, error } = await supabaseAdmin.from('videos').select('*, profiles:profiles(id, username, display_name)').eq('user_id', userId).order('created_at', { ascending: false });
    if (error) throw error;
    return (data || []).map(v => ({ id: v.id, userId: v.user_id, filename: v.filename, caption: v.caption, createdAt: v.created_at, username: v.profiles?.username, displayName: v.profiles?.display_name }));
  },

  delete: async (id) => {
    const { error } = await supabaseAdmin.from('videos').delete().eq('id', id);
    if (error) throw error;
  }
};

// Video likes
const videoLikes = {
  create: async (likeData) => {
    const payload = { id: likeData.id, video_id: likeData.videoId, user_id: likeData.userId };
    const { error } = await supabaseAdmin.from('video_likes').insert(payload);
    if (error) throw error;
  },

  remove: async (videoId, userId) => {
    const { error } = await supabaseAdmin.from('video_likes').delete().eq('video_id', videoId).eq('user_id', userId);
    if (error) throw error;
  },

  findByVideoAndUser: async (videoId, userId) => {
    const { data } = await supabaseAdmin.from('video_likes').select('*').eq('video_id', videoId).eq('user_id', userId).limit(1).maybeSingle();
    return data || null;
  },

  countByVideo: async (videoId) => {
    const { count } = await supabaseAdmin.from('video_likes').select('id', { count: 'exact', head: true }).eq('video_id', videoId);
    return count || 0;
  }
};

// Video comments
const videoComments = {
  create: async (comment) => {
    const payload = { id: comment.id, video_id: comment.videoId, user_id: comment.userId, text: comment.text };
    const { data, error } = await supabaseAdmin.from('video_comments').insert(payload).select().single();
    if (error) throw error;
    const p = await supabaseAdmin.from('profiles').select('username, display_name, profile_pic').eq('id', comment.userId).limit(1).maybeSingle();
    return { id: data.id, videoId: data.video_id, userId: data.user_id, text: data.text, username: p.data?.username, displayName: p.data?.display_name };
  },

  getByVideo: async (videoId) => {
    const { data, error } = await supabaseAdmin.from('video_comments').select('*, profiles:profiles(id, username, display_name, profile_pic)').eq('video_id', videoId).order('created_at', { ascending: true });
    if (error) throw error;
    return (data || []).map(c => ({ id: c.id, videoId: c.video_id, userId: c.user_id, text: c.text, username: c.profiles?.username, displayName: c.profiles?.display_name, profilePic: c.profiles?.profile_pic }));
  },

  findById: async (id) => {
    const { data } = await supabaseAdmin.from('video_comments').select('*').eq('id', id).limit(1).maybeSingle();
    return data || null;
  },

  delete: async (id) => {
    const { error } = await supabaseAdmin.from('video_comments').delete().eq('id', id);
    if (error) throw error;
  }
};

// Password resets & verifications & backup codes
const passwordResets = {
  create: async (token, userId, expiresAt) => {
    const { error } = await supabaseAdmin.from('password_resets').insert({ token, user_id: userId, expires_at: expiresAt });
    if (error) throw error;
  },

  findByToken: async (token) => {
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
    const { error } = await supabaseAdmin.from('password_resets').delete().eq('token', token);
    if (error) throw error;
  },

  deleteByUserId: async (userId) => {
    const { error } = await supabaseAdmin.from('password_resets').delete().eq('user_id', userId);
    if (error) throw error;
  }
};

const verifications = {
  create: async (token, userId, expiresAt) => {
    const { error } = await supabaseAdmin.from('verifications').insert({ token, user_id: userId, expires_at: expiresAt });
    if (error) throw error;
  },

  findByToken: async (token) => {
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
    const { error } = await supabaseAdmin.from('verifications').delete().eq('token', token);
    if (error) throw error;
  },

  deleteByUserId: async (userId) => {
    const { error } = await supabaseAdmin.from('verifications').delete().eq('user_id', userId);
    if (error) throw error;
  }
};

const backupCodes = {
  deleteByUser: async (userId) => {
    const { error } = await supabaseAdmin.from('backup_codes').delete().eq('user_id', userId);
    if (error) throw error;
  },

  insertMany: async (codeHashes) => {
    const { error } = await supabaseAdmin.from('backup_codes').insert(codeHashes);
    if (error) throw error;
    return true;
  },

  getUnusedByUser: async (userId) => {
    const { data, error } = await supabaseAdmin.from('backup_codes').select('*').eq('user_id', userId).eq('used', false).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    return data || [];
  },

  markUsed: async (id) => {
    const { error } = await supabaseAdmin.from('backup_codes').update({ used: true }).eq('id', id);
    if (error) throw error;
  },

  findValidByUserAndCode: async (userId) => {
    const { data, error } = await supabaseAdmin.from('backup_codes').select('*').eq('user_id', userId).eq('used', false).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    return data || [];
  }
};

const magicLinks = {
  create: async (token, userId, expiresAt) => {
    const { error } = await supabaseAdmin.from('magic_links').insert({ token, user_id: userId, expires_at: expiresAt });
    if (error) throw error;
  },

  findByToken: async (token) => {
    const { data, error } = await supabaseAdmin.from('magic_links').select('*').eq('token', token).limit(1).maybeSingle();
    if (error) throw error;
    if (!data) return null;
    return { token: data.token, userId: data.user_id, expiresAt: data.expires_at };
  },

  deleteByToken: async (token) => {
    const { error } = await supabaseAdmin.from('magic_links').delete().eq('token', token);
    if (error) throw error;
  }
};

export default { users, photos, likes, comments, videos, videoLikes, videoComments, passwordResets, verifications, backupCodes, magicLinks };
