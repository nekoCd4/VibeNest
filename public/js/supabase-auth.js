// Client-side Supabase auth helpers for VibeNest (loaded as module)
// This file expects `window.SUPABASE_URL` and `window.SUPABASE_ANON_KEY` to be set by the server view.
// If not set, this script silently does nothing.

console.log('[SUPABASE-AUTH] Script loaded');

(async function(){
  try {
    console.log('[SUPABASE-AUTH] IIFE started');
    // Early return if Supabase credentials are not available on this page
    if (!window.SUPABASE_URL || !window.SUPABASE_ANON_KEY) {
      console.debug('[SUPABASE-AUTH] Credentials not available, skipping initialization');
      return;
    }
    
    // Verify credentials are valid strings (not empty)
    if (typeof window.SUPABASE_URL !== 'string' || window.SUPABASE_URL.trim() === '') {
      console.debug('[SUPABASE-AUTH] SUPABASE_URL is not a valid string, skipping initialization');
      return;
    }
    if (typeof window.SUPABASE_ANON_KEY !== 'string' || window.SUPABASE_ANON_KEY.trim() === '') {
      console.debug('[SUPABASE-AUTH] SUPABASE_ANON_KEY is not a valid string, skipping initialization');
      return;
    }
    
    console.log('[SUPABASE-AUTH] Credentials are available, initializing...');
    console.log('[SUPABASE-AUTH] Loading Supabase library from CDN...');
    
    // Set a timeout to prevent hanging indefinitely
    const importPromise = import('https://unpkg.com/@supabase/supabase-js@2.25.0/dist/main.es.js');
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('CDN load timeout')), 10000)
    );
    
    let module;
    try {
      module = await Promise.race([importPromise, timeoutPromise]);
    } catch (loadErr) {
      console.error('[SUPABASE-AUTH] Failed to load Supabase from CDN:', loadErr && loadErr.message);
      // Continue anyway - we might still be able to extract tokens manually
      module = null;
    }
    
    let supabase = null;
    let createClient = null;
    
    if (module) {
      try {
        ({ createClient } = module);
        console.log('[SUPABASE-AUTH] Supabase library loaded, creating client...');
        supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY, {
          auth: {
            storage: window.localStorage,
            autoRefreshToken: true,
            persistSession: true,
            detectSessionInUrl: true
          }
        });
        console.log('[SUPABASE-AUTH] Client created successfully');
      } catch (createErr) {
        console.error('[SUPABASE-AUTH] Failed to create Supabase client:', createErr && createErr.message);
        supabase = null;
      }
    }

    // Handle URL-visible auth tokens (from OAuth callbacks)
    // This extracts tokens from #access_token=..., #id_token=... etc and creates a session
    const handleVisibleUrl = async () => {
      console.log('[SUPABASE-AUTH] 🔗 Handling visible URL for tokens...');
      if (supabase.auth && typeof supabase.auth.getSessionFromUrl === 'function') {
        try {
          const { data, error } = await supabase.auth.getSessionFromUrl();
          console.log('[SUPABASE-AUTH] getSessionFromUrl:', { hasData: !!data, hasSession: !!(data?.session), error });
          if (data?.session) {
            console.log('[SUPABASE-AUTH] ✓ Got session from URL');
            return data.session;
          }
        } catch (e) {
          console.warn('[SUPABASE-AUTH] getSessionFromUrl failed:', e?.message);
        }
      }
      return null;
    };

    // Helper: send current session (access token + user id) to server bridge
    const sendSessionToServer = async (session) => {
      if (!session || !session.access_token) {
        console.warn('[SUPABASE-AUTH] sendSessionToServer: missing session token', { hasSession: !!session, hasToken: !!(session && session.access_token) });
        return null;
      }
      
      // Extract user ID (handle both full user objects and minimal objects)
      let userId = null;
      if (session.user && typeof session.user === 'object') {
        userId = session.user.id;
      }
      
      try {
        const body = { access_token: session.access_token };
        if (userId && userId !== 'pending') {
          body.userId = userId;
        }
        
        console.log('[SUPABASE-AUTH] Sending session to /auth/supabase/session', { hasUserId: !!userId, tokenLength: session.access_token.length });
        const resp = await fetch('/auth/supabase/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(body)
        });
        console.log('[SUPABASE-AUTH] /auth/supabase/session response status:', resp.status);
        if (!resp.ok) {
          const errBody = await resp.json().catch(() => ({}));
          console.error('[SUPABASE-AUTH] Server error:', errBody);
        }
        return resp;
      } catch (err) {
        console.error('[SUPABASE-AUTH] Failed to POST session to server bridge:', err && err.message);
        return null;
      }
    };

    // On page load: handle redirect sign-in flow first (parse tokens from URL), then fallback to existing session
    try {
      console.log('[SUPABASE-AUTH] Page load: checking for OAuth redirect or existing session...');
      console.log('[SUPABASE-AUTH] Current URL:', window.location.href);
      console.log('[SUPABASE-AUTH] URL hash:', window.location.hash);
      
      // Check for OAuth error in URL
      const urlParams = new URLSearchParams(window.location.search);
      const oauthError = urlParams.get('error') || urlParams.get('error_description');
      if (oauthError) {
        console.error('[SUPABASE-AUTH] ❌ OAuth error in URL:', oauthError);
        console.warn('[SUPABASE-AUTH] Redirecting to /login with error...');
        setTimeout(() => {
          window.location = '/login?error=' + encodeURIComponent(oauthError);
        }, 500);
        return;
      }
      
      // Fallback: manually extract tokens from URL hash first (fastest path)
      console.log('[SUPABASE-AUTH] Checking for tokens in URL hash...');
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      const access_token = hashParams.get('access_token');
      const refresh_token = hashParams.get('refresh_token');
      const token_type = hashParams.get('token_type') || 'Bearer';
      
      console.log('[SUPABASE-AUTH] Token extraction result:', { 
        hasAccessToken: !!access_token, 
        hasRefreshToken: !!refresh_token,
        accessTokenLength: access_token ? access_token.length : 0
      });
      
      if (access_token) {
        console.log('[SUPABASE-AUTH] 🔑 Found access_token in URL hash, creating session manually...');
        try {
          // Create a minimal session object to send to the server
          const session = {
            access_token: access_token,
            refresh_token: refresh_token,
            user: {
              id: 'pending' // Will be fetched from token by server
            },
            token_type: token_type
          };
          
          console.log('[SUPABASE-AUTH] Calling sendSessionToServer...');
          const r = await sendSessionToServer(session);
          console.log('[SUPABASE-AUTH] Server exchange response:', r ? r.status : 'null');
          
          // Clean the URL to remove fragments
          try { window.history.replaceState({}, document.title, window.location.pathname); } catch (e) {}
          
          if (r && r.ok) {
            console.log('[SUPABASE-AUTH] ✓ Server session created successfully, redirecting to /');
            // Give a small delay to ensure logs are sent before redirect
            setTimeout(() => {
              window.location = '/';
            }, 100);
            return;
          } else if (r) {
            const errText = await r.text();
            console.error('[SUPABASE-AUTH] ❌ Failed to exchange session with server:', errText);
            setTimeout(() => {
              window.location = '/login?error=' + encodeURIComponent('Server session failed: ' + errText);
            }, 500);
            return;
          } else {
            console.error('[SUPABASE-AUTH] ❌ No response from server');
            setTimeout(() => {
              window.location = '/login?error=' + encodeURIComponent('No response from server');
            }, 500);
            return;
          }
        } catch (e) {
          console.error('[SUPABASE-AUTH] ❌ Manual session extraction failed:', e && e.message, e);
          setTimeout(() => {
            window.location = '/login?error=' + encodeURIComponent('Error: ' + (e && e.message || 'unknown'));
          }, 500);
          return;
        }
      }
      
      // If no tokens found in hash, try getSessionFromUrl (in case Supabase library handles it)
      // Some supabase versions expose getSessionFromUrl to retrieve redirect tokens after OAuth
      if (supabase.auth && typeof supabase.auth.getSessionFromUrl === 'function') {
        try {
          console.log('[SUPABASE-AUTH] 🔑 Calling getSessionFromUrl()...');
          const { data: redirectData, error: redirectErr } = await supabase.auth.getSessionFromUrl();
          console.log('[SUPABASE-AUTH] getSessionFromUrl result:', { hasData: !!redirectData, hasSession: !!(redirectData && redirectData.session), error: redirectErr });
          if (!redirectErr && redirectData && redirectData.session) {
            const session = redirectData.session;
            console.log('[SUPABASE-AUTH] ✓ Got OAuth redirect session, exchanging with server...');
            console.log('[SUPABASE-AUTH] Session user ID:', session.user?.id?.substring(0, 8));
            console.log('[SUPABASE-AUTH] Session has access_token:', !!session.access_token);
            const r = await sendSessionToServer(session);
            console.log('[SUPABASE-AUTH] Server exchange response:', r ? r.status : 'null');
            // Clean the URL to remove fragments or query params used by Supabase
            try { window.history.replaceState({}, document.title, window.location.pathname + window.location.search); } catch (e) {}
            if (r && r.ok) { 
              console.log('[SUPABASE-AUTH] ✓ Server session created successfully, redirecting to /');
              window.location = '/'; 
              return; 
            } else {
              const errText = await r.text();
              console.error('[SUPABASE-AUTH] ❌ Failed to exchange session with server:', errText);
              // Redirect to login with error message
              setTimeout(() => {
                window.location = '/login?error=' + encodeURIComponent('Server session failed: ' + errText);
              }, 500);
              return;
            }
          } else if (redirectErr) {
            console.warn('[SUPABASE-AUTH] ⚠️  getSessionFromUrl error:', redirectErr?.message);
            // Could be a network error or invalid tokens, try fallback
          }
        } catch (e) {
          console.warn('[SUPABASE-AUTH] ⚠️  getSessionFromUrl exception:', e && e.message);
        }
      } else {
        console.warn('[SUPABASE-AUTH] ⚠️  getSessionFromUrl not available');
      }

      // Fallback: check for an existing client session
      console.log('[SUPABASE-AUTH] Checking for existing client session...');
      let existingSession = null;
      if (supabase && supabase.auth) {
        try {
          const { data: initialSessionData } = await supabase.auth.getSession();
          existingSession = initialSessionData && initialSessionData.session ? initialSessionData.session : null;
        } catch (e) {
          console.warn('[SUPABASE-AUTH] Failed to get existing session:', e && e.message);
        }
      }
      console.log('[SUPABASE-AUTH] Existing session found:', !!existingSession);
      if (existingSession) {
        console.log('[SUPABASE-AUTH] 📤 Sending existing session to server...');
        console.log('[SUPABASE-AUTH] Session user ID:', existingSession.user?.id?.substring(0, 8));
        const r = await sendSessionToServer(existingSession);
        console.log('[SUPABASE-AUTH] Server exchange response:', r ? r.status : 'null');
        if (r && r.ok) { 
          console.log('[SUPABASE-AUTH] ✓ Server session created successfully, redirecting to /');
          window.location = '/'; 
          return; 
        } else {
          console.error('[SUPABASE-AUTH] ❌ Failed to exchange existing session with server');
        }
      }
      console.log('[SUPABASE-AUTH] ℹ️  No Supabase session found on page load - server-side auth will handle redirect if needed');
    } catch (e) {
      console.error('[SUPABASE-AUTH] Error during page load auth check:', e && e.message, e);
    }

    // Listen for auth state changes (useful for popup or client sign-in flows)
    if (supabase.auth && typeof supabase.auth.onAuthStateChange === 'function') {
      supabase.auth.onAuthStateChange(async (event, sessionData) => {
        try {
          const session = sessionData && sessionData.session ? sessionData.session : null;
          if (event === 'SIGNED_IN' && session) {
            const r = await sendSessionToServer(session);
            if (r && r.ok) window.location = '/';
          }
        } catch (err) {
          console.warn('onAuthStateChange handler error:', err && err.message);
        }
      });
    }

    // Handle OAuth links - they will navigate to /auth/google or /auth/entra
    // No need to intercept since we're using standard href links now
    console.log('[SUPABASE-AUTH] OAuth links are using standard href navigation');

    // Register form helper
    const registerForm = document.querySelector('.register-form');
    if (registerForm) {
      registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(registerForm);
        const email = fd.get('email');
        const password = fd.get('password');
        const username = fd.get('username');
        const displayName = fd.get('displayName') || username;

        // create account via Supabase client (this will trigger email confirmation if configured)
        try {
          console.log('[SUPABASE-AUTH] Starting signup...');
          const { data, error } = await supabase.auth.signUp({ email, password }, { data: { username, displayName } });
          if (error) throw error;
          if (data && data.user) {
            console.log('[SUPABASE-AUTH] Signup successful, creating profile...');
            
            // Create profile entry in our database
            try {
              const profileResp = await fetch('/api/register-profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  userId: data.user.id,
                  username: username,
                  displayName: displayName,
                  email: email
                })
              });
              if (profileResp.ok) {
                console.log('[SUPABASE-AUTH] Profile created successfully');
              } else {
                const err = await profileResp.json();
                console.warn('[SUPABASE-AUTH] Profile creation warning:', err);
              }
            } catch (e) {
              console.warn('[SUPABASE-AUTH] Could not create profile:', e?.message);
            }
            
            // If signUp returned a session, exchange it; otherwise server will handle after email confirm
            if (data.session) {
              console.log('[SUPABASE-AUTH] Session available, exchanging with server...');
              const r = await sendSessionToServer(data.session);
              if (r && r.ok) {
                console.log('[SUPABASE-AUTH] Server accepted session, redirecting...');
                window.location = '/';
              } else {
                console.warn('[SUPABASE-AUTH] Server rejected session');
              }
            } else {
              console.log('[SUPABASE-AUTH] No session, redirecting to email check...');
              window.location = '/check-email?email=' + encodeURIComponent(email);
            }
          } else {
            window.location = '/check-email?email=' + encodeURIComponent(email);
          }
        } catch (err) {
          console.error('[SUPABASE-AUTH] Signup error:', err);

          alert(err.message || 'Registration failed');
        }
      });
    }

    // Login form helper
    const loginForm = document.querySelector('.login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fd = new FormData(loginForm);
        const usernameOrEmail = fd.get('username');
        const password = fd.get('password');

        try {
          let email = usernameOrEmail;
          if (!email.includes('@')) {
            const resp = await fetch(`/api/resolve-username?username=${encodeURIComponent(usernameOrEmail)}`);
            if (resp.ok) {
              const d = await resp.json();
              if (d && d.email) email = d.email;
            }
          }

          const { data, error } = await supabase.auth.signInWithPassword({ email, password });
          if (error) throw error;
          const session = data && data.session ? data.session : null;
          if (session) {
            console.log('[SUPABASE-AUTH] Login successful, sending session to server...');
            const r = await sendSessionToServer(session);
            if (r && r.ok) {
              console.log('[SUPABASE-AUTH] Server session created, redirecting to home...');
              // Add a small delay to ensure cookies are set before navigation
              setTimeout(() => { window.location = '/'; }, 100);
            } else {
              const j = await r.json().catch(()=>({}));
              console.error('[SUPABASE-AUTH] Server session failed:', j);
              alert(j.error || 'Login succeeded but server session failed');
            }
          } else if (data && data.user) {
            console.log('[SUPABASE-AUTH] Login successful but no session, sending userId to server...');
            await fetch('/auth/supabase/session', { method: 'POST', headers: { 'Content-Type':'application/json' }, credentials: 'include', body: JSON.stringify({ userId: data.user.id }) });
            setTimeout(() => { window.location = '/'; }, 100);
          }
        } catch (err) {
          console.error('Supabase login error', err);
          console.error('Error message:', err && err.message);
          // Show error to user
          alert('Login failed: ' + (err && err.message || 'Unknown error'));
        }
      });
    }

  } catch (e) {
    // Log detailed error info for debugging
    const errorDetails = {
      message: e && e.message,
      name: e && e.name,
      // Only include stack in development
      stack: process.env.NODE_ENV === 'development' ? (e && e.stack) : undefined
    };
    
    // Check if this is a known Supabase library initialization issue
    // that doesn't actually prevent the app from working
    if (e && e.message && e.message.includes('AuthClient')) {
      console.info('[SUPABASE-AUTH] Library initialization warning (non-critical):', errorDetails.message);
    } else {
      console.warn('[SUPABASE-AUTH] Failed to initialize Supabase:', errorDetails);
    }
  }
})();
