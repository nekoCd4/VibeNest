// Client-side Supabase auth helpers for VibeNest (loaded as module)
// This file expects `window.SUPABASE_URL` and `window.SUPABASE_ANON_KEY` to be set by the server view.

(async function(){
  try {
    if (!window.SUPABASE_URL || !window.SUPABASE_ANON_KEY) return;
    const { createClient } = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm');
    const supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY);

    // Helper: send current session (access token + user id) to server bridge
    const sendSessionToServer = async (session) => {
      if (!session || !session.access_token || !session.user) {
        console.warn('[SUPABASE-AUTH] sendSessionToServer: missing session data', { hasSession: !!session, hasToken: !!(session && session.access_token), hasUser: !!(session && session.user) });
        return null;
      }
      try {
        console.log('[SUPABASE-AUTH] Sending session to /auth/supabase/session (user:', session.user.id, ', token length:', session.access_token.length, ')');
        const resp = await fetch('/auth/supabase/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ access_token: session.access_token, userId: session.user.id })
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
      // Some supabase versions expose getSessionFromUrl to retrieve redirect tokens after OAuth
      if (supabase.auth && typeof supabase.auth.getSessionFromUrl === 'function') {
        try {
          console.log('[SUPABASE-AUTH] Calling getSessionFromUrl()...');
          const { data: redirectData, error: redirectErr } = await supabase.auth.getSessionFromUrl();
          console.log('[SUPABASE-AUTH] getSessionFromUrl result:', { hasData: !!redirectData, hasSession: !!(redirectData && redirectData.session), error: redirectErr });
          if (!redirectErr && redirectData && redirectData.session) {
            const session = redirectData.session;
            console.log('[SUPABASE-AUTH] Got OAuth redirect session, exchanging with server...');
            const r = await sendSessionToServer(session);
            console.log('[SUPABASE-AUTH] Server exchange response:', r ? r.status : 'null');
            // Clean the URL to remove fragments or query params used by Supabase
            try { window.history.replaceState({}, document.title, window.location.pathname + window.location.search); } catch (e) {}
            if (r && r.ok) { 
              console.log('[SUPABASE-AUTH] Server session created successfully, redirecting to /');
              window.location = '/'; 
              return; 
            }
          }
        } catch (e) {
          console.warn('[SUPABASE-AUTH] getSessionFromUrl error:', e && e.message);
        }
      }

      // Fallback: check for an existing client session
      console.log('[SUPABASE-AUTH] Checking for existing client session...');
      const { data: initialSessionData } = await supabase.auth.getSession();
      const session = initialSessionData && initialSessionData.session ? initialSessionData.session : null;
      console.log('[SUPABASE-AUTH] Existing session found:', !!session);
      if (session) {
        console.log('[SUPABASE-AUTH] Sending existing session to server...');
        const r = await sendSessionToServer(session);
        console.log('[SUPABASE-AUTH] Server exchange response:', r ? r.status : 'null');
        if (r && r.ok) { 
          console.log('[SUPABASE-AUTH] Server session created successfully, redirecting to /');
          window.location = '/'; 
          return; 
        }
      }
      console.log('[SUPABASE-AUTH] No session found, staying on current page');
    } catch (e) {
      console.error('[SUPABASE-AUTH] Error during page load auth check:', e && e.message, e);
    }
    } catch (e) {
      // ignore
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
          const { data, error } = await supabase.auth.signUp({ email, password }, { data: { username, displayName } });
          if (error) throw error;
          if (data && data.user) {
            // If signUp returned a session, exchange it; otherwise server will handle after email confirm
            if (data.session) {
              await sendSessionToServer(data.session);
              window.location = '/';
            } else {
              window.location = '/check-email?email=' + encodeURIComponent(email);
            }
          } else {
            window.location = '/check-email?email=' + encodeURIComponent(email);
          }
        } catch (err) {
          console.error(err);
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
            const r = await sendSessionToServer(session);
            if (r && r.ok) window.location = '/';
            else {
              const j = await r.json().catch(()=>({}));
              alert(j.error || 'Login succeeded but server session failed');
            }
          } else if (data && data.user) {
            await fetch('/auth/supabase/session', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ userId: data.user.id }) });
            window.location = '/';
          }
        } catch (err) {
          console.error('Supabase login error', err);
          loginForm.removeEventListener && loginForm.removeEventListener('submit', this);
          loginForm.submit();
        }
      });
    }

  } catch (e) {
    console.warn('Supabase auth client not initialized:', e && e.message);
  }
})();
