// Client-side Supabase auth helpers for VibeNest (loaded as module)
// This file expects `window.SUPABASE_URL` and `window.SUPABASE_ANON_KEY` to be set by the server view.

(async function(){
  try {
    if (!window.SUPABASE_URL || !window.SUPABASE_ANON_KEY) return;
    const { createClient } = await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm');
    const supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY);

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
          // if signUp returns user, we still need to create a server-side session - call bridge
          // Some projects require email confirm; we still call server to bootstrap session if allowed
          if (data && data.user) {
            // create server-side session by exchanging access token
            await fetch('/auth/supabase/session', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ access_token: data.access_token || null, userId: data.user.id }) });
            // Redirect to settings or home
            window.location = '/';
          } else {
            // Signup may require email confirmation — show message and proceed to check-email
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

        // Attempt Supabase sign-in using email; if user submitted username we attempt by username lookup on server.
        try {
          // If the username contains @ assume email
          let email = usernameOrEmail;
          if (!email.includes('@')) {
            // attempt fetch server endpoint to resolve username -> email
            const resp = await fetch(`/api/resolve-username?username=${encodeURIComponent(usernameOrEmail)}`);
            if (resp.ok) {
              const d = await resp.json();
              if (d && d.email) email = d.email;
            }
          }

          const { data, error } = await supabase.auth.signInWithPassword({ email, password });
          if (error) throw error;
          if (data && data.session) {
            // send token to the server to create a session
            const token = data.session.access_token;
            const r = await fetch('/auth/supabase/session', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ access_token: token }) });
            if (r.ok) window.location = '/';
            else {
              const j = await r.json().catch(()=>({}));
              alert(j.error || 'Login succeeded but server session failed');
            }
          } else if (data && data.user) {
            // Some older flows return user object — still try to set session
            await fetch('/auth/supabase/session', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ userId: data.user.id }) });
            window.location = '/';
          }
        } catch (err) {
          console.error('Supabase login error', err);
          // fall back to standard form submit for local auth
          loginForm.removeEventListener('submit', this);
          loginForm.submit();
        }
      });
    }

  } catch (e) {
    console.warn('Supabase auth client not initialized:', e && e.message);
  }
})();
