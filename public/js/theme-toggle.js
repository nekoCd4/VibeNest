// Theme helper: applies theme from localStorage and exposes a setter for settings UI
(function(){
  const key = 'vibenest-theme';
  const defaultTheme = 'dark'; // default to dark as requested

  const prefersDark = () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

  const resolveTheme = (stored) => {
    if (!stored) return defaultTheme;
    if (stored === 'system') return prefersDark() ? 'dark' : 'light';
    return stored;
  };

  const apply = (theme, persist = false) => {
    if (!theme) theme = defaultTheme;
    document.documentElement.setAttribute('data-theme', theme);
    if (persist) {
      try { localStorage.setItem(key, theme); } catch (e) {}
    }
  };

  // Initialize on load
  const currentStored = (() => { try { return localStorage.getItem(key); } catch (e) { return null; } })();
  const current = resolveTheme(currentStored);
  apply(current, false);

  // Handle system changes when stored preference is 'system'
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener && mq.addEventListener('change', (e) => {
      try {
        const stored = localStorage.getItem(key);
        if (stored === 'system') {
          apply(e.matches ? 'dark' : 'light', false);
        }
      } catch (err) {}
    });
  }

  // Expose API for settings page
  window.vibeTheme = {
    get: () => {
      try { return localStorage.getItem(key) || defaultTheme; } catch (e) { return defaultTheme; }
    },
    // set accepts: 'light', 'dark', or 'system'
    set: (val) => {
      try { localStorage.setItem(key, val); } catch (e) {}
      const themeToApply = resolveTheme(val);
      apply(themeToApply, false);
    }
  };
})();
