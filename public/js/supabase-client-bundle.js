// Supabase client bundle for browser - wraps the npm package in a way that works with dynamic import
// This solves CORS and 404 issues by using the already-installed @supabase/supabase-js package

let cachedClient = null;

export async function createSupabaseClient(supabaseUrl, anonKey) {
  if (cachedClient) {
    return cachedClient;
  }

  try {
    // Try to use a dynamically generated ES module that imports from node_modules
    // We'll fetch a special endpoint that serves the Supabase client
    const module = await import('/supabase-client-es.mjs');
    const { createClient } = module;
    
    cachedClient = createClient(supabaseUrl, anonKey);
    return cachedClient;
  } catch (err) {
    console.error('[SUPABASE] Failed to load client:', err);
    throw err;
  }
}

export { cachedClient };
