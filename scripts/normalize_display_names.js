#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import supabaseAdmin from '../lib/supabaseServer.js';

(async function main(){
  try {
    const args = process.argv.slice(2);
    const apply = args.includes('--apply');
    const backupArg = args.find(a => a.startsWith('--backup='));
    const backupFile = backupArg ? backupArg.split('=')[1] : path.resolve(process.cwd(), 'scripts/normalize_display_names.backup.json');

    console.log('[MIGRATE] normalize_display_names starting');

    if (!supabaseAdmin) {
      console.error('[MIGRATE] Supabase admin client not initialized. Ensure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are set.');
      process.exit(2);
    }

    console.log('[MIGRATE] Dry-run mode (no changes) by default. Use --apply to perform updates.');
    if (apply) console.log('[MIGRATE] --apply provided: changes will be applied.');

    // Find profiles whose display_name starts with one or more '@' characters
    const { data: rows, error } = await supabaseAdmin.from('profiles').select('id, username, display_name').ilike('display_name', '@%');
    if (error) throw error;

    if (!rows || !rows.length) {
      console.log('[MIGRATE] No profiles found with leading @ in display_name. Nothing to do.');
      process.exit(0);
    }

    // Backup original rows to a file so changes can be inspected or rolled back
    const backup = { timestamp: (new Date()).toISOString(), count: rows.length, rows };
    fs.writeFileSync(backupFile, JSON.stringify(backup, null, 2), 'utf8');
    console.log('[MIGRATE] Backup written to', backupFile);

    // Prepare and optionally apply updates
    const results = [];
    for (const r of rows) {
      const oldName = r.display_name || '';
      let candidate = oldName.replace(/^@+/, '');
      if (!candidate) {
        candidate = r.username || ('user-' + r.id.slice(0,6));
      }

      // Check for conflicts (case-insensitive)
      const { data: conflict } = await supabaseAdmin.from('profiles').select('id').ilike('display_name', candidate).neq('id', r.id).limit(1).maybeSingle();
      let finalName = candidate;
      let note = null;
      if (conflict && conflict.id) {
        // Make unique by appending short id
        finalName = `${candidate}-${r.id.slice(0,6)}`;
        note = 'conflict-resolved';
      }

      if (apply) {
        const { error: upErr } = await supabaseAdmin.from('profiles').update({ display_name: finalName }).eq('id', r.id);
        if (upErr) {
          results.push({ id: r.id, username: r.username, oldName, finalName, ok: false, error: upErr.message });
          console.error('[MIGRATE] Failed to update', r.id, upErr.message);
          continue;
        }
        results.push({ id: r.id, username: r.username, oldName, finalName, ok: true, note });
        console.log('[MIGRATE] Updated', r.id, '->', finalName, note ? `(${note})` : '');
      } else {
        results.push({ id: r.id, username: r.username, oldName, finalName, ok: null, note });
        console.log('[MIGRATE] DRY-RUN: would update', r.id, '->', finalName, note ? `(${note})` : '');
      }
    }

    // Write results file
    const resultFile = path.resolve(process.cwd(), `scripts/normalize_display_names.results.${(new Date()).toISOString().replace(/[:.]/g,'-')}.json`);
    fs.writeFileSync(resultFile, JSON.stringify({ timestamp: (new Date()).toISOString(), apply, results }, null, 2), 'utf8');
    console.log('[MIGRATE] Results written to', resultFile);

    console.log('[MIGRATE] Done');
    process.exit(0);
  } catch (err) {
    console.error('[MIGRATE] Error:', err && err.message);
    process.exit(1);
  }
})();
