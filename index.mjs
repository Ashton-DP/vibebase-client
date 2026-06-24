// vibebase-client — the client for a Vibebase backend.
// Reads DATABASE_URL + AUTH_SECRET from the environment (Vibebase writes them to .env.local).
import { neon } from '@neondatabase/serverless';

export const sql = neon(process.env.DATABASE_URL);

// ---------------------------------------------------------------------------
// Auth (email + password)
//  - passwords hashed with PBKDF2 (Web Crypto), 100k iterations, per-user salt
//  - queries parameterized via tagged templates (SQL-injection safe)
//  - sessions are HMAC-signed, expiring tokens
// Vibebase generated an AUTH_SECRET in .env.local — keep it secret.
// ---------------------------------------------------------------------------
const SECRET = process.env.AUTH_SECRET || 'dev-insecure-change-me';
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const te = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => new Uint8Array(h.match(/.{2}/g).map((x) => parseInt(x, 16)));

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
const isUuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

let _schema;
function ensureSchema() {
  _schema ||= (async () => {
    await sql`
      create table if not exists users (
        id uuid primary key default gen_random_uuid(),
        email text unique not null,
        password_hash text not null default '',
        provider text,
        provider_id text,
        created_at timestamptz not null default now()
      )`;
    // Migrate tables created before social login existed.
    await sql`alter table users add column if not exists provider text`;
    await sql`alter table users add column if not exists provider_id text`;
    await sql`alter table users add column if not exists email_verified boolean not null default false`;
    await sql`alter table users alter column password_hash set default ''`;
    await sql`create table if not exists _auth_attempts (email text primary key, fails int not null default 0, locked_until timestamptz)`;
    await sql`create table if not exists sessions (
      id uuid primary key default gen_random_uuid(),
      user_id uuid references users(id) on delete cascade,
      created_at timestamptz not null default now(),
      expires_at timestamptz not null,
      revoked boolean not null default false
    )`;
  })();
  return _schema;
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return toHex(salt) + ':' + toHex(bits);
}

async function hmac(value) {
  const key = await crypto.subtle.importKey('raw', te.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, te.encode(value)));
}

// Tokens are server-tracked sessions (revocable). The token is the signed session id.
async function signToken(userId) {
  const rows = await sql`insert into sessions (user_id, expires_at) values (${userId}, now() + interval '7 days') returning id`;
  const sid = rows[0].id;
  return btoa(sid) + '.' + (await hmac(sid));
}

async function readToken(token) {
  const [b64, mac] = (token || '').split('.');
  if (!b64 || !mac) return null;
  let sid;
  try { sid = atob(b64); } catch { return null; }
  if (!safeEqual(await hmac(sid), mac) || !isUuid(sid)) return null;
  const rows = await sql`select user_id from sessions where id = ${sid} and not revoked and expires_at > now()`;
  return rows[0]?.user_id || null;
}

// Revoke a single session (log out this device).
export async function signOut(token) {
  const [b64, mac] = (token || '').split('.');
  if (!b64 || !mac) return;
  let sid;
  try { sid = atob(b64); } catch { return; }
  if (!safeEqual(await hmac(sid), mac) || !isUuid(sid)) return;
  await sql`update sessions set revoked = true where id = ${sid}`;
}

// Revoke every session for a user (log out everywhere).
export async function signOutAll(userId) {
  await sql`update sessions set revoked = true where user_id = ${userId}`;
}

export async function signUp(email, password) {
  await ensureSchema();
  const ph = await hashPassword(password);
  const rows = await sql`insert into users (email, password_hash) values (${email}, ${ph}) returning id, email`;
  return { user: rows[0], token: await signToken(rows[0].id) };
}

const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000; // 5 failures -> 15 min lock
export async function signIn(email, password) {
  await ensureSchema();
  const att = (await sql`select fails, locked_until from _auth_attempts where email = ${email}`)[0];
  if (att?.locked_until && new Date(att.locked_until).getTime() > Date.now()) {
    throw new Error('Too many failed attempts — try again later');
  }
  const u = (await sql`select id, email, password_hash from users where email = ${email}`)[0];
  const good = u && u.password_hash && safeEqual(await hashPassword(password, u.password_hash.split(':')[0]), u.password_hash);
  if (!good) {
    const fails = (att?.fails || 0) + 1;
    const locked = fails >= MAX_FAILS ? new Date(Date.now() + LOCK_MS).toISOString() : null;
    await sql`insert into _auth_attempts (email, fails, locked_until) values (${email}, ${fails}, ${locked})
      on conflict (email) do update set fails = ${fails}, locked_until = ${locked}`;
    throw new Error('Invalid email or password');
  }
  if (att) await sql`delete from _auth_attempts where email = ${email}`;
  return { user: { id: u.id, email: u.email }, token: await signToken(u.id) };
}

export async function getUser(token) {
  const id = await readToken(token);
  if (!id) return null;
  const rows = await sql`select id, email from users where id = ${id}`;
  return rows[0] || null;
}

// --- Password reset (stateless, signed, expiring tokens) ---
const RESET_TTL_MS = 60 * 60 * 1000; // 1 hour
async function signReset(email) {
  const payload = 'reset|' + email + '|' + (Date.now() + RESET_TTL_MS);
  return btoa(payload) + '.' + (await hmac(payload));
}
async function readReset(token) {
  const [b64, mac] = (token || '').split('.');
  if (!b64 || !mac) return null;
  let payload;
  try { payload = atob(b64); } catch { return null; }
  if (!safeEqual(await hmac(payload), mac)) return null;
  const [kind, email, exp] = payload.split('|');
  if (kind !== 'reset' || !email || Date.now() > Number(exp)) return null;
  return email;
}

// Step 1: issue a reset token to email to the user. Returns null if no such user
// (don't reveal whether an email is registered). You send the token/link by email.
export async function requestPasswordReset(email) {
  await ensureSchema();
  const rows = await sql`select id from users where email = ${email}`;
  if (!rows[0]) return null;
  return signReset(email);
}

// Step 2: consume the token from your reset page and set the new password.
export async function resetPassword(token, newPassword) {
  const email = await readReset(token);
  if (!email) throw new Error('Invalid or expired reset token');
  await ensureSchema();
  const ph = await hashPassword(newPassword);
  const rows = await sql`update users set password_hash = ${ph} where email = ${email} returning id, email`;
  if (!rows[0]) throw new Error('User not found');
  return { user: rows[0] };
}

// --- Email verification (same signed-token pattern) ---
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
async function signVerify(email) {
  const payload = 'verify|' + email + '|' + (Date.now() + VERIFY_TTL_MS);
  return btoa(payload) + '.' + (await hmac(payload));
}
async function readVerify(token) {
  const [b64, mac] = (token || '').split('.');
  if (!b64 || !mac) return null;
  let payload;
  try { payload = atob(b64); } catch { return null; }
  if (!safeEqual(await hmac(payload), mac)) return null;
  const [kind, email, exp] = payload.split('|');
  if (kind !== 'verify' || !email || Date.now() > Number(exp)) return null;
  return email;
}
// Issue a verification token to email to the user (null if no such user).
export async function requestEmailVerification(email) {
  await ensureSchema();
  const rows = await sql`select id from users where email = ${email}`;
  if (!rows[0]) return null;
  return signVerify(email);
}
// Consume the token from your verify page; marks the account verified.
export async function verifyEmail(token) {
  const email = await readVerify(token);
  if (!email) throw new Error('Invalid or expired verification token');
  await ensureSchema();
  const rows = await sql`update users set email_verified = true where email = ${email} returning id, email, email_verified`;
  if (!rows[0]) throw new Error('User not found');
  return { user: rows[0] };
}

// ---------------------------------------------------------------------------
// Vector search (pgvector) — store embeddings + nearest-neighbour search for RAG.
// You bring the embedding vectors (from your embedding model, e.g. OpenAI
// text-embedding-3-small = 1536 dims); Vibebase stores them and runs cosine
// similarity search. The `documents` table is created on first use, sized to
// your model's dimension.
// ---------------------------------------------------------------------------
let _vec;
function ensureVectorSchema(dim) {
  if (_vec) return _vec;
  const d = Math.max(1, Math.min(4096, parseInt(dim, 10) || 1536));
  _vec = (async () => {
    await sql`create extension if not exists vector`;
    await sql.query(
      `create table if not exists documents (
        id uuid primary key default gen_random_uuid(),
        content text,
        embedding vector(${d}),
        metadata jsonb,
        created_at timestamptz not null default now()
      )`
    );
  })();
  return _vec;
}

const toVector = (e) => '[' + Array.from(e).join(',') + ']';

// Store a document + its embedding. Returns the new row id.
export async function addDocument(content, embedding, metadata = {}) {
  await ensureVectorSchema(Array.from(embedding).length);
  const v = toVector(embedding);
  const rows = await sql`insert into documents (content, embedding, metadata)
    values (${content}, ${v}::vector, ${JSON.stringify(metadata)}::jsonb) returning id`;
  return rows[0].id;
}

// Nearest-neighbour search by cosine similarity. Returns [{id, content, metadata, similarity}].
export async function searchSimilar(embedding, k = 5) {
  await ensureVectorSchema(Array.from(embedding).length);
  const v = toVector(embedding);
  return sql`select id, content, metadata, 1 - (embedding <=> ${v}::vector) as similarity
    from documents order by embedding <=> ${v}::vector limit ${k}`;
}

// ---------------------------------------------------------------------------
// File storage — store files/images by key. Backed by Postgres (bytea); good
// for avatars, uploads, and documents up to 5 MB. (Larger files: ask Vibebase
// about object storage.) Keys are paths like 'avatars/user-123.png'.
// ---------------------------------------------------------------------------
let _store;
function ensureStorageSchema() {
  _store ||= sql`
    create table if not exists files (
      key text primary key,
      content_type text,
      size integer,
      data bytea not null,
      created_at timestamptz not null default now()
    )`;
  return _store;
}
const MAX_FILE = 5 * 1024 * 1024;

// Store bytes under a key (overwrites). `bytes`: Uint8Array | Buffer | base64 string.
export async function putFile(key, bytes, contentType = 'application/octet-stream') {
  await ensureStorageSchema();
  const buf = typeof bytes === 'string' ? Buffer.from(bytes, 'base64') : Buffer.from(bytes);
  if (buf.length > MAX_FILE) throw new Error('File exceeds 5MB limit');
  const b64 = buf.toString('base64');
  await sql`insert into files (key, content_type, size, data)
    values (${key}, ${contentType}, ${buf.length}, decode(${b64}, 'base64'))
    on conflict (key) do update set content_type = excluded.content_type,
      size = excluded.size, data = excluded.data, created_at = now()`;
  return { key, size: buf.length, contentType };
}

// Retrieve a file. Returns { key, contentType, size, bytes: Buffer } or null.
export async function getFile(key) {
  await ensureStorageSchema();
  const rows = await sql`select key, content_type, size, encode(data, 'base64') as b64 from files where key = ${key}`;
  const r = rows[0];
  if (!r) return null;
  return { key: r.key, contentType: r.content_type, size: r.size, bytes: Buffer.from(r.b64, 'base64') };
}

export async function deleteFile(key) {
  await ensureStorageSchema();
  await sql`delete from files where key = ${key}`;
}

// List file metadata (no data) under an optional key prefix.
export async function listFiles(prefix = '') {
  await ensureStorageSchema();
  return sql`select key, content_type, size, created_at from files where key like ${prefix + '%'} order by created_at desc`;
}

// ---------------------------------------------------------------------------
// Social login (Google / GitHub OAuth).
// Create an OAuth app with the provider, then supply its client id/secret +
// redirect URI — via the conf arg, or GOOGLE_/GITHUB_CLIENT_ID, *_CLIENT_SECRET,
// *_REDIRECT_URI env vars. Flow: (1) redirect the user to oauthRedirectUrl(...);
// (2) in your callback route, pass the ?code to oauthCallback(...) to get
// { user, token } — same session token as email/password auth.
// ---------------------------------------------------------------------------
const OAUTH = {
  google: { authorize: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', scope: 'openid email profile' },
  github: { authorize: 'https://github.com/login/oauth/authorize', token: 'https://github.com/login/oauth/access_token', scope: 'read:user user:email' },
};
function oauthConf(provider, conf = {}) {
  if (!OAUTH[provider]) throw new Error(`Unknown OAuth provider: ${provider}`);
  const P = provider.toUpperCase();
  return {
    ...OAUTH[provider],
    clientId: conf.clientId || process.env[`${P}_CLIENT_ID`],
    clientSecret: conf.clientSecret || process.env[`${P}_CLIENT_SECRET`],
    redirectUri: conf.redirectUri || process.env[`${P}_REDIRECT_URI`],
  };
}

// Step 1: the URL to send the user to.
export function oauthRedirectUrl(provider, conf = {}) {
  const c = oauthConf(provider, conf);
  if (!c.clientId || !c.redirectUri) throw new Error(`Missing ${provider} clientId/redirectUri`);
  const p = new URLSearchParams({ client_id: c.clientId, redirect_uri: c.redirectUri, response_type: 'code', scope: conf.scope || c.scope });
  if (conf.state) p.set('state', conf.state);
  return `${c.authorize}?${p.toString()}`;
}

// Step 2: exchange the callback ?code for a session. Returns { user, token }.
export async function oauthCallback(provider, code, conf = {}) {
  const c = oauthConf(provider, conf);
  if (!c.clientId || !c.clientSecret || !c.redirectUri) throw new Error(`Missing ${provider} OAuth config`);
  const tokRes = await fetch(c.token, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ client_id: c.clientId, client_secret: c.clientSecret, code, redirect_uri: c.redirectUri, grant_type: 'authorization_code' }),
  });
  const tok = await tokRes.json();
  if (!tok.access_token) throw new Error('OAuth token exchange failed');
  const profile = await fetchOAuthProfile(provider, tok.access_token);
  if (!profile.email) throw new Error('Could not get an email from the provider');
  const user = await upsertOAuthUser(provider, profile);
  return { user, token: await signToken(user.id) };
}

async function fetchOAuthProfile(provider, accessToken) {
  const headers = { authorization: `Bearer ${accessToken}`, accept: 'application/json', 'user-agent': 'vibebase' };
  if (provider === 'google') {
    const r = await (await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers })).json();
    return { providerId: String(r.id), email: r.email, name: r.name };
  }
  const u = await (await fetch('https://api.github.com/user', { headers })).json();
  let email = u.email;
  if (!email) {
    const list = await (await fetch('https://api.github.com/user/emails', { headers })).json();
    email = (Array.isArray(list) ? (list.find((e) => e.primary && e.verified) || list[0]) : null)?.email;
  }
  return { providerId: String(u.id), email, name: u.name || u.login };
}

async function upsertOAuthUser(provider, profile) {
  await ensureSchema();
  const rows = await sql`
    insert into users (email, provider, provider_id) values (${profile.email}, ${provider}, ${profile.providerId})
    on conflict (email) do update set provider = excluded.provider, provider_id = excluded.provider_id
    returning id, email`;
  return rows[0];
}

// ---------------------------------------------------------------------------
// Change feed (lightweight realtime). Polls a table for rows newer than a
// cursor — drive live UIs, notifications, or background reactions without
// websockets. The table needs a monotonic column (default `created_at`).
// ---------------------------------------------------------------------------
const ident = (s) => { if (!/^[a-z_][a-z0-9_]*$/i.test(s)) throw new Error(`Invalid identifier: ${s}`); return s; };

// Fetch rows where `column` > `since` (or the first page if no cursor), oldest first.
export async function changesSince(table, { column = 'created_at', since = null, limit = 100 } = {}) {
  const t = ident(table), c = ident(column);
  const res = since == null
    ? await sql.query(`select * from ${t} order by ${c} asc limit $1`, [limit])
    : await sql.query(`select * from ${t} where ${c} > $1 order by ${c} asc limit $2`, [since, limit]);
  return res.rows || res;
}

// Poll `table` and call handler(newRows) as rows appear. Returns a stop() function.
export function onChange(table, handler, { column = 'created_at', since = null, intervalMs = 2000 } = {}) {
  let cursor = since, stopped = false;
  (async () => {
    while (!stopped) {
      try {
        const rows = await changesSince(table, { column, since: cursor });
        if (rows.length) { cursor = rows[rows.length - 1][column]; await handler(rows); }
      } catch { /* transient — retry next tick */ }
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  })();
  return () => { stopped = true; };
}

// ---------------------------------------------------------------------------
// Migrations — versioned, ordered, run-once. Put files in a `migrations/`
// folder: `001_init.sql`, `002_add_x.js`, etc. `.js`/`.mjs` files export
// `export async function up(sql) { ... }`. migrate() applies any not-yet-run
// migrations in filename order and records them in `_vibebase_migrations`.
// (.sql files are split on `;` at line-ends — for functions/triggers with
// inner `;`, use a .js migration instead.)
// ---------------------------------------------------------------------------
export async function migrate(dir = 'migrations') {
  const { readdirSync, readFileSync } = await import('node:fs');
  const path = await import('node:path');
  const { pathToFileURL } = await import('node:url');
  await sql`create table if not exists _vibebase_migrations (name text primary key, applied_at timestamptz not null default now())`;
  const applied = new Set((await sql`select name from _vibebase_migrations`).map((r) => r.name));
  let files;
  try { files = readdirSync(dir).filter((f) => /\.(sql|js|mjs)$/.test(f)).sort(); }
  catch { throw new Error(`migrate(): migrations folder "${dir}" not found`); }
  const ran = [];
  for (const f of files) {
    if (applied.has(f)) continue;
    if (f.endsWith('.sql')) {
      const text = readFileSync(path.join(dir, f), 'utf8');
      for (const stmt of text.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean)) await sql.query(stmt);
    } else {
      const mod = await import(pathToFileURL(path.resolve(dir, f)).href);
      if (typeof mod.up !== 'function') throw new Error(`migration ${f} must export "async function up(sql)"`);
      await mod.up(sql);
    }
    await sql`insert into _vibebase_migrations (name) values (${f})`;
    ran.push(f);
  }
  return ran; // migration filenames applied this run
}

// Bulk-insert an array of row objects via chunked multi-row INSERT — for seeding
// or importing data without N round-trips. Pass `onConflict` (raw SQL you control,
// e.g. 'on conflict (id) do nothing') to make it idempotent. Returns rows inserted.
export async function insertMany(table, rows, { chunkSize = 100, onConflict = '' } = {}) {
  if (!Array.isArray(rows) || rows.length === 0) return 0;
  const t = ident(table);
  const cols = Object.keys(rows[0]).map(ident);
  let total = 0;
  for (let i = 0; i < rows.length; i += chunkSize) {
    const slice = rows.slice(i, i + chunkSize);
    const values = slice.map((_, r) => '(' + cols.map((__, c) => '$' + (r * cols.length + c + 1)).join(',') + ')').join(',');
    const params = slice.flatMap((row) => cols.map((c) => row[c] ?? null));
    await sql.query(`insert into ${t} (${cols.join(',')}) values ${values}${onConflict ? ' ' + onConflict : ''}`, params);
    total += slice.length;
  }
  return total;
}

// Examples:
//   const { user, token } = await signUp('a@b.com', 'secret');
//   const { user, token } = await signIn('a@b.com', 'secret');
//   const me = await getUser(token);
//   // Realtime-ish: react to new rows
//   const stop = onChange('messages', (rows) => console.log('new:', rows), { intervalMs: 1000 });
//   // Social login: redirect to oauthRedirectUrl('google', { state }), then in your callback:
//   const { user, token } = await oauthCallback('google', code);
//   // RAG: embedding is a number[] from your model
//   await addDocument('Paris is the capital of France', embedding, { source: 'wiki' });
//   const hits = await searchSimilar(queryEmbedding, 5);
//   // Files:
//   await putFile('avatars/u1.png', pngBytes, 'image/png');
//   const file = await getFile('avatars/u1.png'); // { bytes, contentType, size }
