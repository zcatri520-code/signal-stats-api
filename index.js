// SIGNAL 登录统计后端（独立 Worker，只读）
// 接口（都需要请求头  Authorization: Bearer <STATS_TOKEN>）：
//   GET /api/summary   汇总：GitHub 登录人数、近 24h / 7d / 30d 活跃、当前有效会话数
//   GET /api/users     GitHub 账号列表（登录名、昵称、头像、ID、首次/最近登录）
//   GET /api/health    不需要口令，仅检查服务是否在线

const USER_NS = 'user';
const SESS_NS = 'sess';
const DAY = 86400000;

function allowedOrigin(request, env) {
  const origin = request.headers.get('Origin') || '';
  const list = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
  return origin && list.indexOf(origin) >= 0 ? origin : '';
}

function corsHeaders(request, env) {
  const o = allowedOrigin(request, env);
  const h = { 'Vary': 'Origin' };
  if (o) {
    h['Access-Control-Allow-Origin'] = o;
    h['Access-Control-Allow-Headers'] = 'Authorization, Content-Type';
    h['Access-Control-Allow-Methods'] = 'GET, OPTIONS';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}

function json(request, env, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json;charset=utf-8', 'Cache-Control': 'no-store' }, corsHeaders(request, env))
  });
}

// 常量时间比较，避免通过响应时间猜口令
function safeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

function authed(request, env) {
  const expected = String(env.STATS_TOKEN || '');
  if (!expected) return false;
  const m = /^Bearer\s+(.+)$/i.exec(request.headers.get('Authorization') || '');
  return !!m && safeEqual(m[1].trim(), expected);
}

// 读取全部 GitHub 账号：D1 为主，KV 里还没迁移到 D1 的旧记录作补充
async function loadGithubUsers(env) {
  const map = new Map();

  if (env.DB && typeof env.DB.prepare === 'function') {
    try {
      const { results } = await env.DB
        .prepare("SELECT k, v, md FROM zc_store WHERE ns = ? AND k LIKE '%@github'")
        .bind(USER_NS).all();
      for (const r of results || []) {
        let u = {}; let md = {};
        try { u = JSON.parse(r.v || '{}'); } catch (e) {}
        try { md = JSON.parse(r.md || '{}'); } catch (e) {}
        map.set(r.k, {
          login: u.ghLogin || md.gh || r.k.replace(/@github$/, ''),
          name: u.ghName || '',
          avatar: u.ghAvatar || '',
          ghId: u.ghId || 0,
          createdAt: u.createdAt || md.c || 0,
          lastLoginAt: u.lastLoginAt || md.l || 0
        });
      }
    } catch (e) { /* D1 不可用时只用 KV */ }
  }

  if (env.ZC_KV) {
    try {
      let cursor;
      for (let i = 0; i < 20; i++) {
        const res = await env.ZC_KV.list({ prefix: 'zc_user:', cursor, limit: 1000 });
        for (const k of res.keys) {
          const email = k.name.slice('zc_user:'.length);
          if (!/@github$/.test(email) || map.has(email)) continue;
          const md = k.metadata || {};
          map.set(email, {
            login: md.gh || email.replace(/@github$/, ''),
            name: '', avatar: '', ghId: 0,
            createdAt: md.c || 0, lastLoginAt: md.l || 0
          });
        }
        if (res.list_complete) break;
        cursor = res.cursor;
      }
    } catch (e) { /* ignore */ }
  }

  return Array.from(map.values()).sort((a, b) => b.lastLoginAt - a.lastLoginAt);
}

async function countActiveSessions(env) {
  if (!(env.DB && typeof env.DB.prepare === 'function')) return null;
  try {
    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB
      .prepare("SELECT COUNT(*) AS n FROM zc_store WHERE ns = ? AND (exp IS NULL OR exp > ?) AND v LIKE '%\"provider\":\"github\"%'")
      .bind(SESS_NS, now).first();
    return row ? row.n : 0;
  } catch (e) { return null; }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }
    if (url.pathname === '/api/health') return json(request, env, { ok: true });

    if (request.method !== 'GET') return json(request, env, { error: 'Method Not Allowed' }, 405);
    if (!String(env.STATS_TOKEN || '')) return json(request, env, { error: '服务端未设置 STATS_TOKEN' }, 501);
    if (!authed(request, env)) return json(request, env, { error: '口令错误或缺失' }, 401);

    if (url.pathname === '/api/users') {
      const users = await loadGithubUsers(env);
      return json(request, env, { total: users.length, users });
    }

    if (url.pathname === '/api/summary') {
      const users = await loadGithubUsers(env);
      const now = Date.now();
      const active = (ms) => users.filter(u => u.lastLoginAt && now - u.lastLoginAt <= ms).length;
      return json(request, env, {
        githubUsers: users.length,
        active24h: active(DAY),
        active7d: active(7 * DAY),
        active30d: active(30 * DAY),
        activeSessions: await countActiveSessions(env),
        latestLogin: users[0] ? { login: users[0].login, at: users[0].lastLoginAt } : null,
        generatedAt: now
      });
    }

    return json(request, env, { error: 'Not Found' }, 404);
  }
};
