// SIGNAL 登录统计后端（独立 Worker，只读）
// 接口（都需要请求头  Authorization: Bearer <STATS_TOKEN>）：
//   GET /api/summary   汇总：GitHub 登录人数、近 24h / 7d / 30d 活跃、当前有效会话数
//   GET /api/users     GitHub 账号列表（登录名、昵称、头像、ID、首次/最近登录）
//   GET /api/health    不需要口令，仅检查服务是否在线
//   GET /              内置查看页（输入口令后查看，页面本身无数据）

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

// ---- 内置查看页：直接打开后端网址即可，输入口令后查看（页面本身不含任何数据） ----
const DASH_HTML = [
'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">',
'<meta name="viewport" content="width=device-width,initial-scale=1">',
'<meta name="robots" content="noindex,nofollow"><title>登录统计</title>',
'<style>',
'*{box-sizing:border-box}body{margin:0;font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f7f7f8;color:#18181b}',
'.w{max-width:900px;margin:0 auto;padding:20px 14px}h1{font-size:19px;margin:0 0 14px}',
'.bar{display:flex;gap:8px;margin-bottom:12px}.bar input{flex:1;min-width:0;height:38px;border:1px solid #d3d3da;border-radius:9px;padding:0 12px}',
'.bar button{height:38px;border:0;border-radius:9px;padding:0 18px;background:#18181b;color:#fff}',
'#msg{color:#55555e;margin:0 0 12px}',
'.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px}',
'.c{background:#fff;border:1px solid #e6e6ea;border-radius:12px;padding:12px}.c b{display:block;font-size:24px}.c span{color:#8b8b95;font-size:12px}',
'.list{background:#fff;border:1px solid #e6e6ea;border-radius:12px}',
'.u{display:flex;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid #efeff2}.u:last-child{border:0}',
'.u img{width:36px;height:36px;border-radius:50%;background:#eee;flex:none}',
'.u div{min-width:0}.u strong{display:block;word-break:break-all}.u small{color:#8b8b95;display:block}',
'</style></head><body><div class="w"><h1>GitHub 登录统计</h1>',
'<div class="bar"><input id="tk" type="password" placeholder="STATS_TOKEN" autocomplete="off"><button id="go" type="button">查看</button></div>',
'<p id="msg">输入口令后点击“查看”。</p><div class="cards" id="cards"></div><div class="list" id="list" hidden></div></div>',
'<script>',
'(function(){',
'var tk=document.getElementById("tk"),go=document.getElementById("go"),msg=document.getElementById("msg"),cards=document.getElementById("cards"),list=document.getElementById("list");',
'try{tk.value=sessionStorage.getItem("st")||""}catch(e){}',
'function fmt(t){return t?new Date(t).toLocaleString("zh-CN",{hour12:false}):"-"}',
'function api(p){return fetch(p,{headers:{Authorization:"Bearer "+tk.value.trim()},cache:"no-store"}).then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})})}',
'function card(n,l){var c=document.createElement("div");c.className="c";var b=document.createElement("b");b.textContent=String(n==null?"-":n);var s=document.createElement("span");s.textContent=l;c.appendChild(b);c.appendChild(s);cards.appendChild(c)}',
'function load(){msg.textContent="加载中…";cards.textContent="";list.textContent="";list.hidden=true;',
'Promise.all([api("/api/summary"),api("/api/users")]).then(function(x){',
'var a=x[0],b=x[1];if(!a.ok){msg.textContent=(a.d&&a.d.error)||"请求失败";return}',
'try{sessionStorage.setItem("st",tk.value.trim())}catch(e){}',
'card(a.d.githubUsers,"GitHub 登录人数");card(a.d.activeSessions,"当前有效会话");card(a.d.active24h,"近 24 小时活跃");card(a.d.active7d,"近 7 天活跃");card(a.d.active30d,"近 30 天活跃");',
'msg.textContent="更新于 "+fmt(a.d.generatedAt);',
'(b.d.users||[]).forEach(function(u){var r=document.createElement("div");r.className="u";',
'var im=document.createElement("img");if(/^https:\\/\\/avatars\\.githubusercontent\\.com\\//.test(u.avatar||""))im.src=u.avatar;r.appendChild(im);',
'var d=document.createElement("div"),s=document.createElement("strong");s.textContent=u.login+(u.name?"（"+u.name+"）":"");',
'var m=document.createElement("small");m.textContent="ID "+(u.ghId||"-")+" · 首次 "+fmt(u.createdAt);',
'var l=document.createElement("small");l.textContent="最近登录 "+fmt(u.lastLoginAt);',
'd.appendChild(s);d.appendChild(m);d.appendChild(l);r.appendChild(d);list.appendChild(r)});',
'list.hidden=!(b.d.users&&b.d.users.length)',
'}).catch(function(){msg.textContent="网络错误，请稍后重试"})}',
'go.addEventListener("click",load);tk.addEventListener("keydown",function(e){if(e.key==="Enter")load()});',
'})();',
'</script></body></html>'
].join('\n');

function dashResponse() {
  return new Response(DASH_HTML, {
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https://avatars.githubusercontent.com; connect-src 'self'; base-uri 'none'; form-action 'none'"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) return dashResponse();
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
