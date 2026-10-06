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
          lastLoginAt: u.lastLoginAt || md.l || 0,
          lastActiveAt: u.lastActiveAt || md.a || 0
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
            createdAt: md.c || 0, lastLoginAt: md.l || 0, lastActiveAt: md.a || 0
          });
        }
        if (res.list_complete) break;
        cursor = res.cursor;
      }
    } catch (e) { /* ignore */ }
  }

  // 最近活跃 = 登录时间与「带着会话直接访问」时间中较新的一个
  const arr = Array.from(map.values());
  arr.forEach(u => { u.lastSeenAt = Math.max(u.lastLoginAt || 0, u.lastActiveAt || 0); });
  return arr.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
}

const SESS_PREFIX = 'zc_sess:';
const SESS_TTL_MS = 30 * DAY; // 与主站 ZC_SESS_TTL_SEC 保持一致

// 有效会话 = D1 中未过期的会话 ∪ KV 中尚未过期的会话（同一会话按哈希去重）
async function sessionStats(env) {
  const now = Date.now(), nowSec = Math.floor(now / 1000);
  const live = new Map();
  let d1ok = false, kvok = false, kvOnly = 0;
  const kind = (email, p) => p || (/@github$/.test(email || '') ? 'github' : (email ? 'email' : 'unknown'));

  if (env.DB && typeof env.DB.prepare === 'function') {
    try {
      const { results } = await env.DB
        .prepare('SELECT k, v, md, exp FROM zc_store WHERE ns = ? AND (exp IS NULL OR exp > ?) LIMIT 20000')
        .bind(SESS_NS, nowSec).all();
      for (const r of results || []) {
        let v = {}, md = {};
        try { v = JSON.parse(r.v || '{}'); } catch (e) {}
        try { md = JSON.parse(r.md || '{}'); } catch (e) {}
        const created = Number(v.createdAt) || 0;
        if (r.exp == null && created && created + SESS_TTL_MS <= now) continue; // 迁移记录无过期时间：按创建时间判断
        live.set(r.k, kind(v.email || md.e, v.provider || md.p));
      }
      d1ok = true;
    } catch (e) { /* ignore */ }
  }

  if (env.ZC_KV) {
    try {
      let cursor;
      for (let i = 0; i < 10; i++) {
        const res = await env.ZC_KV.list({ prefix: SESS_PREFIX, cursor, limit: 1000 });
        for (const k of res.keys) {
          const h = k.name.slice(SESS_PREFIX.length);
          if (live.has(h)) continue;
          if (k.expiration && k.expiration <= nowSec) continue;
          const md = k.metadata || {};
          live.set(h, kind(md.e, md.p));
          kvOnly++;
        }
        if (res.list_complete) break;
        cursor = res.cursor;
      }
      kvok = true;
    } catch (e) { /* ignore */ }
  }
  if (!d1ok && !kvok) return null;
  let github = 0, unknown = 0;
  live.forEach(p => { if (p === 'github') github++; else if (p === 'unknown') unknown++; });
  return { total: live.size, github, kvOnly, unclassified: unknown };
}

// ---- 内置查看页：直接打开后端网址即可，输入口令后查看（页面本身不含任何数据） ----
const DASH_HTML = "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"color-scheme\" content=\"dark light\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>登录统计控制台</title>\n<style>\n:root{--b1:#060a15;--b2:#101a3a;--tx:#eef2ff;--mu:#9aa7c9;--f1:rgba(255,255,255,.13);--f2:rgba(255,255,255,.035);--hi:rgba(255,255,255,.55);--sh:rgba(2,6,23,.55);--ac:#7aa7ff;--ac2:#a78bfa;--ok:#4ade80;--bad:#ff7a88;--in:rgba(255,255,255,.07)}\n@media(prefers-color-scheme:light){:root{--b1:#e6edfb;--b2:#f5f0ff;--tx:#0f1629;--mu:#56627f;--f1:rgba(255,255,255,.62);--f2:rgba(255,255,255,.28);--hi:#fff;--sh:rgba(40,60,130,.26);--ac:#3b6df0;--ac2:#7c5cf0;--in:rgba(255,255,255,.6)}}\n*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{height:100%}\nbody{margin:0;color:var(--tx);font:14px/1.6 -apple-system,BlinkMacSystemFont,\"PingFang SC\",\"Microsoft YaHei\",sans-serif;background:linear-gradient(160deg,var(--b1),var(--b2));overflow-x:hidden;-webkit-font-smoothing:antialiased}\n.bg{position:fixed;inset:0;overflow:hidden;z-index:-1}.o{position:absolute;border-radius:50%;filter:blur(70px);opacity:.75;animation:fl 22s ease-in-out infinite}\n.o1{width:46vmax;height:46vmax;left:-14vmax;top:-12vmax;background:radial-gradient(circle,var(--ac),transparent 68%)}\n.o2{width:40vmax;height:40vmax;right:-12vmax;top:18vh;background:radial-gradient(circle,var(--ac2),transparent 68%);animation-delay:-8s}\n.o3{width:34vmax;height:34vmax;left:12vw;bottom:-14vmax;background:radial-gradient(circle,#22d3ee,transparent 68%);opacity:.5;animation-delay:-15s}\n@keyframes fl{50%{transform:translate3d(6vmax,4vmax,0) scale(1.12)}}\n.gr{position:absolute;inset:0;width:100%;height:100%;opacity:.07;mix-blend-mode:overlay}\n.g{position:relative;isolation:isolate;overflow:hidden;border-radius:24px;background:linear-gradient(135deg,var(--f1),var(--f2));-webkit-backdrop-filter:blur(26px) saturate(185%);backdrop-filter:blur(26px) saturate(185%);box-shadow:inset 0 1px 0 var(--hi),inset 0 -1px 0 rgba(255,255,255,.07),inset 0 0 26px rgba(255,255,255,.05),0 1px 2px var(--sh),0 14px 30px -10px var(--sh),0 36px 70px -28px var(--sh)}\n@supports (backdrop-filter:url(#a)){.g{backdrop-filter:blur(16px) saturate(175%) url(#lq)}}\n.g::before{content:\"\";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(140deg,rgba(255,255,255,.75),rgba(255,255,255,.06) 34%,rgba(255,255,255,.02) 66%,rgba(255,255,255,.4));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}\n.g::after{content:\"\";position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:radial-gradient(280px circle at var(--mx,28%) var(--my,0%),rgba(255,255,255,.28),transparent 62%),linear-gradient(115deg,transparent 40%,rgba(255,255,255,.12) 50%,transparent 60%) -120% 0/250% 100% no-repeat;mix-blend-mode:soft-light;animation:sw 9s ease-in-out infinite}\n@keyframes sw{to{background-position:0 0,220% 0}}\n.g>*{position:relative;z-index:1}\n.stage{min-height:100%;display:flex;align-items:center;justify-content:center;padding:max(20px,env(safe-area-inset-top)) 16px max(20px,env(safe-area-inset-bottom))}\n.gate{width:100%;max-width:420px;padding:30px 26px 22px;animation:in .9s cubic-bezier(.2,.8,.2,1) both}\n@keyframes in{from{opacity:0;transform:translateY(18px) scale(.97);filter:blur(10px)}}\n.brand{display:flex;align-items:center;gap:13px;margin-bottom:22px}\n.chip{width:46px;height:46px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(145deg,rgba(255,255,255,.3),rgba(255,255,255,.06));box-shadow:inset 0 1px 0 rgba(255,255,255,.6),inset 0 -6px 12px rgba(0,0,0,.12),0 8px 18px -6px var(--sh)}\n.chip svg{width:24px;height:24px;stroke:var(--tx);fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}\nh1{font-size:20px;margin:0;letter-spacing:.02em}.sub{color:var(--mu);font-size:12.5px}\nlabel{display:block;font-size:12.5px;color:var(--mu);margin-bottom:7px}\n.fld{position:relative}.fld input{width:100%;height:50px;border-radius:15px;border:0;outline:0;padding:0 48px 0 16px;font:inherit;font-size:15px;color:var(--tx);background:var(--in);box-shadow:inset 0 2px 5px rgba(0,0,0,.2),inset 0 0 0 1px rgba(255,255,255,.12);transition:box-shadow .3s}\n.fld input:focus{box-shadow:inset 0 2px 5px rgba(0,0,0,.2),inset 0 0 0 1.5px var(--ac),0 0 0 5px rgba(122,167,255,.18)}\n.eye{position:absolute;right:6px;top:6px;width:38px;height:38px;border:0;border-radius:11px;background:transparent;color:var(--mu);cursor:pointer;display:grid;place-items:center}.eye svg{width:19px;height:19px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}\n.er{min-height:20px;margin:9px 2px 4px;font-size:12.5px;color:var(--bad)}\n.btn{position:relative;overflow:hidden;width:100%;height:50px;border:0;border-radius:15px;color:#fff;font:inherit;font-size:15px;font-weight:600;letter-spacing:.04em;cursor:pointer;background:linear-gradient(180deg,rgba(255,255,255,.28),rgba(255,255,255,0) 52%),linear-gradient(135deg,var(--ac),var(--ac2));box-shadow:inset 0 1px 0 rgba(255,255,255,.7),inset 0 -8px 16px rgba(0,0,0,.14),0 12px 26px -8px var(--ac);transition:transform .25s cubic-bezier(.3,1.4,.5,1),filter .2s}\n.btn::after{content:\"\";position:absolute;inset:0;background:linear-gradient(110deg,transparent 35%,rgba(255,255,255,.55) 50%,transparent 65%) -130% 0/260% 100% no-repeat;transition:background-position .9s}\n.btn:hover::after{background-position:130% 0}.btn:active{transform:scale(.97);filter:brightness(.95)}\n.btn.busy{pointer-events:none;color:transparent}.btn.busy::before{content:\"\";position:absolute;left:50%;top:50%;width:20px;height:20px;margin:-10px;border-radius:50%;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;animation:sp .7s linear infinite}\n@keyframes sp{to{transform:rotate(360deg)}}\n.shake{animation:sk .45s}@keyframes sk{20%,60%{transform:translateX(-7px)}40%,80%{transform:translateX(7px)}}\n.stt{display:flex;align-items:center;gap:8px;margin:18px 2px 12px;font-size:12.5px;color:var(--mu)}\n.dot{width:8px;height:8px;border-radius:50%;background:#8a93ad}.dot.ok{background:var(--ok);box-shadow:0 0 0 0 rgba(74,222,128,.6);animation:pu 2.2s infinite}.dot.no{background:var(--bad)}\n@keyframes pu{70%{box-shadow:0 0 0 8px rgba(74,222,128,0)}}\n.fine{margin:0;padding:12px 0 0;list-style:none;border-top:1px solid rgba(255,255,255,.12);font-size:12px;color:var(--mu)}.fine li{padding:2px 0 2px 16px;position:relative}.fine li::before{content:\"\";position:absolute;left:2px;top:10px;width:5px;height:5px;border-radius:50%;background:var(--ac)}\n#app{width:100%;max-width:880px;margin:0 auto;padding:max(18px,env(safe-area-inset-top)) 14px max(24px,env(safe-area-inset-bottom))}\n.top{display:flex;align-items:center;gap:10px;margin-bottom:14px;animation:in .8s both}.top h2{margin:0;font-size:19px}.top .sub{margin-top:-2px}.sp{flex:1}\n.sm{height:38px;padding:0 15px;border-radius:12px;border:0;color:var(--tx);font:inherit;cursor:pointer;background:var(--in);box-shadow:inset 0 1px 0 var(--hi),inset 0 0 0 1px rgba(255,255,255,.1)}\n.hero{display:flex;align-items:center;gap:18px;padding:20px;margin-bottom:12px;animation:in .8s .08s both}\n.ring{position:relative;width:104px;height:104px;flex:none}.ring svg{width:100%;height:100%;transform:rotate(-90deg)}.ring circle{fill:none;stroke-width:9;stroke-linecap:round}\n.ring .tr{stroke:rgba(255,255,255,.14)}.ring .pg{stroke:url(#rg);stroke-dasharray:276.5;stroke-dashoffset:276.5;transition:stroke-dashoffset 1.5s cubic-bezier(.2,.8,.2,1);filter:drop-shadow(0 0 6px rgba(122,167,255,.6))}\n.ring b{position:absolute;inset:0;display:grid;place-items:center;font-size:20px}\n.big{font-size:46px;line-height:1.05;font-weight:700;letter-spacing:-.02em}.lb{color:var(--mu);font-size:12.5px}\n.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:12px}@media(min-width:640px){.grid{grid-template-columns:repeat(4,1fr)}}\n.m{padding:15px 16px;border-radius:20px;animation:in .8s both}.m b{display:block;font-size:28px;line-height:1.2}.m span{color:var(--mu);font-size:12px}\n.lst{padding:8px 6px;animation:in .8s .3s both}.sr{padding:8px 8px 10px}.sr input{width:100%;height:42px;border:0;outline:0;border-radius:13px;padding:0 14px;font:inherit;color:var(--tx);background:var(--in);box-shadow:inset 0 2px 4px rgba(0,0,0,.18),inset 0 0 0 1px rgba(255,255,255,.1)}\n.u{display:flex;align-items:center;gap:12px;padding:10px;border-radius:15px;animation:in .6s both;transition:background .25s}.u:hover{background:rgba(255,255,255,.07)}\n.u img{width:42px;height:42px;border-radius:50%;flex:none;background:rgba(255,255,255,.15);box-shadow:0 0 0 2px rgba(255,255,255,.25),0 6px 14px -4px var(--sh)}\n.u div{min-width:0}.u strong{display:block;word-break:break-all}.u small{display:block;color:var(--mu);font-size:12px}\n.em{padding:26px;text-align:center;color:var(--mu)}\n.sk{height:56px;margin:6px;border-radius:15px;background:linear-gradient(90deg,rgba(255,255,255,.05),rgba(255,255,255,.16),rgba(255,255,255,.05)) 0 0/200% 100%;animation:shm 1.4s linear infinite}@keyframes shm{to{background-position:-200% 0}}\n[hidden]{display:none!important}\n@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}\n</style></head><body>\n<div class=\"bg\"><i class=\"o o1\"></i><i class=\"o o2\"></i><i class=\"o o3\"></i><svg class=\"gr\"><filter id=\"n\"><feTurbulence type=\"fractalNoise\" baseFrequency=\".85\" numOctaves=\"2\" stitchTiles=\"stitch\"/></filter><rect width=\"100%\" height=\"100%\" filter=\"url(#n)\"/></svg></div>\n<svg width=\"0\" height=\"0\" style=\"position:absolute\"><defs><filter id=\"lq\" x=\"0\" y=\"0\" width=\"100%\" height=\"100%\"><feTurbulence type=\"fractalNoise\" baseFrequency=\".007 .011\" numOctaves=\"2\" seed=\"7\" result=\"t\"/><feDisplacementMap in=\"SourceGraphic\" in2=\"t\" scale=\"22\" xChannelSelector=\"R\" yChannelSelector=\"G\"/></filter><linearGradient id=\"rg\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\"><stop offset=\"0\" stop-color=\"#7aa7ff\"/><stop offset=\"1\" stop-color=\"#a78bfa\"/></linearGradient></defs></svg>\n<div class=\"stage\" id=\"gw\"><main class=\"g gate\" id=\"gate\">\n<div class=\"brand\"><div class=\"chip\"><svg viewBox=\"0 0 24 24\"><path d=\"M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6z\"/><path d=\"m9 12 2 2 4-4\"/></svg></div><div><h1>登录统计控制台</h1><div class=\"sub\">仅限授权人员访问</div></div></div>\n<label for=\"tk\">访问口令</label><div class=\"fld\"><input id=\"tk\" type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" placeholder=\"请输入 STATS_TOKEN\"><button class=\"eye\" id=\"ey\" type=\"button\" aria-label=\"显示或隐藏口令\"><svg viewBox=\"0 0 24 24\"><path d=\"M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg></button></div>\n<div class=\"er\" id=\"er\" role=\"alert\"></div><button class=\"btn\" id=\"go\" type=\"button\">验证并进入</button>\n<div class=\"stt\"><i class=\"dot\" id=\"dot\"></i><span id=\"st\">正在检测服务状态…</span></div>\n<ul class=\"fine\"><li>只读访问，不会修改任何数据</li><li>口令通过请求头发送，不会出现在网址中</li><li>口令仅保存在本次浏览器会话内</li></ul>\n</main></div>\n<div id=\"app\" hidden>\n<div class=\"top\"><div><h2>GitHub 登录概览</h2><div class=\"sub\" id=\"up\"></div></div><span class=\"sp\"></span><button class=\"sm\" id=\"rf\" type=\"button\">刷新</button><button class=\"sm\" id=\"lo\" type=\"button\">退出</button></div>\n<section class=\"g hero\"><div class=\"ring\"><svg viewBox=\"0 0 100 100\"><circle class=\"tr\" cx=\"50\" cy=\"50\" r=\"44\"/><circle class=\"pg\" id=\"pg\" cx=\"50\" cy=\"50\" r=\"44\"/></svg><b id=\"rt\">0%</b></div><div><div class=\"lb\">GitHub 登录人数</div><div class=\"big\" id=\"n0\">0</div><div class=\"lb\">圆环：近 7 天活跃占比</div></div></section>\n<div class=\"grid\"><div class=\"g m\" style=\"animation-delay:.16s\"><b id=\"n1\">0</b><span>近 24 小时活跃</span></div><div class=\"g m\" style=\"animation-delay:.22s\"><b id=\"n2\">0</b><span>近 7 天活跃</span></div><div class=\"g m\" style=\"animation-delay:.28s\"><b id=\"n3\">0</b><span>近 30 天活跃</span></div><div class=\"g m\" style=\"animation-delay:.34s\"><b id=\"n4\">0</b><span id=\"n4l\">当前有效会话</span></div></div>\n<section class=\"g lst\"><div class=\"sr\"><input id=\"sq\" type=\"search\" placeholder=\"搜索登录名或昵称\"></div><div id=\"ul\"></div></section>\n</div>\n<script>\n(function(){\nvar $=function(i){return document.getElementById(i)},S=null,U=[],T=$(\"tk\"),B=$(\"go\");\nfunction ss(k,v){try{if(v===undefined)return sessionStorage.getItem(k);if(v===null)sessionStorage.removeItem(k);else sessionStorage.setItem(k,v)}catch(e){return null}}\nfunction fmt(t){return t?new Date(t).toLocaleString(\"zh-CN\",{hour12:false}):\"-\"}\nfunction api(p){return fetch(p,{headers:{Authorization:\"Bearer \"+S},cache:\"no-store\"}).then(function(r){return r.json().then(function(d){return{ok:r.ok,s:r.status,d:d}})})}\nfunction cnt(el,to){var t0=performance.now();(function f(n){var k=Math.min(1,(n-t0)/1000);el.textContent=Math.round((to||0)*(1-Math.pow(1-k,3)));if(k<1)requestAnimationFrame(f)})(t0)}\nfunction err(m){$(\"er\").textContent=m||\"\";if(m){var g=$(\"gate\");g.classList.remove(\"shake\");void g.offsetWidth;g.classList.add(\"shake\")}}\nvar t0=performance.now();fetch(\"/api/health\",{cache:\"no-store\"}).then(function(r){return r.json()}).then(function(){$(\"dot\").className=\"dot ok\";$(\"st\").textContent=\"服务在线 · 响应 \"+Math.round(performance.now()-t0)+\" ms\"}).catch(function(){$(\"dot\").className=\"dot no\";$(\"st\").textContent=\"无法连接服务\"});\nfunction list(){var q=$(\"sq\").value.trim().toLowerCase(),box=$(\"ul\");box.textContent=\"\";\nvar a=U.filter(function(u){return !q||(u.login+\" \"+(u.name||\"\")).toLowerCase().indexOf(q)>=0});\nif(!a.length){var e=document.createElement(\"div\");e.className=\"em\";e.textContent=U.length?\"没有匹配的账号\":\"暂无 GitHub 登录记录\";box.appendChild(e);return}\na.forEach(function(u,i){var r=document.createElement(\"div\");r.className=\"u\";r.style.animationDelay=Math.min(i,12)*45+\"ms\";\nvar im=document.createElement(\"img\");im.alt=\"\";if(/^https:\\/\\/avatars\\.githubusercontent\\.com\\//.test(u.avatar||\"\"))im.src=u.avatar;\nvar d=document.createElement(\"div\"),s=document.createElement(\"strong\"),m=document.createElement(\"small\"),l=document.createElement(\"small\");\ns.textContent=u.login+(u.name?\"（\"+u.name+\"）\":\"\");m.textContent=\"GitHub ID \"+(u.ghId||\"-\")+\" · 首次登录 \"+fmt(u.createdAt);l.textContent=\"最近活跃 \"+fmt(u.lastSeenAt)+\" · 上次登录 \"+fmt(u.lastLoginAt);\nd.appendChild(s);d.appendChild(m);d.appendChild(l);r.appendChild(im);r.appendChild(d);box.appendChild(r)})}\nfunction render(a,us){U=us;cnt($(\"n0\"),a.githubUsers);cnt($(\"n1\"),a.active24h);cnt($(\"n2\"),a.active7d);cnt($(\"n3\"),a.active30d);cnt($(\"n4\"),a.activeSessions);$(\"n4l\").textContent=\"当前有效会话（GitHub \"+(a.activeGithubSessions==null?\"-\":a.activeGithubSessions)+\"）\";\nvar r=a.githubUsers?a.active7d/a.githubUsers:0;$(\"rt\").textContent=Math.round(r*100)+\"%\";var p=$(\"pg\");p.style.strokeDashoffset=276.5;void p.getBoundingClientRect();p.style.strokeDashoffset=276.5*(1-r);\n$(\"up\").textContent=\"更新于 \"+fmt(a.generatedAt);list()}\nfunction load(quiet){B.classList.add(\"busy\");$(\"ul\").innerHTML='<div class=\"sk\"></div><div class=\"sk\"></div>';\nreturn Promise.all([api(\"/api/summary\"),api(\"/api/users\")]).then(function(x){B.classList.remove(\"busy\");var a=x[0];\nif(!a.ok){if(a.s===401)ss(\"st\",null);if(!quiet)err(a.s===401?\"口令不正确，请重新输入\":(a.d&&a.d.error)||\"请求失败\");return}\nss(\"st\",S);err(\"\");$(\"gw\").hidden=true;$(\"app\").hidden=false;render(a.d,x[1].d.users||[])}).catch(function(){B.classList.remove(\"busy\");if(!quiet)err(\"网络错误，请稍后重试\")})}\nfunction enter(){S=T.value.trim();if(!S){err(\"请输入访问口令\");return}load(false)}\nB.addEventListener(\"click\",enter);T.addEventListener(\"keydown\",function(e){if(e.key===\"Enter\")enter()});\n$(\"ey\").addEventListener(\"click\",function(){T.type=T.type===\"password\"?\"text\":\"password\"});\n$(\"rf\").addEventListener(\"click\",function(){load(false)});$(\"sq\").addEventListener(\"input\",list);\n$(\"lo\").addEventListener(\"click\",function(){S=null;ss(\"st\",null);T.value=\"\";$(\"app\").hidden=true;$(\"gw\").hidden=false});\nvar q=0;addEventListener(\"pointermove\",function(e){if(q)return;q=requestAnimationFrame(function(){q=0;document.querySelectorAll(\".g\").forEach(function(g){var r=g.getBoundingClientRect();g.style.setProperty(\"--mx\",e.clientX-r.left+\"px\");g.style.setProperty(\"--my\",e.clientY-r.top+\"px\")})})},{passive:true});\nvar k=ss(\"st\");if(k){S=k;load(true)}\n})();\n</script></body></html>\n";

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
      const active = (ms) => users.filter(u => u.lastSeenAt && now - u.lastSeenAt <= ms).length;
      const ss = await sessionStats(env);
      return json(request, env, {
        githubUsers: users.length,
        active24h: active(DAY),
        active7d: active(7 * DAY),
        active30d: active(30 * DAY),
        activeSessions: ss ? ss.total : null,
        activeGithubSessions: ss ? ss.github : null,
        sessionsKvOnly: ss ? ss.kvOnly : null,
        sessionsUnclassified: ss ? ss.unclassified : null,
        latestLogin: users[0] ? { login: users[0].login, at: users[0].lastSeenAt } : null,
        generatedAt: now
      });
    }

    return json(request, env, { error: 'Not Found' }, 404);
  }
};
