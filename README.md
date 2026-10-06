# signal-stats-api 部署

1. 进入目录并安装：`npm install`
2. 改 `wrangler.jsonc` 里的 `ALLOWED_ORIGINS` 为你前端的网址
3. 设置口令（务必长且随机）：`npx wrangler secret put STATS_TOKEN`
4. 部署：`npx wrangler deploy`
5. 测试：
   curl https://signal-stats-api.<子域>.workers.dev/api/health
   curl -H "Authorization: Bearer <口令>" https://signal-stats-api.<子域>.workers.dev/api/summary
