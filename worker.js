#!/usr/bin/env node
'use strict';

/**
 * Coins Alert worker — Node.js 18+; zero third-party dependencies.
 *
 * Required: DEX Screener public REST API.
 * Optional security providers: RugCheck (Solana), GoPlus (EVM).
 *
 * Environment:
 *   PORT=8787
 *   HOST=0.0.0.0
 *   CORS_ORIGIN=https://yourname.github.io
 *   POLL_INTERVAL_MS=15000
 *   MIN_LIQUIDITY_USD=10000
 *   MAX_FDV_USD=1000000
 *   MAX_PAIR_AGE_HOURS=24
 *   REQUIRE_AUDIT_PASS=true
 *   WEBHOOK_URL=https://...
 *   API_BEARER_TOKEN=...   (optional; protects API endpoints)
 *
 * Run: node worker.js
 * Do not expose an unauthenticated worker API directly to the public internet.
 */

const http = require('node:http');
const { URL } = require('node:url');

const CONFIG = {
  host: process.env.HOST || '127.0.0.1',
  port: positiveInt(process.env.PORT, 8787),
  pollIntervalMs: Math.max(5000, positiveInt(process.env.POLL_INTERVAL_MS, 15000)),
  minLiquidityUsd: nonNegative(process.env.MIN_LIQUIDITY_USD, 10000),
  maxFdvUsd: nonNegative(process.env.MAX_FDV_USD, 1000000),
  maxPairAgeHours: positiveNumber(process.env.MAX_PAIR_AGE_HOURS, 24),
  requireAuditPass: String(process.env.REQUIRE_AUDIT_PASS || 'true').toLowerCase() !== 'false',
  corsOrigin: process.env.CORS_ORIGIN || '',
  webhookUrl: process.env.WEBHOOK_URL || '',
  bearerToken: process.env.API_BEARER_TOKEN || '',
  requestTimeoutMs: 12000,
  maxTokensInMemory: 2000,
  maxLogsInMemory: 1500,
};

const API = {
  profiles: 'https://api.dexscreener.com/token-profiles/latest/v1',
  boosts: 'https://api.dexscreener.com/token-boosts/latest/v1',
  tokenPairs: 'https://api.dexscreener.com/latest/dex/tokens/',
  rugcheck: 'https://api.rugcheck.xyz/v1/tokens/',
  goplus: 'https://api.gopluslabs.io/api/v1/token_security/',
};

const seen = new Set();
const tokenStore = new Map();
const logs = [];
const alertDedup = new Set();
let lastPollAt = null;
let pollRunning = false;
let stopped = false;
let logSequence = 0;

function positiveInt(v, fallback) { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : fallback; }
function positiveNumber(v, fallback) { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : fallback; }
function nonNegative(v, fallback) { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : fallback; }
function log(level, message, meta = {}) {
  const entry = { id: `${Date.now()}-${++logSequence}`, timestamp: new Date().toISOString(), level, message, ...meta };
  logs.push(entry);
  if (logs.length > CONFIG.maxLogsInMemory) logs.splice(0, logs.length - CONFIG.maxLogsInMemory);
  const line = `[${entry.timestamp}] ${level.toUpperCase()} ${message}`;
  (level === 'error' ? console.error : console.log)(line);
  return entry;
}
function finite(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }
function ageMinutes(pair) {
  const created = finite(pair.pairCreatedAt);
  return created === null ? null : Math.max(0, (Date.now() - created) / 60000);
}
function chainLabel(id) {
  const map = { solana: 'Solana', base: 'Base', ethereum: 'Ethereum', bsc: 'BSC', 'binance-smart-chain': 'BSC' };
  return map[String(id || '').toLowerCase()] || String(id || 'unknown');
}
function isEvmChain(chainId) {
  // GoPlus chain IDs are provider-specific identifiers, not always DEX Screener names.
  const map = { ethereum: '1', bsc: '56', base: '8453', polygon: '137', arbitrum: '42161', optimism: '10', avalanche: '43114', linea: '59144', opbnb: '204', zksync: '324', scroll: '534352', fantom: '250', gnosis: '100', mantle: '5000', blast: '81457' };
  return map[String(chainId || '').toLowerCase()] || null;
}
async function fetchJson(url, label) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CONFIG.requestTimeoutMs);
  try {
    const response = await fetch(url, {
      headers: { 'accept': 'application/json', 'user-agent': 'CoinsAlert/1.0 (DEX Screener monitor)' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`${label} HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timeout); }
}
async function postWebhook(token) {
  if (!CONFIG.webhookUrl) return;
  const payload = {
    text: `Coins Alert: ${token.name || token.symbol || token.address} (${token.chainId}) matched configured filters.`,
    token: {
      name: token.name, symbol: token.symbol, address: token.address, chainId: token.chainId,
      liquidityUsd: token.liquidityUsd, fdv: token.fdv, pairAgeMinutes: token.pairAgeMinutes,
      audit: token.audit, url: token.url,
    },
  };
  try {
    const r = await fetch(CONFIG.webhookUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload), signal: AbortSignal.timeout(CONFIG.requestTimeoutMs),
    });
    if (!r.ok) log('warn', `Webhook notification failed with HTTP ${r.status} for ${token.address}`);
  } catch (e) { log('warn', `Webhook notification failed for ${token.address}: ${e.message}`); }
}
async function auditSolana(address) {
  const url = `${API.rugcheck}${encodeURIComponent(address)}/report/summary`;
  try {
    let data;
    try { data = await fetchJson(url, 'RugCheck'); }
    catch (e) {
      // The full report is a documented fallback endpoint, not an assumed pass.
      if (!/HTTP 404/.test(e.message)) throw e;
      data = await fetchJson(`${API.rugcheck}${encodeURIComponent(address)}/report`, 'RugCheck report');
    }
    const mintAuthority = data.mintAuthority ?? data.mint_authority ?? data.token?.mintAuthority ?? null;
    const freezeAuthority = data.freezeAuthority ?? data.freeze_authority ?? data.token?.freezeAuthority ?? null;
    const score = finite(data.score ?? data.riskScore ?? data.risk_score);
    const risks = Array.isArray(data.risks) ? data.risks : [];
    const danger = risks.filter(r => /danger|critical|high/i.test(String(r.level || r.severity || '')));
    const authoritiesClear = (mintAuthority === null || mintAuthority === '' || mintAuthority === false) &&
      (freezeAuthority === null || freezeAuthority === '' || freezeAuthority === false);
    // RugCheck schema varies; unknown authority fields are not silently assumed disabled.
    const fieldsPresent = ['mintAuthority','mint_authority'].some(k => Object.prototype.hasOwnProperty.call(data,k)) &&
      ['freezeAuthority','freeze_authority'].some(k => Object.prototype.hasOwnProperty.call(data,k));
    const scoreLimit = 500;
    const passed = fieldsPresent && authoritiesClear && score !== null && score < scoreLimit && danger.length === 0;
    return {
      status: passed ? 'pass' : 'fail',
      provider: 'RugCheck',
      reason: `mintAuthority=${mintAuthority ?? 'unknown'}, freezeAuthority=${freezeAuthority ?? 'unknown'}, riskScore=${score ?? 'unknown'}, high/danger risks=${danger.length}; pass requires both authorities explicitly absent, score < ${scoreLimit}, and no high/danger risks`,
      mintAuthority, freezeAuthority, riskScore: score,
      checkedAt: new Date().toISOString(),
    };
  } catch (e) {
    return { status: 'unknown', provider: 'RugCheck', reason: `Audit unavailable or schema unrecognized: ${e.message}`, checkedAt: new Date().toISOString() };
  }
}
async function auditEvm(chainId, address) {
  const chain = isEvmChain(chainId);
  if (!chain) return { status: 'unknown', provider: 'GoPlus', reason: `No configured GoPlus chain-ID mapping for DEX Screener chain "${chainId}"`, checkedAt: new Date().toISOString() };
  const url = `${API.goplus}${encodeURIComponent(chain)}?contract_addresses=${encodeURIComponent(address)}`;
  try {
    const data = await fetchJson(url, 'GoPlus');
    const resultMap = data.result || {};
    const result = resultMap[String(address).toLowerCase()] || resultMap[address] || Object.values(resultMap)[0];
    if (!result || Number(data.code) !== 1 && data.code !== '1') {
      return { status: 'unknown', provider: 'GoPlus', reason: `GoPlus did not return a recognized result (code=${data.code ?? 'missing'})`, checkedAt: new Date().toISOString() };
    }
    const honeypot = String(result.is_honeypot ?? '').trim() === '1';
    const mintable = String(result.is_mintable ?? '').trim() === '1';
    const buyTax = finite(result.buy_tax);
    const sellTax = finite(result.sell_tax);
    const passed = !honeypot && !mintable;
    return {
      status: passed ? 'pass' : 'fail', provider: 'GoPlus',
      reason: `is_honeypot=${result.is_honeypot ?? 'unknown'}, is_mintable=${result.is_mintable ?? 'unknown'}, buy_tax=${buyTax ?? 'unknown'}, sell_tax=${sellTax ?? 'unknown'}; pass requires honeypot=0 and mintable=0`,
      isHoneypot: honeypot, isMintable: mintable, buyTax, sellTax,
      checkedAt: new Date().toISOString(),
    };
  } catch (e) {
    return { status: 'unknown', provider: 'GoPlus', reason: `Audit unavailable or schema unrecognized: ${e.message}`, checkedAt: new Date().toISOString() };
  }
}
async function auditToken(pair) {
  if (!pair || !pair.baseToken || !pair.baseToken.address) {
    return { status: 'unknown', provider: 'none', reason: 'Pair has no base token address', checkedAt: new Date().toISOString() };
  }
  if (String(pair.chainId).toLowerCase() === 'solana') return auditSolana(pair.baseToken.address);
  return auditEvm(pair.chainId, pair.baseToken.address);
}
function pairToToken(pair, address) {
  const liquidityUsd = finite(pair.liquidity && pair.liquidity.usd);
  const fdv = finite(pair.fdv);
  const created = finite(pair.pairCreatedAt);
  const txns = pair.txns && pair.txns.h24;
  const buys = finite(txns && txns.buys);
  const sells = finite(txns && txns.sells);
  const tokenAddress = String(pair.baseToken && pair.baseToken.address || address);
  return {
    address: tokenAddress,
    name: pair.baseToken && pair.baseToken.name || 'Unknown token',
    symbol: pair.baseToken && pair.baseToken.symbol || '',
    chainId: String(pair.chainId || 'unknown').toLowerCase(),
    chainName: chainLabel(pair.chainId),
    liquidityUsd, fdv,
    pairAgeMinutes: ageMinutes(pair),
    pairCreatedAt: created,
    volumeH24: finite(pair.volume && pair.volume.h24),
    txnsH24: buys === null || sells === null ? null : buys + sells,
    buysH24: buys, sellsH24: sells,
    url: typeof pair.url === 'string' && /^https:\/\/dexscreener\.com\//i.test(pair.url) ? pair.url : null,
    pairAddress: pair.pairAddress || null,
    priceUsd: finite(pair.priceUsd),
    priceChangeH24: finite(pair.priceChange && pair.priceChange.h24),
    audit: { status: 'pending', provider: 'pending', reason: 'Security audit not completed' },
    discoveredAt: new Date().toISOString(),
    source: 'DEX Screener',
  };
}
function filterEvaluation(token) {
  const ageLimit = CONFIG.maxPairAgeHours * 60;
  const checks = [
    { name: 'liquidity', ok: token.liquidityUsd !== null && token.liquidityUsd >= CONFIG.minLiquidityUsd, expression: `${token.liquidityUsd === null ? 'unknown' : `$${token.liquidityUsd}`} >= $${CONFIG.minLiquidityUsd}` },
    { name: 'fdv', ok: token.fdv !== null && token.fdv <= CONFIG.maxFdvUsd, expression: `${token.fdv === null ? 'unknown' : `$${token.fdv}`} <= $${CONFIG.maxFdvUsd}` },
    { name: 'pair age', ok: token.pairAgeMinutes !== null && token.pairAgeMinutes <= ageLimit, expression: `${token.pairAgeMinutes === null ? 'unknown' : `${token.pairAgeMinutes.toFixed(2)} min`} <= ${ageLimit} min` },
    { name: 'chart URL', ok: Boolean(token.url), expression: `pair.url ${token.url ? 'is a valid DEX Screener URL' : 'is missing or not a DEX Screener URL'}` },
  ];
  const marketPass = checks.every(c => c.ok);
  const auditPass = token.audit && token.audit.status === 'pass';
  const overallPass = marketPass && (!CONFIG.requireAuditPass || auditPass);
  return { checks, marketPass, auditPass, overallPass };
}
async function processAddressBatch(addresses) {
  // DEX Screener accepts comma-separated token addresses. Keep batches to 30.
  for (let i = 0; i < addresses.length; i += 30) {
    const batch = addresses.slice(i, i + 30);
    if (!batch.length) continue;
    const endpoint = API.tokenPairs + batch.map(encodeURIComponent).join(',');
    let data;
    try { data = await fetchJson(endpoint, 'DEX Screener token pairs'); }
    catch (e) { log('error', `Pair hydration failed for batch of ${batch.length}: ${e.message}`); continue; }
    const pairs = Array.isArray(data.pairs) ? data.pairs : [];
    if (!pairs.length) {
      for (const address of batch) log('info', `Hydration returned no indexed pairs for token ${address}; not creating a chart link.`);
      continue;
    }
    const grouped = new Map();
    for (const pair of pairs) {
      const addr = String(pair.baseToken && pair.baseToken.address || '').toLowerCase();
      if (!addr) continue;
      if (!grouped.has(addr)) grouped.set(addr, []);
      grouped.get(addr).push(pair);
    }
    for (const address of batch) {
      const candidates = grouped.get(address.toLowerCase()) || [];
      // Prefer the pair with the greatest reported USD liquidity; no synthetic selection/data.
      candidates.sort((a,b) => finite(b.liquidity && b.liquidity.usd) - finite(a.liquidity && a.liquidity.usd));
      const pair = candidates[0];
      if (!pair) { log('info', `No base-token pair matched address ${address}; skipped without inventing pair data.`); continue; }
      const token = pairToToken(pair, address);
      const evaluation = filterEvaluation(token);
      log('info', `${token.name} (${token.symbol}) ${token.address}: liquidity ${token.liquidityUsd === null ? 'unknown' : '$'+token.liquidityUsd} ${evaluation.checks[0].ok?'PASS':'FAIL'} [${evaluation.checks[0].expression}]; FDV ${token.fdv === null?'unknown':'$'+token.fdv} ${evaluation.checks[1].ok?'PASS':'FAIL'} [${evaluation.checks[1].expression}]; age ${token.pairAgeMinutes===null?'unknown':token.pairAgeMinutes.toFixed(2)+'m'} ${evaluation.checks[2].ok?'PASS':'FAIL'} [${evaluation.checks[2].expression}]; ${evaluation.checks[3].expression}.`);
      // Only tokens passing market filters receive the on-chain audit.
      if (evaluation.marketPass) {
        token.audit = await auditToken(pair);
        log(token.audit.status === 'pass' ? 'pass' : token.audit.status === 'fail' ? 'warn' : 'warn',
          `${token.name} (${token.symbol}) audit ${token.audit.status.toUpperCase()} via ${token.audit.provider}: ${token.audit.reason}`);
      } else {
        token.audit = { status: 'not_checked', provider: 'not checked', reason: 'Market filters failed; security audit not requested' };
      }
      const final = filterEvaluation(token);
      token.filterResult = {
        marketPass: final.marketPass, auditPass: token.audit.status === 'pass',
        overallPass: final.overallPass, checks: final.checks,
      };
      token.updatedAt = new Date().toISOString();
      tokenStore.set(token.address.toLowerCase(), token);
      while (tokenStore.size > CONFIG.maxTokensInMemory) tokenStore.delete(tokenStore.keys().next().value);
      if (final.overallPass) {
        const dedupKey = `${token.chainId}:${token.address.toLowerCase()}`;
        if (!alertDedup.has(dedupKey)) {
          alertDedup.add(dedupKey);
          log('success', `MATCH: ${token.name} (${token.symbol}) passed configured market filters${CONFIG.requireAuditPass ? ' and real security audit' : ''}.`);
          await postWebhook(token);
        }
      } else {
        log('info', `${token.name} (${token.symbol}) FINAL RESULT: FAIL — ${!final.marketPass ? 'one or more market checks failed' : `audit status ${token.audit.status} while audit pass is required`}.`);
      }
    }
  }
}
async function pollOnce() {
  if (pollRunning || stopped) return;
  pollRunning = true;
  try {
    log('info', 'Starting DEX Screener discovery cycle.');
    const [profilesResult, boostsResult] = await Promise.allSettled([
      fetchJson(API.profiles, 'DEX Screener token profiles'),
      fetchJson(API.boosts, 'DEX Screener latest boosts'),
    ]);
    const discovered = new Map();
    for (const [label, result] of [['profiles', profilesResult], ['boosts', boostsResult]]) {
      if (result.status !== 'fulfilled') { log('error', `${label} discovery endpoint failed: ${result.reason.message}`); continue; }
      const list = Array.isArray(result.value) ? result.value : Array.isArray(result.value.tokens) ? result.value.tokens : [];
      for (const item of list) {
        const address = String(item.tokenAddress || '').trim();
        if (!address || !item.chainId) continue;
        const key = `${String(item.chainId).toLowerCase()}:${address.toLowerCase()}`;
        if (!seen.has(key)) discovered.set(key, { address, chainId: String(item.chainId).toLowerCase(), source: label });
      }
    }
    const unseen = [...discovered.entries()].filter(([key]) => !seen.has(key));
    // Bound work per cycle. Addresses beyond this cycle's cap remain unseen and can be picked up next poll.
    const queued = unseen.slice(0, 300);
    for (const [key] of queued) seen.add(key);
    log('info', `Discovery complete: ${discovered.size} unique addresses in this cycle; ${queued.length} unseen token/chain pairs queued${unseen.length > queued.length ? `; ${unseen.length - queued.length} deferred to a later poll` : ''}.`);
    // Hydration endpoint batches can mix chains, so addresses are chunked as specified.
    await processAddressBatch(queued.map(([,item]) => item.address));
    lastPollAt = new Date().toISOString();
  } catch (e) {
    log('error', `Unexpected discovery-cycle error: ${e.stack || e.message}`);
  } finally { pollRunning = false; }
}
function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(data) });
  res.end(data);
}
function cors(req, res) {
  const origin = req.headers.origin;
  if (CONFIG.corsOrigin && origin === CONFIG.corsOrigin) res.setHeader('access-control-allow-origin', CONFIG.corsOrigin);
  else if (!CONFIG.corsOrigin) res.setHeader('access-control-allow-origin', '*');
  res.setHeader('vary', 'Origin');
  res.setHeader('access-control-allow-methods', 'GET, OPTIONS');
  res.setHeader('access-control-allow-headers', 'authorization, content-type');
}
function authorized(req) {
  if (!CONFIG.bearerToken) return true;
  const header = String(req.headers.authorization || '');
  return header === `Bearer ${CONFIG.bearerToken}`;
}
const server = http.createServer((req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (!url.pathname.startsWith('/api/')) {
    return sendJson(res, 404, { error: 'Not found', hint: 'This process serves the worker API only. Host index.html on GitHub Pages.' });
  }
  if (!authorized(req)) return sendJson(res, 401, { error: 'Unauthorized', hint: 'Set Authorization: Bearer <API_BEARER_TOKEN>.' });
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'Method not allowed' });
  if (url.pathname === '/api/status') {
    return sendJson(res, 200, {
      status: 'ok', pollIntervalMs: CONFIG.pollIntervalMs, lastPollAt,
      discoveredCount: seen.size, tokenCount: tokenStore.size, pollRunning,
      securityProviders: ['RugCheck', 'GoPlus'], dexscreener: true,
    });
  }
  if (url.pathname === '/api/tokens') {
    const tokens = [...tokenStore.values()].sort((a,b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    return sendJson(res, 200, { tokens, discoveredCount: seen.size, lastPollAt });
  }
  if (url.pathname === '/api/logs') {
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 100));
    return sendJson(res, 200, { logs: logs.slice(-limit) });
  }
  return sendJson(res, 404, { error: 'Unknown API endpoint' });
});
server.listen(CONFIG.port, CONFIG.host, () => {
  log('success', `Coins Alert worker listening at http://${CONFIG.host}:${CONFIG.port}`);
  log('info', `Discovery poll interval: ${CONFIG.pollIntervalMs} ms. DEX Screener is the only token discovery/market-data source.`);
  log('info', `Default market gates: liquidity >= $${CONFIG.minLiquidityUsd}; FDV <= $${CONFIG.maxFdvUsd}; pair age <= ${CONFIG.maxPairAgeHours} hours; audit pass required=${CONFIG.requireAuditPass}.`);
  pollOnce();
  const timer = setInterval(pollOnce, CONFIG.pollIntervalMs);
  const shutdown = signal => {
    if (stopped) return;
    stopped = true; clearInterval(timer);
    log('warn', `Received ${signal}; shutting down.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
});
