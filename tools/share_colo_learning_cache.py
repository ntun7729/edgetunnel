from pathlib import Path

p = Path('worker.js')
s = p.read_text()

old = """const CF_ROUTE_USES_MAX = 2048;
const CF_ROUTE_USES = new Map();
const DEFAULT_CF_EXPLORE_EVERY = 8;
"""
new = """const CF_ROUTE_USES_MAX = 2048;
const CF_ROUTE_USES = new Map();
const DEFAULT_CF_EXPLORE_EVERY = 8;
const SHARED_PERF_TTL_SECONDS = 1800;
const SHARED_ROUTE_TTL_SECONDS = 900;
const CF_HYDRATED_LOCATIONS = new Set();
const CF_HYDRATE_PROMISES = new Map();
let SHARED_ROUTING_CACHE_PROMISE = null;
"""
if old not in s:
    raise SystemExit('constants anchor missing')
s = s.replace(old, new, 1)

old = """function perfKey(locationKey, ip) {
  return `${String(locationKey || 'UNKNOWN')}|${String(ip || '')}`;
}
"""
new = r'''function perfKey(locationKey, ip) {
  return `${String(locationKey || 'UNKNOWN')}|${String(ip || '')}`;
}

function sharedCacheKey(kind, locationKey, id) {
  const location = encodeURIComponent(String(locationKey || 'UNKNOWN'));
  const value = encodeURIComponent(String(id || ''));
  return new Request(`https://scratch-vless-cache.invalid/${kind}/${location}/${value}`);
}

async function sharedRoutingCache() {
  if (typeof caches === 'undefined' || typeof caches.open !== 'function') return null;
  if (!SHARED_ROUTING_CACHE_PROMISE) {
    SHARED_ROUTING_CACHE_PROMISE = caches.open('scratch-vless-routing-v1').catch(() => null);
  }
  return SHARED_ROUTING_CACHE_PROMISE;
}

async function readSharedJson(kind, locationKey, id) {
  const cache = await sharedRoutingCache();
  if (!cache) return null;
  const response = await cache.match(sharedCacheKey(kind, locationKey, id));
  if (!response) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function writeSharedJson(kind, locationKey, id, value, ttlSeconds) {
  const cache = await sharedRoutingCache();
  if (!cache) return false;
  const response = new Response(JSON.stringify(value), {
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${Math.max(60, Number(ttlSeconds) || 60)}`,
    },
  });
  await cache.put(sharedCacheKey(kind, locationKey, id), response);
  return true;
}
'''
if old not in s:
    raise SystemExit('perfKey anchor missing')
s = s.replace(old, new, 1)

old = """      lastFailure: 0,
      lastError: '',
    };
"""
new = """      lastFailure: 0,
      lastError: '',
      updatedAt: 0,
    };
"""
if old not in s:
    raise SystemExit('stat init anchor missing')
s = s.replace(old, new, 1)

old = """  stat.lastSuccess = Date.now();
  stat.lastError = '';
}
"""
new = """  stat.lastSuccess = Date.now();
  stat.updatedAt = stat.lastSuccess;
  stat.lastError = '';
}
"""
if old not in s:
    raise SystemExit('success update anchor missing')
s = s.replace(old, new, 1)

old = """  stat.lastFailure = Date.now();
  stat.lastError = String(error || '').slice(0, 120);
}
"""
new = """  stat.lastFailure = Date.now();
  stat.updatedAt = stat.lastFailure;
  stat.lastError = String(error || '').slice(0, 120);
}

async function persistCfPerfShared(locationKey, ip) {
  const stat = getCfPerf(locationKey, ip);
  if (!stat) return false;
  return writeSharedJson('perf', locationKey, ip, stat, SHARED_PERF_TTL_SECONDS);
}

function mergeSharedPerf(locationKey, ip, stored) {
  if (!stored || stored.ip !== ip) return;
  const stat = touchCfPerf(locationKey, ip);
  const localUpdated = Number(stat.updatedAt || 0);
  const storedUpdated = Number(stored.updatedAt || stored.lastSuccess || stored.lastFailure || 0);
  if (localUpdated > storedUpdated) return;
  stat.successes = Math.max(0, Number(stored.successes) || 0);
  stat.failures = Math.max(0, Number(stored.failures) || 0);
  stat.consecutiveFailures = Math.max(0, Number(stored.consecutiveFailures) || 0);
  stat.ewmaMs = stored.ewmaMs == null ? null : Math.max(0, Number(stored.ewmaMs) || 0);
  stat.lastMs = stored.lastMs == null ? null : Math.max(0, Number(stored.lastMs) || 0);
  stat.lastSuccess = Math.max(0, Number(stored.lastSuccess) || 0);
  stat.lastFailure = Math.max(0, Number(stored.lastFailure) || 0);
  stat.lastError = String(stored.lastError || '').slice(0, 120);
  stat.updatedAt = storedUpdated;
}

async function hydrateCfPerfShared(locationKey, pool, log) {
  const key = String(locationKey || 'UNKNOWN');
  if (CF_HYDRATED_LOCATIONS.has(key)) return true;
  if (CF_HYDRATE_PROMISES.has(key)) return CF_HYDRATE_PROMISES.get(key);

  const promise = (async () => {
    const candidates = [...new Set((pool?.length ? pool : CF_FALLBACK_IPS).filter(Boolean))];
    try {
      const rows = await Promise.all(candidates.map(async (ip) => [ip, await readSharedJson('perf', key, ip)]));
      for (const [ip, stored] of rows) mergeSharedPerf(key, ip, stored);
      CF_HYDRATED_LOCATIONS.add(key);
      return true;
    } catch (error) {
      log?.('shared CF perf hydrate skipped', error?.message || error);
      return false;
    } finally {
      CF_HYDRATE_PROMISES.delete(key);
    }
  })();
  CF_HYDRATE_PROMISES.set(key, promise);
  return promise;
}

async function getSharedRoute(locationKey, host) {
  const value = await readSharedJson('route', locationKey, String(host || '').toLowerCase());
  if (!value || !['cf', 'direct', 'cf-hint', 'not-cf'].includes(value.route)) return null;
  return {
    route: value.route,
    candidateIp: String(value.candidateIp || ''),
  };
}

async function persistSharedRoute(locationKey, host, route, candidateIp = '') {
  const ttl = route === 'cf' ? SHARED_ROUTE_TTL_SECONDS : Math.min(SHARED_ROUTE_TTL_SECONDS, 300);
  return writeSharedJson('route', locationKey, String(host || '').toLowerCase(), {
    route,
    candidateIp: candidateIp || '',
    updatedAt: Date.now(),
  }, ttl);
}
"""
if old not in s:
    raise SystemExit('failure update anchor missing')
s = s.replace(old, new, 1)

old = """  const forceCfFallback = canCfFallback && config.cfFallbackMode === 'force';
  const cachedRoute = getCachedRoute(host);
  const locationKey = requestMeta.locationKey || requestMeta.colo || 'UNKNOWN';
  const immediateCfHint = canCfFallback && (
"""
new = """  const forceCfFallback = canCfFallback && config.cfFallbackMode === 'force';
  const locationKey = requestMeta.locationKey || requestMeta.colo || 'UNKNOWN';
  if (canCfFallback) await hydrateCfPerfShared(locationKey, config.cfFallbackIps, log);
  let cachedRoute = getCachedRoute(host);
  if (canCfFallback && !cachedRoute) {
    try {
      const sharedRoute = await getSharedRoute(locationKey, host);
      if (sharedRoute) {
        cacheRoute(host, sharedRoute.route, sharedRoute.candidateIp);
        cachedRoute = getCachedRoute(host);
        log('shared route hit', `colo=${locationKey}`, host, sharedRoute.route, sharedRoute.candidateIp || '-');
      }
    } catch (error) {
      log('shared route lookup skipped', error?.message || error);
    }
  }
  const immediateCfHint = canCfFallback && (
"""
if old not in s:
    raise SystemExit('tcp cached route anchor missing')
s = s.replace(old, new, 1)

old = """      recordCfSuccess(locationKey, candidateIp, elapsedMs);
      log('CF candidate success', `colo=${locationKey}`, candidateIp, `${Math.round(elapsedMs)}ms`);
    }
    cacheRoute(host, isFallback ? 'cf' : 'direct', isFallback ? candidateIp : '');
    replay.length = 0;
"""
new = """      recordCfSuccess(locationKey, candidateIp, elapsedMs);
      requestMeta.defer?.(persistCfPerfShared(locationKey, candidateIp).catch((error) => log('shared perf write skipped', error?.message || error)));
      log('CF candidate success', `colo=${locationKey}`, candidateIp, `${Math.round(elapsedMs)}ms`);
    }
    const learnedRoute = isFallback ? 'cf' : 'direct';
    const learnedCandidate = isFallback ? candidateIp : '';
    cacheRoute(host, learnedRoute, learnedCandidate);
    requestMeta.defer?.(persistSharedRoute(locationKey, host, learnedRoute, learnedCandidate).catch((error) => log('shared route write skipped', error?.message || error)));
    replay.length = 0;
"""
if old not in s:
    raise SystemExit('markFirstByte persist anchor missing')
s = s.replace(old, new, 1)

old = """      recordCfFailure(locationKey, activeFallbackIp, reason);
      log('CF candidate failure', `colo=${locationKey}`, activeFallbackIp, reason);
"""
new = """      recordCfFailure(locationKey, activeFallbackIp, reason);
      requestMeta.defer?.(persistCfPerfShared(locationKey, activeFallbackIp).catch((error) => log('shared perf write skipped', error?.message || error)));
      log('CF candidate failure', `colo=${locationKey}`, activeFallbackIp, reason);
"""
if old not in s:
    raise SystemExit('active fallback failure anchor missing')
s = s.replace(old, new, 1)

old = """          recordCfFailure(locationKey, fallbackIp, error?.message || error);
          log('CF fallback candidate failed', `colo=${locationKey}`, fallbackIp, error?.message || error);
"""
new = """          recordCfFailure(locationKey, fallbackIp, error?.message || error);
          requestMeta.defer?.(persistCfPerfShared(locationKey, fallbackIp).catch((writeError) => log('shared perf write skipped', writeError?.message || writeError)));
          log('CF fallback candidate failed', `colo=${locationKey}`, fallbackIp, error?.message || error);
"""
if old not in s:
    raise SystemExit('candidate failure anchor missing')
s = s.replace(old, new, 1)

old = """    locationKey: location.key,
  };
"""
new = """    locationKey: location.key,
    defer: (promise) => {
      if (!promise) return;
      try {
        if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(promise);
        else Promise.resolve(promise).catch(() => {});
      } catch {}
    },
  };
"""
if old not in s:
    raise SystemExit('requestMeta anchor missing')
s = s.replace(old, new, 1)

old = """      const location = requestLocation(request);
      const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
      return new Response(JSON.stringify({
        scope: 'current Worker isolate',
"""
new = """      const location = requestLocation(request);
      await hydrateCfPerfShared(location.key, config.cfFallbackIps);
      const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
      return new Response(JSON.stringify({
        scope: 'colo-local Cache API + current isolate hot cache',
"""
if old not in s:
    raise SystemExit('route stats anchor missing')
s = s.replace(old, new, 1)

old = """        routeCacheEntries: ROUTE_CACHE.size,
        perfEntries: CF_PERF_STATS.size,
        candidates: ranked,
"""
new = """        sharedCache: typeof caches !== 'undefined' && typeof caches.open === 'function' ? 'enabled' : 'unavailable',
        routeCacheEntriesCurrentIsolate: ROUTE_CACHE.size,
        perfEntriesCurrentIsolate: CF_PERF_STATS.size,
        candidates: ranked,
"""
if old not in s:
    raise SystemExit('route stats body anchor missing')
s = s.replace(old, new, 1)

old = """        const connectorName = hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets';
        const location = requestLocation(request);
        const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
        const best = ranked.find((entry) => entry.successes > 0);
"""
new = """        const connectorName = hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets';
        const location = requestLocation(request);
        await hydrateCfPerfShared(location.key, config.cfFallbackIps);
        const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
        const best = ranked.find((entry) => entry.successes > 0);
"""
if old not in s:
    raise SystemExit('health ranking anchor missing')
s = s.replace(old, new, 1)

old = """cf_best_ewma_ms=${best?.ewmaMs ?? '-'}\\nconnect_race=${config.connectRace}\\nws_binary=arraybuffer`, healthy ? 200 : 503);
"""
new = """cf_best_ewma_ms=${best?.ewmaMs ?? '-'}\\nlearning_scope=colo-local-cache\\nconnect_race=${config.connectRace}\\nws_binary=arraybuffer`, healthy ? 200 : 503);
"""
if old not in s:
    raise SystemExit('health learning scope anchor missing')
s = s.replace(old, new, 1)

p.write_text(s)
print('patched colo-local shared learning cache')
