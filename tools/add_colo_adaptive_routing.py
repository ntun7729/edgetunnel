from pathlib import Path

p = Path('worker.js')
s = p.read_text()

old = """const ROUTE_CACHE_MAX = 512;
const ROUTE_CACHE = new Map();
"""
new = """const ROUTE_CACHE_MAX = 512;
const ROUTE_CACHE = new Map();
const CF_PERF_STATS_MAX = 2048;
const CF_PERF_STATS = new Map();
const CF_ROUTE_USES_MAX = 2048;
const CF_ROUTE_USES = new Map();
const DEFAULT_CF_EXPLORE_EVERY = 8;
"""
if old not in s:
    raise SystemExit('constants anchor missing')
s = s.replace(old, new, 1)

old = """function getCachedRoute(host) {
  const key = String(host || '').trim().toLowerCase();
  const entry = ROUTE_CACHE.get(key);
  if (!entry) return null;
  if (entry.expires <= Date.now()) {
    ROUTE_CACHE.delete(key);
    return null;
  }
  return entry;
}

function parseFallbackPool(value) {
"""
new = r'''function getCachedRoute(host) {
  const key = String(host || '').trim().toLowerCase();
  const entry = ROUTE_CACHE.get(key);
  if (!entry) return null;
  if (entry.expires <= Date.now()) {
    ROUTE_CACHE.delete(key);
    return null;
  }
  return entry;
}

function requestLocation(request) {
  const colo = String(request?.cf?.colo || '').trim().toUpperCase();
  const placement = String(request?.headers?.get?.('cf-placement') || '').trim();
  return {
    colo: colo || '-',
    placement: placement || '-',
    key: placement || colo || 'UNKNOWN',
  };
}

function perfKey(locationKey, ip) {
  return `${String(locationKey || 'UNKNOWN')}|${String(ip || '')}`;
}

function getCfPerf(locationKey, ip) {
  return CF_PERF_STATS.get(perfKey(locationKey, ip)) || null;
}

function touchCfPerf(locationKey, ip) {
  const key = perfKey(locationKey, ip);
  let stat = CF_PERF_STATS.get(key);
  if (!stat) {
    stat = {
      ip,
      location: String(locationKey || 'UNKNOWN'),
      successes: 0,
      failures: 0,
      consecutiveFailures: 0,
      ewmaMs: null,
      lastMs: null,
      lastSuccess: 0,
      lastFailure: 0,
      lastError: '',
    };
    CF_PERF_STATS.set(key, stat);
  } else {
    CF_PERF_STATS.delete(key);
    CF_PERF_STATS.set(key, stat);
  }
  while (CF_PERF_STATS.size > CF_PERF_STATS_MAX) {
    const oldest = CF_PERF_STATS.keys().next().value;
    if (oldest === undefined) break;
    CF_PERF_STATS.delete(oldest);
  }
  return stat;
}

function recordCfSuccess(locationKey, ip, elapsedMs) {
  if (!ip) return;
  const stat = touchCfPerf(locationKey, ip);
  const ms = Math.max(0, Number(elapsedMs) || 0);
  stat.successes += 1;
  stat.consecutiveFailures = 0;
  stat.lastMs = ms;
  stat.ewmaMs = stat.ewmaMs == null ? ms : (stat.ewmaMs * 0.72) + (ms * 0.28);
  stat.lastSuccess = Date.now();
  stat.lastError = '';
}

function recordCfFailure(locationKey, ip, error = '') {
  if (!ip) return;
  const stat = touchCfPerf(locationKey, ip);
  stat.failures += 1;
  stat.consecutiveFailures += 1;
  stat.lastFailure = Date.now();
  stat.lastError = String(error || '').slice(0, 120);
}

function cfCandidateScore(stat) {
  if (!stat) return 100000;
  const total = stat.successes + stat.failures;
  if (!stat.successes) return 50000 + stat.failures * 5000;
  const failureRate = total ? stat.failures / total : 0;
  return (stat.ewmaMs ?? 1000) + failureRate * 1200 + stat.consecutiveFailures * 1600;
}

function bumpRouteUse(locationKey, host) {
  const key = `${String(locationKey || 'UNKNOWN')}|${String(host || '').toLowerCase()}`;
  const next = (CF_ROUTE_USES.get(key) || 0) + 1;
  CF_ROUTE_USES.delete(key);
  CF_ROUTE_USES.set(key, next);
  while (CF_ROUTE_USES.size > CF_ROUTE_USES_MAX) {
    const oldest = CF_ROUTE_USES.keys().next().value;
    if (oldest === undefined) break;
    CF_ROUTE_USES.delete(oldest);
  }
  return next;
}

function rankFallbackCandidates(host, pool, preferredIp = '', locationKey = 'UNKNOWN', exploreEvery = DEFAULT_CF_EXPLORE_EVERY) {
  const unique = [...new Set((pool?.length ? pool : CF_FALLBACK_IPS).filter(Boolean))];
  if (!unique.length) return [];

  const seed = hashText(`${locationKey}|${host}`) % unique.length;
  const deterministic = unique.map((_, index) => unique[(seed + index) % unique.length]);
  const orderIndex = new Map(deterministic.map((ip, index) => [ip, index]));
  const scored = deterministic.map((ip) => ({ ip, stat: getCfPerf(locationKey, ip) }));
  scored.sort((a, b) => {
    const aKnown = a.stat?.successes > 0 ? 0 : 1;
    const bKnown = b.stat?.successes > 0 ? 0 : 1;
    if (aKnown !== bKnown) return aKnown - bKnown;
    const delta = cfCandidateScore(a.stat) - cfCandidateScore(b.stat);
    if (delta) return delta;
    return orderIndex.get(a.ip) - orderIndex.get(b.ip);
  });

  let ordered = scored.map((entry) => entry.ip);
  if (preferredIp && ordered.includes(preferredIp)) {
    const preferredStat = getCfPerf(locationKey, preferredIp);
    if (!preferredStat || preferredStat.consecutiveFailures < 2) {
      ordered = [preferredIp, ...ordered.filter((ip) => ip !== preferredIp)];
    }
  }

  const useCount = bumpRouteUse(locationKey, host);
  if (exploreEvery > 0 && useCount % exploreEvery === 0 && ordered.length > 1) {
    const exploration = [...ordered].sort((a, b) => {
      const sa = getCfPerf(locationKey, a);
      const sb = getCfPerf(locationKey, b);
      const samplesA = (sa?.successes || 0) + (sa?.failures || 0);
      const samplesB = (sb?.successes || 0) + (sb?.failures || 0);
      if (samplesA !== samplesB) return samplesA - samplesB;
      return orderIndex.get(a) - orderIndex.get(b);
    })[0];
    if (exploration && exploration !== ordered[0]) {
      ordered = [exploration, ...ordered.filter((ip) => ip !== exploration)];
    }
  }
  return ordered;
}

function cfPerfSnapshot(locationKey, pool) {
  const candidates = [...new Set((pool?.length ? pool : CF_FALLBACK_IPS).filter(Boolean))];
  return candidates.map((ip) => {
    const stat = getCfPerf(locationKey, ip);
    return {
      ip,
      samples: (stat?.successes || 0) + (stat?.failures || 0),
      successes: stat?.successes || 0,
      failures: stat?.failures || 0,
      consecutiveFailures: stat?.consecutiveFailures || 0,
      ewmaMs: stat?.ewmaMs == null ? null : Math.round(stat.ewmaMs * 10) / 10,
      lastMs: stat?.lastMs == null ? null : Math.round(stat.lastMs * 10) / 10,
      score: Math.round(cfCandidateScore(stat) * 10) / 10,
      lastSuccess: stat?.lastSuccess || 0,
      lastFailure: stat?.lastFailure || 0,
      lastError: stat?.lastError || '',
    };
  }).sort((a, b) => a.score - b.score || b.successes - a.successes || a.ip.localeCompare(b.ip));
}

function parseFallbackPool(value) {
'''
if old not in s:
    raise SystemExit('cache helper anchor missing')
s = s.replace(old, new, 1)

old = """function buildFallbackCandidates(host, pool, preferredIp = '') {
  const unique = [...new Set((pool?.length ? pool : CF_FALLBACK_IPS).filter(Boolean))];
  if (!unique.length) return [];
  const start = hashText(host) % unique.length;
  const ordered = unique.map((_, index) => unique[(start + index) % unique.length]);
  if (preferredIp && ordered.includes(preferredIp)) {
    return [preferredIp, ...ordered.filter((ip) => ip !== preferredIp)];
  }
  return ordered;
}

"""
if old not in s:
    raise SystemExit('old buildFallbackCandidates missing')
s = s.replace(old, '', 1)

old = """  let fallbackAttempted = false;
  let fallbackAttempt = -1;
  let activeFallbackIp = '';
  let switching = false;
"""
new = """  let fallbackAttempted = false;
  let fallbackAttempt = -1;
  let activeFallbackIp = '';
  let activeFallbackStartMs = 0;
  let switching = false;
"""
if old not in s:
    raise SystemExit('tcp state anchor missing')
s = s.replace(old, new, 1)

old = """  const cachedRoute = getCachedRoute(host);
  const immediateCfHint = canCfFallback && (
"""
new = """  const cachedRoute = getCachedRoute(host);
  const locationKey = requestMeta.locationKey || requestMeta.colo || 'UNKNOWN';
  const immediateCfHint = canCfFallback && (
"""
if old not in s:
    raise SystemExit('cached route anchor missing')
s = s.replace(old, new, 1)

old = """  const fallbackCandidates = buildFallbackCandidates(host, config.cfFallbackIps, cachedRoute?.candidateIp || '');
"""
new = """  const fallbackCandidates = rankFallbackCandidates(
    host,
    config.cfFallbackIps,
    cachedRoute?.candidateIp || '',
    locationKey,
    config.cfExploreEvery,
  );
"""
if old not in s:
    raise SystemExit('fallback candidate anchor missing')
s = s.replace(old, new, 1)

old = """    socket = null;
    activeFallbackIp = '';
  };
"""
new = """    socket = null;
    activeFallbackIp = '';
    activeFallbackStartMs = 0;
  };
"""
if old not in s:
    raise SystemExit('closeCurrent anchor missing')
s = s.replace(old, new, 1)

old = """  const markFirstByte = (isFallback, candidateIp = '') => {
    if (firstByteSeen) return false;
    firstByteSeen = true;
    clearFirstByteTimer();
    cacheRoute(host, isFallback ? 'cf' : 'direct', isFallback ? candidateIp : '');
    replay.length = 0;
    replayBytes = 0;
    return true;
  };
"""
new = """  const markFirstByte = (isFallback, candidateIp = '') => {
    if (firstByteSeen) return false;
    firstByteSeen = true;
    clearFirstByteTimer();
    if (isFallback && candidateIp) {
      const elapsedMs = activeFallbackStartMs ? Math.max(0, performance.now() - activeFallbackStartMs) : 0;
      recordCfSuccess(locationKey, candidateIp, elapsedMs);
      log('CF candidate success', `colo=${locationKey}`, candidateIp, `${Math.round(elapsedMs)}ms`);
    }
    cacheRoute(host, isFallback ? 'cf' : 'direct', isFallback ? candidateIp : '');
    replay.length = 0;
    replayBytes = 0;
    return true;
  };
"""
if old not in s:
    raise SystemExit('markFirstByte anchor missing')
s = s.replace(old, new, 1)

old = """  const openTarget = async (targetHost, label, isFallback, timeoutMs = config.connectTimeoutMs) => {
    const myGeneration = ++generation;
    const newSocket = await connectWithTimeout(connector, targetHost, port, timeoutMs, config.connectRace);
"""
new = """  const openTarget = async (targetHost, label, isFallback, timeoutMs = config.connectTimeoutMs) => {
    const myGeneration = ++generation;
    const attemptStartedAt = performance.now();
    const newSocket = await connectWithTimeout(connector, targetHost, port, timeoutMs, config.connectRace);
"""
if old not in s:
    raise SystemExit('openTarget start anchor missing')
s = s.replace(old, new, 1)

old = """    replayedThroughId = -1;
    activeFallbackIp = isFallback ? targetHost : '';
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost, `race=${config.connectRace}`);
"""
new = """    replayedThroughId = -1;
    activeFallbackIp = isFallback ? targetHost : '';
    activeFallbackStartMs = isFallback ? attemptStartedAt : 0;
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost, `race=${config.connectRace}`, `colo=${locationKey}`);
"""
if old not in s:
    raise SystemExit('openTarget active fallback anchor missing')
s = s.replace(old, new, 1)

old = """  async function triggerCfFallback(reason, advance = false) {
    if (!canCfFallback || firstByteSeen || closed) {
      throw new Error('Cloudflare fallback unavailable');
    }
    if (!fallbackAttempted) {
"""
new = """  async function triggerCfFallback(reason, advance = false) {
    if (!canCfFallback || firstByteSeen || closed) {
      throw new Error('Cloudflare fallback unavailable');
    }
    if (advance && activeFallbackIp) {
      recordCfFailure(locationKey, activeFallbackIp, reason);
      log('CF candidate failure', `colo=${locationKey}`, activeFallbackIp, reason);
    }
    if (!fallbackAttempted) {
"""
if old not in s:
    raise SystemExit('trigger fallback anchor missing')
s = s.replace(old, new, 1)

old = """        } catch (error) {
          lastError = error;
          log('CF fallback candidate failed', fallbackIp, error?.message || error);
          fallbackAttempt += 1;
"""
new = """        } catch (error) {
          lastError = error;
          recordCfFailure(locationKey, fallbackIp, error?.message || error);
          log('CF fallback candidate failed', `colo=${locationKey}`, fallbackIp, error?.message || error);
          fallbackAttempt += 1;
"""
if old not in s:
    raise SystemExit('fallback catch anchor missing')
s = s.replace(old, new, 1)

old = """    cfClassify: !/^(0|false|off|no)$/i.test(String(env.CF_CLASSIFY ?? 'on')),
    cfFallbackIps: parseFallbackPool(env.CF_FALLBACK_IPS).length ? parseFallbackPool(env.CF_FALLBACK_IPS) : CF_FALLBACK_IPS,
"""
new = """    cfClassify: !/^(0|false|off|no)$/i.test(String(env.CF_CLASSIFY ?? 'on')),
    cfExploreEvery: clampInteger(env.CF_EXPLORE_EVERY, DEFAULT_CF_EXPLORE_EVERY, 0, 64),
    cfFallbackIps: parseFallbackPool(env.CF_FALLBACK_IPS).length ? parseFallbackPool(env.CF_FALLBACK_IPS) : CF_FALLBACK_IPS,
"""
if old not in s:
    raise SystemExit('buildConfig anchor missing')
s = s.replace(old, new, 1)

old = """  const log = createLogger(env, request);
  const connector = getConnector(request);
  const requestMeta = {
    connectorName: hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets',
    supportsCloudflareFallback: hasRequestFetcher(request),
  };
"""
new = """  const log = createLogger(env, request);
  const connector = getConnector(request);
  const location = requestLocation(request);
  const requestMeta = {
    connectorName: hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets',
    supportsCloudflareFallback: hasRequestFetcher(request),
    colo: location.colo,
    placement: location.placement,
    locationKey: location.key,
  };
"""
if old not in s:
    raise SystemExit('requestMeta anchor missing')
s = s.replace(old, new, 1)

old = """    if (url.pathname === '/health') {
      const healthy = users.length > 0;
      if (url.searchParams.get('detail') === '1') {
        const connectorName = hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets';
        return textResponse(`${healthy ? 'ok' : 'misconfigured'}\\nconnector=${connectorName}\\ncf_fallback=${config.cfFallbackMode}\\ncf_first_byte_ms=${config.cfFirstByteMs}\\ncf_fallback_first_byte_ms=${config.cfFallbackFirstByteMs}\\ncf_classify=${config.cfClassify ? 'on' : 'off'}\\nconnect_race=${config.connectRace}\\nws_binary=arraybuffer`, healthy ? 200 : 503);
      }
      return textResponse(healthy ? 'ok' : 'misconfigured', healthy ? 200 : 503);
    }
"""
new = """    if (url.pathname === '/health') {
      const healthy = users.length > 0;
      if (url.searchParams.get('detail') === '1') {
        const connectorName = hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets';
        const location = requestLocation(request);
        const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
        const best = ranked.find((entry) => entry.successes > 0);
        return textResponse(`${healthy ? 'ok' : 'misconfigured'}\\nconnector=${connectorName}\\ncolo=${location.colo}\\nplacement=${location.placement}\\nlocation_key=${location.key}\\ncf_fallback=${config.cfFallbackMode}\\ncf_first_byte_ms=${config.cfFirstByteMs}\\ncf_fallback_first_byte_ms=${config.cfFallbackFirstByteMs}\\ncf_classify=${config.cfClassify ? 'on' : 'off'}\\ncf_explore_every=${config.cfExploreEvery}\\ncf_best_candidate=${best?.ip || '-'}\\ncf_best_ewma_ms=${best?.ewmaMs ?? '-'}\\nconnect_race=${config.connectRace}\\nws_binary=arraybuffer`, healthy ? 200 : 503);
      }
      return textResponse(healthy ? 'ok' : 'misconfigured', healthy ? 200 : 503);
    }
"""
if old not in s:
    raise SystemExit('health block anchor missing')
s = s.replace(old, new, 1)

anchor = """    if (url.pathname === '/config') {
      const configuredToken = String(env.CONFIG_TOKEN || '').trim();
      const suppliedToken = url.searchParams.get('token') || '';
      if (!configuredToken || !constantTimeTextEqual(configuredToken, suppliedToken)) return textResponse('Not found', 404);
      return textResponse(configText(env, request, users, config));
    }
"""
addition = anchor + """    if (url.pathname === '/route-stats') {
      const configuredToken = String(env.CONFIG_TOKEN || '').trim();
      const suppliedToken = url.searchParams.get('token') || '';
      if (!configuredToken || !constantTimeTextEqual(configuredToken, suppliedToken)) return textResponse('Not found', 404);
      const location = requestLocation(request);
      const ranked = cfPerfSnapshot(location.key, config.cfFallbackIps);
      return new Response(JSON.stringify({
        scope: 'current Worker isolate',
        colo: location.colo,
        placement: location.placement,
        locationKey: location.key,
        exploreEvery: config.cfExploreEvery,
        routeCacheEntries: ROUTE_CACHE.size,
        perfEntries: CF_PERF_STATS.size,
        candidates: ranked,
      }, null, 2), {
        status: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        },
      });
    }
"""
if anchor not in s:
    raise SystemExit('config endpoint anchor missing')
s = s.replace(anchor, addition, 1)

old = """// Optional env: PATH, DOH_URL, CONNECT_TIMEOUT_MS, IDLE_TIMEOUT_MS, HOST, DEBUG, CONFIG_TOKEN.
"""
new = """// Optional env: PATH, DOH_URL, CONNECT_TIMEOUT_MS, IDLE_TIMEOUT_MS, HOST, DEBUG, CONFIG_TOKEN,
// CF_FALLBACK, CF_FALLBACK_IPS, CF_FIRST_BYTE_MS, CF_FALLBACK_FIRST_BYTE_MS,
// CF_CLASSIFY, CF_CLASSIFY_TIMEOUT_MS, CF_EXPLORE_EVERY, CONNECT_RACE.
"""
if old not in s:
    raise SystemExit('header comment anchor missing')
s = s.replace(old, new, 1)

p.write_text(s)
print('patched colo-adaptive routing')
