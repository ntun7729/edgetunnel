from pathlib import Path

p = Path('worker.js')
s = p.read_text()

old_constants = """const MAX_BUFFERED_AMOUNT = 8 * 1024 * 1024;
const CF_FALLBACK_IPS = [
  '172.71.218.190', '162.158.228.87', '162.158.189.134', '162.158.26.63',
  '162.158.25.86', '162.158.29.216', '162.158.218.160', '162.158.227.214',
  '172.69.118.198', '172.69.119.150',
];
const DEFAULT_CF_FIRST_BYTE_MS = 1200;
const MAX_REPLAY_BYTES = 1024 * 1024;
"""
new_constants = """const MAX_BUFFERED_AMOUNT = 2 * 1024 * 1024;
const CF_FALLBACK_IPS = [
  '172.71.218.190', '162.158.228.87', '162.158.189.134', '162.158.26.63',
  '162.158.25.86', '162.158.29.216', '162.158.218.160', '162.158.227.214',
  '172.69.118.198', '172.69.119.150',
];
const CF_IPV4_CIDRS = [
  '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '104.16.0.0/13',
  '104.24.0.0/14', '108.162.192.0/18', '131.0.72.0/22', '141.101.64.0/18',
  '162.158.0.0/15', '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
  '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
];
const KNOWN_CF_HOST_SUFFIXES = [
  'cloudflare.com', 'cloudflare-dns.com', 'one.one.one.one', 'workers.dev',
  'pages.dev', 'trycloudflare.com', 'cloudflareaccess.com', 'cloudflareclient.com',
];
const DEFAULT_CF_FIRST_BYTE_MS = 1200;
const DEFAULT_CF_FALLBACK_FIRST_BYTE_MS = 600;
const DEFAULT_CF_CLASSIFY_TIMEOUT_MS = 250;
const DEFAULT_CONNECT_RACE = 2;
const WS_DOWNLOAD_BATCH_BYTES = 32 * 1024;
const WS_DOWNLOAD_DIRECT_THRESHOLD = 16 * 1024;
const WS_DOWNLOAD_BATCH_DELAY_MS = 1;
const MAX_REPLAY_BYTES = 1024 * 1024;
const ROUTE_CACHE_MAX = 512;
const ROUTE_CACHE = new Map();
"""
if old_constants not in s:
    raise SystemExit('constants anchor missing')
s = s.replace(old_constants, new_constants, 1)

old_helpers = """function selectCfFallback(host, attempt = 0) {
  let hash = 2166136261;
  const text = String(host || 'cf');
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return CF_FALLBACK_IPS[(hash + attempt) % CF_FALLBACK_IPS.length];
}

function wait(ms, value, reject = false) {
  return new Promise((resolve, rejectFn) => setTimeout(() => (reject ? rejectFn(value) : resolve(value)), ms));
}

async function connectWithTimeout(connector, host, port, timeoutMs) {
  if (isBlockedDestination(host, port)) throw new Error('destination blocked by policy');
  const socket = connector({ hostname: host, port }, { allowHalfOpen: false });
  try {
    await Promise.race([
      socket.opened,
      wait(timeoutMs, new Error('TCP connect timeout'), true),
    ]);
    return socket;
  } catch (error) {
    try { socket.close(); } catch {}
    throw error;
  }
}
"""
new_helpers = r'''function hashText(text) {
  let hash = 2166136261;
  const value = String(text || 'cf');
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0;
}

function parseIpv4(host) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(host || '').trim());
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  if (octets.some((value) => value < 0 || value > 255)) return null;
  return octets;
}

function ipv4ToInt(host) {
  const octets = parseIpv4(host);
  if (!octets) return null;
  return ((((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0);
}

function ipv4InCidr(host, cidr) {
  const ip = ipv4ToInt(host);
  if (ip === null) return false;
  const [networkText, bitsText] = String(cidr).split('/');
  const network = ipv4ToInt(networkText);
  const bits = Number(bitsText);
  if (network === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((network & mask) >>> 0);
}

function isCloudflareIpv4(host) {
  return CF_IPV4_CIDRS.some((cidr) => ipv4InCidr(host, cidr));
}

function isKnownCloudflareHost(host) {
  const value = String(host || '').trim().toLowerCase().replace(/\.$/, '');
  if (!value) return false;
  if (isCloudflareIpv4(value)) return true;
  return KNOWN_CF_HOST_SUFFIXES.some((suffix) => value === suffix || value.endsWith(`.${suffix}`));
}

function isDomainHost(host) {
  const value = String(host || '').trim();
  return Boolean(value) && parseIpv4(value) === null && !value.includes(':');
}

function cacheRoute(host, route, candidateIp = '') {
  const key = String(host || '').trim().toLowerCase();
  if (!key) return;
  const ttl = route === 'cf' ? 15 * 60_000 : route === 'cf-hint' ? 10 * 60_000 : 5 * 60_000;
  ROUTE_CACHE.delete(key);
  ROUTE_CACHE.set(key, { route, candidateIp: candidateIp || '', expires: Date.now() + ttl });
  while (ROUTE_CACHE.size > ROUTE_CACHE_MAX) {
    const oldest = ROUTE_CACHE.keys().next().value;
    if (oldest === undefined) break;
    ROUTE_CACHE.delete(oldest);
  }
}

function getCachedRoute(host) {
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
  const parsed = String(value || '')
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter((item) => parseIpv4(item) && !isBlockedDestination(item, 443));
  return [...new Set(parsed)].slice(0, 32);
}

function buildFallbackCandidates(host, pool, preferredIp = '') {
  const unique = [...new Set((pool?.length ? pool : CF_FALLBACK_IPS).filter(Boolean))];
  if (!unique.length) return [];
  const start = hashText(host) % unique.length;
  const ordered = unique.map((_, index) => unique[(start + index) % unique.length]);
  if (preferredIp && ordered.includes(preferredIp)) {
    return [preferredIp, ...ordered.filter((ip) => ip !== preferredIp)];
  }
  return ordered;
}

async function classifyCloudflareHost(host, timeoutMs, log) {
  const cached = getCachedRoute(host);
  if (cached?.route === 'cf' || cached?.route === 'cf-hint') return true;
  if (cached?.route === 'direct' || cached?.route === 'not-cf') return false;
  if (isKnownCloudflareHost(host)) {
    cacheRoute(host, 'cf-hint');
    return true;
  }
  if (!isDomainHost(host)) return false;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('CF classification timeout'), timeoutMs);
  try {
    const url = new URL('https://cloudflare-dns.com/dns-query');
    url.searchParams.set('name', host);
    url.searchParams.set('type', 'A');
    const response = await fetch(url.toString(), {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const data = await response.json();
    const addresses = Array.isArray(data?.Answer)
      ? data.Answer.filter((answer) => Number(answer?.type) === 1).map((answer) => String(answer?.data || ''))
      : [];
    if (!addresses.length) return false;
    const isCf = addresses.some(isCloudflareIpv4);
    cacheRoute(host, isCf ? 'cf-hint' : 'not-cf');
    return isCf;
  } catch (error) {
    log?.('CF classify skipped', error?.message || error);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function wait(ms, value, reject = false) {
  return new Promise((resolve, rejectFn) => setTimeout(() => (reject ? rejectFn(value) : resolve(value)), ms));
}

async function openSocketOnce(connector, host, port, timeoutMs) {
  const socket = connector({ hostname: host, port });
  let timer = null;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('TCP connect timeout')), timeoutMs);
      }),
    ]);
    return socket;
  } catch (error) {
    try { socket.close(); } catch {}
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function connectWithTimeout(connector, host, port, timeoutMs, raceCount = 1) {
  if (isBlockedDestination(host, port)) throw new Error('destination blocked by policy');
  const count = Math.max(1, Math.min(3, Number(raceCount) || 1));
  if (count === 1) return openSocketOnce(connector, host, port, timeoutMs);

  const attempts = Array.from({ length: count }, () => openSocketOnce(connector, host, port, timeoutMs));
  let winner;
  try {
    winner = await Promise.any(attempts);
  } catch (error) {
    throw error?.errors?.[0] || error;
  }
  for (const attempt of attempts) {
    attempt.then((candidate) => {
      if (candidate !== winner) {
        try { candidate.close(); } catch {}
      }
    }).catch(() => {});
  }
  return winner;
}
'''
if old_helpers not in s:
    raise SystemExit('helper/connect block missing')
s = s.replace(old_helpers, new_helpers, 1)

old_send = """function sendWs(ws, bytes) {
  if (ws.readyState !== 1) throw new Error('WebSocket closed');
  const view = toBytes(bytes);
  const copy = view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
    ? view.buffer
    : view.slice().buffer;
  ws.send(copy);
}
"""
new_send = """function sendWs(ws, bytes) {
  if (ws.readyState !== 1) throw new Error('WebSocket closed');
  ws.send(toBytes(bytes));
}

function createWsBatchSender(ws) {
  let buffer = new Uint8Array(WS_DOWNLOAD_BATCH_BYTES);
  let length = 0;
  let timer = null;

  const clearTimer = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };

  const flush = () => {
    clearTimer();
    if (!length) return;
    if (ws.readyState !== 1) {
      length = 0;
      return;
    }
    ws.send(buffer.subarray(0, length));
    buffer = new Uint8Array(WS_DOWNLOAD_BATCH_BYTES);
    length = 0;
  };

  const send = (chunk, immediate = false) => {
    const view = toBytes(chunk);
    if (!view.byteLength) return;
    if (immediate || view.byteLength >= WS_DOWNLOAD_DIRECT_THRESHOLD) {
      flush();
      sendWs(ws, view);
      return;
    }
    if (length + view.byteLength > buffer.byteLength) flush();
    buffer.set(view, length);
    length += view.byteLength;
    if (length >= buffer.byteLength - 512) flush();
    else if (!timer) timer = setTimeout(flush, WS_DOWNLOAD_BATCH_DELAY_MS);
  };

  return { send, flush };
}
"""
if old_send not in s:
    raise SystemExit('sendWs block missing')
s = s.replace(old_send, new_send, 1)

start = s.index('async function handleTcpSession(')
end = s.index('\nfunction appendUdpBuffer', start)
new_tcp = r'''async function handleTcpSession({ ws, connector, requestMeta, initialPayload, version, host, port, config, log }) {
  let closed = false;
  let socket = null;
  let writer = null;
  let reader = null;
  let generation = 0;
  let firstByteSeen = false;
  let firstByteTimer = null;
  let fallbackAttempted = false;
  let fallbackAttempt = -1;
  let activeFallbackIp = '';
  let switching = false;
  let switchPromise = Promise.resolve();
  let uplink = Promise.resolve();
  let doneResolve;
  const done = new Promise((resolve) => { doneResolve = resolve; });
  const replay = [];
  let replayBytes = 0;
  let nextChunkId = 0;
  let replayedThroughId = -1;
  const downlinkSender = createWsBatchSender(ws);

  const canCfFallback = requestMeta.supportsCloudflareFallback && port === 443 && config.cfFallbackMode !== 'off';
  const forceCfFallback = canCfFallback && config.cfFallbackMode === 'force';
  const cachedRoute = getCachedRoute(host);
  const immediateCfHint = canCfFallback && (
    forceCfFallback ||
    cachedRoute?.route === 'cf' ||
    cachedRoute?.route === 'cf-hint' ||
    isKnownCloudflareHost(host)
  );
  const fallbackCandidates = buildFallbackCandidates(host, config.cfFallbackIps, cachedRoute?.candidateIp || '');
  const shouldClassify = canCfFallback && config.cfClassify && !immediateCfHint &&
    cachedRoute?.route !== 'direct' && cachedRoute?.route !== 'not-cf' && isDomainHost(host);
  const classificationPromise = shouldClassify
    ? classifyCloudflareHost(host, config.cfClassifyTimeoutMs, log)
    : null;

  const idle = createIdleWatchdog(config.idleTimeoutMs, () => {
    log('idle timeout', `${host}:${port}`);
    closeAll(1000, 'idle timeout');
  });

  const clearFirstByteTimer = () => {
    if (firstByteTimer) clearTimeout(firstByteTimer);
    firstByteTimer = null;
  };

  const armFirstByteTimer = (isFallback) => {
    clearFirstByteTimer();
    if (!canCfFallback || firstByteSeen || closed) return;
    const timeoutMs = isFallback ? config.cfFallbackFirstByteMs : config.cfFirstByteMs;
    firstByteTimer = setTimeout(() => {
      if (closed || firstByteSeen) return;
      if (isFallback) {
        triggerCfFallback(`${timeoutMs}ms without first byte on CF fallback`, true).catch(() => {});
      } else if (!fallbackAttempted) {
        triggerCfFallback(`${timeoutMs}ms without first byte`, false).catch(() => {});
      }
    }, timeoutMs);
  };

  const closeCurrent = () => {
    clearFirstByteTimer();
    try { reader?.cancel(); } catch {}
    try { reader?.releaseLock(); } catch {}
    try { writer?.releaseLock(); } catch {}
    try { socket?.close(); } catch {}
    reader = null;
    writer = null;
    socket = null;
    activeFallbackIp = '';
  };

  const closeAll = (code = 1000, reason = '') => {
    if (closed) return;
    closed = true;
    idle.stop();
    clearFirstByteTimer();
    try { downlinkSender.flush(); } catch {}
    generation++;
    closeCurrent();
    safeWsClose(ws, code, reason);
    doneResolve?.();
  };

  const rememberChunk = (chunk) => {
    const bytes = toBytes(chunk);
    const item = { id: nextChunkId++, bytes };
    if (!firstByteSeen && replayBytes + bytes.byteLength <= MAX_REPLAY_BYTES) {
      item.bytes = bytes.slice();
      replay.push(item);
      replayBytes += item.bytes.byteLength;
    }
    return item;
  };

  const markFirstByte = (isFallback, candidateIp = '') => {
    if (firstByteSeen) return false;
    firstByteSeen = true;
    clearFirstByteTimer();
    cacheRoute(host, isFallback ? 'cf' : 'direct', isFallback ? candidateIp : '');
    replay.length = 0;
    replayBytes = 0;
    return true;
  };

  const startDownlink = (myGeneration, isFallback, candidateIp = '') => {
    const myReader = reader;
    (async () => {
      try {
        while (!closed && myGeneration === generation) {
          const { value, done: streamDone } = await myReader.read();
          if (myGeneration !== generation || closed) return;
          if (streamDone) {
            if (!firstByteSeen && canCfFallback) {
              await triggerCfFallback(isFallback ? 'CF fallback EOF before first byte' : 'direct EOF before first byte', isFallback);
            } else {
              try { downlinkSender.flush(); } catch {}
              closeAll(1000, 'remote closed');
            }
            return;
          }
          if (!value?.byteLength) continue;
          const isFirst = markFirstByte(isFallback, candidateIp);
          idle.arm();
          await waitForWsBackpressure(ws);
          downlinkSender.send(value, isFirst);
        }
      } catch (error) {
        if (closed || myGeneration !== generation) return;
        if (!firstByteSeen && canCfFallback) {
          try {
            await triggerCfFallback(`${isFallback ? 'CF fallback' : 'direct'} read failed: ${error?.message || error}`, isFallback);
            return;
          } catch {}
        }
        log('downlink failed', error?.message || error);
        closeAll(1011, 'downlink failed');
      } finally {
        try { myReader.releaseLock(); } catch {}
      }
    })();
  };

  const openTarget = async (targetHost, label, isFallback, timeoutMs = config.connectTimeoutMs) => {
    const myGeneration = ++generation;
    const newSocket = await connectWithTimeout(connector, targetHost, port, timeoutMs, config.connectRace);
    if (closed || myGeneration !== generation) {
      try { newSocket.close(); } catch {}
      throw new Error('connection superseded');
    }
    socket = newSocket;
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();
    replayedThroughId = -1;
    activeFallbackIp = isFallback ? targetHost : '';
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost, `race=${config.connectRace}`);
    startDownlink(myGeneration, isFallback, activeFallbackIp);
  };

  const writeReplay = async () => {
    let i = 0;
    while (!closed && i < replay.length) {
      const item = replay[i++];
      if (item.id <= replayedThroughId) continue;
      await writer.write(item.bytes);
      replayedThroughId = item.id;
    }
  };

  async function triggerCfFallback(reason, advance = false) {
    if (!canCfFallback || firstByteSeen || closed) {
      throw new Error('Cloudflare fallback unavailable');
    }
    if (!fallbackAttempted) {
      fallbackAttempted = true;
      fallbackAttempt = 0;
    } else if (advance) {
      fallbackAttempt += 1;
    }

    switching = true;
    clearFirstByteTimer();
    generation++;
    closeCurrent();

    switchPromise = (async () => {
      let lastError = null;
      const fallbackConnectMs = Math.max(350, Math.min(config.connectTimeoutMs, config.cfFallbackFirstByteMs));
      while (!closed && !firstByteSeen && fallbackAttempt < fallbackCandidates.length) {
        const fallbackIp = fallbackCandidates[fallbackAttempt];
        log('CF fallback', reason, `${host}:${port}`, `candidate=${fallbackAttempt + 1}/${fallbackCandidates.length}`, 'via', fallbackIp);
        try {
          await openTarget(fallbackIp, 'cf-anycast', true, fallbackConnectMs);
          await writeReplay();
          switching = false;
          idle.arm();
          armFirstByteTimer(true);
          return;
        } catch (error) {
          lastError = error;
          log('CF fallback candidate failed', fallbackIp, error?.message || error);
          fallbackAttempt += 1;
          generation++;
          closeCurrent();
        }
      }
      switching = false;
      const message = lastError?.message || 'all Cloudflare fallback candidates exhausted';
      closeAll(1011, 'Cloudflare fallback failed');
      throw new Error(message);
    })();
    return switchPromise;
  }

  const queueUplink = (chunk) => {
    const bytes = toBytes(chunk);
    if (!bytes.byteLength || closed) return uplink;
    const item = rememberChunk(bytes);
    const queuedGeneration = generation;
    idle.arm();
    uplink = uplink.then(async () => {
      if (closed) return;
      if (switching) {
        await switchPromise;
        if (item.id <= replayedThroughId) return;
      }
      if (queuedGeneration !== generation && item.id <= replayedThroughId) return;
      if (!writer) throw new Error('TCP writer unavailable');
      await writer.write(item.bytes);
    }).catch((error) => {
      if (!closed) {
        log('uplink failed', error?.message || error);
        closeAll(1011, 'uplink failed');
      }
      throw error;
    });
    return uplink;
  };

  if (initialPayload?.byteLength) rememberChunk(initialPayload);

  try {
    if (immediateCfHint) {
      log('route hint', `${host}:${port}`, forceCfFallback ? 'forced Cloudflare fallback' : 'Cloudflare destination');
      await triggerCfFallback(forceCfFallback ? 'forced CF fallback' : 'cached/classified CF destination', false);
    } else {
      try {
        await openTarget(host, 'direct', false);
      } catch (error) {
        if (!canCfFallback) throw error;
        await triggerCfFallback(`direct connect failed: ${error?.message || error}`, false);
      }
    }

    sendWs(ws, makeVlessResponseHeader(version));
    idle.arm();
    if (!switching && writer && replay.length) await writeReplay();
    else if (switching) await switchPromise;

    if (classificationPromise && !firstByteSeen && !fallbackAttempted) {
      classificationPromise.then((isCf) => {
        if (isCf && !closed && !firstByteSeen && !fallbackAttempted) {
          log('route hint', `${host}:${port}`, 'DoH resolved to Cloudflare');
          triggerCfFallback('DoH classified Cloudflare destination', false).catch(() => {});
        }
      }).catch(() => {});
    }

    if (!firstByteSeen && canCfFallback) {
      armFirstByteTimer(fallbackAttempted);
    }
  } catch (error) {
    closeAll(1011, error?.message || 'TCP connect failed');
    throw error;
  }

  return { queueUplink, closeAll, done };
}
'''
s = s[:start] + new_tcp + s[end:]

old_config = """    connectTimeoutMs: clampInteger(env.CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS, 500, 15000),
    idleTimeoutMs: clampInteger(env.IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, 10000, 600000),
    cfFirstByteMs: clampInteger(env.CF_FIRST_BYTE_MS, DEFAULT_CF_FIRST_BYTE_MS, 250, 5000),
    cfFallbackMode: ['auto', 'off', 'force'].includes(String(env.CF_FALLBACK || 'auto').toLowerCase())
      ? String(env.CF_FALLBACK || 'auto').toLowerCase()
      : 'auto',
    publicHost: normalizePublicHost(env.HOST || url.host),
"""
new_config = """    connectTimeoutMs: clampInteger(env.CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS, 500, 15000),
    idleTimeoutMs: clampInteger(env.IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, 10000, 600000),
    connectRace: clampInteger(env.CONNECT_RACE, DEFAULT_CONNECT_RACE, 1, 3),
    cfFirstByteMs: clampInteger(env.CF_FIRST_BYTE_MS, DEFAULT_CF_FIRST_BYTE_MS, 250, 5000),
    cfFallbackFirstByteMs: clampInteger(env.CF_FALLBACK_FIRST_BYTE_MS, DEFAULT_CF_FALLBACK_FIRST_BYTE_MS, 250, 3000),
    cfClassifyTimeoutMs: clampInteger(env.CF_CLASSIFY_TIMEOUT_MS, DEFAULT_CF_CLASSIFY_TIMEOUT_MS, 80, 1000),
    cfClassify: !/^(0|false|off|no)$/i.test(String(env.CF_CLASSIFY ?? 'on')),
    cfFallbackIps: parseFallbackPool(env.CF_FALLBACK_IPS).length ? parseFallbackPool(env.CF_FALLBACK_IPS) : CF_FALLBACK_IPS,
    cfFallbackMode: ['auto', 'off', 'force'].includes(String(env.CF_FALLBACK || 'auto').toLowerCase())
      ? String(env.CF_FALLBACK || 'auto').toLowerCase()
      : 'auto',
    publicHost: normalizePublicHost(env.HOST || url.host),
"""
if old_config not in s:
    raise SystemExit('buildConfig anchor missing')
s = s.replace(old_config, new_config, 1)

old_accept = """  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.accept({ allowHalfOpen: true });
"""
new_accept = """  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.binaryType = 'arraybuffer';
  ws.accept({ allowHalfOpen: true });
"""
if old_accept not in s:
    raise SystemExit('WebSocket accept anchor missing')
s = s.replace(old_accept, new_accept, 1)

old_health = """        return textResponse(`${healthy ? 'ok' : 'misconfigured'}\\nconnector=${connectorName}\\ncf_fallback=${config.cfFallbackMode}\\ncf_first_byte_ms=${config.cfFirstByteMs}`, healthy ? 200 : 503);
"""
new_health = """        return textResponse(`${healthy ? 'ok' : 'misconfigured'}\\nconnector=${connectorName}\\ncf_fallback=${config.cfFallbackMode}\\ncf_first_byte_ms=${config.cfFirstByteMs}\\ncf_fallback_first_byte_ms=${config.cfFallbackFirstByteMs}\\ncf_classify=${config.cfClassify ? 'on' : 'off'}\\nconnect_race=${config.connectRace}\\nws_binary=arraybuffer`, healthy ? 200 : 503);
"""
if old_health not in s:
    raise SystemExit('health detail anchor missing')
s = s.replace(old_health, new_health, 1)

p.write_text(s)
print('optimized worker.js')
