import worker from './_worker_core.js';

// cfnew-style Cloudflare anycast retry. This keeps EdgeTunnel's original
// implementation intact and only wraps its native request.fetcher.connect().
const CF_ANYCAST_FALLBACKS = [
  '172.71.218.190',
  '162.158.228.87',
  '162.158.189.134',
  '162.158.26.63',
  '162.158.25.86',
  '162.158.29.216',
  '162.158.218.160',
  '162.158.227.214',
  '172.69.118.198',
  '172.69.119.150',
];

const CF_IPV4_RANGES = [
  ['103.21.244.0', 22], ['103.22.200.0', 22], ['103.31.4.0', 22],
  ['104.16.0.0', 13], ['104.24.0.0', 14], ['108.162.192.0', 18],
  ['131.0.72.0', 22], ['141.101.64.0', 18], ['162.158.0.0', 15],
  ['172.64.0.0', 13], ['173.245.48.0', 20], ['188.114.96.0', 20],
  ['190.93.240.0', 20], ['197.234.240.0', 22], ['198.41.128.0', 17],
];

const CF_IPV6_PREFIXES = [
  '2400:cb00:', '2606:4700:', '2803:f800:', '2405:b500:',
  '2405:8100:', '2a06:98c0:', '2c0f:f248:',
];

const TLS_PORTS = new Set([443, 2053, 2083, 2087, 2096, 8443]);
const DEFAULT_FIRST_BYTE_TIMEOUT_MS = 1200;
const MIN_FIRST_BYTE_TIMEOUT_MS = 250;
const MAX_FIRST_BYTE_TIMEOUT_MS = 5000;
const MAX_REPLAY_BYTES = 512 * 1024;
const cfHostCache = new Map();
const CF_HOST_CACHE_MS = 5 * 60 * 1000;

function stripBrackets(value = '') {
  const text = String(value).trim();
  return text.startsWith('[') && text.endsWith(']') ? text.slice(1, -1) : text;
}

function ipv4ToUint32(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    result = ((result << 8) | n) >>> 0;
  }
  return result >>> 0;
}

function isCloudflareIPv4(value) {
  const ip = ipv4ToUint32(value);
  if (ip === null) return false;
  for (const [baseText, prefix] of CF_IPV4_RANGES) {
    const base = ipv4ToUint32(baseText);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((ip & mask) === (base & mask)) return true;
  }
  return false;
}

function isCloudflareIPv6(value) {
  const ip = stripBrackets(value).toLowerCase();
  return CF_IPV6_PREFIXES.some((prefix) => ip.startsWith(prefix));
}

function getFirstByteTimeout(env = {}) {
  const value = Number(env.WARP_TIMEOUT ?? env.warp_timeout ?? DEFAULT_FIRST_BYTE_TIMEOUT_MS);
  if (!Number.isFinite(value)) return DEFAULT_FIRST_BYTE_TIMEOUT_MS;
  return Math.min(MAX_FIRST_BYTE_TIMEOUT_MS, Math.max(MIN_FIRST_BYTE_TIMEOUT_MS, Math.round(value)));
}

function warpEnabled(env = {}) {
  const value = env.WARP ?? env.warp;
  if (value === undefined || value === null || String(value).trim() === '') return true;
  return !/^(?:0|false|off|no|direct)$/i.test(String(value).trim());
}

function isTunnelRequest(request) {
  const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
  if (upgrade === 'websocket') return true;
  if (request.method !== 'POST') return false;
  try {
    const path = new URL(request.url).pathname.toLowerCase();
    return !path.startsWith('/admin/') && path !== '/admin' && path !== '/login';
  } catch {
    return false;
  }
}

function hasExplicitOutbound(request, env = {}) {
  if (env.PROXYIP) return true;
  let url;
  try { url = new URL(request.url); }
  catch { return true; }

  for (const key of ['proxyip', 'socks5', 'http', 'https', 'turn', 'sstp', 'globalproxy']) {
    if (url.searchParams.has(key)) return true;
  }

  let path = url.pathname;
  try { path = decodeURIComponent(path); } catch { }
  return /\/(?:video\/|trojan=|(?:socks5?|g?s5|g?http|g?https|g?turn|g?sstp)(?::\/?\/?|=)|proxyip[.=]|pyip=|ip=)/i.test(path);
}

function pickFallbackIp() {
  return CF_ANYCAST_FALLBACKS[Math.floor(Math.random() * CF_ANYCAST_FALLBACKS.length)];
}

async function resolveCloudflareHost(hostname) {
  const host = stripBrackets(hostname).toLowerCase();
  if (!host) return false;
  if (isCloudflareIPv4(host) || isCloudflareIPv6(host)) return true;
  if (ipv4ToUint32(host) !== null || host.includes(':')) return false;

  const cached = cfHostCache.get(host);
  const now = Date.now();
  if (cached && cached.expires > now) return cached.value;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 450);
  let value = false;
  try {
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: controller.signal }
    );
    if (response.ok) {
      const body = await response.json();
      const answers = Array.isArray(body?.Answer) ? body.Answer : [];
      value = answers.some((answer) => answer?.type === 1 && isCloudflareIPv4(answer.data));
    }
  } catch { }
  clearTimeout(timer);

  if (cfHostCache.size > 256) cfHostCache.clear();
  cfHostCache.set(host, { value, expires: now + CF_HOST_CACHE_MS });
  return value;
}

function makeFallbackSocket(nativeConnect, options, init, timeoutMs) {
  const originalHost = stripBrackets(options?.hostname || '');
  const primary = init === undefined ? nativeConnect(options) : nativeConnect(options, init);
  let cfCheckPromise = null;
  const isCfDestination = () => (cfCheckPromise ||= resolveCloudflareHost(originalHost));
  let activeSocket = primary;
  let activeReader = null;
  let closed = false;
  let firstByteSeen = false;
  let fallbackStarted = false;
  let fallbackDisabled = false;
  let switchPromise = null;
  let activeWritePromise = null;
  let writeTail = Promise.resolve();
  let replayChunks = [];
  let replayBytes = 0;
  let replayOverflow = false;
  let settleClosedResolve;
  let settleClosedReject;
  let closedSettled = false;

  const syntheticClosed = new Promise((resolve, reject) => {
    settleClosedResolve = resolve;
    settleClosedReject = reject;
  });

  const settleClosed = (error = null) => {
    if (closedSettled) return;
    closedSettled = true;
    if (error) settleClosedReject(error);
    else settleClosedResolve();
  };

  const clearReplay = () => {
    replayChunks = [];
    replayBytes = 0;
  };

  const rememberForReplay = (bytes) => {
    if (firstByteSeen || fallbackStarted || fallbackDisabled || replayOverflow || !bytes.byteLength) return;
    if (replayBytes + bytes.byteLength > MAX_REPLAY_BYTES) {
      replayOverflow = true;
      fallbackDisabled = true;
      clearReplay();
      return;
    }
    replayChunks.push(bytes.slice());
    replayBytes += bytes.byteLength;
  };

  const writeToSocket = async (socket, bytes) => {
    const writer = socket.writable.getWriter();
    try { await writer.write(bytes); }
    finally { try { writer.releaseLock(); } catch { } }
  };

  const queueWrite = (data) => {
    const bytes = data instanceof Uint8Array
      ? data
      : data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : ArrayBuffer.isView(data)
          ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
          : new Uint8Array(data || 0);
    const owned = bytes.slice();

    const task = writeTail.then(async () => {
      if (closed) throw new Error('socket is closed');
      rememberForReplay(owned);
      if (switchPromise) await switchPromise;
      if (closed) throw new Error('socket is closed');
      const writePromise = writeToSocket(activeSocket, owned);
      activeWritePromise = writePromise;
      try { await writePromise; }
      finally { if (activeWritePromise === writePromise) activeWritePromise = null; }
    });
    writeTail = task.catch(() => { });
    return task;
  };

  const switchToFallback = () => {
    if (closed || firstByteSeen || fallbackStarted || fallbackDisabled || replayOverflow) return Promise.resolve(false);
    fallbackStarted = true;
    switchPromise = (async () => {
      try {
        if (activeWritePromise) {
          try { await activeWritePromise; } catch { }
        }
        try { await activeReader?.cancel?.(); } catch { }
        try { activeReader?.releaseLock?.(); } catch { }
        activeReader = null;
        try { activeSocket?.close?.(); } catch { }

        const fallbackIp = pickFallbackIp();
        const fallback = nativeConnect({ hostname: fallbackIp, port: 443 });
        if (fallback?.opened) await fallback.opened;
        if (closed) {
          try { fallback?.close?.(); } catch { }
          return false;
        }

        activeSocket = fallback;
        if (replayChunks.length) {
          const writer = fallback.writable.getWriter();
          try {
            for (const chunk of replayChunks) await writer.write(chunk);
          } finally {
            try { writer.releaseLock(); } catch { }
          }
        }
        clearReplay();
        return true;
      } catch {
        return false;
      } finally {
        switchPromise = null;
      }
    })();
    return switchPromise;
  };

  const close = () => {
    if (closed) return;
    closed = true;
    fallbackDisabled = true;
    clearReplay();
    try { activeReader?.cancel?.().catch?.(() => { }); } catch { }
    try { activeReader?.releaseLock?.(); } catch { }
    activeReader = null;
    try { activeSocket?.close?.(); } catch { }
    if (activeSocket !== primary) {
      try { primary?.close?.(); } catch { }
    }
    settleClosed();
  };

  const primaryOpenOutcome = Promise.resolve(primary?.opened).then(
    () => ({ kind: 'open' }),
    (error) => ({ kind: 'error', error })
  );
  const openProbeMs = Math.min(300, Math.max(150, Math.floor(timeoutMs / 3)));
  const opened = (async () => {
    let timer;
    let outcome = await Promise.race([
      primaryOpenOutcome,
      new Promise((resolve) => { timer = setTimeout(() => resolve({ kind: 'timeout' }), openProbeMs); }),
    ]);
    clearTimeout(timer);
    if (outcome.kind === 'open') return;

    if (outcome.kind === 'timeout') {
      const classification = isCfDestination().then((value) => ({ kind: 'classification', value }));
      outcome = await Promise.race([primaryOpenOutcome, classification]);
      if (outcome.kind === 'open') return;
      if (outcome.kind === 'classification') {
        if (outcome.value && await switchToFallback()) return;
        const finalOutcome = await primaryOpenOutcome;
        if (finalOutcome.kind === 'open') return;
        throw finalOutcome.error;
      }
    }

    if (outcome.kind === 'error') {
      if (await isCfDestination()) {
        if (await switchToFallback()) return;
      }
      throw outcome.error;
    }
  })();

  const readable = new ReadableStream({
    start(controller) {
      (async () => {
        try {
          await opened;
          let useTimeout = true;

          while (!closed) {
            const socketForRead = activeSocket;
            let reader;
            try { reader = socketForRead.readable.getReader({ mode: 'byob' }); }
            catch { reader = socketForRead.readable.getReader(); }
            activeReader = reader;
            let byobBuffer = new ArrayBuffer(64 * 1024);
            const firstByteDeadline = Date.now() + timeoutMs;

            while (!closed && socketForRead === activeSocket) {
              let settledOutcome = null;
              const readPromise = (() => {
                try {
                  const p = reader.read.length > 0
                    ? reader.read(new Uint8Array(byobBuffer))
                    : reader.read();
                  return Promise.resolve(p).then(
                    (result) => ({ kind: 'read', result }),
                    (error) => ({ kind: 'error', error })
                  );
                } catch {
                  return Promise.resolve(reader.read()).then(
                    (result) => ({ kind: 'read', result }),
                    (error) => ({ kind: 'error', error })
                  );
                }
              })();
              readPromise.then((value) => { settledOutcome = value; }, () => { });

              let outcome;
              if (!firstByteSeen && !fallbackStarted && !fallbackDisabled && useTimeout) {
                let timer;
                const timeoutPromise = new Promise((resolve) => {
                  timer = setTimeout(() => resolve({ kind: 'timeout' }), Math.max(0, firstByteDeadline - Date.now()));
                });
                outcome = await Promise.race([readPromise, timeoutPromise]);
                clearTimeout(timer);

                if (outcome.kind === 'timeout') {
                  const isCf = await isCfDestination();
                  if (closed) break;
                  if (settledOutcome) {
                    outcome = settledOutcome;
                  } else if (isCf) {
                    const switched = await switchToFallback();
                    if (switched) break;
                    throw new Error('Cloudflare anycast fallback failed');
                  } else {
                    fallbackDisabled = true;
                    clearReplay();
                    useTimeout = false;
                    outcome = await readPromise;
                  }
                }
              } else {
                outcome = await readPromise;
              }

              if (outcome.kind === 'error') {
                if (!firstByteSeen && !fallbackStarted && !fallbackDisabled) {
                  const isCf = await isCfDestination();
                  if (isCf && await switchToFallback()) break;
                }
                throw outcome.error;
              }

              const { done, value } = outcome.result;
              if (done) {
                if (!firstByteSeen && !fallbackStarted && !fallbackDisabled) {
                  const isCf = await isCfDestination();
                  if (isCf && await switchToFallback()) break;
                }
                closed = true;
                try { controller.close(); } catch { }
                settleClosed();
                return;
              }

              const bytes = value instanceof Uint8Array
                ? value
                : value instanceof ArrayBuffer
                  ? new Uint8Array(value)
                  : ArrayBuffer.isView(value)
                    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
                    : new Uint8Array(value || 0);
              if (!bytes.byteLength) continue;

              if (!firstByteSeen) {
                firstByteSeen = true;
                clearReplay();
              }
              controller.enqueue(bytes.slice());
              if (value?.buffer?.byteLength >= 64 * 1024) byobBuffer = new ArrayBuffer(64 * 1024);
            }

            try { activeReader?.releaseLock?.(); } catch { }
            activeReader = null;
          }
        } catch (error) {
          if (!closed) {
            closed = true;
            try { controller.error(error); } catch { }
            settleClosed(error);
            try { activeSocket?.close?.(); } catch { }
          }
        }
      })();
    },
    cancel() { close(); },
  });

  const writable = new WritableStream({
    write(chunk) { return queueWrite(chunk); },
    close() { close(); },
    abort() { close(); },
  });

  return { readable, writable, opened, closed: syntheticClosed, close };
}

function wrapRequest(request, env) {
  if (!warpEnabled(env) || !isTunnelRequest(request) || hasExplicitOutbound(request, env)) return request;
  const fetcher = request?.fetcher;
  if (!fetcher || typeof fetcher.connect !== 'function') return request;

  const nativeConnect = fetcher.connect.bind(fetcher);
  const timeoutMs = getFirstByteTimeout(env);
  const wrappedFetcher = new Proxy(fetcher, {
    get(target, property) {
      if (property === 'connect') {
        return (options, init) => {
          const port = Number(options?.port);
          if (init !== undefined || !TLS_PORTS.has(port)) {
            return init === undefined ? nativeConnect(options) : nativeConnect(options, init);
          }
          return makeFallbackSocket(nativeConnect, options, init, timeoutMs);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });

  const wrappedRequest = new Request(request);
  try {
    Object.defineProperty(wrappedRequest, 'fetcher', {
      value: wrappedFetcher, configurable: true, enumerable: false, writable: false,
    });
  } catch { return request; }
  try {
    if (request.cf !== undefined) {
      Object.defineProperty(wrappedRequest, 'cf', {
        value: request.cf, configurable: true, enumerable: false, writable: false,
      });
    }
  } catch { }
  return wrappedRequest;
}

export default {
  fetch(request, env, ctx) {
    return worker.fetch(wrapRequest(request, env), env, ctx);
  },
};
