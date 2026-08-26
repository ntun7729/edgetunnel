// Standalone VLESS-over-WebSocket Worker, written from scratch.
// Runtime dependencies: Cloudflare Workers built-ins only.
// Required env: UUID (one UUID) or UUIDS (comma/space-separated UUIDs).
// Optional env: PATH, DOH_URL, CONNECT_TIMEOUT_MS, IDLE_TIMEOUT_MS, HOST, DEBUG, CONFIG_TOKEN.

import { connect } from 'cloudflare:sockets';

const DEFAULT_PATH = '/vless';
const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_CONNECT_TIMEOUT_MS = 5000;
const DEFAULT_IDLE_TIMEOUT_MS = 120000;
const MAX_VLESS_HEADER_BYTES = 4096;
const MAX_UDP_DATAGRAM_BYTES = 65535;
const MAX_WS_MESSAGE_BYTES = 8 * 1024 * 1024;
const MAX_BUFFERED_AMOUNT = 8 * 1024 * 1024;
const CF_FALLBACK_IPS = [
  '172.71.218.190', '162.158.228.87', '162.158.189.134', '162.158.26.63',
  '162.158.25.86', '162.158.29.216', '162.158.218.160', '162.158.227.214',
  '172.69.118.198', '172.69.119.150',
];
const DEFAULT_CF_FIRST_BYTE_MS = 1200;
const MAX_REPLAY_BYTES = 1024 * 1024;

function textResponse(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}

function normalizePath(value) {
  const raw = String(value || DEFAULT_PATH).trim();
  if (!raw) return DEFAULT_PATH;
  return raw.startsWith('/') ? raw : `/${raw}`;
}

function clampInteger(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function parseUuid(uuid) {
  const compact = String(uuid || '').trim().toLowerCase().replaceAll('-', '');
  if (!/^[0-9a-f]{32}$/.test(compact)) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function loadAllowedUsers(env) {
  const raw = [env.UUID, env.UUIDS, env.uuid, env.uuids].filter(Boolean).join(',');
  const values = String(raw)
    .split(/[\s,;]+/)
    .map((v) => v.trim())
    .filter(Boolean);
  const users = values.map(parseUuid).filter(Boolean);
  return users;
}

function timingSafeEqual16(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.byteLength !== 16 || b.byteLength !== 16) return false;
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function authorizedUuid(candidate, allowedUsers) {
  let matched = 0;
  for (const allowed of allowedUsers) matched |= timingSafeEqual16(candidate, allowed) ? 1 : 0;
  return matched === 1;
}

function concatBytes(a, b) {
  if (!a?.byteLength) return b instanceof Uint8Array ? b : new Uint8Array(b || 0);
  if (!b?.byteLength) return a instanceof Uint8Array ? a : new Uint8Array(a || 0);
  const left = a instanceof Uint8Array ? a : new Uint8Array(a);
  const right = b instanceof Uint8Array ? b : new Uint8Array(b);
  const out = new Uint8Array(left.byteLength + right.byteLength);
  out.set(left, 0);
  out.set(right, left.byteLength);
  return out;
}

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new TypeError('binary data required');
}

async function toWebSocketBytes(data) {
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  return toBytes(data);
}

function parseVlessHeader(buf, allowedUsers) {
  const bytes = toBytes(buf);
  if (bytes.byteLength < 18) return { needMore: true };

  let offset = 0;
  const version = bytes[offset++];
  if (version !== 0) throw new Error(`unsupported VLESS version: ${version}`);
  const uuid = bytes.subarray(offset, offset + 16);
  offset += 16;
  if (!authorizedUuid(uuid, allowedUsers)) throw new Error('unauthorized UUID');

  const optLength = bytes[offset++];
  if (offset + optLength + 4 > MAX_VLESS_HEADER_BYTES) throw new Error('VLESS header too large');
  if (bytes.byteLength < offset + optLength + 4) return { needMore: true };
  offset += optLength;

  const command = bytes[offset++];
  if (command !== 1 && command !== 2) {
    if (command === 3) throw new Error('VLESS Mux is not supported');
    throw new Error(`unsupported VLESS command: ${command}`);
  }

  const port = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2;
  if (port < 1 || port > 65535) throw new Error('invalid destination port');

  const addressType = bytes[offset++];
  let host;

  if (addressType === 1) {
    if (bytes.byteLength < offset + 4) return { needMore: true };
    host = `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
    offset += 4;
  } else if (addressType === 2) {
    if (bytes.byteLength < offset + 1) return { needMore: true };
    const len = bytes[offset++];
    if (!len) throw new Error('empty domain');
    if (bytes.byteLength < offset + len) return { needMore: true };
    host = new TextDecoder().decode(bytes.subarray(offset, offset + len));
    offset += len;
    if (!isValidDomain(host)) throw new Error('invalid domain');
  } else if (addressType === 3) {
    if (bytes.byteLength < offset + 16) return { needMore: true };
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
    host = parts.join(':');
    offset += 16;
  } else {
    throw new Error(`unsupported address type: ${addressType}`);
  }

  return {
    needMore: false,
    version,
    command,
    host,
    port,
    consumed: offset,
    payload: bytes.subarray(offset),
  };
}

function isValidDomain(host) {
  if (host.length > 253) return false;
  if (host.includes('\0')) return false;
  if (/\s/.test(host)) return false;
  return host.split('.').every((label) => label.length >= 1 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-'));
}

function isBlockedDestination(host, port) {
  if (port === 25) return true;
  const h = String(host).trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal' || h.endsWith('.metadata.google.internal')) return true;
  if (h === 'instance-data.ec2.internal' || h.endsWith('.instance-data.ec2.internal')) return true;

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;
    const [a, b] = o;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 0 || b === 168)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a >= 224) return true;
    return false;
  }

  if (h === '::' || h === '::1') return true;
  if (h.startsWith('fc') || h.startsWith('fd')) return true;
  if (/^fe[89ab]/.test(h)) return true;
  if (h.startsWith('ff')) return true;
  return false;
}

function parseEarlyData(request) {
  const protocol = request.headers.get('sec-websocket-protocol');
  if (!protocol) return null;
  const token = protocol.split(',')[0].trim();
  if (!token || token.length > 16384) return null;
  try {
    const normalized = token.replaceAll('-', '+').replaceAll('_', '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out.byteLength >= 18 ? out : null;
  } catch {
    return null;
  }
}

function createLogger(env, request) {
  const enabled = /^(1|true|yes|on)$/i.test(String(env.DEBUG || ''));
  const prefix = `[scratch-vless ${request.cf?.colo || '-'}]`;
  return (...args) => {
    if (enabled) console.log(prefix, ...args);
  };
}

function getConnector(request) {
  const requestFetcher = request?.fetcher;
  if (requestFetcher && typeof requestFetcher.connect === 'function') {
    return (target) => requestFetcher.connect(target);
  }
  return (target, options) => connect(target, options);
}

function hasRequestFetcher(request) {
  return Boolean(request?.fetcher && typeof request.fetcher.connect === 'function');
}

function selectCfFallback(host, attempt = 0) {
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

function safeWsClose(ws, code = 1000, reason = '') {
  try {
    if (ws.readyState === 1 || ws.readyState === 0) ws.close(code, String(reason).slice(0, 120));
  } catch {}
}

async function waitForWsBackpressure(ws) {
  while (ws.readyState === 1 && Number(ws.bufferedAmount || 0) > MAX_BUFFERED_AMOUNT) {
    await wait(5);
  }
  if (ws.readyState !== 1) throw new Error('WebSocket closed');
}

function sendWs(ws, bytes) {
  if (ws.readyState !== 1) throw new Error('WebSocket closed');
  const view = toBytes(bytes);
  const copy = view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
    ? view.buffer
    : view.slice().buffer;
  ws.send(copy);
}

function makeVlessResponseHeader(version) {
  return new Uint8Array([version & 0xff, 0]);
}

function createIdleWatchdog(timeoutMs, onTimeout) {
  let timer = null;
  const arm = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(onTimeout, timeoutMs);
  };
  const stop = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  return { arm, stop };
}

async function handleTcpSession({ ws, connector, requestMeta, initialPayload, version, host, port, config, log }) {
  let closed = false;
  let socket = null;
  let writer = null;
  let reader = null;
  let generation = 0;
  let firstByteSeen = false;
  let firstByteTimer = null;
  let fallbackAttempted = false;
  let fallbackAttempt = -1;
  let switching = false;
  let switchPromise = Promise.resolve();
  let uplink = Promise.resolve();
  let doneResolve;
  const done = new Promise((resolve) => { doneResolve = resolve; });
  const replay = [];
  let replayBytes = 0;
  let nextChunkId = 0;
  let replayedThroughId = -1;

  const canCfFallback = requestMeta.supportsCloudflareFallback && port === 443 && config.cfFallbackMode !== 'off';
  const forceCfFallback = canCfFallback && config.cfFallbackMode === 'force';

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
    firstByteTimer = setTimeout(() => {
      if (closed || firstByteSeen) return;
      if (isFallback) {
        triggerCfFallback(`${config.cfFirstByteMs}ms without first byte on CF fallback`, true).catch(() => {});
      } else if (!fallbackAttempted) {
        triggerCfFallback(`${config.cfFirstByteMs}ms without first byte`, false).catch(() => {});
      }
    }, config.cfFirstByteMs);
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
  };

  const closeAll = (code = 1000, reason = '') => {
    if (closed) return;
    closed = true;
    idle.stop();
    generation++;
    closeCurrent();
    safeWsClose(ws, code, reason);
    doneResolve?.();
  };

  const rememberChunk = (chunk) => {
    const bytes = toBytes(chunk);
    const copy = bytes.slice();
    const item = { id: nextChunkId++, bytes: copy };
    if (!firstByteSeen && replayBytes + copy.byteLength <= MAX_REPLAY_BYTES) {
      replay.push(item);
      replayBytes += copy.byteLength;
    }
    return item;
  };

  const markFirstByte = () => {
    if (firstByteSeen) return;
    firstByteSeen = true;
    clearFirstByteTimer();
    replay.length = 0;
    replayBytes = 0;
  };

  const startDownlink = (myGeneration, isFallback) => {
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
              closeAll(1000, 'remote closed');
            }
            return;
          }
          if (!value?.byteLength) continue;
          markFirstByte();
          idle.arm();
          await waitForWsBackpressure(ws);
          sendWs(ws, value);
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
    const newSocket = await connectWithTimeout(connector, targetHost, port, timeoutMs);
    if (closed || myGeneration !== generation) {
      try { newSocket.close(); } catch {}
      throw new Error('connection superseded');
    }
    socket = newSocket;
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();
    replayedThroughId = -1;
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost);
    startDownlink(myGeneration, isFallback);
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
      const fallbackConnectMs = Math.max(500, Math.min(config.connectTimeoutMs, config.cfFirstByteMs));
      while (!closed && !firstByteSeen && fallbackAttempt < CF_FALLBACK_IPS.length) {
        const fallbackIp = selectCfFallback(host, fallbackAttempt);
        log('CF fallback', reason, `${host}:${port}`, `candidate=${fallbackAttempt + 1}/${CF_FALLBACK_IPS.length}`, 'via', fallbackIp);
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
    if (forceCfFallback) {
      await triggerCfFallback('forced CF fallback', false);
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

    if (!firstByteSeen && canCfFallback) {
      armFirstByteTimer(fallbackAttempted);
    }
  } catch (error) {
    closeAll(1011, error?.message || 'TCP connect failed');
    throw error;
  }

  return { queueUplink, closeAll, done };
}

function appendUdpBuffer(state, chunk) {
  state.buffer = concatBytes(state.buffer, chunk);
}

function drainUdpDatagrams(state) {
  const packets = [];
  let offset = 0;
  const buf = state.buffer;
  while (buf.byteLength - offset >= 2) {
    const len = (buf[offset] << 8) | buf[offset + 1];
    if (!len || len > MAX_UDP_DATAGRAM_BYTES) throw new Error('invalid UDP datagram length');
    if (buf.byteLength - offset - 2 < len) break;
    packets.push(buf.slice(offset + 2, offset + 2 + len));
    offset += 2 + len;
  }
  state.buffer = offset ? buf.slice(offset) : buf;
  if (state.buffer.byteLength > MAX_UDP_DATAGRAM_BYTES + 2) throw new Error('UDP frame buffer too large');
  return packets;
}

async function dohExchange(packet, dohUrl, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('DoH timeout'), timeoutMs);
  try {
    const response = await fetch(dohUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'accept': 'application/dns-message',
      },
      body: packet,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`DoH HTTP ${response.status}`);
    const body = new Uint8Array(await response.arrayBuffer());
    if (!body.byteLength || body.byteLength > MAX_UDP_DATAGRAM_BYTES) throw new Error('invalid DoH response size');
    return body;
  } finally {
    clearTimeout(timer);
  }
}

async function handleUdpDnsSession({ ws, initialPayload, version, port, config, log }) {
  if (port !== 53) throw new Error('UDP is supported only for DNS port 53');

  const state = { buffer: new Uint8Array(0) };
  let closed = false;
  let queue = Promise.resolve();
  const idle = createIdleWatchdog(config.idleTimeoutMs, () => closeAll(1000, 'idle timeout'));

  const closeAll = (code = 1000, reason = '') => {
    if (closed) return;
    closed = true;
    idle.stop();
    safeWsClose(ws, code, reason);
  };

  const processChunk = (chunk) => {
    if (closed) return queue;
    appendUdpBuffer(state, toBytes(chunk));
    const packets = drainUdpDatagrams(state);
    for (const packet of packets) {
      queue = queue.then(async () => {
        if (closed) return;
        idle.arm();
        const answer = await dohExchange(packet, config.dohUrl, config.connectTimeoutMs);
        const framed = new Uint8Array(answer.byteLength + 2);
        framed[0] = (answer.byteLength >>> 8) & 0xff;
        framed[1] = answer.byteLength & 0xff;
        framed.set(answer, 2);
        await waitForWsBackpressure(ws);
        sendWs(ws, framed);
      });
    }
    queue = queue.catch((error) => {
      log('DNS forwarding failed', error?.message || error);
      closeAll(1011, 'DNS forwarding failed');
      throw error;
    });
    return queue;
  };

  sendWs(ws, makeVlessResponseHeader(version));
  idle.arm();
  if (initialPayload?.byteLength) await processChunk(initialPayload);
  return { queueUplink: processChunk, closeAll, done: queue };
}

function normalizePublicHost(value) {
  let raw = String(value || '').trim();
  if (!raw) return '';
  try {
    if (raw.includes('://')) raw = new URL(raw).host;
  } catch {}
  return raw.replace(/^\[|\]$/g, '');
}

function constantTimeTextEqual(a, b) {
  const left = new TextEncoder().encode(String(a || ''));
  const right = new TextEncoder().encode(String(b || ''));
  const max = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < max; i++) diff |= (left[i] || 0) ^ (right[i] || 0);
  return diff === 0;
}

function buildConfig(env, request) {
  const url = new URL(request.url);
  const path = normalizePath(env.PATH || env.VLESS_PATH || DEFAULT_PATH);
  const dohUrl = String(env.DOH_URL || DEFAULT_DOH).trim();
  let parsedDoh;
  try { parsedDoh = new URL(dohUrl); } catch { parsedDoh = null; }
  if (!parsedDoh || parsedDoh.protocol !== 'https:') throw new Error('DOH_URL must be an https URL');
  return {
    path,
    dohUrl: parsedDoh.toString(),
    connectTimeoutMs: clampInteger(env.CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS, 500, 15000),
    idleTimeoutMs: clampInteger(env.IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, 10000, 600000),
    cfFirstByteMs: clampInteger(env.CF_FIRST_BYTE_MS, DEFAULT_CF_FIRST_BYTE_MS, 250, 5000),
    cfFallbackMode: ['auto', 'off', 'force'].includes(String(env.CF_FALLBACK || 'auto').toLowerCase())
      ? String(env.CF_FALLBACK || 'auto').toLowerCase()
      : 'auto',
    publicHost: normalizePublicHost(env.HOST || url.host),
  };
}

function htmlLanding() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar</title><style>body{margin:0;font:16px system-ui;background:#f6f6f4;color:#171717;display:grid;min-height:100vh;place-items:center}.card{max-width:620px;padding:42px;border:1px solid #ddd;border-radius:24px;background:#fff;box-shadow:0 14px 60px #0000000d}h1{font-size:38px;margin:0 0 12px}p{line-height:1.6;color:#555}</style></head><body><main class="card"><h1>Northstar</h1><p>A small edge service is running normally.</p></main></body></html>`;
}

function formatUuid(bytes) {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function configText(env, request, users, config) {
  if (!users.length) return 'UUID is not configured.';
  const host = config.publicHost;
  const path = encodeURIComponent(config.path);
  const uuid = formatUuid(users[0]);
  const label = encodeURIComponent('Scratch VLESS');
  const uri = `vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${encodeURIComponent(host)}&path=${path}#${label}`;
  return `${uri}\n`;
}

async function handleVlessWebSocket(request, env, ctx, config, users) {
  if (!users.length) return textResponse('UUID is not configured', 503);
  const pair = new WebSocketPair();
  const [client, ws] = Object.values(pair);
  ws.accept({ allowHalfOpen: true });

  const log = createLogger(env, request);
  const connector = getConnector(request);
  const requestMeta = {
    connectorName: hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets',
    supportsCloudflareFallback: hasRequestFetcher(request),
  };

  let headerBuffer = new Uint8Array(0);
  let session = null;
  let closed = false;
  let processing = Promise.resolve();

  const shutdown = (code = 1000, reason = '') => {
    if (closed) return;
    closed = true;
    try { session?.closeAll?.(code, reason); } catch {}
    safeWsClose(ws, code, reason);
  };

  const consumeBinary = async (chunk) => {
    if (closed) return;
    const bytes = await toWebSocketBytes(chunk);
    if (bytes.byteLength > MAX_WS_MESSAGE_BYTES) throw new Error('WebSocket message too large');

    if (session) {
      await session.queueUplink(bytes);
      return;
    }

    headerBuffer = concatBytes(headerBuffer, bytes);
    const parsed = parseVlessHeader(headerBuffer, users);
    if (parsed.needMore) {
      if (headerBuffer.byteLength > MAX_VLESS_HEADER_BYTES) throw new Error('VLESS header too large');
      return;
    }

    log('request', parsed.command === 1 ? 'TCP' : 'UDP', `${parsed.host}:${parsed.port}`);
    headerBuffer = new Uint8Array(0);

    if (parsed.command === 1) {
      session = await handleTcpSession({
        ws,
        connector,
        requestMeta,
        initialPayload: parsed.payload,
        version: parsed.version,
        host: parsed.host,
        port: parsed.port,
        config,
        log,
      });
    } else {
      session = await handleUdpDnsSession({
        ws,
        initialPayload: parsed.payload,
        version: parsed.version,
        port: parsed.port,
        config,
        log,
      });
    }
  };

  const enqueue = (data) => {
    processing = processing.then(() => consumeBinary(data)).catch((error) => {
      log('session error', error?.message || error);
      shutdown(error?.message === 'unauthorized UUID' ? 1008 : 1011, error?.message || 'session failed');
    });
  };

  ws.addEventListener('message', (event) => {
    if (typeof event.data === 'string') {
      shutdown(1003, 'binary data required');
      return;
    }
    enqueue(event.data);
  });

  ws.addEventListener('close', () => shutdown(1000, 'client closed'));
  ws.addEventListener('error', () => shutdown(1011, 'websocket error'));

  const earlyData = parseEarlyData(request);
  if (earlyData) enqueue(earlyData);

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env, ctx) {
    let config;
    try {
      config = buildConfig(env, request);
    } catch (error) {
      return textResponse(`Configuration error: ${error?.message || error}`, 500);
    }

    const url = new URL(request.url);
    const users = loadAllowedUsers(env);
    const upgrade = (request.headers.get('upgrade') || '').toLowerCase();

    if (upgrade === 'websocket') {
      if (url.pathname !== config.path) return textResponse('Not found', 404);
      return handleVlessWebSocket(request, env, ctx, config, users);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') return textResponse('Method not allowed', 405, { allow: 'GET, HEAD' });
    if (url.pathname === '/config') {
      const configuredToken = String(env.CONFIG_TOKEN || '').trim();
      const suppliedToken = url.searchParams.get('token') || '';
      if (!configuredToken || !constantTimeTextEqual(configuredToken, suppliedToken)) return textResponse('Not found', 404);
      return textResponse(configText(env, request, users, config));
    }
    if (url.pathname === '/health') {
      const healthy = users.length > 0;
      if (url.searchParams.get('detail') === '1') {
        const connectorName = hasRequestFetcher(request) ? 'request.fetcher.connect' : 'cloudflare:sockets';
        return textResponse(`${healthy ? 'ok' : 'misconfigured'}\nconnector=${connectorName}\ncf_fallback=${config.cfFallbackMode}\ncf_first_byte_ms=${config.cfFirstByteMs}`, healthy ? 200 : 503);
      }
      return textResponse(healthy ? 'ok' : 'misconfigured', healthy ? 200 : 503);
    }
    if (url.pathname === '/') {
      const body = request.method === 'HEAD' ? null : htmlLanding();
      return new Response(body, {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'public, max-age=300',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    return textResponse('Not found', 404);
  },
};

export {
  parseUuid,
  parseVlessHeader,
  loadAllowedUsers,
  drainUdpDatagrams,
  appendUdpBuffer,
  isBlockedDestination,
  normalizePath,
};
