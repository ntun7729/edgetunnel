import worker from './_worker_core.js';

// Keep EdgeTunnel's native Request/request.fetcher.connect() path untouched.
// This wrapper only customizes the HTTP admin page and public proxy-list feeds.

const FREE_PROXY_CACHE_TTL_MS = 60 * 1000;
const FREE_PROXY_DEFAULT_LIMIT = 1200;
const FREE_PROXY_MAX_LIMIT = 3000;
const freeProxyCache = new Map();

const FREE_PROXY_SOURCES = {
  socks5: [
    { name: 'EDT-Pages', format: 'json', url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json' },
    { name: 'ProxyScrape', format: 'json', url: 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/socks5/data.json' },
    { name: 'Proxifly', format: 'json', url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json' },
    { name: 'Relayglass', format: 'json', url: 'https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/socks5/socks5.json' },
    { name: 'HProxy', format: 'text', url: 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt' },
    { name: 'IPLocate', format: 'mixed', url: 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt' },
  ],
  http: [
    { name: 'EDT-Pages', format: 'json', url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json' },
    { name: 'ProxyScrape', format: 'json', url: 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/http/data.json' },
    { name: 'Proxifly', format: 'json', url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.json' },
    { name: 'Relayglass', format: 'json', url: 'https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/http/http.json' },
    { name: 'HProxy', format: 'text', url: 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/http.txt' },
    { name: 'IPLocate', format: 'mixed', url: 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt' },
  ],
  https: [
    { name: 'EDT-Pages', format: 'json', url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json' },
    { name: 'ProxyScrape', format: 'json', url: 'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/protocols/https/data.json' },
    { name: 'Proxifly', format: 'json', url: 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.json' },
    { name: 'Relayglass', format: 'json', url: 'https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/https/https.json' },
    { name: 'HProxy', format: 'text', url: 'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/https.txt' },
    { name: 'IPLocate', format: 'mixed', url: 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt' },
  ],
};

const ADMIN_PROXY_SOURCE_REPLACEMENTS = {
  'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json': 'socks5',
  'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json': 'http',
  'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json': 'https',
};

function countryEmoji(code) {
  const value = String(code || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(value)) return '🌐';
  return String.fromCodePoint(...[...value].map(char => 127397 + char.charCodeAt(0)));
}

function normalizeProxyEndpoint(value, expectedType) {
  let raw = String(value || '').trim();
  if (!raw || raw.startsWith('#')) return null;
  raw = raw.split('#', 1)[0].trim();

  let protocol = expectedType;
  const schemeMatch = raw.match(/^([a-z0-9]+):\/\/(.+)$/i);
  if (schemeMatch) {
    protocol = schemeMatch[1].toLowerCase();
    raw = schemeMatch[2].trim();
  }
  if (protocol !== expectedType) return null;

  const atIndex = raw.lastIndexOf('@');
  if (atIndex >= 0) raw = raw.slice(atIndex + 1);

  let host = '';
  let portText = '';
  if (raw.startsWith('[')) {
    const match = raw.match(/^\[([^\]]+)\]:(\d{1,5})(?:\s|\/|\?|$)/);
    if (!match) return null;
    host = match[1];
    portText = match[2];
  } else {
    const match = raw.match(/^([^\s:\/]+):(\d{1,5})(?:\s|\/|\?|$)/);
    if (!match) return null;
    host = match[1];
    portText = match[2];
  }

  const port = Number(portText);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  const formattedHost = host.includes(':') ? `[${host}]` : host;
  return {
    proxy: `${expectedType}://${formattedHost}:${port}`,
    protocol: expectedType,
    ip: host,
    port,
  };
}

function normalizeJsonProxy(item, expectedType, sourceName) {
  if (!item || typeof item !== 'object') return null;
  const declaredProtocol = String(item.protocol || '').toLowerCase();
  if (declaredProtocol && declaredProtocol !== expectedType) return null;

  const candidate = item.proxy || item.url || item.address ||
    ((item.ip || item.host || item.hostname) && item.port
      ? `${item.ip || item.host || item.hostname}:${item.port}`
      : '');
  const endpoint = normalizeProxyEndpoint(candidate, expectedType);
  if (!endpoint) return null;

  const rawCountry = typeof item.country === 'string' ? item.country.trim() : '';
  const geoCountry = typeof item.geolocation?.country === 'string' ? item.geolocation.country.trim() : '';
  const countryCode = String(
    item.country_code || item.countryCode ||
    (rawCountry.length === 2 ? rawCountry : '') ||
    (geoCountry.length === 2 ? geoCountry : '') || ''
  ).toUpperCase();
  const countryName = item.country_en || item.country_name ||
    (rawCountry.length > 2 ? rawCountry : '') ||
    (geoCountry.length > 2 ? geoCountry : '') || 'Unknown';

  return {
    ...item,
    ...endpoint,
    clientIp: item.clientIp || item.client_ip || endpoint.ip,
    country: countryCode || 'XX',
    city: item.city || item.geolocation?.city || 'Unknown',
    asn: item.asn || '',
    asOrganization: item.asOrganization || item.isp || item.organization || '',
    country_cn: item.country_cn || '未知',
    country_en: countryName,
    country_emoji: item.country_emoji || countryEmoji(countryCode),
    continent: item.continent || 'UN',
    continent_cn: item.continent_cn || '未知',
    continent_en: item.continent_en || 'Unknown',
    source: sourceName,
  };
}

function parseJsonProxyList(text, expectedType, sourceName) {
  const parsed = JSON.parse(text);
  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.proxies)
      ? parsed.proxies
      : Array.isArray(parsed?.data)
        ? parsed.data
        : [];
  return rows.map(item => normalizeJsonProxy(item, expectedType, sourceName)).filter(Boolean);
}

function parseTextProxyList(text, expectedType, sourceName, mixedProtocols = false) {
  const output = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const raw = line.trim();
    if (!raw || raw.startsWith('#')) continue;
    if (mixedProtocols && !raw.toLowerCase().startsWith(`${expectedType}://`)) continue;
    const endpoint = normalizeProxyEndpoint(raw, expectedType);
    if (!endpoint) continue;
    output.push({
      ...endpoint,
      clientIp: endpoint.ip,
      country: 'XX',
      city: 'Unknown',
      asn: '',
      asOrganization: '',
      country_cn: '未知',
      country_en: 'Unknown',
      country_emoji: '🌐',
      continent: 'UN',
      continent_cn: '未知',
      continent_en: 'Unknown',
      source: sourceName,
    });
  }
  return output;
}

async function fetchFreeProxySource(source, type) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(source.url, {
      signal: controller.signal,
      headers: { Accept: source.format === 'json' ? 'application/json,text/plain;q=0.9' : 'text/plain,*/*;q=0.8' },
    });
    if (!response.ok) throw new Error(`${source.name}: HTTP ${response.status}`);
    const text = await response.text();
    if (source.format === 'json') return parseJsonProxyList(text, type, source.name);
    return parseTextProxyList(text, type, source.name, source.format === 'mixed');
  } finally {
    clearTimeout(timer);
  }
}

function interleaveProxySources(sourceLists, limit) {
  const output = [];
  const seen = new Set();
  let index = 0;
  let madeProgress = true;

  while (output.length < limit && madeProgress) {
    madeProgress = false;
    for (const list of sourceLists) {
      if (index >= list.length) continue;
      madeProgress = true;
      const item = list[index];
      const key = `${item.protocol}|${item.ip}|${item.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      output.push(item);
      if (output.length >= limit) break;
    }
    index += 1;
  }
  return output;
}

async function getAggregatedFreeProxies(type, limit) {
  const cacheKey = `${type}:${limit}`;
  const cached = freeProxyCache.get(cacheKey);
  if (cached && Date.now() - cached.time < FREE_PROXY_CACHE_TTL_MS) return cached;

  const sources = FREE_PROXY_SOURCES[type];
  const settled = await Promise.allSettled(sources.map(source => fetchFreeProxySource(source, type)));
  const lists = [];
  const okSources = [];
  for (let i = 0; i < settled.length; i++) {
    const result = settled[i];
    if (result.status !== 'fulfilled' || !result.value.length) continue;
    lists.push(result.value);
    okSources.push(sources[i].name);
  }

  const data = interleaveProxySources(lists, limit);
  const entry = { time: Date.now(), data, okSources, totalSources: sources.length };
  freeProxyCache.set(cacheKey, entry);
  return entry;
}

async function handleFreeProxyRequest(url) {
  const type = String(url.searchParams.get('type') || '').toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(FREE_PROXY_SOURCES, type)) {
    return new Response(JSON.stringify({ error: 'type must be socks5, http, or https' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Cache-Control': 'no-store' },
    });
  }

  const requestedLimit = Number(url.searchParams.get('limit'));
  const limit = Number.isFinite(requestedLimit) && requestedLimit > 0
    ? Math.min(FREE_PROXY_MAX_LIMIT, Math.max(1, Math.floor(requestedLimit)))
    : FREE_PROXY_DEFAULT_LIMIT;

  const result = await getAggregatedFreeProxies(type, limit);
  return new Response(JSON.stringify(result.data), {
    status: 200,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'public, max-age=60',
      'X-Proxy-Sources-OK': `${result.okSources.length}/${result.totalSources}`,
      'X-Proxy-Sources': result.okSources.join(','),
    },
  });
}

async function patchAdminProxySources(response, origin) {
  const contentType = response.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().includes('text/html')) return response;

  let html = await response.text();
  for (const [oldUrl, type] of Object.entries(ADMIN_PROXY_SOURCE_REPLACEMENTS)) {
    html = html.split(oldUrl).join(`${origin}/proxy-source?type=${type}`);
  }

  const headers = new Headers(response.headers);
  headers.delete('Content-Length');
  headers.delete('Content-Encoding');
  headers.set('Cache-Control', 'no-store');
  return new Response(html, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/proxy-source') {
      return handleFreeProxyRequest(url);
    }

    const response = await worker.fetch(request, env, ctx);
    if ((url.pathname === '/admin' || url.pathname === '/admin/') && response instanceof Response) {
      return patchAdminProxySources(response, url.origin);
    }
    return response;
  },
};
