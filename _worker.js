import worker from './_worker_core.js';

// Same built-in Cloudflare anycast fallback pool used by cfnew v3.0.
// These are Cloudflare edge addresses, not third-party SOCKS/HTTP/ProxyIP services.
const CF_WARP_FALLBACK_IPS = [
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

function isWarpFallbackEnabled(env) {
  const value = env?.WARP ?? env?.warp;
  if (value === undefined || value === null || String(value).trim() === '') return true;
  return !/^(?:0|false|off|no|direct)$/i.test(String(value).trim());
}

function withCfWarpFallback(env) {
  if (!env || !isWarpFallbackEnabled(env) || env.PROXYIP) return env;

  const fallback = CF_WARP_FALLBACK_IPS[
    Math.floor(Math.random() * CF_WARP_FALLBACK_IPS.length)
  ];

  return new Proxy(env, {
    get(target, property, receiver) {
      if (property === 'PROXYIP') return fallback;
      return Reflect.get(target, property, receiver);
    },
    has(target, property) {
      if (property === 'PROXYIP') return true;
      return Reflect.has(target, property);
    },
  });
}

export default {
  fetch(request, env, ctx) {
    return worker.fetch(request, withCfWarpFallback(env), ctx);
  },
};
