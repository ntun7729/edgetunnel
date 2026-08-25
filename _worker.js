import worker from './_worker_core.js';

// Keep the original EdgeTunnel Request and request.fetcher.connect() path intact.
// cfnew-style retry must be integrated inside the TCP forwarding layer rather
// than by replacing the incoming Request or Cloudflare native Socket objects.
export default worker;
