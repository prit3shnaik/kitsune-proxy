// Kitsune CTI Proxy — Vercel Serverless Function v2
// Fixes: dynamic CORS preflight, x-auth-key case-insensitive, all header variants

const ALLOWED_ORIGINS = [
  'https://0xprit3sh.xyz',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
  'http://localhost',
  'null', // file:// local dev
];

const ALLOWED_HOSTS = new Set([
  // Threat feeds
  'feodotracker.abuse.ch',
  'urlhaus.abuse.ch',
  'urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch',
  'mb-api.abuse.ch',
  'bazaar.abuse.ch',
  // CISA / NVD
  'www.cisa.gov',
  'cisa.gov',
  'services.nvd.nist.gov',
  // Phishing
  'openphish.com',
  'www.openphish.com',
  'phishtank.org',
  'www.phishtank.org',
  'phishstats.info',
  // Spam / ransomware
  'www.spamhaus.org',
  'drop.spamhaus.org',
  'api.ransomware.live',
  'ransomware.live',
  // Enrichment (no-key)
  'ip-api.com',
  'internetdb.shodan.io',
  'crt.sh',
  'rdap.org',
  'rdap.iana.org',
  // Enrichment (keyed)
  'api.greynoise.io',
  'urlscan.io',
  'haveibeenpwned.com',
  'api.haveibeenpwned.com',
  'api.pwnedpasswords.com',
  'www.virustotal.com',
  'api.abuseipdb.com',
  'otx.alienvault.com',
  'api.shodan.io',
  // GitHub raw
  'raw.githubusercontent.com',
  'mitchellkrogza.github.io',
  // MISP community feeds
  'www.circl.lu',
  'www.botvrij.eu',
  'big.oisd.nl',
  // BGP
  'bgpranking.circl.lu',
]);

// All custom headers the client might send — used for dynamic preflight reply
const ALL_ALLOWED_HEADERS = [
  'Content-Type',
  'Accept',
  'Authorization',
  'X-Target-URL',
  'x-target-url',
  'X-Extra-Headers',
  'x-extra-headers',
  'X-Auth-Key',
  'x-auth-key',           // ← the one that was failing
  'X-Api-Key',
  'x-api-key',
  'X-Hibp-Key',
  'x-hibp-key',
  'X-Gn-Key',
  'x-gn-key',
  'X-Urlscan-Key',
  'x-urlscan-key',
  'auth-key',
  'Auth-Key',
  'apiKey',
  'apikey',
  'hibp-api-key',
  'key',
  'API-Key',
  'user-agent',
].join(',');

function corsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : '*';
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': ALL_ALLOWED_HEADERS,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

export default async function handler(req, res) {
  const origin = req.headers['origin'] || '';
  const cors = corsHeaders(origin);

  // ── OPTIONS preflight — must return 200 immediately with full CORS headers
  if (req.method === 'OPTIONS') {
    Object.entries(cors).forEach(([k, v]) => res.setHeader(k, v));
    // Echo back whatever headers the client asked for (most permissive approach)
    const requested = req.headers['access-control-request-headers'];
    if (requested) res.setHeader('Access-Control-Allow-Headers', requested + ',' + ALL_ALLOWED_HEADERS);
    return res.status(200).end();
  }

  // Set CORS on every response
  Object.entries(cors).forEach(([k, v]) => res.setHeader(k, v));

  // ── Parse target URL (check both header and query param)
  const targetUrl = (req.headers['x-target-url'] || req.headers['X-Target-URL'] || req.query.url || '').trim();

  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing X-Target-URL header or ?url= param' });
  }

  // ── Validate host
  let parsed;
  try { parsed = new URL(targetUrl); }
  catch (e) { return res.status(400).json({ error: 'Invalid URL: ' + targetUrl }); }

  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    return res.status(403).json({ error: 'Host not in allowlist: ' + parsed.hostname });
  }

  // ── Build upstream headers
  // Start with sensible defaults
  const upstreamHeaders = {
    'User-Agent': 'Kitsune-CTI-Proxy/2.0',
    'Accept': req.headers['accept'] || 'application/json, text/plain, */*',
  };

  // Forward Content-Type if present (important for POST with form body)
  const ct = req.headers['content-type'];
  if (ct) upstreamHeaders['Content-Type'] = ct;

  // ── API key forwarding — handle all variants case-insensitively
  // abuse.ch Auth-Key
  const authKey = req.headers['x-auth-key'] || req.headers['X-Auth-Key'];
  if (authKey) upstreamHeaders['Auth-Key'] = authKey;

  // Generic API key (VT, etc.)
  const apiKey = req.headers['x-api-key'] || req.headers['X-Api-Key'];
  if (apiKey) upstreamHeaders['apiKey'] = apiKey;

  // HIBP
  const hibpKey = req.headers['x-hibp-key'] || req.headers['X-Hibp-Key'];
  if (hibpKey) {
    upstreamHeaders['hibp-api-key'] = hibpKey;
    upstreamHeaders['user-agent'] = 'Kitsune-CTI/2.0';
  }

  // GreyNoise
  const gnKey = req.headers['x-gn-key'] || req.headers['X-Gn-Key'];
  if (gnKey) upstreamHeaders['key'] = gnKey;

  // URLScan
  const urlscanKey = req.headers['x-urlscan-key'] || req.headers['X-Urlscan-Key'];
  if (urlscanKey) upstreamHeaders['API-Key'] = urlscanKey;

  // Extra passthrough headers blob (JSON-encoded)
  const extra = req.headers['x-extra-headers'] || req.headers['X-Extra-Headers'];
  if (extra) {
    try {
      const parsed = JSON.parse(extra);
      Object.assign(upstreamHeaders, parsed);
    } catch (e) { /* ignore malformed */ }
  }

  // ── Proxy the request
  try {
    const fetchOpts = {
      method: req.method,
      headers: upstreamHeaders,
    };

    // Forward body for POST/PUT
    if (['POST', 'PUT'].includes(req.method)) {
      if (typeof req.body === 'string') {
        fetchOpts.body = req.body;
      } else if (req.body && typeof req.body === 'object') {
        // Vercel may auto-parse JSON body — re-serialize if Content-Type is form
        if (ct && ct.includes('x-www-form-urlencoded')) {
          fetchOpts.body = new URLSearchParams(req.body).toString();
        } else {
          fetchOpts.body = JSON.stringify(req.body);
        }
      }
    }

    const upstream = await fetch(targetUrl, fetchOpts);
    const respCT = upstream.headers.get('content-type') || '';

    res.status(upstream.status);
    res.setHeader('Content-Type', respCT || 'application/json');
    res.setHeader('X-Proxied-Host', parsed.hostname);
    res.setHeader('X-Upstream-Status', String(upstream.status));

    // Stream response
    if (respCT.includes('json')) {
      const data = await upstream.json();
      return res.json(data);
    } else {
      const text = await upstream.text();
      return res.send(text);
    }

  } catch (err) {
    return res.status(502).json({
      error: 'Upstream request failed',
      detail: err.message,
      target: targetUrl,
    });
  }
}
