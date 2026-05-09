// Kitsune CTI Proxy — Vercel Serverless Function v3
// CommonJS format (no "type":"module" needed) — fixes 404 on Vercel

const ALLOWED_ORIGINS = [
  'https://0xprit3sh.xyz',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
  'http://localhost',
];

const ALLOWED_HOSTS = new Set([
  'feodotracker.abuse.ch',
  'urlhaus.abuse.ch','urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch',
  'mb-api.abuse.ch','bazaar.abuse.ch',
  'www.cisa.gov','cisa.gov',
  'services.nvd.nist.gov',
  'openphish.com','www.openphish.com',
  'phishtank.org','www.phishtank.org','phishstats.info',
  'www.spamhaus.org','drop.spamhaus.org',
  'api.ransomware.live','ransomware.live',
  'ip-api.com',
  'internetdb.shodan.io',
  'crt.sh',
  'rdap.org','rdap.iana.org',
  'api.greynoise.io',
  'urlscan.io',
  'haveibeenpwned.com','api.haveibeenpwned.com','api.pwnedpasswords.com',
  'www.virustotal.com',
  'api.abuseipdb.com',
  'otx.alienvault.com',
  'api.shodan.io',
  'raw.githubusercontent.com','mitchellkrogza.github.io',
  'www.circl.lu','www.botvrij.eu','big.oisd.nl',
  'bgpranking.circl.lu',
]);

const ALL_ALLOWED_HEADERS = [
  'Content-Type','Accept','Authorization',
  'X-Target-URL','x-target-url',
  'X-Extra-Headers','x-extra-headers',
  'X-Auth-Key','x-auth-key','Auth-Key','auth-key',
  'X-Api-Key','x-api-key','apiKey','apikey',
  'X-Hibp-Key','x-hibp-key','hibp-api-key',
  'X-Gn-Key','x-gn-key','key',
  'X-Urlscan-Key','x-urlscan-key','API-Key',
  'user-agent',
].join(',');

module.exports = async function handler(req, res) {
  const origin = req.headers['origin'] || '';
  const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : '*';

  // CORS headers on every response
  res.setHeader('Access-Control-Allow-Origin', allowOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');

  // ── OPTIONS preflight — echo back whatever headers were requested
  if (req.method === 'OPTIONS') {
    const requested = req.headers['access-control-request-headers'] || '';
    res.setHeader('Access-Control-Allow-Headers', requested ? requested + ',' + ALL_ALLOWED_HEADERS : ALL_ALLOWED_HEADERS);
    return res.status(200).end();
  }

  // Always set allow-headers on real requests too
  res.setHeader('Access-Control-Allow-Headers', ALL_ALLOWED_HEADERS);

  // ── Get target URL
  const h = req.headers;
  const targetUrl = (h['x-target-url'] || h['X-Target-URL'] || req.query.url || '').trim();
  if (!targetUrl) return res.status(400).json({ error: 'Missing X-Target-URL' });

  // ── Validate host
  let parsedUrl;
  try { parsedUrl = new URL(targetUrl); }
  catch (e) { return res.status(400).json({ error: 'Invalid URL: ' + targetUrl }); }

  if (!ALLOWED_HOSTS.has(parsedUrl.hostname)) {
    return res.status(403).json({ error: 'Host not allowed: ' + parsedUrl.hostname });
  }

  // ── Build upstream headers
  const upstream = {
    'User-Agent': 'Kitsune-CTI-Proxy/3.0',
    'Accept': h['accept'] || 'application/json, text/plain, */*',
  };

  const ct = h['content-type'];
  if (ct) upstream['Content-Type'] = ct;

  // API keys — check both cases
  const authKey = h['x-auth-key'] || h['X-Auth-Key'];
  if (authKey) upstream['Auth-Key'] = authKey;

  const apiKey = h['x-api-key'] || h['X-Api-Key'];
  if (apiKey) upstream['apiKey'] = apiKey;

  const hibp = h['x-hibp-key'] || h['X-Hibp-Key'];
  if (hibp) { upstream['hibp-api-key'] = hibp; upstream['user-agent'] = 'Kitsune-CTI/3.0'; }

  const gn = h['x-gn-key'] || h['X-Gn-Key'];
  if (gn) upstream['key'] = gn;

  const us = h['x-urlscan-key'] || h['X-Urlscan-Key'];
  if (us) upstream['API-Key'] = us;

  // Extra JSON-encoded headers blob (for NVD apiKey, VT x-apikey, OTX, etc.)
  const extra = h['x-extra-headers'] || h['X-Extra-Headers'];
  if (extra) {
    try { Object.assign(upstream, JSON.parse(extra)); }
    catch (e) { /* ignore */ }
  }

  // ── Proxy request
  try {
    const fetchOpts = { method: req.method, headers: upstream };

    if (['POST', 'PUT'].includes(req.method) && req.body) {
      if (typeof req.body === 'string') {
        fetchOpts.body = req.body;
      } else if (ct && ct.includes('x-www-form-urlencoded')) {
        fetchOpts.body = new URLSearchParams(req.body).toString();
      } else {
        fetchOpts.body = JSON.stringify(req.body);
      }
    }

    const upstreamRes = await fetch(targetUrl, fetchOpts);
    const respCT = upstreamRes.headers.get('content-type') || '';

    res.status(upstreamRes.status);
    res.setHeader('Content-Type', respCT || 'application/json');
    res.setHeader('X-Proxied-Host', parsedUrl.hostname);

    if (respCT.includes('json')) {
      return res.json(await upstreamRes.json());
    }
    return res.send(await upstreamRes.text());

  } catch (err) {
    return res.status(502).json({ error: 'Upstream failed', detail: err.message, target: targetUrl });
  }
};
