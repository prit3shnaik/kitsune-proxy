// Kitsune CTI Proxy — Vercel Serverless Function
// Bypasses CORS for all threat intelligence feeds
// Deploy this to Vercel (free tier is fine)

const ALLOWED_ORIGINS = [
  'https://0xprit3sh.xyz',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
  // Add your GitHub Pages URL:
  // 'https://yourusername.github.io',
];

const ALLOWED_HOSTS = new Set([
  'cisa.gov',
  'www.cisa.gov',
  'services.nvd.nist.gov',
  'big.oisd.nl',
  'www.circl.lu',
  'www.botvrij.eu',
  'www.openphish.com',
  'phishstats.info',
  'phishtank.org',
  'mitchellkrogza.github.io',
  'www.phishtank.org',
  'data.phishtank.com',
  'spamhaus.org',
  'www.spamhaus.org',
  'drop.spamhaus.org',
  'ransomware.live',
  'api.ransomware.live',
  'raw.githubusercontent.com',
  'haveibeenpwned.com',
  'api.pwnedpasswords.com',
  'api.haveibeenpwned.com',
  'api.greynoise.io',
  'urlscan.io',
  'ip-api.com',
  'feodotracker.abuse.ch',
  'urlhaus.abuse.ch',
  'urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch',
  'mb-api.abuse.ch',
  'bazaar.abuse.ch',
  'otx.alienvault.com',
  'www.virustotal.com',
  'api.shodan.io',
  'api.abuseipdb.com',
]);

export default async function handler(req, res) {
  // CORS headers
  const origin = req.headers['origin'] || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  
  res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Target-URL, X-Extra-Headers');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Parse target URL
  let targetUrl = req.headers['x-target-url'] || req.query.url;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing x-target-url header or url query param' });
  }

  // Validate target host
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL: ' + targetUrl });
  }

  const host = parsedUrl.hostname;
  if (!ALLOWED_HOSTS.has(host)) {
    return res.status(403).json({ error: `Host not allowed: ${host}` });
  }

  // Build forward headers
  // Determine Content-Type from the incoming request
  // Kitsune sends it as 'Content-Type' header on the proxy call itself
  const incomingCT = req.headers['content-type'] || 'application/json';

  const forwardHeaders = {
    'User-Agent': 'Kitsune-CTI-Proxy/1.0',
    'Accept': req.headers['accept'] || 'application/json, text/plain, */*',
    'Content-Type': incomingCT,
  };

  // Pass through extra headers (for API keys)
  const extraHeaders = req.headers['x-extra-headers'];
  if (extraHeaders) {
    try {
      const parsed = JSON.parse(extraHeaders);
      Object.assign(forwardHeaders, parsed);
    } catch (e) {}
  }

  // Standard auth headers
  const authKey = req.headers['x-auth-key'];
  if (authKey) forwardHeaders['Auth-Key'] = authKey;
  
  const apiKey = req.headers['x-api-key'];
  if (apiKey) forwardHeaders['apiKey'] = apiKey;

  // Handle HIBP key
  const hibpKey = req.headers['x-hibp-key'];
  if (hibpKey) {
    forwardHeaders['hibp-api-key'] = hibpKey;
    forwardHeaders['user-agent'] = 'Kitsune-CTI/1.0';
  }

  // GreyNoise key
  const gnKey = req.headers['x-gn-key'];
  if (gnKey) forwardHeaders['key'] = gnKey;

  // URLScan key  
  const urlscanKey = req.headers['x-urlscan-key'];
  if (urlscanKey) forwardHeaders['API-Key'] = urlscanKey;

  try {
    const fetchOpts = {
      method: req.method === 'GET' ? 'GET' : 'POST',
      headers: forwardHeaders,
    };

    if (req.method === 'POST' && req.body) {
      fetchOpts.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    }

    const upstream = await fetch(targetUrl, fetchOpts);
    const contentType = upstream.headers.get('content-type') || '';
    
    res.status(upstream.status);
    res.setHeader('Content-Type', contentType || 'application/json');
    res.setHeader('X-Proxied-From', host);

    if (contentType.includes('json')) {
      const data = await upstream.json();
      return res.json(data);
    } else {
      const text = await upstream.text();
      return res.send(text);
    }
  } catch (err) {
    return res.status(502).json({
      error: 'Upstream fetch failed',
      detail: err.message,
      target: targetUrl,
    });
  }
}
