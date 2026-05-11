const ALLOWED_HOSTS = new Set([
  'feodotracker.abuse.ch','urlhaus.abuse.ch','urlhaus-api.abuse.ch',
  'threatfox-api.abuse.ch','mb-api.abuse.ch','bazaar.abuse.ch',
  'www.cisa.gov','cisa.gov','services.nvd.nist.gov',
  'openphish.com','www.openphish.com','phishtank.org','phishstats.info',
  'www.spamhaus.org','drop.spamhaus.org',
  'api.ransomware.live','ransomware.live',
  'ip-api.com','internetdb.shodan.io','crt.sh','rdap.org','rdap.iana.org',
  'api.greynoise.io','urlscan.io',
  'haveibeenpwned.com','api.haveibeenpwned.com','api.pwnedpasswords.com',
  'www.virustotal.com','api.abuseipdb.com','otx.alienvault.com','api.shodan.io',
  'raw.githubusercontent.com','mitchellkrogza.github.io',
  'www.circl.lu','www.botvrij.eu','big.oisd.nl','bgpranking.circl.lu',
]);

const CORS = 'Content-Type,Accept,Authorization,X-Target-URL,x-target-url,X-Extra-Headers,x-extra-headers,X-Auth-Key,x-auth-key,Auth-Key,auth-key,X-Api-Key,x-api-key,apiKey,apikey,X-Hibp-Key,x-hibp-key,hibp-api-key,X-Gn-Key,x-gn-key,key,X-Urlscan-Key,x-urlscan-key,API-Key,user-agent';

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    const asked = req.headers['access-control-request-headers'] || '';
    res.setHeader('Access-Control-Allow-Headers', asked ? asked + ',' + CORS : CORS);
    return res.status(200).end();
  }
  res.setHeader('Access-Control-Allow-Headers', CORS);

  const h = req.headers;
  const target = (h['x-target-url'] || req.query.url || '').trim();
  if (!target) return res.status(400).json({ error: 'Missing X-Target-URL' });

  let tURL;
  try { tURL = new URL(target); }
  catch(e) { return res.status(400).json({ error: 'Bad URL' }); }

  if (!ALLOWED_HOSTS.has(tURL.hostname))
    return res.status(403).json({ error: 'Host not allowed: ' + tURL.hostname });

  const up = {
    'User-Agent': 'Kitsune-CTI/4.0',
    'Accept': h['accept'] || 'application/json,text/plain,*/*',
  };
  const ct = h['content-type'];
  if (ct) up['Content-Type'] = ct;
  if (h['x-auth-key'])    up['Auth-Key']    = h['x-auth-key'];
  if (h['x-api-key'])     up['apiKey']      = h['x-api-key'];
  if (h['x-hibp-key'])  { up['hibp-api-key']= h['x-hibp-key']; up['user-agent']='Kitsune/4.0'; }
  if (h['x-gn-key'])      up['key']         = h['x-gn-key'];
  if (h['x-urlscan-key']) up['API-Key']     = h['x-urlscan-key'];
  if (h['x-extra-headers']) {
    try { Object.assign(up, JSON.parse(h['x-extra-headers'])); } catch(e) {}
  }

  try {
    const opts = { method: req.method, headers: up };
    if (['POST','PUT'].includes(req.method) && req.body) {
      if (typeof req.body === 'string') opts.body = req.body;
      else if (ct && ct.includes('x-www-form-urlencoded')) opts.body = new URLSearchParams(req.body).toString();
      else opts.body = JSON.stringify(req.body);
    }
    const r = await fetch(target, opts);
    const rct = r.headers.get('content-type') || '';
    res.setHeader('Content-Type', rct || 'application/json');
    res.setHeader('X-Proxied-Host', tURL.hostname);
    res.status(r.status);
    if (rct.includes('json')) return res.json(await r.json());
    return res.send(await r.text());
  } catch(err) {
    return res.status(502).json({ error: err.message, target });
  }
};
