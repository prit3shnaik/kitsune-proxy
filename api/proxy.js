export default async function handler(req, res) {
  // Allow CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const { target } = req.query;
  if (!target) {
    return res.status(400).json({ error: 'Missing target URL' });
  }

  try {
    const decodedTarget = decodeURIComponent(target);
    
    // Security: only allow specific domains
    const url = new URL(decodedTarget);
    const allowed = ['www.cisa.gov', 'cisa.gov', 'services.nvd.nist.gov', 'nvd.nist.gov'];
    
    if (!allowed.includes(url.hostname)) {
      return res.status(403).json({ error: 'Domain not allowed' });
    }

    // Fetch the real API
    const response = await fetch(decodedTarget, {
      headers: { 'User-Agent': 'Kitsune-Proxy/1.0' }
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    res.status(200).json(data);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
