const MAX_API_BODY_BYTES = 64 * 1024;
const HOP_BY_HOP_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
];

export async function proxyApiRequest(request, env, fetcher = fetch) {
  const pageUrl = new URL(request.url);
  if (pageUrl.pathname !== '/api' && !pageUrl.pathname.startsWith('/api/')) {
    return jsonError(404, 'not_found');
  }

  const apiOrigin = parseApiOrigin(env?.API_ORIGIN);
  if (!apiOrigin) {
    return jsonError(503, 'api_origin_not_configured');
  }

  const targetUrl = new URL(`${pageUrl.pathname}${pageUrl.search}`, apiOrigin);
  const headers = new Headers(request.headers);
  for (const name of HOP_BY_HOP_HEADERS) headers.delete(name);
  headers.delete('host');
  headers.delete('x-forwarded-host');
  headers.delete('x-forwarded-proto');
  headers.delete('x-forwarded-port');
  headers.delete('x-forwarded-for');
  headers.delete('cf-connecting-ip');
  headers.set('x-forwarded-host', pageUrl.host);
  headers.set('x-forwarded-proto', pageUrl.protocol.slice(0, -1));

  const clientIp = request.headers.get('cf-connecting-ip');
  if (clientIp) headers.set('x-forwarded-for', clientIp);

  let body;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const declaredLength = Number(request.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_API_BODY_BYTES) {
      return jsonError(413, 'request_too_large');
    }

    body = await request.arrayBuffer();
    if (body.byteLength > MAX_API_BODY_BYTES) {
      return jsonError(413, 'request_too_large');
    }
  }

  try {
    const upstreamRequest = new Request(targetUrl, {
      method: request.method,
      headers,
      body,
      redirect: 'manual'
    });
    const upstreamResponse = await fetcher(upstreamRequest);
    const responseHeaders = new Headers(upstreamResponse.headers);
    for (const name of HOP_BY_HOP_HEADERS) responseHeaders.delete(name);

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders
    });
  } catch {
    return jsonError(502, 'api_unavailable');
  }
}

function parseApiOrigin(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;

  try {
    const url = new URL(value);
    const isLocalHttp = url.protocol === 'http:'
      && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((url.protocol !== 'https:' && !isLocalHttp)
      || url.username
      || url.password
      || url.pathname !== '/'
      || url.search
      || url.hash) {
      return null;
    }

    return url.origin;
  } catch {
    return null;
  }
}

function jsonError(status, error) {
  return Response.json({ error }, {
    status,
    headers: { 'Cache-Control': 'no-store' }
  });
}
