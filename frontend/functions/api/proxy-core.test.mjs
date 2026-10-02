import assert from 'node:assert/strict';
import { test } from 'node:test';
import { proxyApiRequest } from './proxy-core.mjs';

test('proxies API path, query, cookie, CSRF form and manual OAuth redirect', async () => {
  const request = new Request(
    'https://switchboard.pages.dev/api/connections/github/start?return=%2F',
    {
      method: 'POST',
      headers: {
        Cookie: '__Host-switchboard.sid=opaque-session',
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://switchboard.pages.dev',
        'X-CSRF-Token': 'csrf-value',
        'X-Forwarded-Host': 'attacker.example',
        'X-Forwarded-For': '203.0.113.99',
        'CF-Connecting-IP': '203.0.113.7'
      },
      body: 'csrfToken=csrf-value'
    }
  );
  let forwarded;

  const response = await proxyApiRequest(
    request,
    { API_ORIGIN: 'https://switchboard-api.onrender.com' },
    async forwardedRequest => {
      forwarded = forwardedRequest;
      return new Response(null, {
        status: 302,
        headers: { Location: 'https://github.com/login/oauth/authorize' }
      });
    }
  );

  assert.equal(forwarded.url, 'https://switchboard-api.onrender.com/api/connections/github/start?return=%2F');
  assert.equal(forwarded.method, 'POST');
  assert.equal(forwarded.headers.get('cookie'), '__Host-switchboard.sid=opaque-session');
  assert.equal(forwarded.headers.get('x-csrf-token'), 'csrf-value');
  assert.equal(forwarded.headers.get('origin'), 'https://switchboard.pages.dev');
  assert.equal(forwarded.headers.get('x-forwarded-host'), 'switchboard.pages.dev');
  assert.equal(forwarded.headers.get('x-forwarded-proto'), 'https');
  assert.equal(forwarded.headers.get('x-forwarded-for'), '203.0.113.7');
  assert.equal(forwarded.headers.get('host'), null);
  assert.equal(await forwarded.text(), 'csrfToken=csrf-value');
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('location'), 'https://github.com/login/oauth/authorize');
});

test('preserves the backend HttpOnly session cookie on a proxied response', async () => {
  const request = new Request('https://switchboard.pages.dev/api/session');
  const cookie = '__Host-switchboard.sid=opaque-session; Path=/; HttpOnly; Secure; SameSite=Lax';

  const response = await proxyApiRequest(
    request,
    { API_ORIGIN: 'https://switchboard-api.onrender.com' },
    async () => new Response('{"csrfToken":"safe"}', {
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie }
    })
  );

  assert.equal(response.headers.get('set-cookie'), cookie);
  assert.equal(await response.text(), '{"csrfToken":"safe"}');
});

test('fails closed when the backend origin is missing or not a secure origin', async () => {
  const request = new Request('https://switchboard.pages.dev/api/session');
  let fetchCalled = false;
  const fetcher = async () => {
    fetchCalled = true;
    return new Response('unexpected');
  };

  const missing = await proxyApiRequest(request, {}, fetcher);
  const insecure = await proxyApiRequest(request, { API_ORIGIN: 'http://example.com' }, fetcher);

  assert.equal(missing.status, 503);
  assert.equal(insecure.status, 503);
  assert.equal(fetchCalled, false);
});

test('rejects oversized state-changing request bodies before forwarding', async () => {
  const request = new Request('https://switchboard.pages.dev/api/session/workspace/clear', {
    method: 'POST',
    body: 'x'.repeat(65_537)
  });
  let fetchCalled = false;

  const response = await proxyApiRequest(
    request,
    { API_ORIGIN: 'https://switchboard-api.onrender.com' },
    async () => {
      fetchCalled = true;
      return new Response('unexpected');
    }
  );

  assert.equal(response.status, 413);
  assert.equal(fetchCalled, false);
});
