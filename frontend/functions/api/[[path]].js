import { proxyApiRequest } from './proxy-core.mjs';

export async function onRequest({ request, env }) {
  return proxyApiRequest(request, env);
}
