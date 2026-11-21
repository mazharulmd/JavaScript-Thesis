/**
 * Minimal HTTP client for the scanner: per-request timeout, optional delay between
 * requests (throttling), a hard request budget and a request counter for RQ3.
 */
export function createHttpClient({ baseUrl, timeoutMs = 5000, delayMs = 0, maxRequests = 5000, fetchImpl = fetch } = {}) {
  let count = 0;
  let last = 0;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function request(method, path, { headers = {}, body, query } = {}) {
    if (count >= maxRequests) throw new Error(`Request budget exhausted (maxRequests = ${maxRequests})`);
    if (delayMs > 0) {
      const wait = last + delayMs - Date.now();
      if (wait > 0) await sleep(wait);
    }
    const url = new URL(path, baseUrl);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
    const init = { method, headers: { accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeoutMs) };
    if (body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    count += 1;
    last = Date.now();
    const started = performance.now();
    const res = await fetchImpl(url, init);
    const text = await res.text();
    let json;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: json ?? text,
      isJson: json !== undefined,
      durationMs: performance.now() - started,
      request: { method, url: url.toString(), headers: init.headers, body },
    };
  }

  return { request, get count() { return count; } };
}
