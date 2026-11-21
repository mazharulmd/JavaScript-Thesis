import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';

/**
 * OpenAPI 3.x loader and operation inventory.
 *
 * Produces a flat, dependency-free description of every operation: method, path template,
 * parameters, request-body schema, response schemas, effective security requirement and the
 * documented access-control policy (`x-access-control`, if present). Nothing about a specific
 * API is hard-coded here.
 */
const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

export function loadSpec(path) {
  const text = readFileSync(path, 'utf8');
  const doc = path.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  return validateSpecShape(doc, path);
}

function validateSpecShape(doc, source = 'spec') {
  if (!doc || typeof doc !== 'object') throw new Error(`${source}: not an OpenAPI document`);
  if (typeof doc.openapi !== 'string' || !doc.openapi.startsWith('3.')) {
    throw new Error(`${source}: only OpenAPI 3.x is supported (found ${doc.openapi ?? doc.swagger ?? 'unknown'})`);
  }
  if (!doc.paths || typeof doc.paths !== 'object') throw new Error(`${source}: missing "paths"`);
  return doc;
}

/** Resolves a local JSON pointer reference ("#/components/schemas/User"). */
export function resolveRef(doc, ref) {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) throw new Error(`Only local $ref values are supported: ${ref}`);
  return ref.slice(2).split('/').reduce((node, raw) => {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === undefined || node === null || !(key in node)) throw new Error(`Unresolvable $ref: ${ref}`);
    return node[key];
  }, doc);
}

/** Returns a copy of `node` with all local $refs replaced (cycle-safe). */
export function deref(doc, node, seen = new Set()) {
  if (Array.isArray(node)) return node.map((n) => deref(doc, n, seen));
  if (!node || typeof node !== 'object') return node;
  if (typeof node.$ref === 'string') {
    if (seen.has(node.$ref)) return { $circular: node.$ref };
    const next = new Set(seen).add(node.$ref);
    return deref(doc, resolveRef(doc, node.$ref), next);
  }
  const out = {};
  for (const [k, v] of Object.entries(node)) out[k] = deref(doc, v, seen);
  return out;
}

function mergeParameters(doc, pathLevel = [], opLevel = []) {
  const byKey = new Map();
  for (const p of [...pathLevel, ...opLevel].map((x) => deref(doc, x))) byKey.set(`${p.in}:${p.name}`, p);
  return [...byKey.values()].map((p) => ({
    name: p.name,
    in: p.in,
    required: p.in === 'path' ? true : !!p.required,
    schema: p.schema ?? {},
    example: p.example ?? p.schema?.example,
  }));
}

function jsonContent(content) {
  if (!content) return undefined;
  const key = Object.keys(content).find((k) => /json/i.test(k)) ?? Object.keys(content)[0];
  return key ? { mediaType: key, schema: content[key].schema, example: content[key].example } : undefined;
}

/**
 * Flat list of operations.
 * @returns {Array<{id, method, path, operationId, summary, tags, parameters, pathParams,
 *   requestBody, responses, security, requiresAuth, isPublic, accessControl}>}
 */
export function listOperations(doc) {
  validateSpecShape(doc);
  const globalSecurity = doc.security ?? [];
  const ops = [];
  for (const [path, rawItem] of Object.entries(doc.paths)) {
    const item = rawItem.$ref ? resolveRef(doc, rawItem.$ref) : rawItem;
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const security = op.security ?? globalSecurity;
      const requiresAuth = Array.isArray(security) && security.length > 0 && !security.some((req) => Object.keys(req).length === 0);
      const parameters = mergeParameters(doc, item.parameters, op.parameters);
      const body = op.requestBody ? deref(doc, op.requestBody) : undefined;
      const content = jsonContent(body?.content);
      const responses = {};
      for (const [status, r] of Object.entries(op.responses ?? {})) {
        const resolved = deref(doc, r);
        responses[status] = { description: resolved.description, schema: jsonContent(resolved.content)?.schema };
      }
      ops.push({
        id: `${method.toUpperCase()} ${path}`,
        method: method.toUpperCase(),
        path,
        operationId: op.operationId,
        summary: op.summary,
        tags: op.tags ?? [],
        parameters,
        pathParams: parameters.filter((p) => p.in === 'path').map((p) => p.name),
        requestBody: content ? { required: !!body.required, mediaType: content.mediaType, schema: content.schema, example: content.example } : undefined,
        responses,
        security,
        requiresAuth,
        isPublic: !requiresAuth,
        accessControl: op['x-access-control'] ?? null,
      });
    }
  }
  return ops;
}

/** Concrete URL path for a template and parameter values; values are URI-encoded. */
export function fillPath(template, values) {
  return template.replace(/\{([^}]+)\}/g, (_, name) => {
    if (values[name] === undefined || values[name] === null) throw new Error(`Missing value for path parameter "${name}" in ${template}`);
    return encodeURIComponent(String(values[name]));
  });
}

/** Server base URL declared in the spec (first entry), if any. */
export function specServer(doc) {
  return doc.servers?.[0]?.url ?? null;
}
