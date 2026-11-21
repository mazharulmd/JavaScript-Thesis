/**
 * Builds a syntactically valid example value from a (dereferenced) JSON schema.
 * Priority: example → default → enum[0] → format → type. readOnly properties are skipped
 * because clients must not send them. Used to construct legitimate request bodies.
 */
export function sampleFromSchema(schema, { depth = 0, uniqueSuffix = '' } = {}) {
  if (!schema || typeof schema !== 'object' || depth > 8) return null;
  if (schema.example !== undefined) return uniquify(schema.example, schema, uniqueSuffix);
  if (schema.default !== undefined) return schema.default;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (schema.allOf) return Object.assign({}, ...schema.allOf.map((s) => sampleFromSchema(s, { depth: depth + 1, uniqueSuffix }) ?? {}));
  if (schema.oneOf || schema.anyOf) return sampleFromSchema((schema.oneOf ?? schema.anyOf)[0], { depth: depth + 1, uniqueSuffix });

  const type = Array.isArray(schema.type) ? schema.type.find((t) => t !== 'null') : schema.type;
  switch (type ?? (schema.properties ? 'object' : undefined)) {
    case 'object': {
      const out = {};
      for (const [name, prop] of Object.entries(schema.properties ?? {})) {
        if (prop?.readOnly) continue;
        out[name] = sampleFromSchema(prop, { depth: depth + 1, uniqueSuffix: name.match(/name|email|title|sku/i) ? uniqueSuffix : '' });
      }
      return out;
    }
    case 'array': {
      const item = sampleFromSchema(schema.items, { depth: depth + 1, uniqueSuffix });
      return item === null ? [] : [item];
    }
    case 'integer': return clamp(schema.minimum ?? 1, schema);
    case 'number': return clamp(schema.minimum ?? 1.5, schema);
    case 'boolean': return true;
    case 'string': return stringForFormat(schema.format, uniqueSuffix);
    default: return null;
  }
}

function clamp(v, s) {
  let x = v;
  if (s.maximum !== undefined) x = Math.min(x, s.maximum);
  if (s.minimum !== undefined) x = Math.max(x, s.minimum);
  return x;
}

function stringForFormat(format, suffix) {
  switch (format) {
    case 'email': return `sample${suffix}@example.test`;
    case 'date-time': return '2026-01-01T00:00:00.000Z';
    case 'date': return '2026-01-01';
    case 'uuid': return '00000000-0000-4000-8000-000000000000';
    case 'uri': return 'https://example.test/';
    case 'password': return 'Sample#Pass1';
    default: return `sample${suffix}`;
  }
}

function uniquify(example, schema, suffix) {
  if (!suffix || typeof example !== 'string' || schema.enum) return example;
  if (schema.format === 'email' && example.includes('@')) {
    const [local, domain] = example.split('@');
    return `${local}-${suffix}@${domain}`;
  }
  return `${example}-${suffix}`;
}
