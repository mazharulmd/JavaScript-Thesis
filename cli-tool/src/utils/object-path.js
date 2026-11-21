/** Reads a dot-separated path ("user.id", "data.items.0.id") from a JSON value. */
export function getPath(obj, path) {
  if (!path) return undefined;
  return String(path).split('.').reduce((node, key) => (node === null || node === undefined ? undefined : node[key]), obj);
}

/** Decodes the claims of a JWT WITHOUT verifying it (used only to read the caller's own identity). */
export function readJwtClaims(token) {
  const parts = String(token ?? '').split('.');
  if (parts.length < 2) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
