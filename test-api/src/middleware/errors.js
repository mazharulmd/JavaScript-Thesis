/** Uniform JSON error responses: { error: { code, message } }. */
export function sendError(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

export function notFoundHandler(req, res) {
  sendError(res, 404, 'not_found', `No route for ${req.method} ${req.path}`);
}

// Express recognises error handlers by their arity, so all four parameters are required.
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  if (err?.type === 'entity.parse.failed') return sendError(res, 400, 'bad_request', 'Malformed JSON body');
  const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error('[test-api] unhandled error:', err);
  sendError(res, status, status >= 500 ? 'internal_error' : 'bad_request', status >= 500 ? 'Internal server error' : err.message);
}
