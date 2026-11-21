/**
 * Status-only baseline oracle (RQ2).
 *
 * Inspects nothing beyond the HTTP status code: any 2xx response to a request
 * that the intended policy forbids is reported as a confirmed vulnerability.
 */
export function evaluateStatusOnly(testCase, exec) {
  if (!exec?.attackerRes) {
    return { verdict: 'skipped', reason: exec?.skipReason ?? 'not executed' };
  }
  const status = exec.attackerRes.status;
  if (status >= 200 && status < 300) {
    return {
      verdict: 'vulnerable',
      status: 'confirmed',
      confidence: 0.5,
      expected: testCase.expected,
      observed: `HTTP ${status} returned to unauthorized caller (status-only oracle)`,
    };
  }
  return {
    verdict: 'denied',
    observed: `HTTP ${status}`,
  };
}
