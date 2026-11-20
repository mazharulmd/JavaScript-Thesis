/**
 * Runtime configuration of the benchmark API, read from environment variables.
 * Every default here is a *benchmark-only* value; nothing in this file is a real secret.
 */
export function loadConfig(env = process.env) {
  return {
    port: Number(env.PORT ?? 3000),
    host: env.HOST ?? '0.0.0.0',
    jwtSecret: env.JWT_SECRET ?? 'bench-only-insecure-secret-change-me',
    tokenTtlSeconds: Number(env.TOKEN_TTL_SECONDS ?? 3600),
    flaws: env.FLAWS ?? 'all',
    benchmarkMode: ['1', 'true', 'yes'].includes(String(env.BENCHMARK_MODE ?? '1').toLowerCase()),
    logRequests: ['1', 'true', 'yes'].includes(String(env.LOG_REQUESTS ?? '0').toLowerCase()),
  };
}
