// save as load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// ---- Ramp-Up Profile ----
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // warm up
    { duration: '1m',  target: 50 },   // ramp to 50 VUs
    { duration: '2m',  target: 100 },  // sustained 100 VUs
    { duration: '1m',  target: 200 },  // peak: 200 VUs
    { duration: '30s', target: 0 },    // cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],   // 95th percentile < 500ms
    http_req_failed: ['rate<0.01'],     // < 1% error rate
    'checks': ['rate>0.99'],
  },
};

const API_URL = 'https://api.sentinelayer.com';

// ---- Scenarios ----

export default function () {
  // Mix of endpoint types (weighted)
  const rand = Math.random();

  if (rand < 0.1) {
    // 10%: Health check
    const res = http.get(`${API_URL}/ready`);
    check(res, { 'ready 200': (r) => r.status === 200 });

  } else if (rand < 0.3) {
    // 20%: Public stats (cached endpoint)
    const res = http.get(`${API_URL}/api/v1/public/stats`);
    check(res, { 'stats 200': (r) => r.status === 200 });

  } else {
    // 70%: Telemetry ingestion (the hot path)
    const payload = JSON.stringify({
      schema_version: '1.0',
      tier: 1,
      run: {
        run_id: uuidv4(),
        timestamp_utc: new Date().toISOString(),
        duration_ms: Math.floor(Math.random() * 10000),
        state: ['passed', 'blocked', 'error'][Math.floor(Math.random() * 3)],
      },
      repo: { repo_hash: `loadtest_${__VU}_${__ITER}` },
      scan: {
        mode: 'pr-diff',
        model_used: 'gpt-5.3-codex',
        tokens_in: 1000,
        tokens_out: 500,
        cost_estimate_usd: 0.05,
      },
      findings: {
        P0: Math.floor(Math.random() * 2),
        P1: Math.floor(Math.random() * 5),
        P2: Math.floor(Math.random() * 10),
        P3: Math.floor(Math.random() * 20),
        total: 0,
      },
      gate: { result: 'passed', dedupe_skipped: false, rate_limit_skipped: false },
      stages: { preflight: 50, ingest: 200, analysis: 3000 },
      meta: { action_version: '1.0.0', idempotency_key: uuidv4() },
    });

    const res = http.post(`${API_URL}/api/v1/telemetry`, payload, {
      headers: { 'Content-Type': 'application/json' },
    });

    check(res, {
      'telemetry 200': (r) => r.status === 200,
      'accepted': (r) => {
        try { return JSON.parse(r.body).status === 'accepted'; }
        catch { return false; }
      },
    });
  }

  sleep(0.1); // 100ms between requests per VU
}
