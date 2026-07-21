const { scanStatsStore } = require('./blobs-store');

// Read-only endpoint exposing aggregate, anonymized scan-tool stats.
// No scanned domains or identifying info are ever stored here — only
// running counts (grade distribution, per-check pass/fail totals).
exports.handler = async () => {
  try {
    const store = scanStatsStore();
    const data = (await store.get('aggregate', { type: 'json' })) || {
      totalScans: 0,
      gradeCounts: { A: 0, B: 0, C: 0, D: 0, F: 0 },
      checks: {},
    };
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify(data),
    };
  } catch (e) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: 'Stats unavailable', debugMessage: e && e.message }),
    };
  }
};
