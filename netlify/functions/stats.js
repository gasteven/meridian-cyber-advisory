const { getStore } = require('@netlify/blobs');

// TEMPORARY debug version — surfaces the real error so we can diagnose the
// Blobs write failure. Will be replaced with the clean version once fixed.
exports.handler = async () => {
  try {
    const store = getStore('scan-stats');
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
      body: JSON.stringify({
        error: 'Stats unavailable',
        debugMessage: e && e.message,
        debugName: e && e.name,
        debugStack: e && String(e.stack).split('\n').slice(0, 5),
        hasContext: !!process.env.NETLIFY_BLOBS_CONTEXT,
      }),
    };
  }
};
