const { getStore } = require('@netlify/blobs');

// Shared helper: this Netlify site doesn't get the automatic Blobs context
// injected (a quirk of how it was originally provisioned), so we fall back
// to manual configuration using a Personal Access Token stored as env vars
// (BLOBS_SITE_ID, BLOBS_TOKEN) if present. If those aren't set yet, this
// falls back to the automatic method, which will keep failing gracefully
// until the env vars are added — callers already catch and swallow errors.
function scanStatsStore() {
  if (process.env.BLOBS_SITE_ID && process.env.BLOBS_TOKEN) {
    return getStore({
      name: 'scan-stats',
      siteID: process.env.BLOBS_SITE_ID,
      token: process.env.BLOBS_TOKEN,
    });
  }
  return getStore('scan-stats');
}

module.exports = { scanStatsStore };
