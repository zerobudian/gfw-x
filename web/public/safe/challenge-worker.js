'use strict';
// This is local computational friction, not a server-verifiable access token.
const encoder = new TextEncoder();
function hasZeroBits(bytes, bits) {
  const whole = Math.floor(bits / 8), rest = bits % 8;
  for (let i = 0; i < whole; i++) if (bytes[i] !== 0) return false;
  return rest === 0 || (bytes[whole] >>> (8 - rest)) === 0;
}
self.onmessage = async ({ data }) => {
  const { nonce, bits, budgetMs } = data;
  if (typeof nonce !== 'string' || !/^[a-f0-9]{48}$/.test(nonce) || ![12, 14].includes(bits)) {
    self.postMessage({ error: 'invalid_challenge' }); return;
  }
  try {
    const start = performance.now();
    for (let counter = 0; counter < 2 ** 24; counter++) {
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(nonce + ':' + counter)));
      if (hasZeroBits(hash, bits)) { self.postMessage({ counter }); return; }
      if (counter % 128 === 0 && performance.now() - start > Math.min(budgetMs, 16000)) {
        self.postMessage({ error: 'timeout' }); return;
      }
    }
    self.postMessage({ error: 'timeout' });
  } catch { self.postMessage({ error: 'unavailable' }); }
};
