/**
 * KyoRox Official Node.js HS256 JWT Callback Verifier (Zero Dependencies)
 * Docs: https://kyorox.com/docs
 */
'use strict';

const crypto = require('node:crypto');

/**
 * Verifies an incoming HS256 JWT from KyoRox SAML-to-JWT Proxy (sso.kyorox.com)
 * @param {string} token - Raw JWT from query/body (?token=...)
 * @param {string} clientSecret - Tenant JWT Signing Secret from KyoRox Control Plane
 * @param {string} expectedTenantId - Your KyoRox Tenant UUID v4
 * @returns {object} Verified normalized SAML user claims
 */
function verifyKyoRoxJwt(token, clientSecret, expectedTenantId) {
  if (!token || typeof token !== 'string') {
    throw new Error('Missing or invalid KyoRox JWT token string.');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT structure.');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // 1. Verify Header Algorithm is strictly HS256
  const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
  if (header.alg !== 'HS256') {
    throw new Error(`Unsupported JWT algorithm: ${header.alg}. Expected HS256.`);
  }

  // 2. Constant-Time HMAC-SHA256 Signature Verification
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSig = crypto
    .createHmac('sha256', clientSecret)
    .update(signingInput)
    .digest('base64url');

  const sigBuffer = Buffer.from(encodedSignature, 'utf8');
  const expectedBuffer = Buffer.from(expectedSig, 'utf8');

  if (
    sigBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
  ) {
    throw new Error('Invalid KyoRox JWT cryptographic signature.');
  }

  // 3. Parse Claims & Validate Expiration + Tenant Isolation
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  const nowSeconds = Math.floor(Date.now() / 1000);

  if (typeof payload.exp === 'number' && nowSeconds >= payload.exp) {
    throw new Error('Expired KyoRox SSO JWT token.');
  }

  if (expectedTenantId && payload.tenantId && payload.tenantId !== expectedTenantId) {
    throw new Error('Tenant UUID mismatch in SSO JWT claim.');
  }

  return payload;
}

module.exports = { verifyKyoRoxJwt };
