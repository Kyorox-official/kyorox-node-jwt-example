# KyoRox Node.js SAML-to-JWT Verification Example

Zero-dependency Node.js (`node:crypto`) reference utility for authenticating enterprise users via **[KyoRox Universal SAML 2.0-to-JWT Proxy](https://kyorox.com)**.

## How the Flow Works

1. Redirect your enterprise user to your KyoRox SAML login endpoint:

```text
[https://sso.kyorox.com/auth/sso/](https://sso.kyorox.com/auth/sso/)<YOUR_TENANT_UUID>/login?redirect_uri=[https://yourapp.com/sso/callback](https://yourapp.com/sso/callback)
```

2. KyoRox verifies the Identity Provider's SAML 2.0 XML response (Okta, Microsoft Entra ID, Google Workspace, JumpCloud, PingIdentity) strictly in **volatile RAM (`0 bytes` of PII stored on disk)** and enforces a **300-second atomic nonce replay lock**.
3. KyoRox redirects the user back to your whitelisted `redirect_uri` with a signed `HS256` JWT (`?token=<JWT>`).
4. Verify the token in your Node.js backend using `verifyKyoRoxJwt.js`:

```javascript
const { verifyKyoRoxJwt } = require('./verifyKyoRoxJwt');

app.get('/sso/callback', (req, res) => {
  try {
    const claims = verifyKyoRoxJwt(
      req.query.token,
      process.env.KYOROX_JWT_SECRET,
      process.env.KYOROX_TENANT_UUID
    );
    // Normalized claims: { sub, email, firstName, lastName, groups, tenantId, iat, exp }
    req.session.user = { email: claims.email, groups: claims.groups };
    return res.redirect('/dashboard');
  } catch (err) {
    return res.status(401).send('SSO Authentication Failed');
  }
});
```

## Links & Support

* **Platform Overview & Pricing:** [https://kyorox.com/pricing](https://kyorox.com/pricing)
* **Integration Documentation:** [https://kyorox.com/docs](https://kyorox.com/docs)
* **Security Policy:** [https://kyorox.com/security](https://kyorox.com/security)
* **Support:** `support@kyorox.com`
