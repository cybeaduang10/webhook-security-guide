# Webhook Signature Verification Guide

## Overview
Webhook signature verification ensures that incoming webhook payloads truly originate from GitHub and have not been tampered with in transit. By validating the `X-Hub-Signature-256` header using an HMAC‑SHA256 hash of the payload and a secret token, you protect your service from forged requests and man‑in‑the‑middle attacks, which is essential when handling sensitive data such as payment information.

## Verification Steps
1. **Create a secret token**
   - Generate a high‑entropy random string when configuring the webhook in GitHub.  The secret is stored on the GitHub side and must be kept securely on your server.
2. **Store the secret securely**
   - Do not hard‑code the secret in source files or commit it to a repository. Use environment variables, secret managers, or vault services.
3. **Read the incoming payload**
   - Obtain the raw request body *exactly* as received (e.g., `request.body()` in Ruby, `request.body.read` in Python, or the raw string in Node).
4. **Calculate the HMAC‑SHA256 hash**
   ```
   expected = "sha256=" + HMAC_SHA256(secret, payload_body)
   ```
   - The hash must be expressed as a hex‑encoded string prefixed with `sha256=`.
5. **Compare signatures using a constant‑time function**
   - Do **not** use a simple `==` check. Use language‑specific constant‑time comparison utilities, such as:
     - Ruby: `Rack::Utils.secure_compare`
     - Node.js: `crypto.timingSafeEqual`
     - Python: `hmac.compare_digest`
6. **Reject mismatched signatures**
   - Return a `403` (or equivalent) response if the signatures differ.

### Example snippets
- **Python** (as shown in GitHub docs):
  ```python
  import hashlib, hmac
  def verify_signature(payload_body, secret_token, signature_header):
      if not signature_header:
          raise HTTPException(status_code=403, detail="x-hub-signature-256 header is missing!")
      hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
      expected_signature = "sha256=" + hash_object.hexdigest()
      if not hmac.compare_digest(expected_signature, signature_header):
          raise HTTPException(status_code=403, detail="Request signatures didn't match!")
  ```
- **Node.js (Web Crypto API)**:
  ```javascript
  async function verifySignature(secret, header, payload) {
    const [_, sigHex] = header.split('=');
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['verify']);
    const equal = await crypto.subtle.verify('HMAC', key, hexToBytes(sigHex), encoder.encode(payload));
    return equal;
  }
  ```

## Security Best Practices
- **Use the `X-Hub-Signature-256` header** (HMAC‑SHA256). The older `X-Hub-Signature` (HMAC‑SHA1) is deprecated.
- **Never log or expose the secret**; rotate it periodically.
- **Ensure UTF‑8 handling** – payloads may contain Unicode characters; treat the body as raw bytes.
- **Validate before any processing** – reject invalid signatures early to avoid unnecessary work.
- **Test against known values** – GitHub provides a sample secret (`It's a Secret to Everybody`) and payload (`Hello, World!`) with expected signature `sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17` to verify your implementation.
- **Use constant‑time comparison** to mitigate timing attacks.
- **Keep the webhook endpoint URL secret** where possible; expose it only to services that need to send events.

---
*This guide was compiled from GitHub’s official documentation on securing webhooks.*
