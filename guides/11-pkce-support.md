# Guide 11: Add PKCE Support

**Phase 3: Enhanced Security** | **Week 5-6** | **Task 11 of 30**

## Overview

Implement PKCE (Proof Key for Code Exchange) to protect the authorization code flow from interception attacks. PKCE is essential for public clients like mobile apps and SPAs, and recommended for all OAuth clients.

---

## What You'll Build

- Code challenge generation and validation
- PKCE parameter support in authorization endpoint
- Code verifier validation in token endpoint
- PKCEValidator utility class
- Support for S256 and plain methods

---

## Why PKCE?

### The Problem: Authorization Code Interception

**Scenario**:
1. Malicious app on user's device intercepts authorization code from redirect
2. Attacker exchanges code for tokens before legitimate app
3. Attacker gains access to user's account

**Why it happens**:
- Mobile apps use custom URL schemes (myapp://callback)
- Other apps can register same URL scheme
- Attacker app receives authorization code

### The Solution: PKCE

PKCE cryptographically binds the authorization request to the token request:
- Only the app that requested the code can exchange it
- Even if code is intercepted, attacker can't use it

**Learn More**: https://datatracker.ietf.org/doc/html/rfc7636

---

## Step 1: Understand PKCE Flow

### How PKCE Works

**1. Client generates random string** (code verifier):
```
dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**2. Client creates code challenge** (SHA256 hash):
```
code_challenge = BASE64URL(SHA256(code_verifier))
= E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

**3. Authorization request includes**:
```
GET /oauth2/authorize?
  response_type=code&
  client_id=mobile-app&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256&
  ...
```

**4. IdP stores code challenge** with authorization code

**5. Token request includes** code verifier:
```
POST /oauth2/token
grant_type=authorization_code&
code=AUTH_CODE&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
...
```

**6. IdP validates**: SHA256(code_verifier) == stored code_challenge

### Code Verifier Requirements

- **Length**: 43-128 characters
- **Characters**: [A-Z], [a-z], [0-9], `-`, `.`, `_`, `~`
- **Entropy**: Minimum 256 bits of entropy
- **Generation**: Cryptographically random

### Code Challenge Methods

- **S256**: SHA256 hash (recommended, more secure)
- **plain**: No transformation (not recommended, fallback only)

---

## Step 2: Update Authorization Code Entity

### Modify AuthorizationCode.java

Add fields for PKCE:

```java
@Column(name = "code_challenge", length = 128)
private String codeChallenge;

@Column(name = "code_challenge_method", length = 10)
private String codeChallengeMethod;
```

### Create Migration

**File**: `src/main/resources/db/migration/V9__add_pkce_to_authorization_codes.sql`

**What to include**:
- ALTER TABLE to add `code_challenge` column (VARCHAR 128, nullable)
- ALTER TABLE to add `code_challenge_method` column (VARCHAR 10, nullable)

*Why nullable?*: PKCE is optional for confidential clients (those with client_secret), required for public clients.

---

## Step 3: Create PKCEValidator Utility

### Create PKCEValidator.java

Location: `src/main/java/com/learning/idp/security/PKCEValidator.java`

### Methods to Implement

#### Validate Code Verifier Format

```java
public static boolean isValidCodeVerifier(String codeVerifier) {
    // Check length (43-128)
    // Check characters (unreserved chars only)
    // Pattern: [A-Za-z0-9-._~]+
}
```

*Why validate format?*: Prevent injection attacks and ensure sufficient entropy.

#### Generate Code Challenge

```java
public static String generateCodeChallenge(String codeVerifier, String method) {
    if ("S256".equals(method)) {
        // SHA256 hash then Base64URL encode
        // Use MessageDigest.getInstance("SHA-256")
        // Use Base64.getUrlEncoder().withoutPadding()
    } else if ("plain".equals(method)) {
        // Return code verifier unchanged
    } else {
        throw new IllegalArgumentException("Unsupported method");
    }
}
```

#### Verify Code Challenge

```java
public static boolean verifyChallenge(String codeVerifier, String codeChallenge, String method) {
    String computedChallenge = generateCodeChallenge(codeVerifier, method);
    return computedChallenge.equals(codeChallenge);
}
```

### Dependencies Needed

- **MessageDigest**: For SHA256 hashing (java.security)
- **Base64**: For URL-safe encoding (java.util)
- **Apache Commons Codec**: Already added for Base64 utilities

---

## Step 4: Update Authorization Request DTO

### Modify AuthorizationRequest.java

Add PKCE parameters:

```java
private String codeChallenge;

@Pattern(regexp = "S256|plain", message = "Code challenge method must be S256 or plain")
private String codeChallengeMethod;
```

*Why no @NotBlank?*: PKCE is optional (for now), will be required for public clients.

### Validation Logic

In your service layer, validate:
- If `codeChallenge` is provided, `codeChallengeMethod` must also be provided
- If method is "plain", consider rejecting (S256 is more secure)
- Code challenge length should be reasonable (32-128 characters for S256 hashed values)

---

## Step 5: Update Authorization Endpoint

### Store PKCE Parameters

In `AuthorizationController`, when generating authorization code:

**After user approves consent**:
1. Extract `codeChallenge` and `codeChallengeMethod` from authorization request
2. Pass to authorization code service
3. Store in `AuthorizationCode` entity

**Updated service call**:
```java
String authCode = authorizationCodeService.generateAuthorizationCode(
    clientId,
    userId,
    redirectUri,
    scopes,
    codeChallenge,      // New parameter
    codeChallengeMethod  // New parameter
);
```

### Update AuthorizationCodeService

Modify `generateAuthorizationCode` method signature to accept PKCE parameters.

Store them in the `AuthorizationCode` entity before saving.

---

## Step 6: Update Token Request DTO

### Modify TokenRequest.java

Add code verifier field:

```java
private String codeVerifier;
```

*When is it required?*:
- Required if authorization request included code_challenge
- Not required for client_credentials grant or refresh_token grant

---

## Step 7: Implement PKCE Validation in Token Endpoint

### Update Token Endpoint Handler

In `TokenController`, for authorization_code grant:

**After validating authorization code, before issuing tokens**:

```java
// 1. Retrieve authorization code from database
AuthorizationCode authCode = authCodeService.validateAndConsume(...);

// 2. Check if PKCE was used in authorization request
if (authCode.getCodeChallenge() != null) {
    // PKCE was used, code_verifier is required
    if (request.getCodeVerifier() == null) {
        throw new InvalidGrantException("code_verifier required");
    }

    // 3. Validate code verifier format
    if (!PKCEValidator.isValidCodeVerifier(request.getCodeVerifier())) {
        throw new InvalidGrantException("Invalid code_verifier format");
    }

    // 4. Verify challenge
    boolean valid = PKCEValidator.verifyChallenge(
        request.getCodeVerifier(),
        authCode.getCodeChallenge(),
        authCode.getCodeChallengeMethod()
    );

    if (!valid) {
        throw new InvalidGrantException("Invalid code_verifier");
    }
}

// Proceed with token issuance...
```

### Security Considerations

**Timing attacks**: Use constant-time comparison for challenge verification
```java
// Instead of: computedChallenge.equals(codeChallenge)
// Use: MessageDigest.isEqual(...)
```

**Validation order**:
1. Validate code exists and not expired (existing logic)
2. Then validate PKCE (if applicable)
3. This prevents timing analysis revealing valid codes

---

## Step 8: Make PKCE Required for Public Clients

### Update Client Entity

Add field to track client type:

```java
@Column(name = "is_public", nullable = false)
private boolean isPublic = false;  // false = confidential, true = public
```

*Already exists from earlier guides - verify it's in your schema.*

### Enforce PKCE for Public Clients

In authorization endpoint, after validating client:

```java
Client client = clientService.findByClientId(request.getClientId());

// Require PKCE for public clients
if (client.isPublic() && request.getCodeChallenge() == null) {
    return redirectWithError(
        request.getRedirectUri(),
        "invalid_request",
        "code_challenge required for public clients",
        request.getState()
    );
}

// Recommend S256 method
if (request.getCodeChallenge() != null && "plain".equals(request.getCodeChallengeMethod())) {
    // Log warning or reject for public clients
    log.warn("Client {} using plain PKCE method, recommend S256", client.getClientId());
}
```

### Why Distinguish Client Types?

**Confidential clients** (server-side apps):
- Can securely store client_secret
- PKCE is optional but recommended (defense in depth)

**Public clients** (mobile, SPA):
- Cannot securely store secrets
- PKCE is mandatory (only protection against code interception)

---

## Step 9: Test PKCE Implementation

### Test Case 1: Authorization with PKCE (S256)

**1. Generate code verifier** (client-side):
```javascript
// Example in JavaScript (your client app would do this)
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
}
```

For testing, use a fixed value:
```
code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**2. Generate code challenge**:
```javascript
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64URLEncode(hash);
}
```

Or use online tool: https://tonyxu-io.github.io/pkce-generator/

**3. Authorization request**:
```
GET /oauth2/authorize?
  response_type=code&
  client_id=mobile-app&
  redirect_uri=myapp://callback&
  scope=openid%20profile&
  state=xyz&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

**4. Complete login and consent**

**5. Receive authorization code**

**6. Check database**:
```sql
SELECT code, code_challenge, code_challenge_method
FROM authorization_codes
WHERE code = 'YOUR_CODE';
```

Verify `code_challenge` is stored.

**7. Token request**:
```
POST /oauth2/token
grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=myapp://callback&
client_id=mobile-app&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Expected**: 200 OK with access token

### Test Case 2: Wrong Code Verifier

**Token request with incorrect verifier**:
```
code_verifier=wrong_verifier_value
```

**Expected**: 400 Bad Request, `error: "invalid_grant"`, description about invalid code_verifier

### Test Case 3: Missing Code Verifier

**Token request without code_verifier** when PKCE was used:

**Expected**: 400 Bad Request, `error: "invalid_grant"`, "code_verifier required"

### Test Case 4: Public Client Without PKCE

**Authorization request from public client** without code_challenge:

**Expected**: Error redirect, `error: "invalid_request"`, "code_challenge required for public clients"

### Test Case 5: Plain Method

**Authorization request with**:
```
code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&
code_challenge_method=plain
```

**Token request with same verifier**:
```
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Expected**: Should work (but log warning for plain method)

---

## Step 10: Update Client Application

### Modify Your Client App (from Guide 10)

Spring Security OAuth2 Client automatically supports PKCE (enabled by default in Spring Security 5.7+).

**Verify in logs**:
When your client app initiates OAuth, you should see:
- code_challenge in authorization URL
- code_verifier in token request

**If not automatic**, enable explicitly:
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          custom-idp:
            client-authentication-method: none  # For public clients
```

### For Mobile/SPA Clients

**Mobile apps** should:
1. Generate code_verifier on app launch or per-flow
2. Store securely (don't persist to disk)
3. Use S256 method
4. Include in authorization and token requests

**Example libraries**:
- iOS: AppAuth-iOS (built-in PKCE)
- Android: AppAuth-Android (built-in PKCE)
- JavaScript/SPA: Use Web Crypto API for generation

---

## Understanding PKCE Security

### Attack Mitigation

| Attack | Without PKCE | With PKCE |
|--------|--------------|-----------|
| Authorization code interception | ✗ Attacker can use code | ✓ Attacker can't exchange without verifier |
| Malicious app registration | ✗ Malicious app gets code | ✓ Original app keeps verifier secret |
| Man-in-the-middle | ✗ MITM steals code | ✓ MITM can't generate verifier |

### Why SHA256 Over Plain?

**Plain method**:
- code_challenge = code_verifier (no transformation)
- Vulnerable if challenge is intercepted

**S256 method**:
- code_challenge = SHA256(code_verifier)
- One-way hash prevents deriving verifier from challenge
- Recommended by OAuth Security BCP

### PKCE for Confidential Clients?

**Yes, use it!** Even though they have client_secret:
- **Defense in depth**: Multiple layers of security
- **Future-proofing**: If secret is compromised
- **Best practice**: OAuth Security BCP recommends PKCE for all clients

---

## Common Issues

### Code verifier too short

**Error**: "Invalid code_verifier format"

**Cause**: Generated verifier < 43 characters

**Solution**: Ensure minimum 32 bytes of random data → base64url encodes to 43+ chars

### Base64URL encoding issues

**Error**: Challenge/verifier mismatch

**Cause**: Using standard Base64 instead of Base64URL (padding, `+`, `/` characters)

**Solution**: Use `Base64.getUrlEncoder().withoutPadding()` in Java

### SHA256 vs SHA-256

**Error**: NoSuchAlgorithmException

**Cause**: Wrong algorithm name

**Solution**: Use `"SHA-256"` (with hyphen) for MessageDigest

### Challenge stored incorrectly

**Error**: Validation always fails

**Cause**: Not storing challenge in authorization code entity

**Solution**: Verify database has code_challenge value after authorization

---

## What You've Accomplished

✅ Implemented PKCE code challenge generation and validation
✅ Updated authorization endpoint to accept PKCE parameters
✅ Modified token endpoint to verify code verifier
✅ Created PKCEValidator utility class
✅ Enforced PKCE for public clients
✅ Tested PKCE flow end-to-end
✅ Understood PKCE security benefits

---

## Next Steps

**Proceed to Guide 12**: Implement State Parameter Validation

Before moving on:
- [ ] PKCE parameters accepted in authorization request
- [ ] Code challenge stored with authorization code
- [ ] Code verifier validated in token request
- [ ] Public clients require PKCE
- [ ] S256 method works correctly
- [ ] Error handling returns proper OAuth errors

---

## Key Concepts Learned

### PKCE Flow
- Code verifier: Random secret generated by client
- Code challenge: SHA256 hash of code verifier
- Binding: Challenge in authorization, verifier in token request
- Validation: IdP verifies SHA256(verifier) == challenge

### Code Verifier Requirements
- Length: 43-128 characters
- Characters: Unreserved URI characters only
- Entropy: Cryptographically random
- Storage: Client memory only (not persisted)

### Public vs Confidential Clients
- Public: Cannot keep secrets (mobile, SPA) → PKCE required
- Confidential: Can keep secrets (server-side) → PKCE recommended

### Defense in Depth
- PKCE + client_secret (confidential clients)
- PKCE + HTTPS (all clients)
- PKCE + state parameter (CSRF protection)
- Multiple layers provide stronger security

---

## Additional Resources

- **RFC 7636 - PKCE**: https://datatracker.ietf.org/doc/html/rfc7636
- **OAuth Security BCP**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- **PKCE Generator Tool**: https://tonyxu-io.github.io/pkce-generator/
- **AppAuth Libraries**: https://appauth.io/
- **Spring Security PKCE**: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html#oauth2login-advanced-pkce
- **Base64URL Encoding**: https://datatracker.ietf.org/doc/html/rfc4648#section-5
