# Guide 12: Implement State Parameter Validation

**Phase 3: Enhanced Security** | **Week 5-6** | **Task 12 of 30**

## Overview

Enforce and validate the state parameter throughout the OAuth flow to prevent Cross-Site Request Forgery (CSRF) attacks. The state parameter is a critical security mechanism that ensures authorization responses match the original requests.

---

## What You'll Build

- State parameter requirement in authorization endpoint
- State preservation through login/consent flow
- State validation on callback
- CSRF protection for OAuth flows
- Error handling for state mismatches

---

## Why State Parameter?

### The CSRF Attack Scenario

**Without state parameter**:
1. Attacker initiates OAuth flow with their account
2. Attacker obtains authorization code for their account
3. Attacker tricks victim into clicking link with this code
4. Victim's session gets linked to attacker's account
5. Victim's data flows into attacker's account

**With state parameter**:
- Client generates random state, stores in session
- State included in authorization request
- IdP returns state in response
- Client verifies returned state matches stored state
- Mismatched state = reject (CSRF detected)

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12

---

## Step 1: Understand State Parameter Flow

### How State Works

**1. Client generates random state**:
```
state = generateRandomString()  // e.g., "x8Yd2kF9mN"
session.setAttribute("oauth_state", state)
```

**2. Authorization request includes state**:
```
GET /oauth2/authorize?
  response_type=code&
  client_id=demo-client&
  state=x8Yd2kF9mN&
  ...
```

**3. IdP preserves state** (in session or hidden form fields)

**4. Authorization response includes state**:
```
http://localhost:3000/callback?
  code=AUTH_CODE&
  state=x8Yd2kF9mN
```

**5. Client validates**:
```
if (response.state !== session.getAttribute("oauth_state")) {
    throw new SecurityException("CSRF detected");
}
```

### State Requirements

- **Random**: Cryptographically random, unguessable
- **Unique**: Different for each authorization request
- **Opaque**: No meaningful information (just random string)
- **Short-lived**: Tied to session or expires after use

---

## Step 2: Make State Required

### Update Authorization Request Validation

In `AuthorizationRequest.java`, make state required:

```java
@NotBlank(message = "state parameter is required")
private String state;
```

### Validate in Authorization Endpoint

In `AuthorizationController`:

```java
// State is now validated by @Valid annotation
// Add additional checks if needed

if (request.getState().length() < 8) {
    return redirectWithError(
        request.getRedirectUri(),
        "invalid_request",
        "state too short (minimum 8 characters)",
        null  // Don't return invalid state
    );
}
```

*Why minimum length?*: Ensures sufficient entropy, prevents brute force guessing.

---

## Step 3: Preserve State Through Flow

### Challenge: Multi-Step Flow

The OAuth flow has multiple steps:
1. Authorization request (state provided)
2. Login page (if not authenticated)
3. Consent page
4. Redirect back to client (state must be returned)

**Problem**: State must survive across these steps.

### Solution 1: Session Storage

Store state in HTTP session:

```java
@GetMapping("/oauth2/authorize")
public String authorize(
        @Valid @ModelAttribute AuthorizationRequest request,
        HttpSession session) {
    
    // Store state in session
    session.setAttribute("PENDING_AUTH_STATE", request.getState());
    
    // ... rest of authorization logic
}
```

**When redirecting back**:
```java
String state = (String) session.getAttribute("PENDING_AUTH_STATE");
session.removeAttribute("PENDING_AUTH_STATE");

String redirectUrl = UriComponentsBuilder
    .fromUriString(redirectUri)
    .queryParam("code", authorizationCode)
    .queryParam("state", state)
    .toUriString();
```

### Solution 2: Hidden Form Fields

Pass state through forms (login, consent):

**In consent.html**:
```html
<form method="post" th:action="@{/oauth2/authorize/consent}">
    <input type="hidden" name="state" th:value="${state}" />
    <!-- other fields -->
</form>
```

### Recommended Approach

**Use both**:
- Session storage as primary
- Hidden fields as backup (if session expires)
- Validate both match for extra security

---

## Step 4: Return State in All Responses

### Success Response (Authorization Code)

**After user approves**:
```java
String redirectUrl = UriComponentsBuilder
    .fromUriString(authCode.getRedirectUri())
    .queryParam("code", authCode.getCode())
    .queryParam("state", authCode.getState())  // Always include
    .toUriString();

return "redirect:" + redirectUrl;
```

### Error Responses

**For all OAuth errors**:
```java
private String redirectWithError(
        String redirectUri,
        String error,
        String errorDescription,
        String state) {  // State parameter
    
    UriComponentsBuilder builder = UriComponentsBuilder
        .fromUriString(redirectUri)
        .queryParam("error", error)
        .queryParam("error_description", errorDescription);
    
    // Include state even in error responses
    if (state != null) {
        builder.queryParam("state", state);
    }
    
    return "redirect:" + builder.toUriString();
}
```

*Why return state in errors?*: Client needs to match error response to original request.

---

## Step 5: Update Authorization Code Entity

### Store State with Code

Modify `AuthorizationCode` entity:

```java
@Column(name = "state", length = 255)
private String state;
```

### Migration

Create `V10__add_state_to_authorization_codes.sql`:

```sql
ALTER TABLE authorization_codes
ADD COLUMN state VARCHAR(255);
```

*Why store state?*: Associates the state with the authorization code for validation and audit purposes.

---

## Step 6: Validate State in Client App

### Client-Side Validation

Your client app (Guide 10) should validate state. Spring Security OAuth2 Client does this automatically.

### Manual Validation (if building custom client)

**Before authorization**:
```java
String state = generateRandomState();
session.setAttribute("oauth_state", state);

String authUrl = "/oauth2/authorize?state=" + state + "...";
```

**On callback**:
```java
String returnedState = request.getParameter("state");
String expectedState = (String) session.getAttribute("oauth_state");

if (!expectedState.equals(returnedState)) {
    throw new SecurityException("State validation failed - possible CSRF attack");
}

session.removeAttribute("oauth_state");
```

---

## Step 7: Generate Secure State Values

### State Generation Best Practices

**Requirements**:
- Cryptographically random
- Minimum 128 bits of entropy
- URL-safe characters

**Implementation**:
```java
public static String generateState() {
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[32];  // 256 bits
    random.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}
```

**Result**: String like `k7Jy9Gm3Lp2Nq8Hs5Ft1Vb6Xc4Zw0Er`

### What Not to Do

❌ **Don't use**:
- Sequential numbers (predictable)
- Timestamps (guessable)
- User IDs (exposes information)
- Simple random (not cryptographically secure)

✅ **Do use**:
- SecureRandom
- UUID.randomUUID()
- Cryptographic random number generators

---

## Step 8: Handle State in Error Scenarios

### When Redirect URI is Invalid

**Problem**: Can't redirect with error if redirect_uri is invalid

**Solution**: Show error page instead
```java
if (!isValidRedirectUri(redirectUri, client)) {
    // Can't redirect (would be open redirect vulnerability)
    model.addAttribute("error", "invalid_redirect_uri");
    return "error";  // Show error page
}
```

### When State is Missing

**OAuth spec**: State is optional (but you can require it)

**Recommendation**: Require state for public clients, recommend for all

```java
if (client.isPublic() && StringUtils.isEmpty(request.getState())) {
    return redirectWithError(
        request.getRedirectUri(),
        "invalid_request",
        "state parameter required for public clients",
        null
    );
}
```

---

## Step 9: Testing State Parameter

### Test Case 1: Valid State

**1. Authorization request with state**:
```
GET /oauth2/authorize?...&state=abc123
```

**2. Complete flow (login, consent)**

**3. Check redirect**:
```
http://localhost:3000/callback?code=...&state=abc123
```

**Expected**: State matches original request

### Test Case 2: Missing State (Public Client)

**Authorization request without state** from public client

**Expected**: Error redirect or error page

### Test Case 3: State Modified

**Manual test**:
1. Start authorization with state=abc123
2. Before final redirect, modify session to state=different
3. Complete authorization

**Expected**: Client validation should fail (if implementing client-side validation)

### Test Case 4: Error Response Includes State

**Trigger error** (e.g., deny consent):

**Expected redirect**:
```
http://localhost:3000/callback?
  error=access_denied&
  error_description=User%20denied&
  state=abc123
```

---

## Understanding State Security

### State vs PKCE

**Different purposes**:
- **State**: Prevents CSRF (links response to request)
- **PKCE**: Prevents code interception (cryptographically binds authorization to token exchange)

**Use both**: Defense in depth

### State vs Nonce (OIDC)

**Nonce** (Phase 5):
- Similar concept for ID tokens
- Binds token to client session
- Prevents replay attacks

**State**:
- For authorization response
- CSRF protection

**Both are needed** in OpenID Connect.

### Attack Scenarios Prevented

| Attack | State Prevents? |
|--------|----------------|
| CSRF in OAuth flow | ✓ Yes |
| Authorization code interception | ✗ No (use PKCE) |
| Replay attacks | Partial (one-time state use helps) |
| Session fixation | ✓ Yes (ties auth to session) |

---

## Common Issues

### State not preserved through login

**Symptom**: State is null when trying to redirect back

**Cause**: Session expired or not configured correctly

**Solution**:
- Ensure session storage working (Redis configured)
- Check session timeout settings
- Use hidden form fields as backup

### State validation fails on client

**Symptom**: Client rejects valid state

**Cause**: Case sensitivity or encoding issues

**Solution**:
- Use exact string comparison
- Ensure URL encoding/decoding consistency
- Don't modify state (keep it opaque)

### Multiple tabs/windows

**Symptom**: State mismatch when user has multiple OAuth flows open

**Solution**:
- Store state by key (e.g., indexed by client_id + timestamp)
- Clean up old states after timeout
- Educate users to complete one flow at a time

---

## What You've Accomplished

✅ Required state parameter in authorization requests
✅ Preserved state through multi-step authorization flow
✅ Returned state in success and error responses
✅ Stored state with authorization codes
✅ Understood CSRF protection mechanisms
✅ Implemented secure state generation

---

## Next Steps

**Proceed to Guide 13**: Add Refresh Token Flow

Before moving on:
- [ ] State parameter is required (or recommended based on client type)
- [ ] State is preserved through login and consent
- [ ] State is returned in authorization response
- [ ] State is returned in error responses
- [ ] State generation is cryptographically secure
- [ ] Testing confirms state validation works

---

## Key Concepts Learned

### CSRF in OAuth
- Attack: Trick victim into authorizing attacker's account
- Defense: State parameter ties response to request
- Validation: Client checks returned state matches sent state

### State Lifecycle
1. Client generates random state
2. Client stores in session
3. Client sends in authorization request
4. IdP preserves through flow
5. IdP returns in response
6. Client validates match

### Secure Random Generation
- Use SecureRandom, not Random
- Minimum 128 bits entropy
- URL-safe encoding
- One-time use

### Defense in Depth
- State + PKCE + client authentication
- Multiple security layers
- Each protects against different threats

---

## Additional Resources

- **RFC 6749 Section 10.12 (CSRF)**: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
- **OAuth Security BCP**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-13#section-2.1
- **OWASP CSRF**: https://owasp.org/www-community/attacks/csrf
- **Spring Security CSRF**: https://docs.spring.io/spring-security/reference/features/exploits/csrf.html
