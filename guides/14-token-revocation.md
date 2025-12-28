# Guide 14: Token Revocation Endpoint

**Phase 3: Enhanced Security** | **Week 5-6** | **Task 14 of 30**

## Overview

Implement the token revocation endpoint to allow clients to explicitly invalidate access and refresh tokens. This is essential for logout functionality and security event response.

---

## What You'll Build

- `/oauth2/revoke` endpoint
- Token revocation for refresh tokens
- Token revocation for access tokens
- Client authentication for revocation
- Bulk revocation capabilities

---

## Why Token Revocation?

### Use Cases

**User logout**: User wants to end session
**Security breach**: Suspected token theft
**Device loss**: User lost phone with app
**Permission change**: User revokes app access
**Administrative action**: Admin disables client or user

### Without Revocation

**JWTs are self-contained**: Resource servers validate without calling IdP
**Problem**: Can't invalidate before expiration
**Workaround**: Keep tokens short-lived (but impacts UX)

### With Revocation

**Refresh tokens**: Stored in database, can revoke anytime
**Access tokens**: More complex (need token storage or blocklist)

**Learn More**: https://datatracker.ietf.org/doc/html/rfc7009

---

## Step 1: Create Revocation Endpoint

### Add to TokenController

```java
@PostMapping(value = "/revoke",
             consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
public ResponseEntity<Void> revoke(@Valid @ModelAttribute TokenRevocationRequest request) {
    // Implementation
    return ResponseEntity.ok().build();
}
```

*Why POST?*: RFC 7009 requires POST for revocation endpoint

*Why always 200 OK?*: Don't reveal whether token existed (security)

---

## Step 2: Create Revocation Request DTO

### TokenRevocationRequest.java

```java
@Data
public class TokenRevocationRequest {
    @NotBlank
    private String token;  // The token to revoke
    
    private String tokenTypeHint;  // "access_token" or "refresh_token"
    
    @NotBlank
    private String clientId;
    
    private String clientSecret;
}
```

### Token Type Hint

**Purpose**: Performance optimization
- Tells server what type of token
- Server checks that type first
- Falls back to other type if hint wrong

---

## Step 3: Implement Revocation Logic

### Handle Refresh Token Revocation

```java
public void revokeToken(String token, String tokenTypeHint, String clientId) {
    // Try refresh token first (if hinted or as fallback)
    if ("refresh_token".equals(tokenTypeHint) || tokenTypeHint == null) {
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByToken(token);
        if (refreshToken.isPresent() &&
refreshToken.get().getClientId().equals(clientId)) {
            refreshToken.get().setRevoked(true);
            refreshTokenRepository.save(refreshToken.get());
            log.info("Revoked refresh token for client {}", clientId);
            return;
        }
    }
    
    // Try access token if refresh token not found
    if ("access_token".equals(tokenTypeHint) || tokenTypeHint == null) {
        // If storing access tokens, revoke them
        // If using stateless JWTs, add to blocklist
        revokeAccessToken(token, clientId);
    }
    
    // Per spec, return success even if token not found
    log.debug("Token revocation requested but token not found");
}
```

---

## Step 4: Handle Access Token Revocation

### Option 1: Token Blocklist (for JWTs)

Create `token_blocklist` table:
```sql
CREATE TABLE token_blocklist (
    jti VARCHAR(255) PRIMARY KEY,  -- JWT ID claim
    expires_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_token_blocklist_expires ON token_blocklist(expires_at);
```

**Add to JWTs**: Include `jti` (JWT ID) claim

**On revocation**: Add `jti` to blocklist

**On validation**: Check if `jti` in blocklist

**Cleanup**: Remove entries after token expiration

### Option 2: Store All Access Tokens

If using `access_tokens` table, mark as revoked:
```java
Optional<AccessToken> accessToken = accessTokenRepository.findByToken(token);
if (accessToken.isPresent()) {
    accessToken.get().setRevoked(true);
    accessTokenRepository.save(accessToken.get());
}
```

---

## Step 5: Revoke Token Families

### Cascade Revocation

When revoking refresh token, optionally revoke entire family:

```java
public void revokeTokenAndFamily(String token) {
    RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
        .orElseThrow(() -> new TokenNotFoundException());
    
    // Revoke all tokens in same family
    List<RefreshToken> familyTokens = 
        refreshTokenRepository.findByTokenFamily(refreshToken.getTokenFamily());
    
    familyTokens.forEach(t -> t.setRevoked(true));
    refreshTokenRepository.saveAll(familyTokens);
    
    log.info("Revoked token family {} ({} tokens)", 
        refreshToken.getTokenFamily(), familyTokens.size());
}
```

### When to Use

**User logout**: Revoke only current token
**Security event**: Revoke entire family
**Device loss**: Revoke all tokens for that client

---

## Step 6: Implement Bulk Revocation

### Revoke All Tokens for User

```java
public void revokeAllUserTokens(Long userId) {
    List<RefreshToken> userTokens = refreshTokenRepository.findByUserId(userId);
    userTokens.forEach(t -> t.setRevoked(true));
    refreshTokenRepository.saveAll(userTokens);
    
    log.info("Revoked all tokens for user {}", userId);
}
```

### Revoke All Tokens for Client

```java
public void revokeAllClientTokens(String clientId) {
    List<RefreshToken> clientTokens = 
        refreshTokenRepository.findByClientId(clientId);
    clientTokens.forEach(t -> t.setRevoked(true));
    refreshTokenRepository.saveAll(clientTokens);
    
    log.info("Revoked all tokens for client {}", clientId);
}
```

### Use Cases

**User account deletion**: Revoke all user's tokens
**Client disabled**: Revoke all client's tokens
**Password change**: Optionally revoke all sessions

---

## Step 7: Client Authentication

### Require Client Authentication

```java
@PostMapping("/revoke")
public ResponseEntity<Void> revoke(@Valid @ModelAttribute TokenRevocationRequest request) {
    // Authenticate client
    Client client = clientService.authenticateClient(
        request.getClientId(),
        request.getClientSecret()
    );
    
    // Revoke token (only if belongs to this client)
    tokenRevocationService.revokeToken(
        request.getToken(),
        request.getTokenTypeHint(),
        client.getClientId()
    );
    
    return ResponseEntity.ok().build();
}
```

*Why authenticate?*: Prevent clients from revoking each other's tokens

---

## Step 8: Update Logout Flow

### User Logout Endpoint

Create logout endpoint that revokes tokens:

```java
@PostMapping("/logout")
public ResponseEntity<Void> logout(Principal principal, 
                                    HttpServletRequest request) {
    // Get access token from request
    String accessToken = extractToken(request);
    
    // Revoke associated refresh tokens
    if (accessToken != null) {
        Long userId = jwtTokenProvider.getUserIdFromToken(accessToken);
        tokenRevocationService.revokeAllUserTokens(userId);
    }
    
    // Invalidate HTTP session
    request.getSession().invalidate();
    
    return ResponseEntity.ok().build();
}
```

---

## Step 9: Testing Token Revocation

### Test Case 1: Revoke Refresh Token

**1. Get tokens**:
```
POST /oauth2/token
grant_type=authorization_code&...
```

**2. Revoke refresh token**:
```
POST /oauth2/revoke
token=REFRESH_TOKEN&
token_type_hint=refresh_token&
client_id=demo-client&
client_secret=demo-secret
```

**Expected**: 200 OK

**3. Try to use revoked refresh token**:
```
POST /oauth2/token
grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&...
```

**Expected**: 400 Bad Request, "Refresh token revoked"

**4. Verify in database**:
```sql
SELECT revoked FROM refresh_tokens WHERE token = 'REFRESH_TOKEN';
```
Should show `revoked = true`

### Test Case 2: Revoke Non-Existent Token

**Request**:
```
POST /oauth2/revoke
token=FAKE_TOKEN&...
```

**Expected**: 200 OK (per spec, don't reveal if token existed)

### Test Case 3: Wrong Client Tries to Revoke

**1. Get token for client A**
**2. Try to revoke with client B credentials**

**Expected**: Token not revoked (silently fails per spec)

---

## Common Issues

### Token still works after revocation

**Cause**: Resource server using stateless JWT validation

**Solution**: Implement token blocklist or switch to introspection endpoint

### Database performance degradation

**Cause**: Large number of revoked tokens not cleaned up

**Solution**: Implement cleanup job to remove old revoked tokens

### Revocation affects wrong tokens

**Cause**: Not checking client_id ownership

**Solution**: Always verify token belongs to requesting client

---

## What You've Accomplished

✅ Implemented token revocation endpoint
✅ Added refresh token revocation
✅ Created token family revocation
✅ Built bulk revocation capabilities
✅ Integrated with logout flow
✅ Understood revocation security model

---

## Next Steps

**Proceed to Guide 15**: Client Credentials Flow

Before moving on:
- [ ] Revocation endpoint accepts POST requests
- [ ] Refresh tokens can be revoked
- [ ] Client authentication protects revocation
- [ ] Revoked tokens can't be reused
- [ ] Logout revokes user's tokens

---

## Key Concepts Learned

### Token Revocation
- Explicit invalidation before expiration
- Critical for logout and security events
- Different strategies for refresh vs access tokens

### Revocation Endpoint
- POST to /oauth2/revoke
- Client authentication required
- Always returns 200 OK (don't reveal token existence)

### Token Blocklist
- For stateless JWTs
- Store revoked JTI until expiration
- Performance trade-off vs security

### Cascade Revocation
- Revoke token families on security events
- Bulk revoke for users or clients
- Balance security vs UX

---

## Additional Resources

- **RFC 7009 (Token Revocation)**: https://datatracker.ietf.org/doc/html/rfc7009
- **OAuth Security BCP**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
- **JWT Revocation Strategies**: https://www.baeldung.com/spring-security-oauth-revoke-tokens
