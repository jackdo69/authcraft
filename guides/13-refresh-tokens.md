# Guide 13: Add Refresh Token Flow

**Phase 3: Enhanced Security** | **Week 5-6** | **Task 13 of 30**

## Overview

Implement the refresh token grant type to allow clients to obtain new access tokens without user interaction. Refresh tokens enable long-lived sessions while maintaining short-lived access tokens for security.

---

## What You'll Build

- Refresh token generation and storage
- Refresh token grant type handler
- Token rotation (issuing new refresh token on each refresh)
- Token family tracking for security
- Refresh token revocation

---

## Why Refresh Tokens?

### The Access Token Dilemma

**Short-lived access tokens** (15 min - 1 hour):
- ✅ Limits damage if stolen
- ✅ Forces periodic re-validation
- ❌ Poor UX (user must re-login frequently)

**Long-lived access tokens** (days/weeks):
- ✅ Better UX (stay logged in)
- ❌ High security risk if stolen
- ❌ Can't revoke before expiration (with JWTs)

### The Solution: Refresh Tokens

**Combination**:
- Short-lived access tokens (security)
- Long-lived refresh tokens (UX)
- Client refreshes access token automatically
- User stays logged in without re-authenticating

**Workflow**:
1. User logs in → receive access token + refresh token
2. Access token expires after 1 hour
3. Client uses refresh token → get new access token
4. Repeat until refresh token expires (30 days) or revoked
5. Then user must re-authenticate

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-1.5

---

## Step 1: Review Refresh Token Entity

### RefreshToken Model

Already created in Guide 04. Verify it exists:

Location: `src/main/java/com/learning/idp/model/RefreshToken.java`

**Required fields**:
- `id`: Primary key
- `token`: The refresh token value (UUID or random string)
- `userId`: Owner of the token
- `clientId`: Which client obtained it
- `accessTokenId`: Associated access token (optional, for tracking)
- `expiresAt`: When refresh token expires
- `revoked`: Whether token has been revoked
- `tokenFamily`: For rotation tracking
- `createdAt`: Issuance time

### Token Family Concept

**Why track families?**:
- Detect refresh token theft
- If old refresh token is reused → revoke entire family
- Indicates token was stolen and replayed

**How it works**:
1. Initial refresh token: family_id = UUID
2. On refresh: new token gets same family_id
3. Old token marked as used/revoked
4. If used token attempted again → revoke all tokens in family

---

## Step 2: Create Refresh Token Repository

### RefreshTokenRepository Interface

Location: `src/main/java/com/learning/idp/repository/RefreshTokenRepository.java`

**Methods needed**:

```java
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByToken(String token);
    
    Optional<RefreshToken> findByTokenAndRevokedFalse(String token);
    
    List<RefreshToken> findByTokenFamily(String tokenFamily);
    
    List<RefreshToken> findByUserIdAndClientId(Long userId, String clientId);
    
    void deleteByExpiresAtBefore(LocalDateTime dateTime);
    
    void deleteByUserId(Long userId);  // For user logout
}
```

---

## Step 3: Enhance Token Service

### Add Refresh Token Methods

In `TokenService`:

#### Generate Refresh Token

```java
public String generateRefreshToken(Long userId, String clientId) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setUserId(userId);
    refreshToken.setClientId(clientId);
    refreshToken.setTokenFamily(UUID.randomUUID().toString());  // New family
    refreshToken.setExpiresAt(LocalDateTime.now().plusDays(30));
    refreshToken.setRevoked(false);
    
    refreshTokenRepository.save(refreshToken);
    
    return refreshToken.getToken();
}
```

#### Validate Refresh Token

```java
public RefreshToken validateRefreshToken(String token, String clientId) {
    RefreshToken refreshToken = refreshTokenRepository
        .findByToken(token)
        .orElseThrow(() -> new InvalidGrantException("Invalid refresh token"));
    
    // Check if revoked
    if (refreshToken.isRevoked()) {
        // Security event! Token reuse detected
        revokeTokenFamily(refreshToken.getTokenFamily());
        throw new InvalidGrantException("Refresh token revoked");
    }
    
    // Check expiration
    if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
        throw new InvalidGrantException("Refresh token expired");
    }
    
    // Check client_id matches
    if (!refreshToken.getClientId().equals(clientId)) {
        throw new InvalidGrantException("Client ID mismatch");
    }
    
    return refreshToken;
}
```

#### Rotate Refresh Token

```java
public String rotateRefreshToken(RefreshToken oldToken) {
    // Mark old token as revoked
    oldToken.setRevoked(true);
    refreshTokenRepository.save(oldToken);
    
    // Create new token in same family
    RefreshToken newToken = new RefreshToken();
    newToken.setToken(UUID.randomUUID().toString());
    newToken.setUserId(oldToken.getUserId());
    newToken.setClientId(oldToken.getClientId());
    newToken.setTokenFamily(oldToken.getTokenFamily());  // Same family
    newToken.setExpiresAt(LocalDateTime.now().plusDays(30));
    newToken.setRevoked(false);
    
    refreshTokenRepository.save(newToken);
    
    return newToken.getToken();
}
```

#### Revoke Token Family

```java
private void revokeTokenFamily(String tokenFamily) {
    List<RefreshToken> familyTokens = refreshTokenRepository.findByTokenFamily(tokenFamily);
    
    familyTokens.forEach(token -> {
        token.setRevoked(true);
    });
    
    refreshTokenRepository.saveAll(familyTokens);
    
    log.warn("Revoked token family {} due to suspected theft", tokenFamily);
}
```

---

## Step 4: Add Refresh Grant to Token Endpoint

### Update TokenRequest DTO

Add field:

```java
private String refreshToken;  // For grant_type=refresh_token
```

### Handle Refresh Token Grant

In `TokenController`:

```java
@PostMapping(value = "/token")
public ResponseEntity<TokenResponse> token(@Valid @ModelAttribute TokenRequest request) {
    
    if ("authorization_code".equals(request.getGrantType())) {
        return handleAuthorizationCodeGrant(request);
    } 
    else if ("refresh_token".equals(request.getGrantType())) {
        return handleRefreshTokenGrant(request);
    }
    else if ("client_credentials".equals(request.getGrantType())) {
        return handleClientCredentialsGrant(request);
    }
    
    throw new UnsupportedGrantTypeException("Grant type not supported");
}
```

### Implement Refresh Token Handler

```java
private ResponseEntity<TokenResponse> handleRefreshTokenGrant(TokenRequest request) {
    
    // 1. Authenticate client
    Client client = clientService.authenticateClient(
        request.getClientId(),
        request.getClientSecret()
    );
    
    // 2. Validate refresh token is provided
    if (request.getRefreshToken() == null) {
        throw new InvalidRequestException("refresh_token parameter required");
    }
    
    // 3. Validate refresh token
    RefreshToken refreshToken = tokenService.validateRefreshToken(
        request.getRefreshToken(),
        client.getClientId()
    );
    
    // 4. Generate new access token
    // Use scopes from original authorization (stored with refresh token)
    String accessToken = tokenService.generateAccessToken(
        refreshToken.getUserId(),
        client.getClientId(),
        parseScopes(refreshToken.getScopes())  // Assuming scopes stored
    );
    
    // 5. Rotate refresh token (optional but recommended)
    String newRefreshToken = tokenService.rotateRefreshToken(refreshToken);
    
    // 6. Build response
    TokenResponse response = TokenResponse.builder()
        .accessToken(accessToken)
        .tokenType("Bearer")
        .expiresIn(3600)
        .refreshToken(newRefreshToken)
        .scope(refreshToken.getScopes())
        .build();
    
    return ResponseEntity.ok(response);
}
```

---

## Step 5: Store Scopes with Refresh Token

### Update Refresh Token Entity

Add scopes field:

```java
@Column(name = "scopes", length = 500)
private String scopes;  // Space-separated
```

### Migration

Create `V11__add_scopes_to_refresh_tokens.sql`:

```sql
ALTER TABLE refresh_tokens
ADD COLUMN scopes VARCHAR(500);
```

### Update Generation Method

When creating refresh token, store granted scopes:

```java
refreshToken.setScopes(String.join(" ", scopes));
```

*Why store scopes?*: Refresh token can only get access token with same or narrower scopes as originally granted.

---

## Step 6: Implement Scope Downgrading

### Optional: Allow Scope Reduction

Client can request fewer scopes when refreshing:

```java
POST /oauth2/token
grant_type=refresh_token&
refresh_token=REFRESH_TOKEN&
scope=openid profile  // Fewer than original (openid profile email)
```

**Implementation**:
```java
Set<String> requestedScopes = parseScopes(request.getScope());
Set<String> grantedScopes = parseScopes(refreshToken.getScopes());

// Requested scopes must be subset of granted scopes
if (!grantedScopes.containsAll(requestedScopes)) {
    throw new InvalidScopeException("Requested scopes exceed granted scopes");
}

// Use requested scopes for new access token
String accessToken = tokenService.generateAccessToken(
    refreshToken.getUserId(),
    client.getClientId(),
    requestedScopes.isEmpty() ? grantedScopes : requestedScopes
);
```

*Why allow downgrading?*: Client may need fewer permissions for specific operation.

---

## Step 7: Configure Refresh Token Expiration

### Update application.yml

```yaml
jwt:
  access-token-expiration: 3600000      # 1 hour
  refresh-token-expiration: 2592000000  # 30 days
  
oauth:
  refresh-token-rotation: true  # Enable rotation
  refresh-token-reuse-interval: 60000  # 1 min grace period
```

### Grace Period for Reuse

**Problem**: Network issues may cause duplicate requests

**Solution**: Allow refresh token reuse for short period (60 seconds)

```java
// Before revoking on reuse
if (refreshToken.isRevoked()) {
    // Check if revoked recently (within grace period)
    Duration timeSinceRevoked = Duration.between(
        refreshToken.getRevokedAt(),  // Need to add this field
        LocalDateTime.now()
    );
    
    if (timeSinceRevoked.toMillis() < gracePeriod) {
        // Allow reuse (return same new token or generate again)
        return handleGracePeriodRefresh(refreshToken);
    } else {
        // Token theft suspected
        revokeTokenFamily(refreshToken.getTokenFamily());
        throw new InvalidGrantException("Refresh token revoked");
    }
}
```

---

## Step 8: Implement Cleanup Job

### Scheduled Task for Expired Tokens

Location: `src/main/java/com/learning/idp/service/RefreshTokenCleanupService.java`

```java
@Service
@RequiredArgsConstructor
public class RefreshTokenCleanupService {
    
    private final RefreshTokenRepository refreshTokenRepository;
    
    @Scheduled(cron = "0 0 2 * * *")  // Run at 2 AM daily
    public void cleanupExpiredTokens() {
        LocalDateTime cutoff = LocalDateTime.now();
        int deleted = refreshTokenRepository.deleteByExpiresAtBefore(cutoff);
        log.info("Deleted {} expired refresh tokens", deleted);
    }
}
```

*Why cleanup?*: Prevent database bloat, remove expired credentials.

---

## Step 9: Testing Refresh Token Flow

### Test Case 1: Complete Refresh Flow

**1. Get tokens via authorization code flow**:
```
POST /oauth2/token
grant_type=authorization_code&
code=AUTH_CODE&
...
```

**Response**:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
  "expires_in": 3600
}
```

**2. Wait for access token to expire** (or use immediately for testing)

**3. Use refresh token**:
```
POST /oauth2/token
grant_type=refresh_token&
refresh_token=550e8400-e29b-41d4-a716-446655440000&
client_id=demo-client&
client_secret=demo-secret
```

**Expected**: New access token + new refresh token (if rotation enabled)

**4. Check database**:
```sql
SELECT * FROM refresh_tokens
WHERE token_family = 'FAMILY_ID';
```

Verify old token is revoked, new token is active.

### Test Case 2: Reuse Detection

**1. Use refresh token to get new tokens**
**2. Try using old refresh token again**

**Expected**: 
- First use: Success
- Second use: Error "Refresh token revoked"
- All tokens in family revoked (check database)

### Test Case 3: Expired Refresh Token

**1. Create refresh token with short expiration** (or manually update database)
**2. Wait for expiration**
**3. Attempt to use**

**Expected**: 400 Bad Request, "Refresh token expired"

### Test Case 4: Wrong Client

**1. Get refresh token for client A**
**2. Try to use with client B credentials**

**Expected**: 400 Bad Request, "Client ID mismatch"

---

## Understanding Refresh Token Security

### Refresh Token vs Access Token

| Aspect | Access Token | Refresh Token |
|--------|--------------|---------------|
| Lifetime | Short (1 hour) | Long (30 days) |
| Usage | Every API call | Only to get new access token |
| Storage | Memory (client app) | Secure storage (keychain, etc.) |
| Revocable | Difficult (if JWT) | Yes (database-backed) |
| Theft impact | Limited (expires soon) | High (long-lived) |

### Token Rotation Benefits

**Without rotation**:
- Same refresh token used repeatedly
- If stolen, attacker has indefinite access
- Can't detect theft

**With rotation**:
- New refresh token on each use
- Old token invalidated immediately
- Reuse detected → revoke family
- Limits theft impact

### Storage Recommendations

**Server-side** (recommended for confidential clients):
- Store in database
- Associate with session
- Clear on logout

**Client-side** (mobile/SPA):
- Secure storage (Keychain on iOS, Keystore on Android)
- Never localStorage (XSS vulnerable)
- HttpOnly cookies (for web apps)

---

## Common Issues

### Refresh token not found

**Cause**: Database query failing, token not saved

**Solution**: Check repository save logic, verify database schema

### Infinite rotation loop

**Symptom**: Every refresh creates new token but client still uses old

**Cause**: Client not updating stored refresh token

**Solution**: Ensure client replaces old refresh token with new one

### Token family revoked unintentionally

**Cause**: Grace period too short, network retry

**Solution**: Increase grace period to 60-120 seconds

### Refresh token exposed in logs

**Security issue**: Logging refresh tokens

**Solution**: Never log tokens, use token ID or partial value for debugging

---

## What You've Accomplished

✅ Implemented refresh token generation and storage
✅ Added refresh_token grant type to token endpoint
✅ Implemented token rotation for security
✅ Created token family tracking
✅ Added refresh token validation
✅ Built cleanup job for expired tokens
✅ Tested complete refresh flow

---

## Next Steps

**Proceed to Guide 14**: Token Revocation Endpoint

Before moving on:
- [ ] Refresh tokens are generated and stored
- [ ] Refresh token grant works
- [ ] Token rotation is implemented
- [ ] Reuse detection revokes token family
- [ ] Expiration is enforced
- [ ] Cleanup job runs successfully

---

## Key Concepts Learned

### Refresh Token Pattern
- Long-lived credential for obtaining new access tokens
- Enables persistent sessions without storing long-lived access tokens
- Balance between security and UX

### Token Rotation
- Issue new refresh token on each use
- Revoke old token immediately
- Detect theft through reuse attempts

### Token Families
- Group related refresh tokens
- Track rotation lineage
- Enable bulk revocation on security events

### Grace Period
- Allow brief window for network retry
- Prevent false positives for theft detection
- Typically 60-120 seconds

---

## Additional Resources

- **RFC 6749 Section 6 (Refresh Tokens)**: https://datatracker.ietf.org/doc/html/rfc6749#section-6
- **OAuth Security BCP on Refresh Tokens**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.13
- **Token Rotation Best Practices**: https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
- **Spring Security Refresh Tokens**: https://www.baeldung.com/spring-security-oauth-refresh-token
