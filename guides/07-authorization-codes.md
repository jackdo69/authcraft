# Guide 07: Generate and Validate Authorization Codes

**Phase 2: Basic OAuth** | **Week 3-4** | **Task 7 of 10**

## Overview

Implement authorization code generation, storage, and validation. Authorization codes are temporary credentials exchanged for access tokens - a critical security component of OAuth 2.0.

---

## What You'll Build

- Authorization code generation service
- Secure random code generation
- Code storage with expiration
- Code validation and one-time-use enforcement
- Code exchange logic

---

## Understanding Authorization Codes

### What They Are

Authorization codes are **short-lived, one-time-use tokens** that represent:
- A user has authenticated
- A user has authorized a client
- The authorization hasn't been used yet
- The authorization hasn't expired

### Why Not Issue Tokens Directly?

**Security**: Authorization codes are exchanged via the **front channel** (browser redirects):
- Visible in browser history
- Visible in server logs
- Can be intercepted

Access tokens are exchanged via the **back channel** (direct server-to-server):
- Not visible to user
- Includes client authentication
- More secure

This two-step process (code → token) prevents token theft via browser exploits.

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.1

---

## Step 1: Create AuthorizationCode Entity

### Create AuthorizationCode.java

Location: `src/main/java/com/learning/idp/model/AuthorizationCode.java`

### Fields Required

Based on the schema from Guide 04:

- **id** (Long): Primary key
- **code** (String): The actual authorization code
- **clientId** (String): Which client this code is for
- **userId** (Long): Which user authorized
- **redirectUri** (String): Original redirect URI from request
- **scopes** (String): Comma or space-separated scopes
- **codeChallenge** (String, nullable): PKCE challenge (Phase 3)
- **codeChallengeMethod** (String, nullable): PKCE method (Phase 3)
- **expiresAt** (LocalDateTime): When code expires
- **createdAt** (LocalDateTime): When code was issued
- **used** (Boolean): Whether code has been exchanged

### JPA Annotations

- **@Entity**
- **@Table(name = "authorization_codes")**
- **@Column**: Specify uniqueness for code, nullable for PKCE fields
- **@CreationTimestamp**: Auto-populate createdAt

### Why Track "used"?

Prevents **authorization code replay attacks**:
- Attacker intercepts code
- Attacker tries to use code after legitimate exchange
- IdP rejects because `used = true`

---

## Step 2: Create Authorization Code Repository

### Create AuthorizationCodeRepository.java

Location: `src/main/java/com/learning/idp/repository/AuthorizationCodeRepository.java`

### Extend JpaRepository

```java
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {
    // Custom methods here
}
```

### Query Methods Needed

- **findByCode(String code)**: Retrieve by code value
  - *Why*: During token exchange, lookup code
- **findByCodeAndUsedFalse(String code)**: Find unused codes only
  - *Why*: Reject already-used codes
- **deleteByExpiresAtBefore(LocalDateTime dateTime)**: Cleanup expired codes
  - *Why*: Prevent database bloat
- **deleteByUsedTrue()**: Cleanup used codes
  - *Why*: After grace period, no need to keep them

---

## Step 3: Create Authorization Code Service

### Create AuthorizationCodeService.java

Location: `src/main/java/com/learning/idp/service/AuthorizationCodeService.java`

### Generate Authorization Code Method

**Method signature**: `generateAuthorizationCode(String clientId, Long userId, String redirectUri, Set<String> scopes)`

**Steps**:
1. **Generate random code**: Use `SecureRandom` or UUID
2. **Calculate expiration**: Current time + 10 minutes
3. **Create entity**: Populate all fields
4. **Save to database**
5. **Return code value**

### Generate Secure Random Code

```java
// Option 1: UUID (simple, secure)
String code = UUID.randomUUID().toString();

// Option 2: SecureRandom with Base64 (more control over length)
SecureRandom secureRandom = new SecureRandom();
byte[] randomBytes = new byte[32];  // 256 bits
secureRandom.nextBytes(randomBytes);
String code = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
```

*Why URL-safe Base64?*: Code will be in URL parameters, avoid special characters that need encoding.

### Code Expiration

**Recommendation**: 5-10 minutes

- **Shorter**: More secure (smaller attack window)
- **Longer**: Better UX if user is slow to complete flow
- **OAuth spec recommendation**: As short as practical

---

## Step 4: Integrate Code Generation into Authorization Flow

### Update AuthorizationController

In your consent approval handler:

**After user approves**:
1. **Call service**: `authorizationCodeService.generateAuthorizationCode(...)`
2. **Build redirect URL**:
   ```java
   String redirectUrl = UriComponentsBuilder
       .fromUriString(redirectUri)
       .queryParam("code", authorizationCode)
       .queryParam("state", state)
       .toUriString();
   ```
3. **Redirect**: `return "redirect:" + redirectUrl;`

### Why UriComponentsBuilder?

Spring utility for safely building URLs:
- Handles URL encoding automatically
- Prevents malformed URLs
- Cleaner than string concatenation

**Learn More**: https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/util/UriComponentsBuilder.html

---

## Step 5: Create Code Validation Method

### Add to AuthorizationCodeService

**Method signature**: `validateAndConsume(String code, String clientId, String redirectUri)`

**Validation steps**:

```java
// 1. Find code
AuthorizationCode authCode = repository.findByCode(code)
    .orElseThrow(() -> new InvalidGrantException("Invalid authorization code"));

// 2. Check if already used
if (authCode.isUsed()) {
    // Security event! Possible replay attack
    // Revoke all tokens for this authorization
    throw new InvalidGrantException("Authorization code already used");
}

// 3. Check expiration
if (authCode.getExpiresAt().isBefore(LocalDateTime.now())) {
    throw new InvalidGrantException("Authorization code expired");
}

// 4. Verify client_id matches
if (!authCode.getClientId().equals(clientId)) {
    throw new InvalidGrantException("Client ID mismatch");
}

// 5. Verify redirect_uri matches
if (!authCode.getRedirectUri().equals(redirectUri)) {
    throw new InvalidGrantException("Redirect URI mismatch");
}

// 6. Mark as used
authCode.setUsed(true);
repository.save(authCode);

// 7. Return authorization details
return authCode;
```

### Why Each Check Matters

- **Used check**: Prevents replay attacks
- **Expiration**: Limits attack window
- **Client ID match**: Prevents code theft between clients
- **Redirect URI match**: Prevents authorization code injection attacks

**Critical Security**: If code is already used, consider revoking all related tokens - indicates an attack is in progress.

---

## Step 6: Implement Code Cleanup Job

### Create Scheduled Task

Location: `src/main/java/com/learning/idp/service/AuthorizationCodeCleanupService.java`

### Enable Scheduling

In main application class or configuration:
```java
@EnableScheduling
```

### Cleanup Method

```java
@Scheduled(fixedRate = 3600000)  // Run every hour
public void cleanupExpiredCodes() {
    LocalDateTime cutoff = LocalDateTime.now();
    int deleted = repository.deleteByExpiresAtBefore(cutoff);
    log.info("Deleted {} expired authorization codes", deleted);
}
```

### Why Cleanup?

- **Database size**: Prevent unbounded growth
- **Performance**: Fewer rows = faster queries
- **Security**: Old codes are noise, harder to audit

### Cleanup Strategy

**Option 1**: Delete on expiration
- Simpler
- Database might accumulate many expired codes between runs

**Option 2**: Keep for audit period, then delete
- Better for security auditing
- Delete codes older than 24 hours

---

## Step 7: Handle Authorization Code Errors

### Create Custom Exceptions

Location: `src/main/java/com/learning/idp/exception/`

#### InvalidGrantException

For all authorization code validation failures:
- Code doesn't exist
- Code expired
- Code already used
- Client/redirect mismatch

#### Exception Handler

Create `@RestControllerAdvice` class:

```java
@ExceptionHandler(InvalidGrantException.class)
public ResponseEntity<ErrorResponse> handleInvalidGrant(InvalidGrantException ex) {
    ErrorResponse error = new ErrorResponse("invalid_grant", ex.getMessage());
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
}
```

### OAuth Error Format

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

Standard OAuth error codes:
- `invalid_request`
- `invalid_client`
- `invalid_grant`
- `unauthorized_client`
- `unsupported_grant_type`

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2

---

## Step 8: Test Authorization Code Generation

### Test Flow

1. **Complete authorization** (login + consent)
2. **Check redirect URL**: Should contain `code` parameter
3. **Extract code** from URL
4. **Check database**:
   ```sql
   SELECT * FROM authorization_codes WHERE code = 'YOUR_CODE';
   ```

### Verify Code Properties

- [ ] Code is unique (UUID or long random string)
- [ ] `expires_at` is ~10 minutes in future
- [ ] `used` is FALSE
- [ ] `client_id`, `user_id`, `redirect_uri`, `scopes` are correct
- [ ] `created_at` is current timestamp

---

## Step 9: Test Authorization Code Validation

### Test Cases

#### Valid Code Exchange
**Test**: Exchange code immediately after generation
**Expected**: Success, code marked as used

#### Expired Code
**Test**: Generate code, wait for expiration, attempt exchange
**Expected**: `invalid_grant` error

#### Replay Attack
**Test**: Exchange code twice
**Expected**: Second attempt fails with `invalid_grant`

#### Wrong Client ID
**Test**: Try to exchange code with different client_id
**Expected**: `invalid_grant` error

#### Wrong Redirect URI
**Test**: Try to exchange code with different redirect_uri
**Expected**: `invalid_grant` error

### Testing Tips

For expiration testing during development:
- **Temporarily shorten expiration**: Use 30 seconds instead of 10 minutes
- **Or**: Manually update `expires_at` in database to past time

---

## Understanding Authorization Code Security

### Threat Model

**Attacker goals**:
1. **Intercept code**: Get code from browser history, logs, or network
2. **Replay code**: Use code after legitimate exchange
3. **Steal code**: Use code meant for different client

### Mitigations

| Threat | Mitigation |
|--------|-----------|
| Code interception | Short expiration + HTTPS + PKCE (Phase 3) |
| Code replay | One-time use check + mark as used |
| Code theft | Client ID validation + Redirect URI validation |
| Code injection | State parameter (CSRF) + Redirect URI validation |

### Why Authorization Codes Are Still Vulnerable

Despite mitigations, codes can be intercepted. That's why:
- **PKCE** (Phase 3) adds cryptographic binding
- **Client authentication** (for confidential clients) provides additional security
- **Refresh token rotation** (Phase 3) limits damage if tokens are compromised

---

## Code Storage Considerations

### Database vs Cache

**Current approach**: Database (PostgreSQL)
- **Pros**: Durable, survives restarts, easy to audit
- **Cons**: Slower than cache

**Alternative**: Redis cache
- **Pros**: Faster, automatic expiration with TTL
- **Cons**: Lost on Redis restart (unless persistence enabled)

**Recommendation**: Start with database for learning, consider Redis for production performance.

### Indexing

Ensure index on `code` column for fast lookup:
```sql
CREATE INDEX idx_authorization_codes_code ON authorization_codes(code);
```

Already created if you used `UNIQUE` constraint in migration.

---

## What You've Accomplished

✅ Implemented secure authorization code generation
✅ Created code storage with expiration
✅ Built code validation with security checks
✅ Implemented one-time-use enforcement
✅ Added cleanup job for expired codes
✅ Understood authorization code security

---

## Next Steps

**Proceed to Guide 08**: Build Token Endpoint

Before moving on:
- [ ] Authorization codes are generated on consent approval
- [ ] Codes are stored with all required fields
- [ ] Codes expire after configured time
- [ ] Validation checks prevent misuse
- [ ] Cleanup job removes old codes
- [ ] Error handling returns proper OAuth errors

---

## Key Concepts Learned

### Authorization Code Flow Security
- Codes are temporary credentials
- Short-lived reduces attack window
- One-time use prevents replay
- Binding to client and redirect_uri prevents theft

### Secure Random Generation
- Use `SecureRandom` or `UUID` for unpredictability
- URL-safe encoding for codes in URLs
- Sufficient entropy (128-256 bits)

### Validation Defense in Depth
- Multiple checks catch different attack vectors
- Early validation prevents wasted processing
- Clear error messages help debugging (in dev)

### Database Cleanup
- Scheduled tasks prevent unbounded growth
- Balance cleanup frequency with database load
- Consider audit requirements before deletion

---

## Additional Resources

- **OAuth 2.0 Authorization Code**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
- **Secure Random in Java**: https://www.baeldung.com/java-secure-random
- **Spring Scheduling**: https://docs.spring.io/spring-framework/reference/integration/scheduling.html
- **Authorization Code Security**: https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
- **Spring @Scheduled**: https://www.baeldung.com/spring-scheduled-tasks
