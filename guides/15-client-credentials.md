# Guide 15: Client Credentials Flow

**Phase 3: Enhanced Security** | **Week 5-6** | **Task 15 of 30**

## Overview

Implement the client credentials grant type for server-to-server authentication. This OAuth flow allows backend services to authenticate without user involvement, essential for microservices and API integrations.

---

## What You'll Build

- Client credentials grant handler
- Service account token generation
- Client-only scopes configuration
- Machine-to-machine authentication

---

## Why Client Credentials?

### Use Cases

**Backend services**: Microservice calling another microservice
**Scheduled jobs**: Cron jobs accessing APIs
**Server-to-server**: No user interaction needed
**Service accounts**: Applications acting on their own behalf

### Example Scenarios

- Payment processor calling transaction API
- Analytics service fetching user data
- Backup service accessing database API
- Monitoring service checking health endpoints

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4

---

## Step 1: Understand Client Credentials Flow

### Flow Diagram

```
Client App                    Authorization Server
    |                                 |
    |-- POST /oauth2/token ---------->|
    |   grant_type=client_credentials |
    |   client_id=service-app         |
    |   client_secret=secret           |
    |   scope=api.read                 |
    |                                 |
    |<---- Access Token --------------|
    |   (no refresh token)            |
    |                                 |
```

### Key Differences from Authorization Code

**No user involvement**: Client authenticates itself
**No authorization code**: Direct token issuance
**No refresh token**: Can always request new token
**Subject is client**: Token represents client, not user

---

## Step 2: Update Client Entity

### Add Allowed Grant Types

```java
@Column(name = "grant_types", length = 255, nullable = false)
private String grantTypes;  // Comma-separated: "authorization_code,refresh_token,client_credentials"
```

**Migration**: `V12__add_grant_types_to_clients.sql`

```sql
ALTER TABLE clients
ADD COLUMN grant_types VARCHAR(255) DEFAULT 'authorization_code,refresh_token';
```

### Service Account Scopes

```java
@Column(name = "service_scopes", length = 500)
private String serviceScopes;  // Scopes available for client_credentials
```

*Why separate scopes?*: Service account may have different permissions than when acting on behalf of user

---

## Step 3: Validate Client Grant Type

### Add Validation Method

In `ClientService`:

```java
public boolean isGrantTypeAllowed(Client client, String grantType) {
    Set<String> allowedGrants = Set.of(client.getGrantTypes().split(","));
    return allowedGrants.contains(grantType);
}
```

### Check in Token Endpoint

```java
if (!clientService.isGrantTypeAllowed(client, request.getGrantType())) {
    throw new UnauthorizedClientException(
        "Client not authorized for this grant type"
    );
}
```

---

## Step 4: Implement Client Credentials Handler

### Add to TokenController

```java
@PostMapping("/token")
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
    
    throw new UnsupportedGrantTypeException(request.getGrantType());
}
```

### Implement Handler Method

```java
private ResponseEntity<TokenResponse> handleClientCredentialsGrant(
        TokenRequest request) {
    
    // 1. Authenticate client (required for this grant)
    Client client = clientService.authenticateClient(
        request.getClientId(),
        request.getClientSecret()
    );
    
    // 2. Verify grant type allowed
    if (!clientService.isGrantTypeAllowed(client, "client_credentials")) {
        throw new UnauthorizedClientException(
            "Client not authorized for client_credentials grant"
        );
    }
    
    // 3. Determine scopes
    Set<String> requestedScopes = request.getScope() != null
        ? Set.of(request.getScope().split("\\s+"))
        : Set.of();
    
    Set<String> allowedScopes = Set.of(
        client.getServiceScopes().split("\\s+")
    );
    
    // 4. Validate requested scopes
    if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
        throw new InvalidScopeException("Requested scopes not allowed");
    }
    
    Set<String> grantedScopes = requestedScopes.isEmpty() 
        ? allowedScopes 
        : requestedScopes;
    
    // 5. Generate access token (no user context)
    String accessToken = tokenService.generateClientToken(
        client.getClientId(),
        grantedScopes
    );
    
    // 6. Build response (no refresh token)
    TokenResponse response = TokenResponse.builder()
        .accessToken(accessToken)
        .tokenType("Bearer")
        .expiresIn(3600)
        // No refresh_token for client_credentials
        .scope(String.join(" ", grantedScopes))
        .build();
    
    return ResponseEntity.ok(response);
}
```

---

## Step 5: Generate Client-Only Tokens

### Add Method to JwtTokenProvider

```java
public String generateClientToken(String clientId, Set<String> scopes) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtConfig.getAccessTokenExpiration());
    
    return Jwts.builder()
        .setSubject(clientId)  // Subject is client, not user
        .setIssuer(jwtConfig.getIssuer())
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .claim("client_id", clientId)
        .claim("scope", String.join(" ", scopes))
        .claim("grant_type", "client_credentials")  // Mark token type
        // No user claims (username, email, etc.)
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
}
```

### Key Differences

**Subject (sub)**: Client ID, not user ID
**No user claims**: No username, email, user_id
**Grant type claim**: Identifies how token was obtained
**Scopes**: Client-specific scopes only

---

## Step 6: Configure Service Account Scopes

### Define Service Scopes

Create scope categories:

**User-delegated scopes**: `openid`, `profile`, `email`
- Only for authorization_code flow
- Require user consent

**Service scopes**: `api.read`, `api.write`, `admin.users`
- For client_credentials flow
- No user consent needed

### Update Clients Table

**Seed data** (`V13__seed_service_client.sql`):

```sql
INSERT INTO clients (
    client_id, 
    client_secret, 
    client_name,
    grant_types,
    scopes,
    service_scopes,
    is_public
) VALUES (
    'analytics-service',
    '$2a$10$...hashed_secret...',
    'Analytics Background Service',
    'client_credentials',
    '',  -- No user-delegated scopes
    'analytics.read,users.read',  -- Service scopes
    false
);
```

---

## Step 7: Update Resource Server

### Validate Token Type

Resource server should check if endpoint requires user context:

```java
@GetMapping("/api/users")
@PreAuthorize("hasAuthority('SCOPE_users.read')")
public List<User> getUsers(@AuthenticationPrincipal Jwt jwt) {
    
    // Check if token has user context
    String grantType = jwt.getClaimAsString("grant_type");
    
    if ("client_credentials".equals(grantType)) {
        // No user context - return all users
        return userService.getAllUsers();
    } else {
        // User context - return user's own data
        Long userId = Long.parseLong(jwt.getSubject());
        return userService.getUserById(userId);
    }
}
```

### Endpoint Requirements

Some endpoints **require user context**:
```java
@GetMapping("/api/profile")
public UserProfile getProfile(@AuthenticationPrincipal Jwt jwt) {
    if ("client_credentials".equals(jwt.getClaimAsString("grant_type"))) {
        throw new ForbiddenException("Endpoint requires user authentication");
    }
    
    Long userId = Long.parseLong(jwt.getSubject());
    return userService.getUserProfile(userId);
}
```

Some endpoints **allow service accounts**:
```java
@GetMapping("/api/health")
public HealthStatus getHealth() {
    // Open to all authenticated clients
    return healthService.getStatus();
}
```

---

## Step 8: Testing Client Credentials Flow

### Test Case 1: Valid Request

**Request**:
```
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=analytics-service&
client_secret=service-secret&
scope=analytics.read
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "analytics.read"
}
```

**Note**: No `refresh_token` in response

### Test Case 2: Decode Token

Visit jwt.io and decode the access token.

**Verify**:
- `sub`: Contains client_id (e.g., "analytics-service")
- `scope`: Contains requested scopes
- `grant_type`: "client_credentials"
- No `username`, `email`, or user-specific claims

### Test Case 3: Invalid Grant Type

**Setup**: Client configured with only `authorization_code` grant

**Request**:
```
POST /oauth2/token
grant_type=client_credentials&
client_id=web-client&...
```

**Expected**: 400 Bad Request, `error: "unauthorized_client"`

### Test Case 4: Invalid Scope

**Request**:
```
grant_type=client_credentials&
scope=openid profile&  // User scopes, not service scopes
...
```

**Expected**: 400 Bad Request, `error: "invalid_scope"`

### Test Case 5: Missing Client Secret

**Request** (public client trying client_credentials):
```
grant_type=client_credentials&
client_id=mobile-app&  // Public client
```

**Expected**: 401 Unauthorized, `error: "invalid_client"`

---

## Step 9: Rate Limiting for Service Accounts

### Higher Limits for Services

Service accounts may need higher rate limits:

```java
@Configuration
public class RateLimitConfig {
    
    @Bean
    public RateLimiter tokenEndpointLimiter() {
        return RateLimiter.create(100.0);  // 100 req/sec for services
    }
    
    public int getLimit(String clientId, String grantType) {
        if ("client_credentials".equals(grantType)) {
            return 1000;  // Higher limit for service accounts
        }
        return 100;  // Normal limit for user flows
    }
}
```

---

## Step 10: Audit Logging

### Log Service Account Activity

```java
@Aspect
@Component
public class ServiceAccountAuditAspect {
    
    @AfterReturning(
        pointcut = "execution(* handleClientCredentialsGrant(..))",
        returning = "response"
    )
    public void logServiceAccountToken(JoinPoint joinPoint, Object response) {
        TokenRequest request = (TokenRequest) joinPoint.getArgs()[0];
        
        auditLogService.logServiceAccountToken(
            request.getClientId(),
            request.getScope(),
            extractIpAddress()
        );
    }
}
```

**Why audit?**: Service accounts can be powerful - track their usage

---

## Understanding Client Credentials Security

### When to Use

**✅ Good use cases**:
- Backend service integration
- Scheduled tasks
- Administrative operations
- Internal microservices

**❌ Don't use for**:
- User-facing applications
- Browser-based apps
- Mobile apps
- Anything requiring user context

### Security Considerations

**Strong client secrets**: Use long, random secrets (32+ characters)
**Secret rotation**: Regularly rotate service account credentials
**Least privilege**: Grant minimum necessary scopes
**Network security**: Service accounts often bypass user auth - secure network
**Monitoring**: Alert on unusual service account behavior

### Client Credentials vs Service Accounts

This flow is essentially **OAuth-based service accounts**:
- Traditional service accounts: API keys, username/password
- OAuth client credentials: Standard protocol, scoped access, time-limited tokens

---

## Common Issues

### Client secret not working

**Cause**: Secret not hashed correctly in database

**Solution**: Ensure using same PasswordEncoder for client secrets as user passwords

### Token has user claims

**Cause**: Using wrong token generation method

**Solution**: Use `generateClientToken()` not `generateAccessToken()`

### Scope validation too strict

**Cause**: Checking against user scopes instead of service scopes

**Solution**: Use `client.getServiceScopes()` for client_credentials

---

## What You've Accomplished

✅ Implemented client credentials grant type
✅ Created service account token generation
✅ Configured client-specific scopes
✅ Added grant type validation
✅ Tested machine-to-machine authentication
✅ Understood service account security

**Phase 3 Complete!** 🎉

---

## Next Steps

**Proceed to Phase 4 - Guide 16**: Build Consent Screen

Before moving on:
- [ ] Client credentials grant works
- [ ] Tokens don't include user claims
- [ ] No refresh tokens issued
- [ ] Scope validation enforces service scopes
- [ ] Service clients configured in database

---

## Key Concepts Learned

### Client Credentials Grant
- Server-to-server authentication
- No user involvement
- Direct token issuance
- Client is the subject

### Service Scopes
- Different from user-delegated scopes
- No consent required
- API-specific permissions
- Configured per client

### Token Characteristics
- Subject is client_id
- No user claims
- No refresh token
- Shorter or longer expiration based on use case

### Security Model
- Strong client authentication required
- Least privilege scope assignment
- Audit logging essential
- Network security critical

---

## Additional Resources

- **RFC 6749 Section 4.4**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
- **Client Credentials Best Practices**: https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/
- **Service Account Security**: https://www.baeldung.com/spring-security-oauth2-client-credentials-flow
