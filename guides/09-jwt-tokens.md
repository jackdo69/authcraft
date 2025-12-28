# Guide 09: JWT Token Generation

**Phase 2: Basic OAuth** | **Week 3-4** | **Task 9 of 10**

## Overview

Implement JWT (JSON Web Token) generation for access tokens. Learn how JWTs work, why they're used in OAuth, and how to create and sign tokens securely.

---

## What You'll Build

- JWT token generation service
- Token signing with HMAC-SHA256
- Claims (payload) configuration
- Token expiration handling
- JwtTokenProvider utility class

---

## Understanding JWT

### What is JWT?

JWT (JSON Web Token) is a compact, URL-safe way to represent claims between two parties. It consists of three parts:

```
Header.Payload.Signature
```

**Example**:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### JWT Structure

#### 1. Header (Algorithm & Token Type)
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
- Base64URL encoded
- Specifies signing algorithm (HMAC SHA256, RSA, etc.)

#### 2. Payload (Claims)
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622
}
```
- Base64URL encoded
- Contains claims (statements about user and token)

#### 3. Signature
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```
- Verifies token wasn't tampered with
- Proves it was created by someone with the secret key

**Learn More**: https://jwt.io/introduction

---

## Step 1: Add JJWT Dependencies

### Verify Dependencies in pom.xml

You should have added these in Guide 01:

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.3</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.3</version>
    <scope>runtime</scope>
</dependency>
```

Check Maven Central for latest versions: https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api

---

## Step 2: Configure JWT Settings

### Update application.yml

Add JWT configuration:

```yaml
jwt:
  secret: your-256-bit-secret-key-change-this-in-production-please-use-very-long-random-string
  access-token-expiration: 3600000  # 1 hour in milliseconds
  refresh-token-expiration: 2592000000  # 30 days in milliseconds
  issuer: http://localhost:8080  # Your IdP URL
```

### Secret Key Requirements

**For HMAC algorithms** (HS256):
- **Minimum**: 256 bits (32 bytes)
- **Recommendation**: Generate cryptographically random key
- **Never commit real secrets** to version control

### Generate Secure Secret

```java
// Run this once to generate a secret
SecureRandom random = new SecureRandom();
byte[] secret = new byte[32];
random.nextBytes(secret);
String secretKey = Base64.getEncoder().encodeToString(secret);
System.out.println(secretKey);  // Use this in application.yml
```

**Production**: Use environment variables or secret management service (AWS Secrets Manager, HashiCorp Vault).

---

## Step 3: Create JWT Configuration Class

### Create JwtConfig.java

Location: `src/main/java/com/learning/idp/config/JwtConfig.java`

### Load Properties

```java
@Configuration
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtConfig {
    private String secret;
    private Long accessTokenExpiration;
    private Long refreshTokenExpiration;
    private String issuer;
}
```

*Why @ConfigurationProperties?*: Type-safe configuration binding from application.yml.

**Learn More**: https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config.typesafe-configuration-properties

---

## Step 4: Create JwtTokenProvider

### Create JwtTokenProvider.java

Location: `src/main/java/com/learning/idp/security/JwtTokenProvider.java`

### Class Structure

```java
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final JwtConfig jwtConfig;
    private final UserRepository userRepository;  // To load user details

    // Methods: generateAccessToken, generateRefreshToken, validateToken, etc.
}
```

### Initialize Signing Key

```java
private Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(jwtConfig.getSecret());
    return Keys.hmacShaKeyFor(keyBytes);
}
```

*Why convert to Key object?*: JJWT requires Key instance for signing/validation.

---

## Step 5: Implement Access Token Generation

### Generate Access Token Method

```java
public String generateAccessToken(Long userId, String clientId, Set<String> scopes) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new IllegalArgumentException("User not found"));

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtConfig.getAccessTokenExpiration());

    return Jwts.builder()
        .setSubject(user.getId().toString())  // User ID
        .setIssuer(jwtConfig.getIssuer())  // Your IdP
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .claim("username", user.getUsername())
        .claim("email", user.getEmail())
        .claim("client_id", clientId)
        .claim("scope", String.join(" ", scopes))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
}
```

### Understanding Claims

**Standard claims** (registered in JWT spec):
- **sub** (subject): User identifier
- **iss** (issuer): Who created token
- **iat** (issued at): When token was created
- **exp** (expiration): When token expires
- **aud** (audience): Who should accept token (optional)

**Custom claims**:
- **username**, **email**: User information
- **client_id**: Which client obtained token
- **scope**: Granted permissions

*Why include scopes in token?*: Resource server needs to know what user authorized without calling back to IdP.

---

## Step 6: Implement Token Validation

### Validate Token Method

```java
public Claims validateToken(String token) {
    try {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    } catch (JwtException ex) {
        throw new InvalidTokenException("Invalid or expired token", ex);
    }
}
```

### What Validation Checks

JJWT automatically validates:
- **Signature**: Token wasn't tampered with
- **Expiration**: Token hasn't expired (exp claim)
- **Not before**: Token is not used before nbf claim (if present)

### Extract Claims

```java
public Long getUserIdFromToken(String token) {
    Claims claims = validateToken(token);
    return Long.parseLong(claims.getSubject());
}

public String getUsernameFromToken(String token) {
    Claims claims = validateToken(token);
    return claims.get("username", String.class);
}

public Set<String> getScopesFromToken(String token) {
    Claims claims = validateToken(token);
    String scopes = claims.get("scope", String.class);
    return Set.of(scopes.split("\\s+"));
}
```

---

## Step 7: Implement Refresh Token Generation

### For Now: Use UUIDs

Refresh tokens don't need to be JWTs (they're opaque to client):

```java
public String generateRefreshToken(Long userId, String clientId) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setUserId(userId);
    refreshToken.setClientId(clientId);
    refreshToken.setExpiresAt(LocalDateTime.now().plusDays(30));
    refreshToken.setRevoked(false);

    refreshTokenRepository.save(refreshToken);

    return refreshToken.getToken();
}
```

*Why not JWT for refresh tokens?*:
- Need to revoke refresh tokens (store in database)
- Longer-lived (more risky if JWT secret compromised)
- Opaque to client anyway (client just sends it back)

**Phase 3** will cover refresh tokens in detail.

---

## Step 8: Integrate with Token Service

### Create TokenService.java

Location: `src/main/java/com/learning/idp/service/TokenService.java`

### Delegate to JwtTokenProvider

```java
@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public String generateAccessToken(Long userId, String clientId, Set<String> scopes) {
        return jwtTokenProvider.generateAccessToken(userId, clientId, scopes);
    }

    public String generateRefreshToken(Long userId, String clientId) {
        return jwtTokenProvider.generateRefreshToken(userId, clientId);
    }

    // More methods in later guides
}
```

*Why separate TokenService?*: Business logic layer, can add additional operations beyond JWT generation (logging, metrics, etc.).

---

## Step 9: Update Token Endpoint to Use JWT

### In TokenController

Update the authorization code grant handler:

```java
Set<String> scopes = Set.of(authCode.getScopes().split("\\s+"));

String accessToken = tokenService.generateAccessToken(
    authCode.getUserId(),
    authCode.getClientId(),
    scopes
);

String refreshToken = tokenService.generateRefreshToken(
    authCode.getUserId(),
    authCode.getClientId()
);

TokenResponse response = TokenResponse.builder()
    .accessToken(accessToken)
    .tokenType("Bearer")
    .expiresIn((int) (jwtConfig.getAccessTokenExpiration() / 1000))  // Seconds
    .refreshToken(refreshToken)
    .scope(authCode.getScopes())
    .build();

return ResponseEntity.ok(response);
```

---

## Step 10: Test JWT Token Generation

### Complete OAuth Flow

1. **Authorize**: `/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&state=xyz`
2. **Login**: Submit credentials
3. **Consent**: Approve authorization
4. **Get code**: Extract code from redirect URL
5. **Exchange**: POST to `/oauth2/token` with code
6. **Receive JWT**: Response contains access_token

### Decode JWT

Visit https://jwt.io/ and paste your access token.

**Verify**:
- Header: `{"alg":"HS256","typ":"JWT"}`
- Payload contains:
  - `sub`: User ID
  - `iss`: Your IdP URL
  - `iat`: Issued at timestamp
  - `exp`: Expiration timestamp
  - `username`, `email`: User info
  - `client_id`: Client identifier
  - `scope`: Granted scopes
- Signature: Shows "Signature Verified" if you paste your secret

### Important Security Note

**Never paste production tokens** or secrets into online tools! For learning, it's OK with localhost tokens.

---

## Understanding JWT vs Opaque Tokens

### JWT (Self-Contained)

**Pros**:
- Resource server can validate without calling IdP
- Stateless (no database lookup)
- Contains user/scope information

**Cons**:
- Can't revoke before expiration
- Larger size (hundreds of bytes)
- Payload is readable (base64, not encrypted)

### Opaque Tokens (Random Strings)

**Pros**:
- Smaller size
- Can revoke anytime
- Payload hidden

**Cons**:
- Resource server must validate with IdP (introspection endpoint)
- Requires database lookup
- More network calls

**Recommendation**: JWTs for access tokens (short-lived), opaque for refresh tokens (need revocation).

---

## JWT Security Considerations

### DO

- ✅ Use strong secret (256+ bits)
- ✅ Use HTTPS in production (prevents token interception)
- ✅ Short expiration for access tokens (15 min - 1 hour)
- ✅ Validate signature on every use
- ✅ Use `exp` claim to enforce expiration

### DON'T

- ❌ Store sensitive data in JWT (it's base64, not encrypted)
- ❌ Use same secret for different environments
- ❌ Trust JWT without signature validation
- ❌ Use symmetric keys (HS256) for public clients (use RS256 instead)
- ❌ Make tokens long-lived (defeats purpose of refresh tokens)

### Algorithm Confusion Attack

Always verify `alg` header:
- Attacker changes `alg` from RS256 to HS256
- Uses public key as HMAC secret
- Can forge tokens

**Protection**: JJWT validates algorithm, but always use `setSigningKey()` with expected algorithm.

**Learn More**: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

---

## What You've Accomplished

✅ Implemented JWT token generation
✅ Configured signing with HMAC-SHA256
✅ Added standard and custom claims
✅ Created token validation logic
✅ Integrated JWT into token endpoint
✅ Understood JWT security considerations

---

## Next Steps

**Proceed to Guide 10**: Create a Simple Client App to Test

Before moving on:
- [ ] JWTs are generated with correct structure
- [ ] Tokens contain all required claims
- [ ] Signature validation works
- [ ] Token expiration is enforced
- [ ] Complete OAuth flow issues JWT access tokens

---

## Key Concepts Learned

### JWT Structure
- Header: Algorithm and token type
- Payload: Claims about user and token
- Signature: Cryptographic proof of authenticity

### Claims
- Standard claims follow JWT spec
- Custom claims add application-specific data
- Resource servers use claims for authorization

### Stateless Authentication
- JWTs don't require database lookup
- Resource servers can validate independently
- Trade-off: Can't revoke before expiration

### Token Signing
- HMAC: Symmetric key (same secret signs and verifies)
- RSA: Asymmetric keys (private signs, public verifies)
- Choose based on architecture and security needs

---

## Additional Resources

- **JWT.io**: https://jwt.io/ (decode and test JWTs)
- **RFC 7519 (JWT)**: https://datatracker.ietf.org/doc/html/rfc7519
- **JJWT Documentation**: https://github.com/jwtk/jjwt
- **JWT Security Best Practices**: https://datatracker.ietf.org/doc/html/rfc8725
- **JWT vs Opaque Tokens**: https://www.oauth.com/oauth2-servers/access-tokens/
