# Guide 08: Build Token Endpoint

**Phase 2: Basic OAuth** | **Week 3-4** | **Task 8 of 10**

## Overview

Build the token endpoint where clients exchange authorization codes for access tokens. This is the core of the authorization code flow and uses server-to-server communication for enhanced security.

---

## What You'll Build

- Token endpoint (`/oauth2/token`)
- Client authentication
- Authorization code exchange
- Token generation (covered in Guide 09)
- Token response formatting

---

## Understanding the Token Endpoint

### What It Does

The token endpoint is where:
1. **Client sends authorization code** (obtained from user authorization)
2. **Client authenticates itself** (proves it's the legitimate client)
3. **IdP validates code** and client credentials
4. **IdP issues access token** (and optionally refresh token, ID token)

### Back Channel Communication

Unlike the authorization endpoint (front channel via browser), the token endpoint uses:
- **Server-to-server HTTP POST**
- **No user involvement**
- **Client authentication required** (for confidential clients)
- **Secure exchange** (not visible to user)

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-3.2

---

## Step 1: Understand the Token Request

### Request Format

**Method**: POST
**URL**: `/oauth2/token`
**Content-Type**: `application/x-www-form-urlencoded`

**Body parameters**:
```
grant_type=authorization_code&
code=AUTHORIZATION_CODE&
redirect_uri=http://localhost:3000/callback&
client_id=demo-client&
client_secret=demo-secret
```

### Required Parameters

| Parameter | Description | Validation |
|-----------|-------------|------------|
| **grant_type** | Type of token request | Must be "authorization_code" |
| **code** | Authorization code from /authorize | Must be valid, unused, unexpired |
| **redirect_uri** | Original redirect URI | Must match authorization request |
| **client_id** | Client identifier | Must exist |
| **client_secret** | Client credential | Must match (for confidential clients) |

### Grant Types

For now, implement:
- **authorization_code**: Exchange code for tokens

Later phases add:
- **refresh_token**: Exchange refresh token for new access token
- **client_credentials**: Server-to-server authentication

---

## Step 2: Create Token Request DTO

### Create TokenRequest.java

Location: `src/main/java/com/learning/idp/dto/TokenRequest.java`

### Fields

```java
@NotBlank
private String grantType;

@NotBlank
private String code;  // For authorization_code grant

@NotBlank
private String redirectUri;

@NotBlank
private String clientId;

private String clientSecret;  // Optional for public clients

private String codeVerifier;  // For PKCE (Phase 3)
```

### Validation

- **@NotBlank**: On required fields
- **@Pattern** on grantType: Validate it's a supported type

---

## Step 3: Create Token Endpoint Controller

### Create TokenController.java

Location: `src/main/java/com/learning/idp/controller/TokenController.java`

### Endpoint Mapping

**Annotations**:
- `@RestController`
- `@RequestMapping("/oauth2")`

**Method**:
- `@PostMapping("/token")`
- Consumes: `MediaType.APPLICATION_FORM_URLENCODED_VALUE`
- Produces: `MediaType.APPLICATION_JSON_VALUE`

*Why form-urlencoded?*: OAuth 2.0 spec requires this format for token endpoint.

### Method Signature

```java
@PostMapping(value = "/token",
             consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
             produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<TokenResponse> token(@Valid @ModelAttribute TokenRequest request) {
    // Implementation
}
```

*Why @ModelAttribute?*: For form-urlencoded data (not JSON).

---

## Step 4: Implement Client Authentication

### Create ClientService

Location: `src/main/java/com/learning/idp/service/ClientService.java`

### Authenticate Client Method

```java
public Client authenticateClient(String clientId, String clientSecret) {
    Client client = clientRepository.findByClientId(clientId)
        .orElseThrow(() -> new InvalidClientException("Invalid client"));

    // Public clients don't have secrets
    if (client.isPublic()) {
        return client;
    }

    // Confidential clients must provide correct secret
    if (clientSecret == null || !passwordEncoder.matches(clientSecret, client.getClientSecret())) {
        throw new InvalidClientException("Invalid client credentials");
    }

    return client;
}
```

### Why Hash Client Secrets?

Same reason as user passwords:
- **Security**: If database is compromised, secrets aren't exposed
- **Best practice**: Treat client secrets like passwords
- **Use BCrypt**: Same `PasswordEncoder` bean

### Client Authentication Methods

**Current approach**: client_id + client_secret in request body

**Alternative** (more secure): HTTP Basic Authentication
- Header: `Authorization: Basic base64(client_id:client_secret)`
- More standard for OAuth
- Consider implementing this instead/additionally

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3

---

## Step 5: Handle Authorization Code Grant

### In TokenController

```java
if ("authorization_code".equals(request.getGrantType())) {
    return handleAuthorizationCodeGrant(request);
}
```

### Implement Handler Method

**Steps**:
1. **Authenticate client**:
   ```java
   Client client = clientService.authenticateClient(request.getClientId(), request.getClientSecret());
   ```

2. **Validate and consume authorization code**:
   ```java
   AuthorizationCode authCode = authCodeService.validateAndConsume(
       request.getCode(),
       request.getClientId(),
       request.getRedirectUri()
   );
   ```

3. **Generate access token** (Guide 09):
   ```java
   String accessToken = tokenService.generateAccessToken(
       authCode.getUserId(),
       authCode.getClientId(),
       authCode.getScopes()
   );
   ```

4. **Generate refresh token** (Phase 3):
   ```java
   String refreshToken = tokenService.generateRefreshToken(
       authCode.getUserId(),
       authCode.getClientId()
   );
   ```

5. **Build response**:
   ```java
   TokenResponse response = TokenResponse.builder()
       .accessToken(accessToken)
       .tokenType("Bearer")
       .expiresIn(3600)  // 1 hour in seconds
       .refreshToken(refreshToken)  // Optional
       .scope(String.join(" ", authCode.getScopes()))
       .build();

   return ResponseEntity.ok(response);
   ```

---

## Step 6: Create Token Response DTO

### Create TokenResponse.java

Location: `src/main/java/com/learning/idp/dto/TokenResponse.java`

### Fields

According to OAuth 2.0 spec:

```java
@JsonProperty("access_token")
private String accessToken;  // Required

@JsonProperty("token_type")
private String tokenType;  // Required, always "Bearer"

@JsonProperty("expires_in")
private Integer expiresIn;  // Required, seconds until expiration

@JsonProperty("refresh_token")
private String refreshToken;  // Optional

@JsonProperty("scope")
private String scope;  // Optional, space-separated scopes

@JsonProperty("id_token")
private String idToken;  // For OpenID Connect (Phase 5)
```

*Why @JsonProperty?*: OAuth spec uses snake_case (access_token), Java uses camelCase (accessToken).

### Use Lombok @Builder

Makes it easy to construct responses:
```java
@Data
@Builder
public class TokenResponse { ... }
```

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

---

## Step 7: Configure Security for Token Endpoint

### Update SecurityConfig

The token endpoint should be:
- **Publicly accessible** (no session authentication)
- **Protected by client authentication** (in request parameters or headers)

```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/oauth2/token").permitAll()
        // ... other rules
    )
```

### Why permitAll?

Spring Security's session-based authentication doesn't apply here:
- No cookies involved
- Authentication is client credentials, not user session
- Client authentication happens in controller logic

---

## Step 8: Implement Error Handling

### Token Error Response

OAuth spec defines error format:

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

### Error Codes

| Error Code | When to Use |
|------------|-------------|
| **invalid_request** | Missing or malformed parameter |
| **invalid_client** | Client authentication failed |
| **invalid_grant** | Authorization code invalid/expired/used |
| **unauthorized_client** | Client not authorized for this grant type |
| **unsupported_grant_type** | Grant type not recognized |

### Exception Handler

```java
@ExceptionHandler(InvalidClientException.class)
public ResponseEntity<OAuth2ErrorResponse> handleInvalidClient(InvalidClientException ex) {
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(new OAuth2ErrorResponse("invalid_client", ex.getMessage()));
}
```

**Security note**: Don't reveal whether client_id exists or if secret is wrong - always return generic "Invalid client credentials".

---

## Step 9: Test the Token Endpoint

### Using Postman or cURL

#### 1. Obtain Authorization Code
Complete the authorization flow (login + consent) to get a code.

#### 2. Exchange Code for Tokens

**Request**:
```
POST http://localhost:8080/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=YOUR_AUTHORIZATION_CODE&
redirect_uri=http://localhost:3000/callback&
client_id=demo-client&
client_secret=demo-secret
```

**Expected Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "openid profile email"
}
```

### Test Cases

#### Invalid Authorization Code
**Test**: Use random code
**Expected**: 400 Bad Request, `error: "invalid_grant"`

#### Expired Authorization Code
**Test**: Use code after expiration
**Expected**: 400 Bad Request, `error: "invalid_grant"`

#### Wrong Client Secret
**Test**: Use incorrect client_secret
**Expected**: 401 Unauthorized, `error: "invalid_client"`

#### Mismatched Redirect URI
**Test**: Use different redirect_uri than authorization request
**Expected**: 400 Bad Request, `error: "invalid_grant"`

#### Code Replay
**Test**: Use same code twice
**Expected**: Second attempt fails with `invalid_grant`

---

## Understanding Token Endpoint Security

### Threat Model

**Attacks**:
1. **Stolen authorization code**: Attacker intercepts code from redirect
2. **Client impersonation**: Attacker uses code with wrong client credentials
3. **Code injection**: Attacker tricks client into using attacker's code

### Mitigations

| Threat | Mitigation |
|--------|-----------|
| Stolen code | Client authentication + PKCE (Phase 3) |
| Client impersonation | Client secret validation |
| Code injection | State parameter + redirect_uri validation |
| Replay attacks | One-time use check |

### Why Client Authentication Matters

Without client authentication:
- Attacker who intercepts code can use it
- Public clients (mobile/SPA) can't securely store secrets
- **Solution**: PKCE (Phase 3) provides security for public clients

---

## Step 10: Implement Token Storage (Optional)

### Should You Store Access Tokens?

**Arguments for storing**:
- Enable token revocation
- Track token usage for analytics
- Enforce token limits per user/client

**Arguments against**:
- JWTs are self-contained (don't need database lookup)
- Database becomes bottleneck
- Increases database size

**Recommendation**:
- **Store refresh tokens** (always) - needed for revocation
- **Don't store access tokens** (for learning project) - use stateless JWTs
- **Production**: Depends on requirements (revocation vs performance)

If you do store tokens, use the `access_tokens` table from Guide 04.

---

## What You've Accomplished

✅ Built OAuth 2.0 token endpoint
✅ Implemented client authentication
✅ Created authorization code exchange flow
✅ Formatted token responses per OAuth spec
✅ Added comprehensive error handling
✅ Tested complete authorization code flow

---

## Next Steps

**Proceed to Guide 09**: JWT Token Generation

Before moving on:
- [ ] Token endpoint accepts POST requests
- [ ] Client authentication works
- [ ] Authorization codes are validated and consumed
- [ ] Token responses are properly formatted
- [ ] Errors return OAuth-compliant error responses
- [ ] Complete flow works: authorize → consent → code → token

---

## Key Concepts Learned

### Front Channel vs Back Channel
- Front channel: Browser redirects (less secure)
- Back channel: Server-to-server (more secure)
- Authorization codes bridge the two channels

### Client Authentication
- Confidential clients use client_secret
- Public clients can't securely store secrets
- Secrets should be hashed like passwords

### OAuth Error Handling
- Standard error codes defined by spec
- Consistent error format
- Security: Don't reveal sensitive information in errors

### Grant Types
- authorization_code: Exchange code for tokens
- refresh_token: Refresh access tokens (Phase 3)
- client_credentials: Server-to-server (Phase 3)

---

## Additional Resources

- **Token Endpoint**: https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
- **Token Request**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
- **Token Response**: https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
- **Client Authentication**: https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
- **Spring @ModelAttribute**: https://www.baeldung.com/spring-mvc-annotations#modelattribute
