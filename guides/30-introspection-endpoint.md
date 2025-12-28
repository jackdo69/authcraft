# Guide 30: Introspection Endpoint

**Phase 6: Resource Server** | **Week 11-12** | **Task 30 of 30**

## Overview

Implement the token introspection endpoint for resource servers to validate opaque tokens and retrieve token metadata.

---

## What You'll Build

- Token introspection endpoint (/oauth2/introspect)
- Opaque token validation
- Token metadata response
- Client authentication

---

## Step 1: Create Introspection Endpoint

```java
@RestController
@RequestMapping("/oauth2")
public class IntrospectionController {
    
    @PostMapping(value = "/introspect",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<IntrospectionResponse> introspect(
            @RequestParam String token,
            @RequestParam(required = false) String token_type_hint,
            @RequestHeader("Authorization") String authorization) {
        
        // Authenticate resource server
        String[] credentials = extractBasicAuth(authorization);
        Client client = clientService.authenticateClient(credentials[0], credentials[1]);
        
        // Introspect token
        IntrospectionResponse response = introspectToken(token, token_type_hint);
        
        return ResponseEntity.ok(response);
    }
    
    private IntrospectionResponse introspectToken(String token, String hint) {
        
        // Try as refresh token first if hinted
        if ("refresh_token".equals(hint)) {
            RefreshToken refreshToken = refreshTokenRepository.findByToken(token).orElse(null);
            if (refreshToken != null && !refreshToken.isRevoked()) {
                return buildActiveResponse(refreshToken);
            }
        }
        
        // Try as JWT access token
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (jwt.getExpiresAt().isAfter(Instant.now())) {
                return buildActiveResponse(jwt);
            }
        } catch (JwtException e) {
            // Not a valid JWT
        }
        
        // Token not found or invalid
        return IntrospectionResponse.inactive();
    }
    
    private IntrospectionResponse buildActiveResponse(RefreshToken refreshToken) {
        return IntrospectionResponse.builder()
            .active(true)
            .scope(refreshToken.getScopes())
            .clientId(refreshToken.getClientId())
            .username(getUsernameForId(refreshToken.getUserId()))
            .tokenType("refresh_token")
            .exp(refreshToken.getExpiresAt().getEpochSecond())
            .iat(refreshToken.getCreatedAt().getEpochSecond())
            .build();
    }
    
    private IntrospectionResponse buildActiveResponse(Jwt jwt) {
        return IntrospectionResponse.builder()
            .active(true)
            .scope(jwt.getClaimAsString("scope"))
            .clientId(jwt.getClaimAsString("client_id"))
            .username(jwt.getClaimAsString("username"))
            .tokenType("Bearer")
            .exp(jwt.getExpiresAt().getEpochSecond())
            .iat(jwt.getIssuedAt().getEpochSecond())
            .sub(jwt.getSubject())
            .aud(jwt.getAudience())
            .iss(jwt.getIssuer().toString())
            .jti(jwt.getId())
            .build();
    }
}
```

---

## Step 2: Introspection Response DTO

```java
@Data
@Builder
public class IntrospectionResponse {
    private boolean active;
    private String scope;
    private String clientId;
    private String username;
    private String tokenType;
    private Long exp;
    private Long iat;
    private String sub;
    private List<String> aud;
    private String iss;
    private String jti;
    
    public static IntrospectionResponse inactive() {
        return IntrospectionResponse.builder()
            .active(false)
            .build();
    }
}
```

---

## Step 3: Resource Server Usage

Configure resource server to use introspection:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: http://localhost:8080/oauth2/introspect
          client-id: resource-server
          client-secret: resource-secret
```

---

## Key Concepts

- **Introspection**: Validate opaque tokens
- **Metadata**: Return token information
- **Client Auth**: Protect introspection endpoint
- **Active Field**: Boolean indicating validity

---

## Resources

- **RFC 7662**: https://datatracker.ietf.org/doc/html/rfc7662
- **Spring Introspection**: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/opaque-token.html

**Congratulations! Core OAuth/OIDC implementation complete!** 🎉
