# Guide 23: Discovery Endpoint (.well-known)

**Phase 5: OpenID Connect** | **Week 9-10** | **Task 23 of 30**

## Overview

Implement the OpenID Connect Discovery endpoint to publish metadata about your IdP, enabling automatic client configuration.

---

## What You'll Build

- /.well-known/openid-configuration endpoint
- IdP metadata document
- Public, unauthenticated access
- Dynamic metadata generation

---

## Step 1: Create Discovery Controller

```java
@RestController
@RequestMapping("/.well-known")
public class DiscoveryController {
    
    @Value("${server.url}")
    private String issuer;
    
    @GetMapping("/openid-configuration")
    public ResponseEntity<OidcProviderMetadata> getConfiguration() {
        
        OidcProviderMetadata metadata = OidcProviderMetadata.builder()
            .issuer(issuer)
            .authorizationEndpoint(issuer + "/oauth2/authorize")
            .tokenEndpoint(issuer + "/oauth2/token")
            .userinfoEndpoint(issuer + "/oauth2/userinfo")
            .jwksUri(issuer + "/oauth2/jwks")
            .revocationEndpoint(issuer + "/oauth2/revoke")
            .introspectionEndpoint(issuer + "/oauth2/introspect")
            .registrationEndpoint(issuer + "/oauth2/register")
            
            .scopesSupported(List.of("openid", "profile", "email", "address", "phone"))
            .responseTypesSupported(List.of("code"))
            .grantTypesSupported(List.of("authorization_code", "refresh_token", "client_credentials"))
            .subjectTypesSupported(List.of("public"))
            .idTokenSigningAlgValuesSupported(List.of("HS256", "RS256"))
            .tokenEndpointAuthMethodsSupported(List.of("client_secret_post", "client_secret_basic"))
            .claimsSupported(List.of("sub", "name", "email", "email_verified", "given_name", "family_name", "picture"))
            .codeChallengeMethodsSupported(List.of("S256", "plain"))
            
            .build();
        
        return ResponseEntity.ok(metadata);
    }
}
```

---

## Step 2: Security Configuration

Make endpoint public:
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/.well-known/**").permitAll()
    // ... other rules
)
```

---

## Step 3: Testing

```
GET https://localhost:8080/.well-known/openid-configuration
```

Response:
```json
{
  "issuer": "https://localhost:8080",
  "authorization_endpoint": "https://localhost:8080/oauth2/authorize",
  "token_endpoint": "https://localhost:8080/oauth2/token",
  "userinfo_endpoint": "https://localhost:8080/oauth2/userinfo",
  "jwks_uri": "https://localhost:8080/oauth2/jwks",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```

---

## Key Concepts

- **Discovery**: Auto-configuration for OAuth clients
- **Metadata**: Advertises IdP capabilities
- **Well-Known**: Standard URL path (/.well-known)
- **Public**: No authentication required

---

## Resources

- **OIDC Discovery**: https://openid.net/specs/openid-connect-discovery-1_0.html
