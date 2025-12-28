# Guide 25: Claims Mapping

**Phase 5: OpenID Connect** | **Week 9-10** | **Task 25 of 30**

## Overview

Implement flexible claims mapping to transform user attributes into standard and custom JWT claims based on granted scopes.

---

## What You'll Build

- Claims mapper service
- Scope-to-claims mappings
- Custom claim transformations
- Claim request support

---

## Step 1: Create Claims Mapper

```java
@Service
public class ClaimsMapperService {
    
    private static final Map<String, Set<String>> SCOPE_TO_CLAIMS = Map.of(
        "profile", Set.of("name", "given_name", "family_name", "middle_name", "picture", "updated_at"),
        "email", Set.of("email", "email_verified"),
        "address", Set.of("address"),
        "phone", Set.of("phone_number", "phone_number_verified")
    );
    
    public Map<String, Object> mapClaims(User user, Set<String> scopes) {
        Map<String, Object> claims = new HashMap<>();
        
        // Get all claims for granted scopes
        Set<String> allowedClaims = scopes.stream()
            .filter(SCOPE_TO_CLAIMS::containsKey)
            .flatMap(scope -> SCOPE_TO_CLAIMS.get(scope).stream())
            .collect(Collectors.toSet());
        
        // Map user fields to claims
        if (allowedClaims.contains("name")) {
            claims.put("name", user.getFullName());
        }
        if (allowedClaims.contains("given_name")) {
            claims.put("given_name", user.getFirstName());
        }
        // ... other claims ...
        
        return claims;
    }
}
```

---

## Step 2: Support Claims Parameter

Optional claims request:
```java
@Data
public class AuthorizationRequest {
    private String claims;  // JSON: {"userinfo": {"email": null}, "id_token": {"name": null}}
}
```

Parse and filter:
```java
public Set<String> parseClaimsRequest(String claimsJson) {
    // Parse JSON and extract requested claims
    // Return set of claim names
}
```

---

## Key Concepts

- **Standard Claims**: Defined by OIDC spec
- **Custom Claims**: Application-specific attributes
- **Scope Mapping**: Which scopes grant which claims
- **Claims Request**: Explicit claim requests via parameter

---

## Resources

- **OIDC Claims**: https://openid.net/specs/openid-connect-core-1_0.html#Claims
