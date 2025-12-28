# Guide 17: Scope Management

**Phase 4: User Experience** | **Week 7-8** | **Task 17 of 30**

## Overview

Implement comprehensive scope management including scope registration, validation, hierarchical scopes, and scope-to-claim mapping for OpenID Connect.

---

## What You'll Build

- Scope CRUD operations
- Hierarchical scope relationships
- Dynamic scope validation
- Scope-to-claim mappings
- Administrative scope management API

---

## Step 1: Enhance Scope Entity

Add relationships and metadata:

```java
@Entity
@Table(name = "scopes")
public class Scope {
    @Id
    private String name;
    
    private String displayName;
    private String description;
    private String category;
    private boolean userConsentRequired;
    
    @Column(name = "parent_scope")
    private String parentScope;  // For hierarchical scopes
    
    @Column(name = "claims_mapping", length = 1000)
    private String claimsMapping;  // JSON: which claims this scope grants
    
    @Column(name = "is_default")
    private boolean isDefault;  // Automatically granted
    
    @Column(name = "is_sensitive")
    private boolean isSensitive;  // Requires extra verification
}
```

---

## Step 2: Implement Scope Hierarchy

Parent-child relationships for scopes:

```java
@Service
public class ScopeService {
    
    public Set<String> expandScopes(Set<String> requestedScopes) {
        Set<String> expanded = new HashSet<>(requestedScopes);
        
        for (String scope : requestedScopes) {
            // Add implied parent scopes
            addParentScopes(scope, expanded);
        }
        
        return expanded;
    }
    
    private void addParentScopes(String scope, Set<String> result) {
        Scope scopeEntity = scopeRepository.findById(scope).orElse(null);
        if (scopeEntity != null && scopeEntity.getParentScope() != null) {
            result.add(scopeEntity.getParentScope());
            addParentScopes(scopeEntity.getParentScope(), result);
        }
    }
}
```

Example: `email.write` implies `email.read`

---

## Step 3: Scope-to-Claim Mapping

Map OIDC scopes to JWT claims:

```java
public Map<String, Object> getClaimsForScopes(Set<String> scopes, User user) {
    Map<String, Object> claims = new HashMap<>();
    
    for (String scopeName : scopes) {
        Scope scope = scopeRepository.findById(scopeName).orElse(null);
        if (scope != null && scope.getClaimsMapping() != null) {
            Map<String, String> mapping = parseClaimsMapping(scope.getClaimsMapping());
            
            for (Map.Entry<String, String> entry : mapping.entrySet()) {
                String claim = entry.getKey();
                String userField = entry.getValue();
                claims.put(claim, getUserField(user, userField));
            }
        }
    }
    
    return claims;
}
```

Mapping configuration:
```json
{
  "profile": {
    "name": "fullName",
    "given_name": "firstName",
    "family_name": "lastName",
    "picture": "profilePictureUrl"
  },
  "email": {
    "email": "email",
    "email_verified": "emailVerified"
  }
}
```

---

## Key Concepts

- **Standard Scopes**: openid, profile, email, address, phone
- **Custom Scopes**: Application-specific permissions
- **Hierarchical**: Parent scopes imply children
- **Dynamic**: Runtime scope registration and validation

---

## Resources

- **OAuth Scopes**: https://www.oauth.com/oauth2-servers/scope/
- **OIDC Standard Claims**: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
