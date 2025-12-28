# Guide 21: Add ID Token Support

**Phase 5: OpenID Connect** | **Week 9-10** | **Task 21 of 30**

## Overview

Implement ID tokens for OpenID Connect, providing authentication information about the user separate from the access token used for API authorization.

---

## What You'll Build

- ID token generation with OIDC claims
- Nonce parameter support
- auth_time tracking
- ID token validation
- Integration with token endpoint

---

## Step 1: Understand ID Tokens

**ID Token** = JWT containing authentication claims
**Purpose**: Prove user identity to client
**vs Access Token**: ID token for identity, access token for authorization

Standard claims:
- `sub`: Subject (user ID)
- `iss`: Issuer (your IdP URL)
- `aud`: Audience (client_id)
- `exp`: Expiration
- `iat`: Issued at
- `auth_time`: When user authenticated
- `nonce`: Client-provided value for replay protection

---

## Step 2: Track Authentication Time

Add to User session:
```java
@Service
public class AuthenticationService {
    
    public void recordAuthenticationTime(HttpSession session) {
        session.setAttribute("auth_time", Instant.now().getEpochSecond());
    }
    
    public Long getAuthenticationTime(HttpSession session) {
        return (Long) session.getAttribute("auth_time");
    }
}
```

---

## Step 3: Generate ID Tokens

```java
public String generateIdToken(Long userId, String clientId, String nonce, Long authTime) {
    User user = userRepository.findById(userId).orElseThrow();
    
    Date now = new Date();
    Date expiry = new Date(now.getTime() + 3600000); // 1 hour
    
    JwtBuilder builder = Jwts.builder()
        .setSubject(user.getId().toString())
        .setIssuer(jwtConfig.getIssuer())
        .setAudience(clientId)
        .setIssuedAt(now)
        .setExpiration(expiry)
        .claim("auth_time", authTime);
    
    if (nonce != null) {
        builder.claim("nonce", nonce);
    }
    
    // Add profile claims if 'profile' scope granted
    if (scopes.contains("profile")) {
        builder.claim("name", user.getFullName())
              .claim("given_name", user.getFirstName())
              .claim("family_name", user.getLastName())
              .claim("picture", user.getProfilePictureUrl());
    }
    
    // Add email claims if 'email' scope granted
    if (scopes.contains("email")) {
        builder.claim("email", user.getEmail())
              .claim("email_verified", user.isEmailVerified());
    }
    
    return builder.signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
}
```

---

## Step 4: Support Nonce Parameter

Update AuthorizationRequest:
```java
private String nonce;  // Optional, for ID token replay protection
```

Store with authorization code:
```java
@Column(name = "nonce", length = 255)
private String nonce;
```

Include in ID token during token issuance.

---

## Step 5: Return ID Token

Only when `openid` scope requested:

```java
if (scopes.contains("openid")) {
    String idToken = tokenService.generateIdToken(
        userId,
        clientId,
        authCode.getNonce(),
        authCode.getAuthTime()
    );
    
    response.setIdToken(idToken);
}
```

---

## Key Concepts

- **ID Token**: JWT proving user authentication
- **Nonce**: Prevents replay attacks on ID tokens
- **auth_time**: When user last authenticated
- **Standard Claims**: sub, iss, aud, exp, iat

---

## Resources

- **OIDC Core**: https://openid.net/specs/openid-connect-core-1_0.html
- **ID Token Spec**: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
