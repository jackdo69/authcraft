# Guide 22: UserInfo Endpoint

**Phase 5: OpenID Connect** | **Week 9-10** | **Task 22 of 30**

## Overview

Implement the UserInfo endpoint to provide user profile information based on the access token and granted scopes.

---

## What You'll Build

- UserInfo endpoint (/oauth2/userinfo)
- Bearer token authentication
- Scope-based claim filtering
- UserInfo response formatting

---

## Step 1: Create UserInfo Controller

```java
@RestController
@RequestMapping("/oauth2/userinfo")
public class UserInfoController {
    
    @GetMapping
    public ResponseEntity<Map<String, Object>> getUserInfo(
            @RequestHeader("Authorization") String authorization) {
        
        // Extract token
        String token = authorization.replace("Bearer ", "");
        
        // Validate and extract claims
        Claims claims = jwtTokenProvider.validateToken(token);
        
        // Get user
        Long userId = Long.parseLong(claims.getSubject());
        User user = userService.findById(userId);
        
        // Get scopes from token
        String scopeString = claims.get("scope", String.class);
        Set<String> scopes = Set.of(scopeString.split("\\s+"));
        
        // Build response based on scopes
        Map<String, Object> userInfo = buildUserInfo(user, scopes);
        
        return ResponseEntity.ok(userInfo);
    }
    
    @PostMapping
    public ResponseEntity<Map<String, Object>> getUserInfoPost(
            @RequestHeader("Authorization") String authorization) {
        return getUserInfo(authorization);
    }
}
```

---

## Step 2: Filter Claims by Scope

```java
private Map<String, Object> buildUserInfo(User user, Set<String> scopes) {
    Map<String, Object> userInfo = new HashMap<>();
    
    // Always include sub
    userInfo.put("sub", user.getId().toString());
    
    // Profile scope
    if (scopes.contains("profile")) {
        userInfo.put("name", user.getFullName());
        userInfo.put("given_name", user.getFirstName());
        userInfo.put("family_name", user.getLastName());
        userInfo.put("picture", user.getProfilePictureUrl());
        userInfo.put("updated_at", user.getUpdatedAt().getEpochSecond());
    }
    
    // Email scope
    if (scopes.contains("email")) {
        userInfo.put("email", user.getEmail());
        userInfo.put("email_verified", user.isEmailVerified());
    }
    
    // Address scope
    if (scopes.contains("address")) {
        userInfo.put("address", buildAddressClaim(user));
    }
    
    // Phone scope
    if (scopes.contains("phone")) {
        userInfo.put("phone_number", user.getPhoneNumber());
        userInfo.put("phone_number_verified", user.isPhoneVerified());
    }
    
    return userInfo;
}

private Map<String, String> buildAddressClaim(User user) {
    Map<String, String> address = new HashMap<>();
    address.put("formatted", user.getFormattedAddress());
    address.put("street_address", user.getStreetAddress());
    address.put("locality", user.getCity());
    address.put("region", user.getState());
    address.put("postal_code", user.getPostalCode());
    address.put("country", user.getCountry());
    return address;
}
```

---

## Step 3: Error Handling

```java
@ExceptionHandler(JwtException.class)
public ResponseEntity<OAuth2ErrorResponse> handleInvalidToken(JwtException ex) {
    return ResponseEntity
        .status(401)
        .body(new OAuth2ErrorResponse("invalid_token", "The access token is invalid or expired"));
}

@ExceptionHandler(InsufficientScopeException.class)
public ResponseEntity<OAuth2ErrorResponse> handleInsufficientScope(InsufficientScopeException ex) {
    return ResponseEntity
        .status(403)
        .body(new OAuth2ErrorResponse("insufficient_scope", "Token lacks required scope"));
}
```

---

## Step 4: Testing

Request with access token:
```
GET /oauth2/userinfo
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Response:
```json
{
  "sub": "12345",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john@example.com",
  "email_verified": true
}
```

---

## Key Concepts

- **UserInfo Endpoint**: Returns user claims
- **Bearer Token**: Access token in Authorization header
- **Scope Filtering**: Only return claims for granted scopes
- **Standard Claims**: Defined by OIDC specification

---

## Resources

- **UserInfo Endpoint Spec**: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
- **Standard Claims**: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
