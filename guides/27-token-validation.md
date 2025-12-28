# Guide 27: Implement Token Validation

**Phase 6: Resource Server** | **Week 11-12** | **Task 27 of 30**

## Overview

Implement comprehensive JWT token validation including signature verification, expiration checks, and custom validation logic.

---

## What You'll Build

- Custom JWT validator
- Audience validation
- Issuer validation
- Claim validation
- Token deny list support

---

## Step 1: Custom JWT Validator

```java
@Component
public class CustomJwtValidator implements OAuth2TokenValidator<Jwt> {
    
    private final String expectedIssuer = "http://localhost:8080";
    private final String expectedAudience = "resource-server";
    
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<OAuth2Error> errors = new ArrayList<>();
        
        // Validate issuer
        if (!expectedIssuer.equals(jwt.getIssuer().toString())) {
            errors.add(new OAuth2Error("invalid_token", "Invalid issuer", null));
        }
        
        // Validate audience
        List<String> audiences = jwt.getAudience();
        if (!audiences.contains(expectedAudience)) {
            errors.add(new OAuth2Error("invalid_token", "Invalid audience", null));
        }
        
        // Validate token not on deny list
        if (isTokenDenied(jwt.getId())) {
            errors.add(new OAuth2Error("invalid_token", "Token revoked", null));
        }
        
        return errors.isEmpty() 
            ? OAuth2TokenValidatorResult.success()
            : OAuth2TokenValidatorResult.failure(errors);
    }
    
    private boolean isTokenDenied(String jti) {
        // Check Redis deny list
        return tokenDenyListRepository.existsById(jti);
    }
}
```

---

## Step 2: Configure Custom Validator

```java
@Bean
public JwtDecoder jwtDecoder() {
    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder
        .withJwkSetUri(jwkSetUri)
        .build();
    
    OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuerUri);
    OAuth2TokenValidator<Jwt> customValidator = new CustomJwtValidator();
    OAuth2TokenValidator<Jwt> combined = new DelegatingOAuth2TokenValidator<>(
        defaultValidators, customValidator
    );
    
    jwtDecoder.setJwtValidator(combined);
    
    return jwtDecoder;
}
```

---

## Step 3: Handle Validation Errors

```java
@ExceptionHandler(JwtException.class)
public ResponseEntity<ErrorResponse> handleJwtException(JwtException ex) {
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(new ErrorResponse("invalid_token", ex.getMessage()));
}
```

---

## Key Concepts

- **Signature Validation**: Verify JWT not tampered
- **Expiration**: Reject expired tokens
- **Issuer**: Ensure from trusted IdP
- **Audience**: Token intended for this resource server

---

## Resources

- **JWT Validation**: https://datatracker.ietf.org/doc/html/rfc7519#section-7.2
- **Spring JWT Decoder**: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
