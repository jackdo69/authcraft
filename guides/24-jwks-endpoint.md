# Guide 24: JWKS Endpoint

**Phase 5: OpenID Connect** | **Week 9-10** | **Task 24 of 30**

## Overview

Implement the JSON Web Key Set (JWKS) endpoint to publish cryptographic public keys for JWT signature verification.

---

## What You'll Build

- JWKS endpoint (/oauth2/jwks)
- RSA key pair generation
- Public key publication
- Key rotation support

---

## Step 1: Generate RSA Key Pair

```java
@Configuration
public class JwksConfig {
    
    @Bean
    public KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
```

---

## Step 2: Create JWKS Endpoint

```java
@RestController
@RequestMapping("/oauth2")
public class JwksController {
    
    private final KeyPair keyPair;
    
    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> getJwks() {
        
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        
        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("kid", "key-1");  // Key ID
        jwk.put("n", Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray()));
        jwk.put("e", Base64.getUrlEncoder().encodeToString(publicKey.getPublicExponent().toByteArray()));
        
        Map<String, Object> response = new HashMap<>();
        response.put("keys", List.of(jwk));
        
        return ResponseEntity.ok(response);
    }
}
```

---

## Step 3: Sign JWTs with RSA

Update JwtTokenProvider to use RSA:
```java
public String generateToken(...) {
    return Jwts.builder()
        // ... claims ...
        .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
        .setHeaderParam("kid", "key-1")
        .compact();
}
```

---

## Key Concepts

- **JWKS**: JSON Web Key Set format
- **RSA**: Asymmetric encryption (public/private keys)
- **Key ID (kid)**: Identifies which key signed the JWT
- **Public Keys**: Safe to expose for verification

---

## Resources

- **JWKS Spec**: https://datatracker.ietf.org/doc/html/rfc7517
- **JWK**: https://www.rfc-editor.org/rfc/rfc7517.html
