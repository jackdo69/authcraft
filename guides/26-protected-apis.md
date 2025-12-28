# Guide 26: Build Protected API Endpoints

**Phase 6: Resource Server** | **Week 11-12** | **Task 26 of 30**

## Overview

Create a separate resource server application with protected API endpoints that validate OAuth access tokens.

---

## What You'll Build

- Resource server Spring Boot application
- Protected REST API endpoints
- JWT token validation
- User context extraction

---

## Step 1: Create Resource Server Project

Use Spring Initializr:
- Dependencies: Spring Web, OAuth2 Resource Server, Spring Security
- Group: com.learning
- Artifact: resource-server
- Port: 8081

---

## Step 2: Configure OAuth2 Resource Server

application.yml:
```yaml
server:
  port: 8081

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080
          jwk-set-uri: http://localhost:8080/oauth2/jwks
```

---

## Step 3: Create Protected Endpoints

```java
@RestController
@RequestMapping("/api")
public class UserApiController {
    
    @GetMapping("/profile")
    public ResponseEntity<UserProfile> getProfile(@AuthenticationPrincipal Jwt jwt) {
        
        Long userId = Long.parseLong(jwt.getSubject());
        String email = jwt.getClaimAsString("email");
        
        UserProfile profile = UserProfile.builder()
            .userId(userId)
            .email(email)
            .name(jwt.getClaimAsString("name"))
            .build();
        
        return ResponseEntity.ok(profile);
    }
    
    @GetMapping("/data")
    public ResponseEntity<List<String>> getData() {
        return ResponseEntity.ok(List.of("data1", "data2", "data3"));
    }
}
```

---

## Step 4: Security Configuration

```java
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );
        
        return http.build();
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = 
            new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("SCOPE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("scope");
        
        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return jwtConverter;
    }
}
```

---

## Step 5: Testing

Get access token from IdP, then call resource server:
```
GET http://localhost:8081/api/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## Key Concepts

- **Resource Server**: API protected by OAuth tokens
- **JWT Validation**: Verify signature, expiration, issuer
- **Authentication Principal**: Extract user from JWT
- **Stateless**: No session, token contains all info

---

## Resources

- **Spring Security Resource Server**: https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/
