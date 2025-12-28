# OAuth 2.0 Identity Provider - Learning Project

## Project Overview

Build a complete OAuth 2.0/OpenID Connect Identity Provider system locally to master authentication and authorization concepts using industry-standard Java technologies.

---

## Project Structure

```
oauth-learning-project/
│
├── identity-provider/          # Authorization Server (Port 8080)
│   ├── src/main/java/
│   │   └── com/learning/idp/
│   │       ├── config/
│   │       │   ├── SecurityConfig.java
│   │       │   ├── AuthorizationServerConfig.java
│   │       │   └── RedisConfig.java
│   │       ├── controller/
│   │       │   ├── AuthorizationController.java
│   │       │   ├── TokenController.java
│   │       │   ├── UserController.java
│   │       │   └── ConsentController.java
│   │       ├── service/
│   │       │   ├── UserService.java
│   │       │   ├── ClientService.java
│   │       │   ├── TokenService.java
│   │       │   └── AuthorizationCodeService.java
│   │       ├── repository/
│   │       │   ├── UserRepository.java
│   │       │   ├── ClientRepository.java
│   │       │   └── TokenRepository.java
│   │       ├── model/
│   │       │   ├── User.java
│   │       │   ├── Client.java
│   │       │   ├── AuthorizationCode.java
│   │       │   ├── AccessToken.java
│   │       │   └── RefreshToken.java
│   │       ├── security/
│   │       │   ├── JwtTokenProvider.java
│   │       │   ├── PKCEValidator.java
│   │       │   └── PasswordEncoder.java
│   │       └── IdpApplication.java
│   ├── src/main/resources/
│   │   ├── application.yml
│   │   ├── schema.sql
│   │   └── templates/
│   │       ├── login.html
│   │       └── consent.html
│   └── pom.xml
│
├── resource-server/             # Protected API (Port 8081)
│   ├── src/main/java/
│   │   └── com/learning/api/
│   │       ├── config/
│   │       │   └── ResourceServerConfig.java
│   │       ├── controller/
│   │       │   ├── UserApiController.java
│   │       │   └── ProtectedResourceController.java
│   │       ├── security/
│   │       │   ├── JwtTokenValidator.java
│   │       │   └── ScopeValidator.java
│   │       └── ApiApplication.java
│   ├── src/main/resources/
│   │   └── application.yml
│   └── pom.xml
│
├── client-app/                  # OAuth Client (Port 3000)
│   ├── src/main/java/
│   │   └── com/learning/client/
│   │       ├── config/
│   │       │   └── OAuth2ClientConfig.java
│   │       ├── controller/
│   │       │   ├── HomeController.java
│   │       │   ├── CallbackController.java
│   │       │   └── DashboardController.java
│   │       ├── service/
│   │       │   └── OAuth2ClientService.java
│   │       └── ClientApplication.java
│   ├── src/main/resources/
│   │   ├── application.yml
│   │   └── templates/
│   │       ├── index.html
│   │       ├── callback.html
│   │       └── dashboard.html
│   └── pom.xml
│
├── docker-compose.yml           # PostgreSQL + Redis
└── README.md
```

---

## Core Concepts You'll Learn

### 1. OAuth 2.0 Flows

#### Authorization Code Flow (Most Important)
- User authentication and login
- Authorization request handling
- Authorization code generation and validation
- Code exchange for tokens
- Redirect URI validation
- State parameter (CSRF protection)
- **Use case**: Web applications with backend

#### Authorization Code Flow with PKCE
- Code Challenge and Code Verifier generation
- SHA-256 hashing
- Protection against authorization code interception
- **Use case**: Mobile apps, SPAs, public clients

#### Client Credentials Flow
- Machine-to-machine authentication
- No user involvement
- Service accounts
- **Use case**: Backend services calling APIs

#### Refresh Token Flow
- Access token renewal without user interaction
- Refresh token rotation
- Token family tracking
- Refresh token revocation
- **Use case**: Long-lived sessions

### 2. Token Management

#### JWT (JSON Web Tokens)
- Token structure (Header, Payload, Signature)
- Claims (standard and custom)
- Token signing (HMAC, RSA)
- Token validation and verification
- Token expiration handling
- JWS (JSON Web Signature)
- JWK (JSON Web Key)

#### Access Tokens
- Short-lived credentials
- Bearer token usage
- Token introspection
- Token format (JWT vs opaque)

#### Refresh Tokens
- Long-lived credentials
- Refresh token rotation strategies
- Token family binding
- Revocation mechanisms

#### ID Tokens (OpenID Connect)
- User identity information
- Claims about authentication event
- Nonce validation
- ID token validation rules

### 3. Security Concepts

#### PKCE (Proof Key for Code Exchange)
- Code challenge generation
- Code verifier validation
- Protection against authorization code interception attacks
- S256 vs plain methods

#### CSRF Protection
- State parameter generation
- State validation
- Session binding

#### Client Authentication
- client_id and client_secret
- Client credential storage
- Public vs confidential clients
- Client authentication methods (POST, Basic Auth)

#### Password Security
- BCrypt hashing
- Salt generation
- Password policies
- Credential storage best practices

#### Token Security
- Token binding
- Token theft prevention
- Secure token storage
- Token revocation

### 4. Scopes and Permissions

#### Scopes
- Scope definition and registration
- Scope-based access control
- Standard scopes (openid, profile, email)
- Custom application scopes
- Scope consent

#### Claims
- Standard OpenID Connect claims
- Custom claims
- Claim mapping
- User info endpoint

#### Authorization
- Role-based access control (RBAC)
- Permission management
- Resource-level authorization
- Scope enforcement

### 5. Session Management

#### User Sessions
- Session creation and validation
- Session storage (Redis)
- Session timeout
- Remember-me functionality
- Single Sign-On (SSO) concepts

#### OAuth Sessions
- Authorization session tracking
- Consent persistence
- Session fixation prevention

### 6. Client Management

#### Client Registration
- Dynamic client registration
- Client metadata (redirect URIs, grant types, scopes)
- Client types (confidential, public)
- Client authentication methods

#### Redirect URI Validation
- Exact match validation
- URI component validation
- Security considerations
- Localhost handling

### 7. User Management

#### Authentication
- Username/password authentication
- Multi-factor authentication concepts
- Account lockout policies
- Password reset flow

#### User Consent
- Consent screen implementation
- Scope consent tracking
- Consent revocation
- Pre-approved clients

### 8. OpenID Connect (OIDC)

#### Discovery
- Well-known endpoints (.well-known/openid-configuration)
- Metadata publication
- JWKS endpoint

#### UserInfo Endpoint
- User profile data exposure
- Claim filtering by scope
- Bearer token authentication

#### ID Token
- Token structure and validation
- Authentication claims
- Nonce parameter

### 9. Error Handling

#### OAuth Error Responses
- Standard error codes
- Error descriptions
- Error URI
- Proper HTTP status codes

#### Security Error Handling
- Invalid client handling
- Invalid grant errors
- Unauthorized client errors
- Rate limiting

### 10. Database Design

#### Schema Design
- Users table
- Clients table
- Authorization codes table
- Access tokens table
- Refresh tokens table
- User consents table
- Scopes table

#### Token Storage
- Token indexing strategies
- Expiration cleanup
- Token revocation lists

---

## Technology Stack (Industry Standard)

### Identity Provider Server

#### Framework
- **Spring Boot 3.2+** - Application framework
- **Spring Security 6.2+** - Security framework
- **Spring Authorization Server 1.2+** - OAuth 2.0/OIDC implementation

#### Security
- **Spring Security OAuth2** - OAuth 2.0 support
- **JJWT (io.jsonwebtoken)** - JWT creation and validation
- **BCrypt** - Password hashing (via Spring Security)

#### Database
- **Spring Data JPA** - ORM framework
- **Hibernate** - JPA implementation
- **PostgreSQL Driver** - Database connectivity
- **Flyway/Liquibase** - Database migrations

#### Caching/Session
- **Spring Data Redis** - Redis integration
- **Lettuce** - Redis client (default in Spring Boot)

#### Validation
- **Hibernate Validator** - Bean validation
- **Jakarta Validation API** - Validation annotations

#### Template Engine
- **Thymeleaf** - Server-side rendering for login/consent pages

#### Utilities
- **Lombok** - Reduce boilerplate code
- **MapStruct** - DTO mapping
- **Apache Commons Codec** - PKCE encoding

### Resource Server

#### Framework
- **Spring Boot 3.2+**
- **Spring Security 6.2+**
- **Spring Web** - REST API

#### Security
- **Spring Security OAuth2 Resource Server** - Token validation
- **JJWT** - JWT parsing

### Client Application

#### Framework
- **Spring Boot 3.2+**
- **Spring Web** - MVC
- **Thymeleaf** - Frontend templates

#### OAuth Client
- **Spring Security OAuth2 Client** - OAuth 2.0 client support
- **WebClient** - HTTP client for API calls

### Infrastructure

#### Database
- **PostgreSQL 15+** - Primary database
- **Docker** - Container for PostgreSQL

#### Cache/Session Store
- **Redis 7+** - Session storage, token caching
- **Docker** - Container for Redis

#### Build Tool
- **Maven 3.9+** - Dependency management and build

#### Development Tools
- **Spring Boot DevTools** - Hot reload
- **H2 Database** - Optional in-memory DB for quick testing

---

## Learning Path (Recommended Order)

### Phase 1: Foundation (Week 1-2)
1. Set up project structure
2. Configure PostgreSQL and Redis with Docker
3. Implement user registration and login (basic Spring Security)
4. Create user database schema
5. Password hashing and validation

### Phase 2: Basic OAuth (Week 3-4)
6. Implement authorization endpoint
7. Generate and validate authorization codes
8. Build token endpoint
9. JWT token generation
10. Create a simple client app to test

### Phase 3: Enhanced Security (Week 5-6)
11. Add PKCE support
12. Implement state parameter validation
13. Add refresh token flow
14. Token revocation endpoint
15. Client credentials flow

### Phase 4: User Experience (Week 7-8)
16. Build consent screen
17. Scope management
18. Session management with Redis
19. Remember-me functionality
20. Error handling and user feedback

### Phase 5: OpenID Connect (Week 9-10)
21. Add ID token support
22. UserInfo endpoint
23. Discovery endpoint (.well-known)
24. JWKS endpoint
25. Claims mapping

### Phase 6: Resource Server (Week 11-12)
26. Build protected API endpoints
27. Implement token validation
28. Scope-based authorization
29. API rate limiting
30. Introspection endpoint

---

## Docker Compose Setup

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: oauth-postgres
    environment:
      POSTGRES_DB: oauth_idp
      POSTGRES_USER: oauth_user
      POSTGRES_PASSWORD: oauth_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - oauth-network

  redis:
    image: redis:7-alpine
    container_name: oauth-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - oauth-network

volumes:
  postgres_data:
  redis_data:

networks:
  oauth-network:
    driver: bridge
```

---

## Key Dependencies (Maven)

### Identity Provider - pom.xml

```xml
<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>

    <!-- Spring Authorization Server -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-oauth2-authorization-server</artifactId>
        <version>1.2.0</version>
    </dependency>

    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.3</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.3</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.3</version>
        <scope>runtime</scope>
    </dependency>

    <!-- Database -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
        <scope>runtime</scope>
    </dependency>

    <!-- Redis -->
    <dependency>
        <groupId>io.lettuce</groupId>
        <artifactId>lettuce-core</artifactId>
    </dependency>

    <!-- Utilities -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    <dependency>
        <groupId>commons-codec</groupId>
        <artifactId>commons-codec</artifactId>
    </dependency>

    <!-- Development -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-devtools</artifactId>
        <scope>runtime</scope>
        <optional>true</optional>
    </dependency>

    <!-- Testing -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

---

## Application Configuration Examples

### Identity Provider - application.yml

```yaml
spring:
  application:
    name: identity-provider
  
  datasource:
    url: jdbc:postgresql://localhost:5432/oauth_idp
    username: oauth_user
    password: oauth_password
    driver-class-name: org.postgresql.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.PostgreSQLDialect
  
  data:
    redis:
      host: localhost
      port: 6379
      timeout: 60000ms
  
  session:
    store-type: redis
    timeout: 1800s

server:
  port: 8080

# JWT Configuration
jwt:
  secret: your-256-bit-secret-key-change-this-in-production
  expiration: 3600000  # 1 hour in milliseconds
  refresh-expiration: 86400000  # 24 hours

# OAuth Configuration
oauth:
  authorization-code-expiration: 600000  # 10 minutes
  pkce-required: true
```

### Resource Server - application.yml

```yaml
spring:
  application:
    name: resource-server
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080
          jwk-set-uri: http://localhost:8080/oauth2/jwks

server:
  port: 8081
```

### Client App - application.yml

```yaml
spring:
  application:
    name: client-app
  
  security:
    oauth2:
      client:
        registration:
          custom-client:
            client-id: demo-client
            client-secret: demo-secret
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:3000/callback
            scope: openid,profile,email
        provider:
          custom-client:
            authorization-uri: http://localhost:8080/oauth2/authorize
            token-uri: http://localhost:8080/oauth2/token
            user-info-uri: http://localhost:8080/oauth2/userinfo
            jwk-set-uri: http://localhost:8080/oauth2/jwks

server:
  port: 3000
```

---

## Testing Checklist

### Authorization Code Flow
- [ ] User can login
- [ ] Authorization code is generated
- [ ] Redirect to client with code
- [ ] Client exchanges code for token
- [ ] Access token works for API calls

### PKCE Flow
- [ ] Code challenge generation
- [ ] Code verifier validation
- [ ] Invalid verifier rejected

### Token Management
- [ ] JWT tokens are properly signed
- [ ] Token expiration is enforced
- [ ] Refresh token rotation works
- [ ] Token revocation works

### Security
- [ ] State parameter prevents CSRF
- [ ] Invalid redirect URIs rejected
- [ ] Expired codes rejected
- [ ] Invalid client credentials rejected

### Scopes
- [ ] Scope consent screen appears
- [ ] Token limited to requested scopes
- [ ] Resource server validates scopes

---

## Learning Resources

### Documentation
- [Spring Authorization Server Reference](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

### Books
- "OAuth 2.0 in Action" by Justin Richer and Antonio Sanso
- "OAuth 2.0 Simplified" by Aaron Parecki

### Online Resources
- [OAuth.net](https://oauth.net/)
- [JWT.io](https://jwt.io/)
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/)

---

## Success Criteria

By the end of this project, you should be able to:

✅ Explain OAuth 2.0 flows in detail  
✅ Implement secure authorization code flow with PKCE  
✅ Generate and validate JWT tokens  
✅ Design database schemas for OAuth systems  
✅ Implement session management with Redis  
✅ Build consent and authorization screens  
✅ Secure APIs with token validation  
✅ Handle token refresh and revocation  
✅ Understand OpenID Connect basics  
✅ Debug OAuth flows using browser tools  

---

## Next Steps After Completion

1. **Add MFA (Multi-Factor Authentication)**
2. **Implement Social Login** (Google, GitHub OAuth)
3. **Add Rate Limiting** and DDoS protection
4. **Deploy with Docker** and test with HTTPS (using mkcert)
5. **Implement Token Introspection** endpoint
6. **Add Audit Logging** for all authentication events
7. **Study production IdPs**: Keycloak, Auth0, Okta implementations
8. **Explore Federation**: SAML integration
9. **Add Device Flow**: For IoT/TV applications
10. **Performance Testing**: Load test with JMeter

---

## Project Timeline

**Estimated completion time: 10-12 weeks** (part-time, 10-15 hours/week)

This is an ambitious but achievable project that will make you very competent in OAuth 2.0, Spring Security, and modern Java development practices.

Good luck with your learning journey! 🚀
