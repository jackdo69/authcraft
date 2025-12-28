# OAuth 2.0 Identity Provider - Learning Guides

Welcome to the comprehensive guide collection for building an OAuth 2.0 / OpenID Connect Identity Provider from scratch using Java and Spring Boot!

---

## 📚 How to Use These Guides

### Learning Approach
These guides are designed to be followed **sequentially**. Each guide builds on concepts from previous ones, gradually increasing in complexity.

### Philosophy
- **Guidelines over code**: These guides explain WHAT to build and WHY, not exact code implementations
- **Hands-on learning**: You'll implement features yourself, reinforcing understanding
- **Research encouraged**: Links to official documentation help you dive deeper
- **Real-world focus**: Learn industry practices and security standards

### For AI Assistant Users
If you're using Claude Code or another AI assistant, share the relevant guide and ask for implementation help. The assistant can provide detailed code while you maintain understanding of the concepts.

---

## 🗺️ Complete Learning Path

### Getting Started

**[Guide 00: Getting Started - Environment Setup](./00-getting-started.md)**
- Install Java, Maven, Docker, and IDE
- Verify your development environment
- Understand the Java development workflow
- ~2 hours

---

## Phase 1: Foundation (Week 1-2)

Build the foundational components: project structure, database, user authentication, and password security.

**[Guide 01: Set Up Project Structure](./01-project-structure.md)**
- Generate Spring Boot project with Spring Initializr
- Configure Maven dependencies
- Understand project structure and package organization
- Key concepts: Spring Boot auto-configuration, Maven dependency management

**[Guide 02: Configure PostgreSQL and Redis with Docker](./02-docker-setup.md)**
- Set up Docker Compose for infrastructure services
- Configure Spring Boot to connect to PostgreSQL and Redis
- Understand database and session storage architecture
- Key concepts: Containers, volumes, networks, JDBC connections

**[Guide 03: Implement User Registration and Login](./03-user-auth.md)**
- Create User entity with JPA
- Build registration and login endpoints
- Configure Spring Security for authentication
- Key concepts: JPA entities, Spring Data repositories, Spring Security authentication

**[Guide 04: Create User Database Schema](./04-database-schema.md)**
- Implement database migrations with Flyway
- Design schemas for users, clients, authorization codes, tokens
- Add indexes and foreign key constraints
- Key concepts: Database migrations, schema versioning, referential integrity

**[Guide 05: Password Hashing and Validation](./05-password-security.md)**
- Implement BCrypt password hashing
- Create password strength validation
- Add password change functionality
- Key concepts: Hashing vs encryption, salts, BCrypt work factor

---

## Phase 2: Basic OAuth (Week 3-4)

Implement the core OAuth 2.0 authorization code flow.

**[Guide 06: Implement Authorization Endpoint](./06-authorization-endpoint.md)**
- Build `/oauth2/authorize` endpoint
- Create login and consent screens
- Validate authorization requests
- Key concepts: OAuth authorization request, redirect URI validation, consent

**[Guide 07: Generate and Validate Authorization Codes](./07-authorization-codes.md)**
- Generate secure authorization codes
- Store codes with expiration
- Validate codes and enforce one-time use
- Key concepts: Secure random generation, code expiration, replay attack prevention

**[Guide 08: Build Token Endpoint](./08-token-endpoint.md)**
- Create `/oauth2/token` endpoint
- Implement client authentication
- Exchange authorization codes for tokens
- Key concepts: Back-channel communication, client credentials, grant types

**[Guide 09: JWT Token Generation](./09-jwt-tokens.md)**
- Generate JWT access tokens
- Configure token signing with HMAC-SHA256
- Add standard and custom claims
- Key concepts: JWT structure, claims, signature validation

**[Guide 10: Create a Simple Client App to Test](./10-client-app.md)**
- Build Spring Boot OAuth 2.0 client
- Test complete authorization code flow
- Display user information
- Key concepts: OAuth client configuration, redirect handling, token usage

---

## Phase 3: Enhanced Security (Week 5-6)

Add advanced security features: PKCE, refresh tokens, and additional grant types.

### [PHASES-3-6-SUMMARY.md](./PHASES-3-6-SUMMARY.md)
Comprehensive overview of guides 11-30. **Read this first** for Phase 3-6 overview, then implement detailed steps.

**Guide 11: Add PKCE Support**
- Implement Proof Key for Code Exchange
- Generate and validate code challenges
- Protect public clients from code interception
- Key concepts: Code challenge/verifier, SHA256 hashing, public vs confidential clients

**Guide 12: Implement State Parameter Validation**
- Enforce state parameter for CSRF protection
- Preserve state through authorization flow
- Validate state on callback
- Key concepts: CSRF protection, state parameter

**Guide 13: Add Refresh Token Flow**
- Issue refresh tokens with access tokens
- Implement `grant_type=refresh_token`
- Add token rotation for security
- Key concepts: Refresh tokens, token rotation, revocation

**Guide 14: Token Revocation Endpoint**
- Create `/oauth2/revoke` endpoint
- Revoke access and refresh tokens
- Implement token family revocation
- Key concepts: Token lifecycle management, OAuth revocation spec

**Guide 15: Client Credentials Flow**
- Implement server-to-server authentication
- Handle `grant_type=client_credentials`
- Issue tokens without user context
- Key concepts: Machine-to-machine auth, service accounts

---

## Phase 4: User Experience (Week 7-8)

Enhance user-facing features: consent management, session handling, and error handling.

**Guide 16: Build Consent Screen**
- Create professional consent UI
- Implement consent storage and recall
- Add granular scope control
- Key concepts: User consent, scope descriptions, UX patterns

**Guide 17: Scope Management**
- Define and register OAuth scopes
- Implement scope validation
- Map scopes to claims
- Key concepts: Scope registry, standard vs custom scopes

**Guide 18: Session Management with Redis**
- Configure Spring Session with Redis
- Implement session timeout policies
- Prepare for Single Sign-On
- Key concepts: Distributed sessions, session fixation prevention

**Guide 19: Remember-Me Functionality**
- Add persistent login option
- Implement token rotation
- Create backup codes
- Key concepts: Persistent tokens, remember-me security

**Guide 20: Error Handling and User Feedback**
- Create custom error pages
- Implement OAuth error responses
- Add comprehensive logging
- Key concepts: Error standards, user-friendly messages, security logging

---

## Phase 5: OpenID Connect (Week 9-10)

Implement OpenID Connect on top of OAuth 2.0.

**Guide 21: Add ID Token Support**
- Generate ID tokens (JWTs about authentication)
- Include standard OIDC claims
- Support nonce parameter
- Key concepts: ID token vs access token, authentication claims

**Guide 22: UserInfo Endpoint**
- Create `/oauth2/userinfo` endpoint
- Return user claims based on scopes
- Validate bearer tokens
- Key concepts: UserInfo endpoint, scope-to-claim mapping

**Guide 23: Discovery Endpoint (.well-known)**
- Implement `/.well-known/openid-configuration`
- Publish IdP metadata
- Enable client auto-configuration
- Key concepts: OIDC Discovery, metadata publication

**Guide 24: JWKS Endpoint**
- Create `/oauth2/jwks` endpoint
- Publish public keys for JWT verification
- Support key rotation
- Key concepts: JWK Set, public key distribution, RS256 vs HS256

**Guide 25: Claims Mapping**
- Map user attributes to OIDC standard claims
- Implement scope-based claim filtering
- Support custom claims
- Key concepts: Standard claims, claim sources

---

## Phase 6: Resource Server (Week 11-12)

Build a protected API that validates OAuth access tokens.

**Guide 26: Build Protected API Endpoints**
- Create separate resource server project
- Define protected endpoints
- Configure as OAuth2 Resource Server
- Key concepts: Resource server architecture, API design

**Guide 27: Implement Token Validation**
- Validate JWT signatures
- Check token expiration and issuer
- Extract user information from tokens
- Key concepts: JWT validation, signature verification

**Guide 28: Scope-Based Authorization**
- Enforce scope requirements on endpoints
- Use `@PreAuthorize` for method security
- Return 403 for insufficient scopes
- Key concepts: Scope enforcement, method security

**Guide 29: API Rate Limiting**
- Implement request rate limiting
- Store rate limit state in Redis
- Return rate limit headers
- Key concepts: Rate limiting strategies, Bucket4j

**Guide 30: Introspection Endpoint**
- Create `/oauth2/introspect` endpoint
- Support opaque token validation
- Return token metadata
- Key concepts: Token introspection, opaque vs JWT tokens

---

## Beyond the Basics

### [Next Steps: Advanced Topics](./next-steps.md)

After completing the 30 core guides, explore these advanced topics:

1. **Multi-Factor Authentication (MFA)** - TOTP, SMS, WebAuthn/FIDO2
2. **Social Login Integration** - Google, GitHub, Facebook OAuth
3. **Rate Limiting and DDoS Protection** - Protect from abuse
4. **Deploy with Docker and HTTPS** - Production deployment
5. **Audit Logging** - Security event tracking
6. **Study Production IdPs** - Learn from Keycloak, Auth0, Okta
7. **Federation: SAML Integration** - Enterprise SSO
8. **Device Authorization Flow** - For IoT and CLI tools
9. **Performance Testing** - Load testing with JMeter
10. **Advanced Security Features** - Anomaly detection, passwordless auth
11. **Monitoring and Observability** - Metrics, tracing, logging
12. **Multi-Tenancy** - Support multiple organizations
13. **GraphQL API** - Alternative to REST
14. **Mobile App Integration** - iOS and Android
15. **Career Opportunities** - Where this knowledge takes you

---

## 📖 How to Navigate

### By Skill Level

**Beginner** (New to OAuth/Java):
- Start with Phase 1 (Guides 00-05)
- Take time to understand each concept
- Research linked resources thoroughly
- Don't skip ahead - each guide builds on previous

**Intermediate** (Know Java, learning OAuth):
- Skim Phase 1, focus on Phases 2-3
- Deep dive into OAuth/OIDC specifications
- Compare your implementation with standards
- Pay attention to security considerations

**Advanced** (Know OAuth, want production skills):
- Review Phases 2-3 for implementation details
- Focus on Phases 4-6 for production features
- Jump to "Next Steps" for advanced topics
- Study production IdP architectures

### By Goal

**Goal: Understand OAuth/OIDC deeply**
→ Follow all guides sequentially, read linked RFCs

**Goal: Build production IdP**
→ Complete Phases 1-6, then implement all "Next Steps"

**Goal: Integrate OAuth into existing app**
→ Phase 2 (OAuth basics) + Guide 10 (client) + Guide 26-27 (resource server)

**Goal: Pass OAuth/OIDC certification**
→ All phases + study OIDC conformance requirements

**Goal: Job interview prep**
→ All phases + understand security considerations in each guide

---

## 🔑 Key Concepts Index

### Security
- Password hashing (Guide 05)
- PKCE (Guide 11)
- CSRF protection with state (Guide 12)
- Token revocation (Guide 14)
- MFA (Next Steps #1)
- Audit logging (Next Steps #6)

### OAuth 2.0 Flows
- Authorization Code (Guides 06-10)
- Refresh Token (Guide 13)
- Client Credentials (Guide 15)
- Device Flow (Next Steps #8)

### OpenID Connect
- ID Tokens (Guide 21)
- UserInfo Endpoint (Guide 22)
- Discovery (Guide 23)
- JWKS (Guide 24)

### Tokens
- JWT structure (Guide 09)
- Token validation (Guide 27)
- Token introspection (Guide 30)

### Architecture
- Project structure (Guide 01)
- Database schema (Guide 04)
- Multi-tier (client/IdP/resource server)
- Scaling and performance (Next Steps #10)

---

## 🛠️ Quick Reference

### Ports
- **8080**: Identity Provider
- **8081**: Resource Server
- **3000**: Client Application
- **5432**: PostgreSQL
- **6379**: Redis

### Key Endpoints

**Identity Provider (IdP)**:
- `GET /oauth2/authorize` - Authorization endpoint
- `POST /oauth2/token` - Token endpoint
- `POST /oauth2/revoke` - Token revocation
- `GET /oauth2/userinfo` - User information
- `GET /.well-known/openid-configuration` - OIDC discovery
- `GET /oauth2/jwks` - Public keys

**Resource Server**:
- `GET /api/profile` - Protected endpoint example

**Client Application**:
- `GET /` - Home page
- `GET /oauth2/authorization/custom-idp` - Initiate login
- `GET /login/oauth2/code/custom-idp` - OAuth callback
- `GET /dashboard` - User dashboard

---

## 📊 Estimated Timeline

- **Part-time (10-15 hours/week)**: 10-12 weeks for Phases 1-6
- **Full-time (40 hours/week)**: 3-4 weeks for Phases 1-6
- **Advanced topics**: Additional 4-8 weeks based on topics chosen

### Suggested Weekly Schedule

**Week 1**: Environment setup + Phase 1 (Guides 00-05)
**Week 2**: Phase 1 completion + testing
**Week 3**: Phase 2 - Basic OAuth (Guides 06-10)
**Week 4**: Phase 2 completion + end-to-end testing
**Week 5**: Phase 3 - Enhanced Security (Guides 11-15)
**Week 6**: Phase 3 completion
**Week 7**: Phase 4 - User Experience (Guides 16-20)
**Week 8**: Phase 4 completion
**Week 9**: Phase 5 - OpenID Connect (Guides 21-25)
**Week 10**: Phase 5 completion
**Week 11**: Phase 6 - Resource Server (Guides 26-30)
**Week 12**: Phase 6 completion + comprehensive testing
**Week 13+**: Advanced topics from Next Steps

---

## 🤝 Getting Help

### When You're Stuck

1. **Re-read the guide**: Often the answer is there
2. **Check linked resources**: RFCs and docs have details
3. **Google the error**: Spring/OAuth errors are well-documented
4. **Use AI assistant**: Claude Code, GitHub Copilot (provide context from guides)
5. **Debug systematically**: Check logs, database state, network requests
6. **Start fresh**: Sometimes easier to redo a section than debug

### Common Pitfalls

- **Skipping validation**: Always validate input (client_id, redirect_uri, scopes)
- **Not reading errors**: Spring Security errors are verbose but informative
- **Copy-paste without understanding**: Leads to hard-to-debug issues
- **Not testing edge cases**: Test failures, not just happy paths
- **Ignoring security**: Shortcuts in learning project become bad habits

---

## 🎯 Learning Outcomes

After completing these guides, you will be able to:

✅ Explain OAuth 2.0 and OpenID Connect flows in detail
✅ Implement all major OAuth grant types
✅ Secure APIs with token-based authentication
✅ Design database schemas for identity systems
✅ Apply security best practices (PKCE, state, token rotation)
✅ Build production-ready authentication systems
✅ Debug OAuth flows and troubleshoot issues
✅ Read and understand OAuth/OIDC specifications
✅ Make informed architectural decisions for auth systems
✅ Work confidently with production IdPs like Keycloak, Auth0, Okta

---

## 📚 Essential Resources

### Specifications (Authoritative)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7519 - JWT](https://datatracker.ietf.org/doc/html/rfc7519)

### Documentation
- [Spring Authorization Server](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/)
- [Spring Security](https://docs.spring.io/spring-security/reference/)
- [Spring Boot](https://docs.spring.io/spring-boot/docs/current/reference/html/)

### Learning Resources
- [OAuth.net](https://oauth.net/) - Official OAuth community site
- [JWT.io](https://jwt.io/) - Decode and verify JWTs
- [OAuth 2.0 Simplified](https://www.oauth.com/) - Excellent explanations
- [Baeldung Spring Security](https://www.baeldung.com/security-spring) - Java/Spring tutorials

### Tools
- [Postman](https://www.postman.com/) - API testing
- [IntelliJ IDEA](https://www.jetbrains.com/idea/) - Java IDE
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) - Containerization
- [pgAdmin](https://www.pgadmin.org/) - PostgreSQL GUI

---

## 🚀 Ready to Start?

Begin with **[Guide 00: Getting Started](./00-getting-started.md)**

Good luck on your OAuth 2.0 learning journey! Remember:
- **Take your time** - Understanding is more important than speed
- **Build it yourself** - Typing code builds muscle memory
- **Ask questions** - Use AI assistants and online resources
- **Have fun** - You're building something powerful!

---

## 📝 Feedback

This is a learning project, and we welcome your feedback:
- Found an error? Note it for future reference
- Have a suggestion? Consider extending the guides
- Learned something new? Share it with others
- Built something cool? Document your enhancements

**Happy learning!** 🎓
