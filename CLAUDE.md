# AuthCraft - OAuth 2.0 Identity Provider Learning Project

## Project Context

This repository is a **hands-on learning project** for building a complete OAuth 2.0/OpenID Connect Identity Provider (IdP) system from scratch using Java and industry-standard technologies.

## Purpose

- **Educational**: Learn authentication and authorization concepts by implementing them
- **Practical**: Build a real OAuth2/OIDC provider with Spring Boot ecosystem
- **From Scratch**: No shortcuts - implement core concepts manually to deeply understand them

## Target Audience

This project assumes:
- **Limited Java knowledge** (university-level Java exposure)
- **Senior engineering background** in other languages (TypeScript/JavaScript)
- **Desire to learn** OAuth 2.0, OIDC, Spring Security, and modern Java patterns
- **Willingness to read documentation** and research concepts

## Project Structure

The project consists of three main components:

1. **identity-provider/** (Port 8080) - The Authorization Server that handles:
   - User authentication and login
   - Authorization code generation
   - Token issuance and management
   - Consent screens
   - OpenID Connect endpoints

2. **resource-server/** (Port 8081) - A protected API that:
   - Validates access tokens
   - Enforces scope-based authorization
   - Serves protected resources

3. **client-app/** (Port 3000) - An OAuth client application that:
   - Initiates OAuth flows
   - Exchanges codes for tokens
   - Calls protected APIs

## Technology Stack

- **Spring Boot 3.2+** - Modern Java application framework
- **Spring Security 6.2+** - Security framework
- **Spring Authorization Server 1.2+** - Official OAuth2/OIDC implementation
- **PostgreSQL 15+** - Relational database for users, clients, tokens
- **Redis 7+** - Session storage and caching
- **Maven 3.9+** - Build tool and dependency management
- **Docker** - For running PostgreSQL and Redis locally

## Learning Philosophy

**Guidelines over Code**: The `/guides` folder contains step-by-step instructions explaining WHAT to build and WHY, but not exact code implementations. This forces you to:
- Read official Spring documentation
- Understand concepts before implementing
- Make architectural decisions
- Debug and troubleshoot independently
- Develop real-world problem-solving skills

## How to Use This Repository

1. **Read the guides sequentially** - They're numbered in the recommended learning order
2. **Start with `/guides/00-getting-started.md`** - Set up your development environment
3. **Follow the phases** - Each phase builds on previous knowledge
4. **Research when stuck** - Links are provided to official documentation
5. **Test thoroughly** - Each guide includes what to verify
6. **Ask questions** - Use Claude Code or other resources when concepts are unclear

## Project Timeline

**Estimated**: 10-12 weeks at 10-15 hours/week (part-time)

This is an ambitious project, but upon completion, you will have:
- Deep understanding of OAuth 2.0 and OpenID Connect
- Practical experience with Spring Security ecosystem
- A portfolio project demonstrating security expertise
- Ability to work on production identity systems

## Quick Reference

- **Main project documentation**: `oauth-idp-learning-project.md`
- **Learning guides**: `/guides/` folder
- **Phase-based structure**: Guides are organized by the 6 learning phases
- **Prerequisites**: Java 17+, Docker, Maven, IDE (IntelliJ IDEA recommended)

## Important Notes for AI Assistants

When helping with this project:
- **Provide guidance, not complete code** - Help the user understand, don't solve everything
- **Explain WHY** - Always explain the reasoning behind architectural decisions
- **Reference documentation** - Point to official Spring/OAuth specs
- **Encourage research** - This is a learning project, struggle is part of the process
- **Focus on security** - Emphasize security best practices in OAuth/OIDC
- **Build incrementally** - Follow the phase structure, don't skip ahead
- **Test frequently** - Encourage testing after each implementation step

## Current Project Status (Updated: 2025-12-28)

### Guides Completion Status

**Total Guides**: 46 (numbered 00-45)

**✅ Fully Comprehensive (35 guides)**: 10-22KB each, production-ready
- Guides 00-16: Complete and detailed
- Guide 18: Session Management (expanded to 22KB)
- Guides 32-45: All advanced topics complete
  - Guide 32: Social Login Integration
  - Guide 33: Docker Deployment with HTTPS
  - Guide 34: Comprehensive Audit Logging
  - Guide 35: Production IdP Analysis (Keycloak/Auth0/Okta)
  - Guide 36: SAML Federation
  - Guide 37: Device Authorization Flow
  - Guide 38: Performance Testing & Load Testing
  - Guide 39: Advanced Security Features
  - Guide 40: Monitoring, Metrics & Distributed Tracing
  - Guide 41: Multi-Tenancy & Tenant Isolation
  - Guide 42: GraphQL API Integration
  - Guide 43: Mobile App OAuth Integration
  - Guide 44: Passwordless Authentication (WebAuthn/Passkeys)
  - Guide 45: Zero Trust Architecture (FINAL GUIDE)

**⚠️ Needs Expansion (11 guides)**: Currently 2-5KB, need expansion to 10-15KB
- Guide 17: Scope Management (3.4KB)
- Guide 19: Remember-Me Functionality (2.2KB)
- Guide 20: Error Handling and User Feedback (4.4KB)
- Guide 21: ID Token Support (3.5KB)
- Guide 22: UserInfo Endpoint (4.4KB)
- Guide 23: Discovery Endpoint (.well-known) (3.2KB)
- Guide 24: JWKS Endpoint (2.3KB)
- Guide 25: Claims Mapping (2.2KB)
- Guide 26: Build Protected API Endpoints (3.3KB)
- Guide 27: Implement Token Validation (2.9KB)
- Guide 28: Scope-Based Authorization (2.9KB)
- Guide 29: API Rate Limiting (3.8KB)
- Guide 30: Introspection Endpoint (4.5KB)
- Guide 31: Multi-Factor Authentication (4.6KB)

### Next Session Task

**TASK**: Expand guides 17, 19-31 (11 guides) to match the comprehensive detail level of guides 00-16, 18, 32-45.

**Target**: Each guide should be 10-15KB with:
- Comprehensive overview and "Why" section
- Detailed step-by-step implementation (10 steps)
- Code structure guidelines (not full implementations)
- Testing procedures
- Common issues and solutions
- Security considerations
- Key concepts learned
- Additional resources

**Priority Order** (expand shortest first):
1. Guide 25 (Claims Mapping) - 2.2KB → 10-15KB
2. Guide 19 (Remember-Me) - 2.2KB → 10-15KB
3. Guide 24 (JWKS) - 2.3KB → 10-15KB
4. Guide 27 (Token Validation) - 2.9KB → 10-15KB
5. Guide 28 (Scope Authorization) - 2.9KB → 10-15KB
6. Guide 23 (Discovery) - 3.2KB → 10-15KB
7. Guide 26 (Protected APIs) - 3.3KB → 10-15KB
8. Guide 17 (Scope Management) - 3.4KB → 10-15KB
9. Guide 21 (ID Tokens) - 3.5KB → 10-15KB
10. Guide 29 (Rate Limiting) - 3.8KB → 10-15KB
11. Guide 20 (Error Handling) - 4.4KB → 10-15KB
12. Guide 22 (UserInfo) - 4.4KB → 10-15KB
13. Guide 30 (Introspection) - 4.5KB → 10-15KB
14. Guide 31 (MFA) - 4.6KB → 10-15KB

**Reference Examples**:
- See guides 32-45 for the level of detail expected
- See guide 18 (22KB) for comprehensive expansion example
- Follow the same structure and depth

## Getting Started

Begin with: `/guides/00-getting-started.md`
