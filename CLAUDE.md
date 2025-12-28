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

## Getting Started

Begin with: `/guides/00-getting-started.md`
