# Guide 19: Remember-Me Functionality

**Phase 4: User Experience** | **Week 7-8** | **Task 19 of 30**

## Overview

Implement persistent login functionality allowing users to stay authenticated across browser sessions.

---

## What You'll Build

- Persistent token-based remember-me
- Token rotation on each use
- Backup codes for account recovery
- Security monitoring for remember-me tokens

---

## Step 1: Database Schema

```sql
CREATE TABLE persistent_logins (
    username VARCHAR(64) NOT NULL,
    series VARCHAR(64) PRIMARY KEY,
    token VARCHAR(64) NOT NULL,
    last_used TIMESTAMP NOT NULL
);
```

---

## Step 2: Configure Remember-Me

```java
@Bean
public PersistentTokenRepository persistentTokenRepository(DataSource dataSource) {
    JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
    tokenRepository.setDataSource(dataSource);
    return tokenRepository;
}

// In SecurityFilterChain
http.rememberMe(remember -> remember
    .tokenRepository(persistentTokenRepository)
    .tokenValiditySeconds(2592000) // 30 days
    .key("uniqueAndSecret")
    .userDetailsService(userDetailsService)
);
```

---

## Step 3: Login Form Integration

```html
<form method="post" action="/login">
    <input type="text" name="username"/>
    <input type="password" name="password"/>
    <label>
        <input type="checkbox" name="remember-me"/> Keep me logged in
    </label>
    <button type="submit">Login</button>
</form>
```

---

## Step 4: Token Security

Rotate tokens on each use:
```java
public class RotatingTokenRememberMeServices extends PersistentTokenBasedRememberMeServices {
    
    @Override
    protected void onLoginSuccess(...) {
        // Generate new token
        // Invalidate old token
        // Store new token
    }
}
```

---

## Key Concepts

- **Persistent Tokens**: Database-backed remember-me
- **Token Rotation**: New token on each authentication
- **Security**: Detect stolen tokens through duplicate use
- **Expiration**: Long-lived but time-limited

---

## Resources

- **Spring Security Remember-Me**: https://docs.spring.io/spring-security/reference/servlet/authentication/rememberme.html
- **Remember-Me Best Practices**: https://www.baeldung.com/spring-security-remember-me
