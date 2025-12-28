# Guide 28: Scope-Based Authorization

**Phase 6: Resource Server** | **Week 11-12** | **Task 28 of 30**

## Overview

Implement fine-grained authorization using OAuth scopes to control access to different API endpoints and operations.

---

## What You'll Build

- Method-level security with scopes
- Custom authorization expressions
- Scope hierarchies
- Dynamic scope checking

---

## Step 1: Enable Method Security

```java
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
}
```

---

## Step 2: Protect Endpoints with Scopes

```java
@RestController
@RequestMapping("/api")
public class DataController {
    
    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_users.read')")
    public List<User> getUsers() {
        return userService.findAll();
    }
    
    @PostMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_users.write')")
    public User createUser(@RequestBody UserRequest request) {
        return userService.create(request);
    }
    
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}
```

---

## Step 3: Custom Authorization Logic

```java
@Component("customAuth")
public class CustomAuthorizationService {
    
    public boolean canAccessResource(Authentication authentication, Long resourceId) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        Long userId = Long.parseLong(jwt.getSubject());
        
        // Check if user owns resource or has admin scope
        return resourceService.isOwner(userId, resourceId) ||
               hasScope(authentication, "admin");
    }
    
    private boolean hasScope(Authentication authentication, String scope) {
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("SCOPE_" + scope));
    }
}
```

Usage:
```java
@PreAuthorize("@customAuth.canAccessResource(authentication, #id)")
@GetMapping("/resources/{id}")
public Resource getResource(@PathVariable Long id) {
    return resourceService.findById(id);
}
```

---

## Step 4: Scope Hierarchies

```java
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy(
        "SCOPE_admin > SCOPE_users.write\n" +
        "SCOPE_users.write > SCOPE_users.read"
    );
    return hierarchy;
}
```

Now `admin` scope automatically grants `users.write` and `users.read`.

---

## Key Concepts

- **@PreAuthorize**: Method-level security
- **Scope Prefix**: Spring adds "SCOPE_" prefix
- **Hierarchies**: Parent scopes imply children
- **Custom Logic**: Beyond simple scope checking

---

## Resources

- **Method Security**: https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
- **Expression-Based Access Control**: https://docs.spring.io/spring-security/reference/servlet/authorization/expression-based.html
