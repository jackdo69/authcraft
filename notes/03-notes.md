# Guide 03 Notes: User Authentication Implementation

## Lombok - Boilerplate Code Reduction

**Lombok** generates code at compile time using annotations.

### Common Annotations

| Annotation | Generates |
|------------|-----------|
| `@Data` | Getters, setters, `toString()`, `equals()`, `hashCode()` |
| `@NoArgsConstructor` | Empty constructor |
| `@AllArgsConstructor` | Constructor with all fields |
| `@RequiredArgsConstructor` | Constructor for `final` fields only (key for DI) |
| `@Builder` | Builder pattern |
| `@Slf4j` | Logger instance |

### IntelliJ Setup
1. Install Lombok plugin (Settings → Plugins)
2. Enable annotation processing (Settings → Compiler → Annotation Processors)
3. Restart IDE

---

## Spring Data JPA Repository

### UserRepository Implementation

```java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### Key Points

- **Interface only** - Spring implements at runtime
- **JpaRepository<User, Long>** - `User` = entity type, `Long` = ID type
- **Method naming** - Spring parses names to generate SQL
  - `findBy{Field}` → `SELECT * WHERE field = ?`
  - `existsBy{Field}` → `SELECT COUNT(*) > 0 WHERE field = ?`
- **Optional<T>** - Safe handling of found/not found cases

### Built-in Methods (from JpaRepository)

```java
userRepository.save(user);           // Insert or update
userRepository.findById(1L);         // Find by ID
userRepository.findAll();            // Get all
userRepository.delete(user);         // Delete
userRepository.count();              // Count all
```

---

## Spring Security & UserDetails

### What is Spring Security?

Framework providing:
- **Authentication** - "Who are you?" (verify identity)
- **Authorization** - "What can you do?" (check permissions)
- **Protection** - CSRF, XSS, session fixation, etc.

### UserDetails Interface

Bridge between your User entity and Spring Security.

```java
public interface UserDetails {
    String getUsername();
    String getPassword();
    Collection<? extends GrantedAuthority> getAuthorities();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

### UserDetailsService Implementation

```java
@Service
public class UserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("Not found"));

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())  // Already hashed
            .authorities("ROLE_USER")
            .build();
    }
}
```

**Spring Security calls this during login** to load user data and verify credentials.

### Authentication Flow

```
1. User submits username/password
2. Spring Security calls loadUserByUsername()
3. Your code returns UserDetails with hashed password
4. Spring compares: passwordEncoder.matches(inputPassword, hashedPassword)
5. If match → Create session, user logged in
6. If no match → Return 401 Unauthorized
```

---

## BCrypt Password Encoding

### Why BCrypt?

- **One-way encryption** - Can hash but never decrypt
- **Built-in salt** - Prevents rainbow table attacks
- **Adaptive cost** - Can increase difficulty over time
- **Slow by design** - ~100-200ms (prevents brute-force)

### Hash Structure

```
$2a$10$N9qo8uLOickgx2ZMRZoMye/IVI9lMZOEk8Mg.jC4rx.nYSv4FLgTa
│ │ │  │                      │
│ │ │  └─ Salt (22 chars)     └─ Hash (31 chars)
│ │ └─ Cost factor (10 = 2^10 = 1024 rounds)
│ └─ Algorithm version
└─ BCrypt identifier
```

### Usage

```java
// Registration - hash password
String hashed = passwordEncoder.encode("password123");
// $2a$10$ABC... (different each time due to random salt)

// Login - verify password
boolean matches = passwordEncoder.matches("password123", storedHash);
```

---

## Step 5: Registration Controller

### AuthController Implementation

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegistrationRequest request) {
        UserResponse response = userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
```

### Annotation Breakdown

- **@RestController** - `@Controller` + `@ResponseBody` (returns JSON)
- **@RequestMapping("/api/auth")** - Base path for all endpoints
- **@PostMapping("/register")** - Maps to `POST /api/auth/register`
- **@Valid** - Triggers validation (@NotBlank, @Email, @Size)
- **@RequestBody** - Deserializes JSON → Java object
- **@RequiredArgsConstructor** - Generates constructor for `final` fields (DI)

### Error Handling

**Custom Exceptions** (`exception/` package):
```java
public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException(String message) {
        super(message);
    }
}
```

**Global Exception Handler** (`controller/` package):
```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUsernameExists(UsernameAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(new ErrorResponse("USERNAME_EXISTS", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
            .map(e -> e.getField() + ": " + e.getDefaultMessage())
            .collect(Collectors.joining(", "));
        return ResponseEntity.badRequest()
            .body(new ErrorResponse("VALIDATION_ERROR", message));
    }
}
```

**ErrorResponse DTO** (`dto/` package):
```java
@Data
@AllArgsConstructor
public class ErrorResponse {
    private String errorCode;
    private String message;
    private LocalDateTime timestamp;
}
```

---

## Step 6: Spring Security Configuration

### SecurityConfig Implementation

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserService userService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.disable())  // For API development
            .formLogin(form -> form.loginProcessingUrl("/api/auth/login").permitAll())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}
```

### Configuration Breakdown

**SecurityFilterChain**:
- `.permitAll()` - Public endpoints (no auth required)
- `.authenticated()` - All other endpoints require login
- `.csrf().disable()` - Disable CSRF for API testing
- `.sessionCreationPolicy(IF_REQUIRED)` - Create session when user logs in

**AuthenticationProvider**:
- **DaoAuthenticationProvider** - Database-backed authentication
- **setUserDetailsService** - How to load users (calls `loadUserByUsername`)
- **setPasswordEncoder** - How to verify passwords (BCrypt)

### Session Policies

| Policy | Behavior |
|--------|----------|
| `IF_REQUIRED` | Create session if needed (default) |
| `ALWAYS` | Always create session |
| `NEVER` | Don't create, use existing if present |
| `STATELESS` | No sessions (JWT/token-based) |

---

## Spring Boot Fundamentals

### Entry Point Explained

```java
@SpringBootApplication
public class IdentityProviderApplication {
    public static void main(String[] args) {
        SpringApplication.run(IdentityProviderApplication.class, args);
    }
}
```

**This one line does EVERYTHING**:

```
SpringApplication.run()
    ↓
1. Create Application Context (bean container)
2. Component Scan (@Component, @Service, @Controller, @Configuration)
3. Create bean instances
4. Inject dependencies (constructor injection)
5. Execute @Bean methods in @Configuration classes
6. Auto-configure (Tomcat, Hibernate, Jackson from pom.xml)
7. Start embedded Tomcat on port 8080
8. Connect to database (application.yaml)
    ↓
Application Ready!
```

### @SpringBootApplication Combines Three

- **@SpringBootConfiguration** - Configuration class
- **@EnableAutoConfiguration** - Auto-configure based on dependencies
- **@ComponentScan** - Scan for annotated classes

---

## Dependency Injection: Spring vs Node.js

### Node.js (Imperative - You Control)

```javascript
// YOU create and wire everything
const userRepo = new UserRepository();
const encoder = bcrypt;
const userService = new UserService(userRepo, encoder);
const controller = new AuthController(userService);

app.post('/register', controller.register);
app.listen(3000);  // YOU start server
```

### Spring Boot (Declarative - Framework Controls)

```java
// YOU declare what you need
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;  // Spring injects
    private final PasswordEncoder passwordEncoder;  // Spring injects
}

// Spring automatically:
// - Creates instances (singleton by default)
// - Wires dependencies
// - Starts Tomcat server
```

### How Spring Autowires

```java
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
}
```

**Spring's Process**:
1. Sees `@Service` → "Create UserService bean"
2. Sees `@RequiredArgsConstructor` → "Constructor injection needed"
3. Looks for constructor parameters:
   - `UserRepository` → Found @Repository bean
   - `PasswordEncoder` → Found @Bean in SecurityConfig
4. Creates: `new UserService(userRepository, passwordEncoder)`
5. Stores in Application Context (singleton)

---

## Configuration Management

### application.yaml Location

`src/main/resources/application.yaml` (equivalent to `.env` in Node.js)

### Current Configuration

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/oauth_idp
    username: oauth_user
    password: oauth_password

  jpa:
    hibernate:
      ddl-auto: update  # Auto-create tables (DON'T use in production!)
    show-sql: true      # Print SQL to console

  data:
    redis:
      host: localhost
      port: 6379

  session:
    store-type: redis
    timeout: 30m

server:
  port: 8080  # Change to use different port
```

### JDBC URL Breakdown

```
jdbc:postgresql://localhost:5432/oauth_idp
│    │            │         │    │
│    │            │         │    └─ Database name
│    │            │         └────── Port
│    │            └──────────────── Host
│    └───────────────────────────── Database type
└────────────────────────────────── JDBC protocol
```

### Environment Variables

```yaml
spring:
  datasource:
    url: ${DATABASE_URL:jdbc:postgresql://localhost:5432/oauth_idp}
    username: ${DB_USER:oauth_user}
    password: ${DB_PASSWORD:oauth_password}
```

**Syntax**: `${ENV_VAR:default_value}`

### Profile-Specific Config

```
src/main/resources/
├── application.yaml       # Common
├── application-dev.yaml   # Development
├── application-prod.yaml  # Production
```

**Activate**: `mvn spring-boot:run -Dspring-boot.run.profiles=dev`

---

## Maven vs npm

### Dependency Storage

| Aspect | Maven | npm |
|--------|-------|-----|
| **Location** | `~/.m2/repository/` (global) | `./node_modules/` (per project) |
| **Storage** | Shared across projects | Duplicated per project |
| **Config** | `pom.xml` | `package.json` |
| **Install** | `mvn install` | `npm install` |
| **Run** | `mvn spring-boot:run` | `npm start` |

### Dependency Sources (pom.xml → Classes)

| Dependency | Provides | Usage |
|-----------|----------|-------|
| `spring-boot-starter-security` | `SecurityFilterChain`, `PasswordEncoder` | SecurityConfig |
| `spring-boot-starter-web` | `@RestController`, `@RequestMapping` | Controllers |
| `spring-boot-starter-data-jpa` | `@Entity`, `JpaRepository` | Models, Repositories |
| `spring-boot-starter-validation` | `@NotBlank`, `@Email`, `@Valid` | DTOs |
| `lombok` | `@Data`, `@RequiredArgsConstructor` | All classes |

---

## Key Annotations Reference

### Configuration
- **@Configuration** - Bean definitions source
- **@EnableWebSecurity** - Activate Spring Security
- **@Bean** - Register object as Spring-managed bean

### Components
- **@Service** - Business logic layer
- **@Repository** - Data access layer (auto-implemented by Spring Data)
- **@RestController** - REST API controller (@Controller + @ResponseBody)

### Dependency Injection
- **@RequiredArgsConstructor** - Constructor for `final` fields (Lombok)
- **@Autowired** - Explicit injection (constructor injection preferred)

### Web
- **@RequestMapping** - Map HTTP requests to methods
- **@PostMapping** - POST requests shortcut
- **@GetMapping** - GET requests shortcut
- **@RequestBody** - Deserialize JSON to object
- **@Valid** - Trigger Bean Validation
- **@RestControllerAdvice** - Global exception handler

### Validation
- **@NotBlank** - Not null, not empty, not whitespace
- **@Email** - Valid email format
- **@Size(min, max)** - String length or collection size

### Transaction
- **@Transactional** - Execute in database transaction (auto-commit/rollback)

---

## Node.js vs Spring Boot

### Code Equivalents

| Spring Boot | Node.js/Express |
|-------------|-----------------|
| `@PostMapping("/register")` | `router.post('/register', handler)` |
| `@RequestBody` | `req.body` |
| `@Valid` | `express-validator` |
| `ResponseEntity.status(201)` | `res.status(201).json(data)` |
| `SecurityFilterChain` | Middleware chain |
| `passwordEncoder.encode()` | `bcrypt.hash()` |
| `passwordEncoder.matches()` | `bcrypt.compare()` |
| `@Service` + DI | Manual `new Service()` |
| `SpringApplication.run()` | `app.listen(3000)` |

### Philosophy

| Aspect | Node.js | Spring Boot |
|--------|---------|-------------|
| **Style** | Imperative | Declarative |
| **Wiring** | Manual | Automatic (DI) |
| **Server** | You create | Auto-created |
| **Config** | `.env` + code | `application.yaml` |

---

## Common Issues & Solutions

### "There is no PasswordEncoder mapped for id null"
**Fix**: Add `@Bean PasswordEncoder passwordEncoder()` in SecurityConfig

### "Circular dependency detected"
**Fix**: Make PasswordEncoder separate `@Bean`, use constructor injection

### Login returns 403 Forbidden
**Fix**: Disable CSRF for APIs: `.csrf(csrf -> csrf.disable())`

### Validation errors not returned
**Fix**: Create `@RestControllerAdvice` with `@ExceptionHandler(MethodArgumentNotValidException.class)`

### Database constraint violation
**Fix**: Check `existsByUsername()` in UserService before saving

---

## Summary: Key Concepts

1. **Spring Boot Entry**: `SpringApplication.run()` scans, creates beans, injects dependencies, starts server
2. **Dependency Injection**: Spring auto-wires objects via constructor injection
3. **Annotations**: Declare needs (@Service, @Bean), Spring handles creation
4. **Configuration**: `application.yaml` for database, server, sessions
5. **Maven**: `~/.m2/repository/` stores dependencies globally
6. **Security**: `SecurityFilterChain` intercepts requests, `AuthenticationProvider` verifies credentials
7. **Beans**: Singleton by default, managed lifecycle
8. **Philosophy**: Declarative (Spring) vs Imperative (Node.js)
