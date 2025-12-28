# Guide 18: Distributed Session Management with Redis

**Phase 4: User Experience** | **Week 7-8** | **Task 18 of 30**

## Overview

Implement distributed session management using Redis for scalable, stateless application architecture. Enable session sharing across multiple server instances, handle session persistence, implement session fixation protection, and build concurrent session control.

---

## What You'll Build

- Spring Session with Redis backend
- Distributed session storage
- Session timeout and idle timeout policies
- Session fixation prevention
- Concurrent session control (limit sessions per user)
- Custom session attributes
- Session event listeners
- Active session management UI
- Session migration strategies
- Session security best practices

---

## Why Redis for Sessions?

### Problems with In-Memory Sessions

**Scalability**: Sessions tied to specific server instance
**Load Balancing**: Requires sticky sessions (sub-optimal)
**Failover**: Sessions lost when server crashes
**Deployment**: Rolling updates cause session loss

###  Redis Benefits

**Distributed**: All servers share session data
**Persistence**: Sessions survive server restarts
**Performance**: In-memory speed with optional disk persistence
**Scalability**: Horizontal scaling without sticky sessions
**High Availability**: Redis Sentinel/Cluster for failover

**Learn More**: https://redis.io/docs/manual/keyspace/

---

## Step 1: Add Dependencies

### Maven Dependencies

```xml
<dependencies>
    <!-- Spring Session with Redis -->
    <dependency>
        <groupId>org.springframework.session</groupId>
        <artifactId>spring-session-data-redis</artifactId>
    </dependency>

    <!-- Redis client (Lettuce) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>

    <!-- Connection pooling -->
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-pool2</artifactId>
    </dependency>
</dependencies>
```

**Why Lettuce?**: Modern Redis client with async support and connection pooling

---

## Step 2: Configure Redis Connection

### Application Configuration

`application.yml`:
```yaml
spring:
  data:
    redis:
      host: localhost
      port: 6379
      password: ${REDIS_PASSWORD:}  # Optional password
      database: 0
      timeout: 2000ms

      # Lettuce pool configuration
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 0
          max-wait: -1ms
        shutdown-timeout: 100ms

  # Session configuration
  session:
    store-type: redis
    timeout: 30m  # Session timeout
    redis:
      namespace: "spring:session"  # Redis key prefix
      flush-mode: on_save           # Write to Redis on save
      cleanup-cron: "0 * * * * *"  # Cleanup expired sessions every minute
```

### Redis Sentinel Configuration (High Availability)

For production with Redis Sentinel:

```yaml
spring:
  data:
    redis:
      sentinel:
        master: mymaster
        nodes:
          - localhost:26379
          - localhost:26380
          - localhost:26381
      password: ${REDIS_PASSWORD}
```

---

## Step 3: Enable Spring Session

### Configuration Class

```java
@Configuration
@EnableRedisHttpSession(
    maxInactiveIntervalInSeconds = 1800,  // 30 minutes
    redisNamespace = "spring:session"
)
public class SessionConfig {

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        // Use JSON instead of JDK serialization (more readable in Redis)
        return new GenericJackson2JsonRedisSerializer();
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("SESSIONID");
        serializer.setCookiePath("/");
        serializer.setDomainNamePattern("^.+?\\.(\\w+\\.[a-z]+)$");  // Match domain
        serializer.setUseHttpOnlyCookie(true);    // Prevent JavaScript access
        serializer.setUseSecureCookie(true);      // HTTPS only
        serializer.setSameSite("Lax");            // CSRF protection
        return serializer;
    }

    @Bean
    public HttpSessionIdResolver httpSessionIdResolver() {
        // Support both cookie and header-based sessions
        return HeaderHttpSessionIdResolver.xAuthToken();  // Or CookieHttpSessionIdResolver
    }
}
```

**Why JSON serialization?**: Human-readable in Redis, language-agnostic

---

## Step 4: Session Security Configuration

### Prevent Session Fixation

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                // Prevent session fixation attack
                .sessionFixation().changeSessionId()

                // Limit concurrent sessions
                .maximumSessions(5)
                .maxSessionsPreventsLogin(false)  // Allow new login, expire oldest
                .expiredUrl("/login?expired=true")

                // Session creation policy
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )

            // CSRF protection (requires session)
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }
}
```

**Session Fixation**: Attacker tricks victim into using known session ID. `changeSessionId()` prevents this by creating new session ID after login.

---

## Step 5: Custom Session Attributes

### Store Custom Data in Session

```java
@Service
public class UserSessionService {

    private static final String ATTR_MFA_VERIFIED = "mfaVerified";
    private static final String ATTR_LAST_ACTIVITY = "lastActivity";
    private static final String ATTR_LOGIN_TIMESTAMP = "loginTimestamp";

    public void markMfaVerified(HttpSession session) {
        session.setAttribute(ATTR_MFA_VERIFIED, true);
        session.setAttribute("mfaVerifiedAt", LocalDateTime.now());
    }

    public boolean isMfaVerified(HttpSession session) {
        Boolean verified = (Boolean) session.getAttribute(ATTR_MFA_VERIFIED);
        return Boolean.TRUE.equals(verified);
    }

    public void updateLastActivity(HttpSession session) {
        session.setAttribute(ATTR_LAST_ACTIVITY, LocalDateTime.now());
    }

    public void setLoginTimestamp(HttpSession session) {
        session.setAttribute(ATTR_LOGIN_TIMESTAMP, LocalDateTime.now());
    }

    public Optional<LocalDateTime> getLoginTimestamp(HttpSession session) {
        return Optional.ofNullable((LocalDateTime) session.getAttribute(ATTR_LOGIN_TIMESTAMP));
    }

    public Duration getSessionAge(HttpSession session) {
        return getLoginTimestamp(session)
            .map(loginTime -> Duration.between(loginTime, LocalDateTime.now()))
            .orElse(Duration.ZERO);
    }
}
```

---

## Step 6: Session Event Listeners

### Track Session Lifecycle

```java
@Component
public class SessionEventListener implements ApplicationListener<AbstractSessionEvent> {

    @Autowired
    private AuditService auditService;

    @Autowired
    private MetricsService metricsService;

    @Override
    public void onApplicationEvent(AbstractSessionEvent event) {
        if (event instanceof SessionCreatedEvent) {
            handleSessionCreated((SessionCreatedEvent) event);
        } else if (event instanceof SessionDeletedEvent) {
            handleSessionDeleted((SessionDeletedEvent) event);
        } else if (event instanceof SessionExpiredEvent) {
            handleSessionExpired((SessionExpiredEvent) event);
        }
    }

    private void handleSessionCreated(SessionCreatedEvent event) {
        String sessionId = event.getSessionId();
        log.info("Session created: {}", sessionId);

        metricsService.incrementCounter("sessions.created");
        metricsService.recordGauge("sessions.active", getActiveSessionCount());
    }

    private void handleSessionDeleted(SessionDeletedEvent event) {
        String sessionId = event.getSessionId();
        Session session = event.getSession();

        String username = session.getAttribute("username");

        log.info("Session deleted: {} for user: {}", sessionId, username);

        auditService.logSessionEnded(username, sessionId, "user_logout");
        metricsService.incrementCounter("sessions.deleted");
    }

    private void handleSessionExpired(SessionExpiredEvent event) {
        String sessionId = event.getSessionId();
        Session session = event.getSession();

        String username = session.getAttribute("username");

        log.info("Session expired: {} for user: {}", sessionId, username);

        auditService.logSessionEnded(username, sessionId, "timeout");
        metricsService.incrementCounter("sessions.expired");
    }

    private long getActiveSessionCount() {
        // Query Redis for active sessions
        return sessionRepository.findAll().size();
    }
}
```

---

## Step 7: Active Session Management

### List User Sessions

```java
@Service
public class SessionManagementService {

    @Autowired
    private FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    @Autowired
    private SessionRegistry sessionRegistry;

    public List<SessionInfo> getUserActiveSessions(String username) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);

        return sessions.entrySet().stream()
            .map(entry -> buildSessionInfo(entry.getKey(), entry.getValue()))
            .sorted(Comparator.comparing(SessionInfo::getLastAccessedAt).reversed())
            .collect(Collectors.toList());
    }

    private SessionInfo buildSessionInfo(String sessionId, Session session) {
        SessionInfo info = new SessionInfo();
        info.setSessionId(sessionId);
        info.setCreatedAt(Instant.ofEpochMilli(session.getCreationTime().toEpochMilli()));
        info.setLastAccessedAt(Instant.ofEpochMilli(session.getLastAccessedTime().toEpochMilli()));
        info.setMaxInactiveInterval(session.getMaxInactiveInterval());

        // Extract custom attributes
        info.setIpAddress((String) session.getAttribute("ipAddress"));
        info.setUserAgent((String) session.getAttribute("userAgent"));
        info.setLoginTimestamp((LocalDateTime) session.getAttribute("loginTimestamp"));

        return info;
    }

    public void invalidateSession(String sessionId) {
        sessionRepository.deleteById(sessionId);
        log.info("Manually invalidated session: {}", sessionId);
    }

    public void invalidateAllUserSessions(String username) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);

        sessions.keySet().forEach(sessionId -> {
            sessionRepository.deleteById(sessionId);
            log.info("Invalidated session {} for user {}", sessionId, username);
        });
    }

    public void invalidateAllExceptCurrent(String username, String currentSessionId) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(username);

        sessions.keySet().stream()
            .filter(sessionId -> !sessionId.equals(currentSessionId))
            .forEach(sessionId -> {
                sessionRepository.deleteById(sessionId);
                log.info("Invalidated session {} (keeping current)", sessionId);
            });
    }
}
```

### REST API for Session Management

```java
@RestController
@RequestMapping("/api/sessions")
@PreAuthorize("isAuthenticated()")
public class SessionController {

    @Autowired
    private SessionManagementService sessionService;

    @GetMapping("/active")
    public List<SessionInfo> getActiveSessions(@AuthenticationPrincipal User user) {
        return sessionService.getUserActiveSessions(user.getEmail());
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<?> invalidateSession(
        @PathVariable String sessionId,
        @AuthenticationPrincipal User user
    ) {
        // Verify session belongs to user
        List<SessionInfo> userSessions = sessionService.getUserActiveSessions(user.getEmail());

        boolean belongsToUser = userSessions.stream()
            .anyMatch(s -> s.getSessionId().equals(sessionId));

        if (!belongsToUser) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        sessionService.invalidateSession(sessionId);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/all")
    public ResponseEntity<?> invalidateAllSessions(
        @AuthenticationPrincipal User user,
        HttpSession currentSession
    ) {
        sessionService.invalidateAllExceptCurrent(user.getEmail(), currentSession.getId());
        return ResponseEntity.ok().build();
    }
}
```

---

## Step 8: Session Timeout Strategies

### Idle Timeout vs Absolute Timeout

```java
@Component
public class SessionTimeoutFilter extends OncePerRequestFilter {

    private static final String ATTR_ABSOLUTE_TIMEOUT = "absoluteTimeout";
    private static final Duration ABSOLUTE_TIMEOUT = Duration.ofHours(8);  // Max 8 hours

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws ServletException, IOException {
        HttpSession session = request.getSession(false);

        if (session != null) {
            // Check absolute timeout
            LocalDateTime absoluteTimeout = (LocalDateTime) session.getAttribute(ATTR_ABSOLUTE_TIMEOUT);

            if (absoluteTimeout == null) {
                // Set absolute timeout on first request
                session.setAttribute(ATTR_ABSOLUTE_TIMEOUT, LocalDateTime.now().plus(ABSOLUTE_TIMEOUT));
            } else if (LocalDateTime.now().isAfter(absoluteTimeout)) {
                // Absolute timeout exceeded
                session.invalidate();
                response.sendRedirect("/login?timeout=absolute");
                return;
            }

            // Update idle timeout (handled by Spring Session automatically)
        }

        chain.doFilter(request, response);
    }
}
```

**Idle Timeout**: Session expires after X minutes of inactivity (Spring Session handles this)
**Absolute Timeout**: Session expires after X hours regardless of activity (custom implementation)

---

## Step 9: Session Persistence and Recovery

### Handle Redis Failures

```java
@Configuration
public class RedisFailoverConfig {

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
            .commandTimeout(Duration.ofSeconds(2))
            .shutdownTimeout(Duration.ofMillis(100))
            .build();

        return new LettuceConnectionFactory(redisStandaloneConfiguration(), clientConfig);
    }

    @Bean
    public SessionRepository<? extends Session> sessionRepository() {
        RedisIndexedSessionRepository repository = new RedisIndexedSessionRepository(redisConnectionFactory());

        // Fallback to in-memory if Redis unavailable (dev only!)
        return new FallbackSessionRepository(repository);
    }
}

public class FallbackSessionRepository implements SessionRepository<Session> {

    private final RedisIndexedSessionRepository primaryRepository;
    private final Map<String, Session> fallbackStore = new ConcurrentHashMap<>();

    @Override
    public Session createSession() {
        try {
            return primaryRepository.createSession();
        } catch (RedisConnectionFailureException e) {
            log.warn("Redis unavailable, using fallback");
            return new MapSession();
        }
    }

    @Override
    public void save(Session session) {
        try {
            primaryRepository.save(session);
        } catch (RedisConnectionFailureException e) {
            fallbackStore.put(session.getId(), session);
        }
    }

    @Override
    public Session findById(String id) {
        try {
            return primaryRepository.findById(id);
        } catch (RedisConnectionFailureException e) {
            return fallbackStore.get(id);
        }
    }

    @Override
    public void deleteById(String id) {
        try {
            primaryRepository.deleteById(id);
        } catch (RedisConnectionFailureException e) {
            fallbackStore.remove(id);
        }
    }
}
```

**Production**: Use Redis Sentinel or Cluster for high availability, NOT in-memory fallback

---

## Step 10: Session Migration

### Migrate from Cookie Sessions to Redis

```java
@Component
public class SessionMigrationFilter extends OncePerRequestFilter {

    @Autowired
    private SessionRepository<Session> redisSessionRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("OLD_SESSION_ID".equals(cookie.getName())) {
                    // Migrate old session to Redis
                    migrateSession(cookie.getValue(), request);

                    // Remove old cookie
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                    break;
                }
            }
        }

        chain.doFilter(request, response);
    }

    private void migrateSession(String oldSessionId, HttpServletRequest request) {
        // Create new Redis session
        Session newSession = redisSessionRepository.createSession();

        // Copy attributes from old session (if accessible)
        // ... migration logic

        redisSessionRepository.save(newSession);
    }
}
```

---

## Testing Session Management

### Test Session Creation

```bash
# Login to create session
curl -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=john@example.com&password=password123"

# Verify session in Redis
redis-cli
> KEYS "spring:session:*"
1) "spring:session:sessions:abc123"
2) "spring:session:index:..."

> HGETALL "spring:session:sessions:abc123"
1) "sessionAttr:username"
2) "john@example.com"
3) "creationTime"
4) "1234567890"
5) "lastAccessedTime"
6) "1234567900"
```

### Test Session Sharing

```bash
# Login on server 1
curl -c cookies.txt -X POST http://server1:8080/login \
  -d "username=john@example.com&password=password123"

# Access resource on server 2 (should work)
curl -b cookies.txt http://server2:8080/api/profile
# Response: User profile (session shared via Redis)
```

### Test Concurrent Sessions

```bash
# Login from device 1
curl -c device1.txt -X POST http://localhost:8080/login \
  -d "username=john@example.com&password=password123"

# Login from device 2
curl -c device2.txt -X POST http://localhost:8080/login \
  -d "username=john@example.com&password=password123"

# List active sessions
curl -b device1.txt http://localhost:8080/api/sessions/active

# Response:
# [
#   {"sessionId": "abc123", "ipAddress": "192.168.1.1", ...},
#   {"sessionId": "def456", "ipAddress": "192.168.1.2", ...}
# ]
```

---

## Common Issues

### Session Lost After Server Restart

**Problem**: Users logged out when server restarts

**Solution**: Verify Redis persistence:
```bash
# Check Redis data persistence
redis-cli CONFIG GET save
# Should show: "900 1 300 10 60 10000"  # Save to disk periodically

# Or use AOF (Append-Only File)
redis-cli CONFIG SET appendonly yes
```

### Session Not Shared Across Servers

**Problem**: Session created on server1 not found on server2

**Solutions**:
- Verify all servers use same Redis instance
- Check `spring.session.redis.namespace` is identical
- Verify Redis is accessible from all servers
- Check serialization format matches

### High Redis Memory Usage

**Problem**: Redis consuming too much RAM

**Solutions**:
```bash
# Set expiration on sessions (Spring Session does this automatically)
redis-cli
> TTL "spring:session:sessions:abc123"
(integer) 1800  # 30 minutes in seconds

# Monitor memory
> INFO memory

# Reduce session timeout
spring.session.timeout=15m
```

### Cookie Not Sent

**Problem**: SESSIONID cookie not included in requests

**Solutions**:
- Check `SameSite` attribute (use `Lax` or `None` with HTTPS)
- Verify cookie domain matches request domain
- Ensure `HttpOnly` flag set (security)
- For HTTPS only, set `Secure` flag

---

## What You've Accomplished

✅ Configured Spring Session with Redis
✅ Implemented distributed session storage
✅ Added session fixation prevention
✅ Built concurrent session control
✅ Created custom session attributes
✅ Implemented session event listeners
✅ Built active session management UI
✅ Added session timeout strategies
✅ Handled Redis failover scenarios

---

## Next Steps

**Proceed to Guide 19**: Remember-Me Functionality

Before moving on:
- [ ] Sessions stored in Redis
- [ ] Sessions shared across server instances
- [ ] Session fixation protection working
- [ ] Concurrent sessions limited per user
- [ ] Active sessions viewable by user
- [ ] Session events logged

---

## Key Concepts Learned

### Distributed Sessions

- **Stateless Servers**: No session state on application servers
- **Central Store**: Redis holds all session data
- **Scalability**: Add servers without sticky sessions
- **Resilience**: Sessions survive server failures

### Session Security

- **Session Fixation**: Change session ID after login
- **HttpOnly Cookie**: Prevent JavaScript access
- **Secure Cookie**: HTTPS only
- **SameSite**: CSRF protection

### Session Lifecycle

- **Created**: On first request or explicit creation
- **Accessed**: Read/write operations update last accessed time
- **Expired**: Idle timeout or absolute timeout
- **Deleted**: Manual invalidation or expiration

---

## Additional Resources

- **Spring Session**: https://docs.spring.io/spring-session/reference/
- **Redis Session Store**: https://redis.io/docs/manual/keyspace/
- **Session Fixation**: https://owasp.org/www-community/attacks/Session_fixation
- **Spring Session + Redis**: https://www.baeldung.com/spring-session
- **Redis Persistence**: https://redis.io/docs/management/persistence/
- **Session Best Practices**: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
