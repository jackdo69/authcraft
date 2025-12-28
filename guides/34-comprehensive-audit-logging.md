# Guide 34: Comprehensive Audit Logging

**Advanced Topics** | **Task 34 of 45**

## Overview

Implement comprehensive audit logging to track all security-relevant events in your OAuth Identity Provider. This enables compliance, security analysis, incident investigation, and regulatory requirements (GDPR, HIPAA, SOC 2).

---

## What You'll Build

- Audit event entity and repository
- Security event tracking service
- Login/logout event logging
- OAuth flow event tracking (authorization, token issuance, revocation)
- Admin action logging
- Failed attempt tracking
- Retention and archival policies
- Audit log API endpoints
- Log export functionality

---

## Why Audit Logging?

### Compliance Requirements

**GDPR**: Requires logging of data access and modifications
**HIPAA**: Mandates audit trails for protected health information
**SOC 2**: Requires monitoring and logging of security events
**PCI DSS**: Requires tracking and monitoring access to cardholder data

### Security Benefits

- **Incident Response**: Investigate security breaches
- **Threat Detection**: Identify suspicious patterns
- **Accountability**: Track who did what and when
- **Forensics**: Reconstruct events after incidents
- **Compliance**: Meet regulatory requirements

**Learn More**: https://owasp.org/www-project-application-security-verification-standard/

---

## Step 1: Design Audit Event Schema

### Create Migration

Create `src/main/resources/db/migration/V14__create_audit_log.sql`:

```sql
CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    user_id BIGINT,
    username VARCHAR(255),
    client_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    event_data JSONB,
    result VARCHAR(20) NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    session_id VARCHAR(255),
    correlation_id VARCHAR(255),

    CONSTRAINT fk_audit_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes for common queries
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_created_at ON audit_events(created_at);
CREATE INDEX idx_audit_ip_address ON audit_events(ip_address);
CREATE INDEX idx_audit_result ON audit_events(result);
CREATE INDEX idx_audit_correlation_id ON audit_events(correlation_id);

-- Composite index for user activity timeline
CREATE INDEX idx_audit_user_timeline ON audit_events(user_id, created_at DESC);
```

**Why JSONB?**: Flexible storage for event-specific data without schema changes
**Why correlation_id?**: Track related events across distributed systems

---

## Step 2: Create Audit Event Entity

### Audit Event Model

Create `AuditEvent.java`:

**Fields to include**:
- `id`: Primary key
- `eventType`: Enum (LOGIN, LOGOUT, TOKEN_ISSUED, etc.)
- `eventCategory`: Enum (AUTHENTICATION, AUTHORIZATION, ADMINISTRATION)
- `userId`: User who performed the action
- `username`: Username (denormalized for deleted users)
- `clientId`: OAuth client involved
- `ipAddress`: Source IP
- `userAgent`: Browser/client info
- `eventData`: Map<String, Object> for flexible data
- `result`: SUCCESS or FAILURE
- `failureReason`: Error message if failed
- `createdAt`: When event occurred
- `sessionId`: HTTP session identifier
- `correlationId`: UUID to correlate related events

### Event Type Enum

Create enums for:
- `EventType`: LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, PASSWORD_CHANGE, MFA_ENABLED, TOKEN_ISSUED, TOKEN_REVOKED, CONSENT_GRANTED, ADMIN_ACTION, etc.
- `EventCategory`: AUTHENTICATION, AUTHORIZATION, ADMINISTRATION, DATA_ACCESS, CONFIGURATION
- `EventResult`: SUCCESS, FAILURE

---

## Step 3: Implement Audit Service

### Audit Event Service

Create `AuditService.java`:

**Methods**:
```java
// Log authentication events
void logLoginSuccess(User user, HttpServletRequest request)
void logLoginFailure(String username, String reason, HttpServletRequest request)
void logLogout(User user, HttpServletRequest request)

// Log OAuth events
void logAuthorizationCodeGenerated(User user, String clientId, String scope)
void logTokenIssued(User user, String clientId, String tokenType)
void logTokenRevoked(String tokenId, String clientId, String reason)
void logConsentGranted(User user, String clientId, String scope)

// Log security events
void logPasswordChange(User user)
void logMfaEnabled(User user)
void logMfaDisabled(User user)
void logAccountLocked(User user, String reason)

// Log admin actions
void logAdminAction(User admin, String action, String targetEntity, String entityId)

// Query methods
Page<AuditEvent> findUserActivity(Long userId, Pageable pageable)
List<AuditEvent> findFailedAttempts(String username, LocalDateTime since)
List<AuditEvent> findByCorrelationId(String correlationId)
```

**Implementation Notes**:
- Use `@Async` for non-blocking logging (don't slow down user requests)
- Extract IP from `X-Forwarded-For` header (behind proxy)
- Include correlation ID from MDC (Mapped Diagnostic Context)
- Handle null users (failed login attempts)

---

## Step 4: Integrate with Authentication Flow

### Login Event Tracking

In `AuthenticationSuccessHandler`:
```java
@Override
public void onAuthenticationSuccess(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication authentication) {
    User user = (User) authentication.getPrincipal();
    auditService.logLoginSuccess(user, request);
    // ... existing logic
}
```

In `AuthenticationFailureHandler`:
```java
@Override
public void onAuthenticationFailure(HttpServletRequest request,
                                   HttpServletResponse response,
                                   AuthenticationException exception) {
    String username = request.getParameter("username");
    auditService.logLoginFailure(username, exception.getMessage(), request);
    // ... existing logic
}
```

In `LogoutSuccessHandler`:
```java
@Override
public void onLogoutSuccess(HttpServletRequest request,
                           HttpServletResponse response,
                           Authentication authentication) {
    if (authentication != null) {
        User user = (User) authentication.getPrincipal();
        auditService.logLogout(user, request);
    }
    // ... existing logic
}
```

---

## Step 5: Track OAuth Flow Events

### Authorization Endpoint

In `OAuth2AuthorizationEndpointFilter` or controller:
- Log when authorization request received
- Log when authorization code generated
- Log when consent granted/denied

```java
// After generating authorization code
auditService.logAuthorizationCodeGenerated(
    user,
    clientId,
    String.join(" ", scopes)
);
```

### Token Endpoint

In `OAuth2TokenEndpointFilter` or service:
- Log access token issuance
- Log refresh token issuance
- Log token exchange (refresh)

```java
// After issuing tokens
auditService.logTokenIssued(user, clientId, "access_token");
if (refreshToken != null) {
    auditService.logTokenIssued(user, clientId, "refresh_token");
}
```

### Revocation Endpoint

In token revocation service:
```java
auditService.logTokenRevoked(tokenId, clientId, "user_requested");
```

---

## Step 6: Add Request Context Filter

### MDC Filter for Correlation

Create `CorrelationIdFilter.java`:

**Purpose**: Add correlation ID to every request for distributed tracing

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String CORRELATION_ID_KEY = "correlationId";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) {
        try {
            String correlationId = request.getHeader(CORRELATION_ID_HEADER);
            if (correlationId == null) {
                correlationId = UUID.randomUUID().toString();
            }

            MDC.put(CORRELATION_ID_KEY, correlationId);
            response.setHeader(CORRELATION_ID_HEADER, correlationId);

            chain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }
}
```

**Why MDC?**: Thread-local context available to all logging calls
**Why correlation ID?**: Track a request across multiple services

---

## Step 7: Create Audit Log API

### REST Controller

Create `AuditLogController.java`:

```java
@RestController
@RequestMapping("/admin/audit")
@PreAuthorize("hasRole('ADMIN')")
public class AuditLogController {

    // Get audit logs with filtering
    @GetMapping
    public Page<AuditEvent> getAuditLogs(
        @RequestParam(required = false) String eventType,
        @RequestParam(required = false) Long userId,
        @RequestParam(required = false) LocalDateTime startDate,
        @RequestParam(required = false) LocalDateTime endDate,
        Pageable pageable
    )

    // Get specific user's activity
    @GetMapping("/user/{userId}")
    public Page<AuditEvent> getUserActivity(@PathVariable Long userId, Pageable pageable)

    // Get failed login attempts
    @GetMapping("/failures")
    public List<AuditEvent> getFailedAttempts(
        @RequestParam String username,
        @RequestParam(required = false) LocalDateTime since
    )

    // Export audit logs
    @GetMapping("/export")
    public ResponseEntity<byte[]> exportAuditLogs(
        @RequestParam LocalDateTime startDate,
        @RequestParam LocalDateTime endDate,
        @RequestParam(defaultValue = "CSV") String format
    )
}
```

**Security**: Only admins can access audit logs
**Pagination**: Required for large datasets
**Export**: CSV or JSON for external analysis

---

## Step 8: Implement Retention Policy

### Automatic Archival

Create `AuditRetentionService.java`:

```java
@Service
public class AuditRetentionService {

    @Value("${audit.retention.days:90}")
    private int retentionDays;

    @Scheduled(cron = "0 0 2 * * *") // 2 AM daily
    public void archiveOldAuditLogs() {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(retentionDays);

        // Archive to file or separate database
        List<AuditEvent> oldEvents = auditRepository.findByCreatedAtBefore(cutoffDate);
        archiveToFile(oldEvents);

        // Delete from main database
        auditRepository.deleteByCreatedAtBefore(cutoffDate);

        log.info("Archived {} audit events older than {}", oldEvents.size(), cutoffDate);
    }

    private void archiveToFile(List<AuditEvent> events) {
        // Write to compressed JSON file
        // Or send to S3, Azure Blob Storage, etc.
    }
}
```

**Why retention?**: Comply with data minimization principles
**Why archival?**: Keep historical data for compliance audits
**Schedule**: Run during low-traffic hours

---

## Step 9: Add Anomaly Detection

### Suspicious Activity Detection

Create `AnomalyDetectionService.java`:

```java
@Service
public class AnomalyDetectionService {

    // Detect multiple failed logins
    public boolean isLoginBruteForce(String username) {
        List<AuditEvent> failures = auditRepository
            .findFailedLoginsByUsername(username, LocalDateTime.now().minusMinutes(5));
        return failures.size() >= 5;
    }

    // Detect login from unusual location
    public boolean isUnusualLocation(User user, String ipAddress) {
        List<String> recentIps = auditRepository
            .findRecentIpAddresses(user.getId(), LocalDateTime.now().minusDays(30));
        return !recentIps.contains(ipAddress);
    }

    // Detect rapid token requests
    public boolean isSuspiciousTokenActivity(String clientId) {
        long tokenCount = auditRepository
            .countTokenIssued(clientId, LocalDateTime.now().minusMinutes(1));
        return tokenCount > 10;
    }

    // Alert on detection
    @EventListener
    public void onLoginFailure(LoginFailureEvent event) {
        if (isLoginBruteForce(event.getUsername())) {
            alertService.sendAlert("Possible brute force attack: " + event.getUsername());
        }
    }
}
```

**Patterns to detect**:
- Brute force attacks (rapid failed logins)
- Credential stuffing
- Token abuse
- Unusual access patterns
- Impossible travel (logins from distant locations quickly)

---

## Step 10: Configure Logging Infrastructure

### Structured Logging

Update `application.yml`:

```yaml
logging:
  level:
    com.learning.idp.audit: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

audit:
  retention:
    days: 90
  async:
    enabled: true
    core-pool-size: 2
    max-pool-size: 5
    queue-capacity: 100
```

### Async Configuration

Create `AsyncConfig.java`:

```java
@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "auditExecutor")
    public Executor auditExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("audit-");
        executor.initialize();
        return executor;
    }
}
```

**Why async?**: Don't block user requests waiting for audit logging
**Thread pool**: Limit concurrent audit writes

---

## Testing Audit Logging

### Test Authentication Events

```bash
# Login success
curl -X POST http://localhost:8080/login \
  -d "username=john@example.com&password=password123"

# Verify audit log created
psql -h localhost -U oauth_user -d oauth_idp \
  -c "SELECT * FROM audit_events WHERE event_type = 'LOGIN_SUCCESS' ORDER BY created_at DESC LIMIT 1;"
```

### Test Failed Login

```bash
# Wrong password
curl -X POST http://localhost:8080/login \
  -d "username=john@example.com&password=wrong"

# Check failed attempt logged
psql -h localhost -U oauth_user -d oauth_idp \
  -c "SELECT * FROM audit_events WHERE event_type = 'LOGIN_FAILURE' AND username = 'john@example.com';"
```

### Test OAuth Events

```bash
# Complete OAuth flow
# Then check audit logs for:
# - AUTHORIZATION_REQUEST
# - CONSENT_GRANTED
# - AUTHORIZATION_CODE_GENERATED
# - TOKEN_ISSUED

psql -h localhost -U oauth_user -d oauth_idp \
  -c "SELECT event_type, client_id, result, created_at FROM audit_events WHERE user_id = 1 ORDER BY created_at DESC;"
```

### Test Audit API

```bash
# Get recent audit logs (admin only)
curl -H "Authorization: Bearer <admin_token>" \
  "http://localhost:8080/admin/audit?page=0&size=20"

# Get user's activity
curl -H "Authorization: Bearer <admin_token>" \
  "http://localhost:8080/admin/audit/user/1?page=0&size=50"

# Get failed attempts
curl -H "Authorization: Bearer <admin_token>" \
  "http://localhost:8080/admin/audit/failures?username=john@example.com"
```

---

## Common Issues

### Audit logs slowing down requests

**Problem**: Synchronous audit logging blocks request threads

**Solution**: Use `@Async` on audit methods:
```java
@Async("auditExecutor")
public void logLoginSuccess(User user, HttpServletRequest request) {
    // ... logging logic
}
```

### Database growing too large

**Problem**: Millions of audit records consuming disk space

**Solution**: Implement retention policy and archival:
- Delete records older than X days
- Archive to external storage (S3, Azure Blob)
- Partition table by date

### Missing IP address behind proxy

**Problem**: Getting proxy IP instead of client IP

**Solution**: Read `X-Forwarded-For` header:
```java
String ipAddress = request.getHeader("X-Forwarded-For");
if (ipAddress == null) {
    ipAddress = request.getRemoteAddr();
}
```

### Performance impact on database

**Problem**: High insert rate on audit_events table

**Solution**:
- Batch inserts using Spring Batch
- Use separate database for audit logs
- Use time-series database (InfluxDB, TimescaleDB)

---

## What You've Accomplished

✅ Created audit event schema with comprehensive tracking
✅ Implemented audit service for all security events
✅ Integrated with authentication and OAuth flows
✅ Added correlation IDs for distributed tracing
✅ Built admin API for audit log queries
✅ Implemented retention and archival policies
✅ Added anomaly detection for suspicious activity
✅ Configured async logging for performance

---

## Next Steps

**Proceed to Guide 35**: Production IdP Analysis (Keycloak, Auth0, Okta)

Before moving on:
- [ ] Audit events logged for all authentication events
- [ ] OAuth flow events tracked (authorization, token, revocation)
- [ ] Correlation IDs working across requests
- [ ] Audit API accessible to admins
- [ ] Retention policy configured
- [ ] Anomaly detection alerts working

---

## Key Concepts Learned

### Audit Logging Principles

- **Completeness**: Log all security-relevant events
- **Integrity**: Protect audit logs from tampering
- **Availability**: Ensure logs are accessible for investigation
- **Non-repudiation**: Cryptographically sign logs if needed

### Event Tracking

- Authentication events (login, logout, password change)
- Authorization events (consent, token issuance)
- Administrative actions
- Data access (who accessed what)

### Performance Considerations

- Async logging to avoid blocking requests
- Batch inserts for high throughput
- Separate database for audit logs
- Indexes on frequently queried fields

### Compliance Requirements

- GDPR: Track data access and processing
- HIPAA: Audit trail for PHI access
- SOC 2: Monitoring and alerting on security events
- PCI DSS: Access logs for cardholder data

---

## Additional Resources

- **OWASP Logging Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- **NIST SP 800-92 - Log Management**: https://csrc.nist.gov/publications/detail/sp/800-92/final
- **GDPR Audit Requirements**: https://gdpr.eu/article-30-processing-activities/
- **Spring Boot Async**: https://spring.io/guides/gs/async-method/
- **Logback MDC**: http://logback.qos.ch/manual/mdc.html
- **ELK Stack for Logs**: https://www.elastic.co/what-is/elk-stack
