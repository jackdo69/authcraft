# Guide 41: Multi-Tenancy and Tenant Isolation

**Advanced Topics** | **Task 41 of 45**

## Overview

Implement multi-tenancy to support multiple organizations (tenants) in a single OAuth IdP instance. Learn tenant isolation strategies, data partitioning, custom domains, and tenant-specific configuration for B2B SaaS applications.

---

## What You'll Build

- Tenant entity and database schema
- Tenant-scoped data isolation
- Tenant context resolution
- Custom domains per tenant
- Tenant-specific branding
- Tenant admin dashboard
- Tenant onboarding flow
- Cross-tenant security

---

## Why Multi-Tenancy?

### B2B SaaS Use Case

**Scenario**: Your IdP serves multiple companies (Acme Corp, Beta Inc, etc.)
**Requirements**:
- Each company has its own users, clients, and configuration
- Complete data isolation between tenants
- Custom branding per tenant
- Tenant-specific subdomain (acme.idp.example.com)

### Deployment Models

**1. Shared Database, Shared Schema** (this guide):
- All tenants in one database
- `tenant_id` column on all tables
- Most cost-effective

**2. Shared Database, Separate Schemas**:
- Each tenant has own PostgreSQL schema
- Better isolation

**3. Separate Databases**:
- Each tenant has own database instance
- Highest isolation, highest cost

**Learn More**: https://www.postgresql.org/docs/current/ddl-schemas.html

---

## Step 1: Design Tenant Schema

### Create Tenant Table

`src/main/resources/db/migration/V16__create_tenants.sql`:

```sql
CREATE TABLE tenants (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(100) UNIQUE NOT NULL,
    custom_domain VARCHAR(255) UNIQUE,
    logo_url VARCHAR(500),
    primary_color VARCHAR(7) DEFAULT '#007bff',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    max_users INTEGER DEFAULT 100,
    subscription_plan VARCHAR(50) DEFAULT 'FREE',

    -- Configuration JSON
    settings JSONB
);

-- Add tenant_id to existing tables
ALTER TABLE users ADD COLUMN tenant_id BIGINT NOT NULL;
ALTER TABLE oauth_clients ADD COLUMN tenant_id BIGINT NOT NULL;
ALTER TABLE authorization_codes ADD COLUMN tenant_id BIGINT NOT NULL;
ALTER TABLE access_tokens ADD COLUMN tenant_id BIGINT NOT NULL;
ALTER TABLE refresh_tokens ADD COLUMN tenant_id BIGINT NOT NULL;

-- Foreign keys
ALTER TABLE users ADD CONSTRAINT fk_user_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE oauth_clients ADD CONSTRAINT fk_client_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Composite unique constraints (unique within tenant)
ALTER TABLE users ADD CONSTRAINT uk_email_tenant UNIQUE (email, tenant_id);
ALTER TABLE oauth_clients ADD CONSTRAINT uk_client_id_tenant UNIQUE (client_id, tenant_id);

-- Indexes
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_clients_tenant ON oauth_clients(tenant_id);
CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_tenants_custom_domain ON tenants(custom_domain);
```

**Why JSONB settings?**: Tenant-specific configuration without schema changes

---

## Step 2: Implement Tenant Entity

### Tenant Model

```java
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(unique = true, nullable = false)
    private String subdomain;

    @Column(unique = true)
    private String customDomain;

    private String logoUrl;
    private String primaryColor;

    @Enumerated(EnumType.STRING)
    private TenantStatus status;

    private Integer maxUsers;
    private String subscriptionPlan;

    @Type(JsonBinaryType.class)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> settings;

    @CreationTimestamp
    private LocalDateTime createdAt;

    // Getters/setters
}

public enum TenantStatus {
    ACTIVE, SUSPENDED, DELETED
}
```

---

## Step 3: Tenant Context Resolution

### Tenant Context

```java
public class TenantContext {

    private static final ThreadLocal<Long> CURRENT_TENANT = new ThreadLocal<>();

    public static void setCurrentTenant(Long tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    public static Long getCurrentTenant() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
```

### Tenant Resolution Filter

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TenantResolutionFilter extends OncePerRequestFilter {

    @Autowired
    private TenantService tenantService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws IOException, ServletException {
        try {
            Long tenantId = resolveTenantId(request);

            if (tenantId == null) {
                response.sendError(HttpStatus.BAD_REQUEST.value(), "Tenant not found");
                return;
            }

            TenantContext.setCurrentTenant(tenantId);
            chain.doFilter(request, response);

        } finally {
            TenantContext.clear();
        }
    }

    private Long resolveTenantId(HttpServletRequest request) {
        // Strategy 1: Subdomain
        String host = request.getServerName();
        if (host.contains(".")) {
            String subdomain = host.split("\\.")[0];
            return tenantService.findBySubdomain(subdomain)
                .map(Tenant::getId)
                .orElse(null);
        }

        // Strategy 2: Custom domain
        return tenantService.findByCustomDomain(host)
            .map(Tenant::getId)
            .orElse(null);

        // Strategy 3: Header (for API calls)
        String tenantHeader = request.getHeader("X-Tenant-ID");
        if (tenantHeader != null) {
            return Long.parseLong(tenantHeader);
        }

        // Strategy 4: Path parameter
        // /tenant/{tenantId}/...
    }
}
```

---

## Step 4: Tenant-Scoped Repositories

### Hibernate Filter

```java
@Entity
@Table(name = "users")
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = "long"))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class User {
    // ... existing fields

    @Column(name = "tenant_id", nullable = false)
    private Long tenantId;
}
```

### Enable Filter

```java
@Component
@Aspect
public class TenantFilterAspect {

    @Autowired
    private EntityManager entityManager;

    @Before("execution(* com.learning.idp.repository.*.*(..))")
    public void enableTenantFilter() {
        Long tenantId = TenantContext.getCurrentTenant();
        if (tenantId != null) {
            Session session = entityManager.unwrap(Session.class);
            Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", tenantId);
        }
    }
}
```

**Automatic filtering**: All queries now filtered by tenant_id

### Manual Tenant Scoping (Alternative)

```java
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.tenantId = :tenantId AND u.email = :email")
    Optional<User> findByEmailAndTenant(@Param("email") String email, @Param("tenantId") Long tenantId);

    default Optional<User> findByEmail(String email) {
        return findByEmailAndTenant(email, TenantContext.getCurrentTenant());
    }
}
```

---

## Step 5: Tenant Onboarding

### Tenant Registration API

```java
@RestController
@RequestMapping("/api/tenants")
public class TenantController {

    @Autowired
    private TenantService tenantService;

    @PostMapping("/register")
    public ResponseEntity<TenantRegistrationResponse> registerTenant(
        @RequestBody TenantRegistrationRequest request
    ) {
        // Validate subdomain availability
        if (tenantService.existsBySubdomain(request.getSubdomain())) {
            throw new ConflictException("Subdomain already taken");
        }

        // Create tenant
        Tenant tenant = new Tenant();
        tenant.setName(request.getCompanyName());
        tenant.setSubdomain(request.getSubdomain());
        tenant.setStatus(TenantStatus.ACTIVE);
        tenant.setSubscriptionPlan("FREE");
        tenant.setMaxUsers(100);
        tenant = tenantService.save(tenant);

        // Create admin user for tenant
        User admin = new User();
        admin.setTenantId(tenant.getId());
        admin.setEmail(request.getAdminEmail());
        admin.setPassword(passwordEncoder.encode(request.getAdminPassword()));
        admin.setRole("TENANT_ADMIN");
        userService.save(admin);

        // Create default OAuth client for tenant
        OAuth2Client client = new OAuth2Client();
        client.setTenantId(tenant.getId());
        client.setClientId(generateClientId());
        client.setClientSecret(generateClientSecret());
        client.setName("Default Client");
        clientService.save(client);

        // Return response
        TenantRegistrationResponse response = new TenantRegistrationResponse();
        response.setTenantId(tenant.getId());
        response.setSubdomain(tenant.getSubdomain());
        response.setLoginUrl("https://" + tenant.getSubdomain() + ".idp.example.com/login");

        return ResponseEntity.ok(response);
    }
}
```

### Subdomain Validation

```java
public boolean isSubdomainValid(String subdomain) {
    // Must be lowercase alphanumeric and hyphens
    if (!subdomain.matches("^[a-z0-9-]+$")) {
        return false;
    }

    // Reserved subdomains
    List<String> reserved = Arrays.asList("www", "api", "admin", "app", "dashboard");
    if (reserved.contains(subdomain)) {
        return false;
    }

    // Length constraints
    return subdomain.length() >= 3 && subdomain.length() <= 63;
}
```

---

## Step 6: Tenant-Specific Branding

### Branding Service

```java
@Service
public class BrandingService {

    @Autowired
    private TenantService tenantService;

    public TenantBranding getBranding() {
        Long tenantId = TenantContext.getCurrentTenant();
        Tenant tenant = tenantService.findById(tenantId)
            .orElseThrow(() -> new TenantNotFoundException());

        TenantBranding branding = new TenantBranding();
        branding.setCompanyName(tenant.getName());
        branding.setLogoUrl(tenant.getLogoUrl());
        branding.setPrimaryColor(tenant.getPrimaryColor());
        branding.setFaviconUrl(tenant.getSettings().get("faviconUrl"));

        return branding;
    }
}
```

### Dynamic Login Page

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title th:text="${branding.companyName} + ' - Login'">Login</title>
    <link rel="icon" th:href="${branding.faviconUrl}">
    <style>
        :root {
            --primary-color: /*[[${branding.primaryColor}]]*/;
        }
        .btn-primary {
            background-color: var(--primary-color);
        }
    </style>
</head>
<body>
    <div class="login-container">
        <img th:src="${branding.logoUrl}" alt="Logo" class="logo">
        <h1 th:text="'Sign in to ' + ${branding.companyName}">Sign in</h1>

        <form th:action="@{/login}" method="post">
            <input type="email" name="username" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="btn-primary">Sign In</button>
        </form>
    </div>
</body>
</html>
```

### Controller

```java
@Controller
public class LoginController {

    @Autowired
    private BrandingService brandingService;

    @GetMapping("/login")
    public String loginPage(Model model) {
        TenantBranding branding = brandingService.getBranding();
        model.addAttribute("branding", branding);
        return "login";
    }
}
```

---

## Step 7: Custom Domains

### Domain Verification

```java
@Service
public class DomainVerificationService {

    public boolean verifyDomain(String domain, Long tenantId) {
        // Generate verification token
        String token = UUID.randomUUID().toString();

        // Store token
        domainVerificationRepository.save(new DomainVerification(domain, tenantId, token));

        // Instructions to user:
        // "Add TXT record to your DNS: _idp-verify.yourdomain.com = {token}"

        return checkDNSRecord(domain, token);
    }

    private boolean checkDNSRecord(String domain, String expectedToken) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext ctx = new InitialDirContext(env);

            Attributes attrs = ctx.getAttributes("_idp-verify." + domain, new String[]{"TXT"});
            Attribute txtRecord = attrs.get("TXT");

            if (txtRecord != null) {
                String value = (String) txtRecord.get();
                return value.contains(expectedToken);
            }
        } catch (Exception e) {
            log.error("DNS verification failed", e);
        }
        return false;
    }
}
```

### SSL Certificate Provisioning

Use Let's Encrypt with ACME protocol:

```java
// Use acme4j library
@Service
public class CertificateService {

    public void provisionCertificate(String domain) throws Exception {
        // 1. Create ACME session
        Session session = new Session("acme://letsencrypt.org");

        // 2. Get account or register
        KeyPair accountKeyPair = loadOrGenerateKeyPair();
        Account account = new AccountBuilder()
            .agreeToTermsOfService()
            .useKeyPair(accountKeyPair)
            .create(session);

        // 3. Order certificate
        Order order = account.newOrder()
            .domain(domain)
            .create();

        // 4. Complete HTTP-01 challenge
        for (Authorization auth : order.getAuthorizations()) {
            Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
            // Serve challenge token at: http://{domain}/.well-known/acme-challenge/{token}
            challenge.trigger();
        }

        // 5. Wait for validation
        order.waitForCompletion();

        // 6. Generate CSR and download certificate
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(domain);
        csrb.sign(domainKeyPair);

        order.execute(csrb.getEncoded());
        Certificate certificate = order.getCertificate();

        // 7. Save certificate
        saveCertificate(domain, certificate, domainKeyPair);
    }
}
```

**Alternative**: Use Cloudflare or AWS ACM for managed certificates

---

## Step 8: Tenant Admin Dashboard

### Admin Endpoints

```java
@RestController
@RequestMapping("/api/tenant/admin")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class TenantAdminController {

    // Get tenant settings
    @GetMapping("/settings")
    public TenantSettings getSettings() {
        Tenant tenant = getCurrentTenant();
        return mapToSettings(tenant);
    }

    // Update branding
    @PutMapping("/branding")
    public ResponseEntity<?> updateBranding(@RequestBody BrandingUpdate request) {
        Tenant tenant = getCurrentTenant();
        tenant.setLogoUrl(request.getLogoUrl());
        tenant.setPrimaryColor(request.getPrimaryColor());
        tenantService.save(tenant);
        return ResponseEntity.ok().build();
    }

    // List users in tenant
    @GetMapping("/users")
    public Page<UserDTO> listUsers(Pageable pageable) {
        Long tenantId = TenantContext.getCurrentTenant();
        return userService.findByTenantId(tenantId, pageable);
    }

    // Create user
    @PostMapping("/users")
    public UserDTO createUser(@RequestBody CreateUserRequest request) {
        Long tenantId = TenantContext.getCurrentTenant();
        User user = new User();
        user.setTenantId(tenantId);
        user.setEmail(request.getEmail());
        // ... set other fields
        return userService.save(user);
    }

    // Usage statistics
    @GetMapping("/usage")
    public TenantUsageStats getUsageStats() {
        Long tenantId = TenantContext.getCurrentTenant();

        TenantUsageStats stats = new TenantUsageStats();
        stats.setTotalUsers(userRepository.countByTenantId(tenantId));
        stats.setActiveUsers(userRepository.countActiveByTenantId(tenantId));
        stats.setTotalClients(clientRepository.countByTenantId(tenantId));
        stats.setTokensIssued(auditRepository.countTokensIssuedLastMonth(tenantId));

        Tenant tenant = getCurrentTenant();
        stats.setMaxUsers(tenant.getMaxUsers());
        stats.setSubscriptionPlan(tenant.getSubscriptionPlan());

        return stats;
    }
}
```

---

## Step 9: Cross-Tenant Security

### Prevent Cross-Tenant Access

```java
@Service
public class TenantSecurityService {

    public void validateUserAccess(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException());

        Long currentTenant = TenantContext.getCurrentTenant();

        if (!user.getTenantId().equals(currentTenant)) {
            throw new UnauthorizedException("Access denied: user belongs to different tenant");
        }
    }

    public void validateClientAccess(String clientId) {
        OAuth2Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new ClientNotFoundException());

        Long currentTenant = TenantContext.getCurrentTenant();

        if (!client.getTenantId().equals(currentTenant)) {
            throw new UnauthorizedException("Access denied: client belongs to different tenant");
        }
    }
}
```

### Audit Cross-Tenant Attempts

```java
@Aspect
@Component
public class CrossTenantAuditAspect {

    @AfterThrowing(pointcut = "execution(* com.learning.idp.service.*.*(..))",
                   throwing = "ex")
    public void logCrossTenantAttempt(JoinPoint joinPoint, UnauthorizedException ex) {
        if (ex.getMessage().contains("different tenant")) {
            String method = joinPoint.getSignature().getName();
            Object[] args = joinPoint.getArgs();

            auditService.logSecurityViolation(
                "CROSS_TENANT_ACCESS_ATTEMPT",
                String.format("Method: %s, Args: %s", method, Arrays.toString(args))
            );
        }
    }
}
```

---

## Step 10: Tenant Metrics and Billing

### Track Usage

```java
@Service
public class TenantMetricsService {

    public void trackLogin(Long userId) {
        Long tenantId = TenantContext.getCurrentTenant();
        metricsRepository.incrementCounter(tenantId, "logins", LocalDate.now());
    }

    public void trackTokenIssued(String tokenType) {
        Long tenantId = TenantContext.getCurrentTenant();
        metricsRepository.incrementCounter(tenantId, "tokens_" + tokenType, LocalDate.now());
    }

    public TenantUsageReport getMonthlyUsage(Long tenantId, YearMonth month) {
        LocalDate start = month.atDay(1);
        LocalDate end = month.atEndOfMonth();

        return TenantUsageReport.builder()
            .logins(metricsRepository.sumCounter(tenantId, "logins", start, end))
            .tokensIssued(metricsRepository.sumCounter(tenantId, "tokens_access_token", start, end))
            .activeUsers(userRepository.countActiveInPeriod(tenantId, start, end))
            .build();
    }
}
```

### Billing Integration

```java
@Service
public class BillingService {

    @Scheduled(cron = "0 0 1 * * *")  // First day of each month
    public void generateMonthlyInvoices() {
        YearMonth lastMonth = YearMonth.now().minusMonths(1);

        List<Tenant> tenants = tenantRepository.findAllActive();

        for (Tenant tenant : tenants) {
            TenantUsageReport usage = metricsService.getMonthlyUsage(tenant.getId(), lastMonth);

            // Calculate charges based on plan
            BigDecimal amount = calculateCharges(tenant.getSubscriptionPlan(), usage);

            // Create invoice
            Invoice invoice = new Invoice();
            invoice.setTenantId(tenant.getId());
            invoice.setPeriod(lastMonth);
            invoice.setAmount(amount);
            invoice.setUsageReport(usage);
            invoiceRepository.save(invoice);

            // Send to payment processor (Stripe, etc.)
            paymentService.charge(tenant, invoice);
        }
    }
}
```

---

## What You've Accomplished

✅ Implemented multi-tenant database schema
✅ Created tenant context resolution
✅ Built tenant-scoped data access
✅ Added tenant onboarding flow
✅ Implemented custom branding per tenant
✅ Configured custom domains with SSL
✅ Created tenant admin dashboard
✅ Enforced cross-tenant security
✅ Added usage tracking and billing

---

## Next Steps

**Proceed to Guide 42**: GraphQL API

Before moving on:
- [ ] Tenants can be created via API
- [ ] Subdomain resolution working
- [ ] Data properly isolated by tenant_id
- [ ] Custom branding loads per tenant
- [ ] Cross-tenant access blocked
- [ ] Tenant admin dashboard functional

---

## Key Concepts Learned

### Multi-Tenancy Patterns

- **Shared Everything**: All tenants share database and tables (most efficient)
- **Shared Database**: Tenants have separate schemas (better isolation)
- **Separate Databases**: Each tenant has own database (highest isolation)

### Tenant Isolation

- Row-level security with tenant_id
- Hibernate filters for automatic scoping
- ThreadLocal for tenant context
- Cross-tenant access prevention

### B2B SaaS Features

- Subdomain per tenant
- Custom domains and SSL
- White-label branding
- Tenant admin roles
- Usage-based billing

---

## Additional Resources

- **PostgreSQL Row-Level Security**: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- **Hibernate Filters**: https://docs.jboss.org/hibernate/orm/6.0/userguide/html_single/Hibernate_User_Guide.html#pc-filter
- **Multi-Tenant Spring Boot**: https://www.baeldung.com/hibernate-5-multitenancy
- **Let's Encrypt ACME**: https://letsencrypt.org/docs/
- **Stripe Billing**: https://stripe.com/docs/billing
