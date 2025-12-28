# Guide 39: Advanced Security Features & Hardening

**Advanced Topics** | **Task 39 of 45**

## Overview

Implement advanced security features to protect your OAuth IdP from modern threats: bot detection, anomaly detection, breached password checking, account takeover prevention, and security hardening best practices.

---

## What You'll Build

- Bot detection and CAPTCHA integration
- Breached password detection (Have I Been Pwned API)
- Account takeover (ATO) prevention
- IP reputation checking
- Device fingerprinting
- Impossible travel detection
- Security headers configuration
- Secrets management with Vault
- WAF (Web Application Firewall) integration

---

## Why Advanced Security?

### Modern Threats

**Credential Stuffing**: Attackers use leaked credentials from other breaches
**Account Takeover (ATO)**: Automated bots try to access accounts
**Brute Force**: Dictionary attacks against passwords
**Session Hijacking**: Stealing session cookies
**XSS/CSRF**: Injection attacks

**Learn More**: https://owasp.org/www-project-top-ten/

---

## Step 1: Breached Password Detection

### Have I Been Pwned Integration

Add dependency:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webclient</artifactId>
</dependency>
```

Create `BreachedPasswordChecker.java`:

```java
@Service
public class BreachedPasswordChecker {

    private static final String HIBP_API = "https://api.pwnedpasswords.com/range/";
    private final WebClient webClient = WebClient.create(HIBP_API);

    public boolean isPasswordBreached(String password) {
        // SHA-1 hash of password
        String hash = DigestUtils.sha1Hex(password).toUpperCase();
        String prefix = hash.substring(0, 5);
        String suffix = hash.substring(5);

        // Query HIBP API (k-anonymity model)
        String response = webClient.get()
            .uri(prefix)
            .retrieve()
            .bodyToMono(String.class)
            .block();

        // Check if suffix appears in response
        return response != null && response.contains(suffix);
    }
}
```

**k-Anonymity**: Only send first 5 chars of hash, HIBP never sees full password

**Integrate with registration**:
```java
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegistrationRequest request) {
    if (breachedPasswordChecker.isPasswordBreached(request.getPassword())) {
        throw new WeakPasswordException("This password has been exposed in a data breach");
    }
    // ... continue registration
}
```

**Learn More**: https://haveibeenpwned.com/API/v3

---

## Step 2: Bot Detection with CAPTCHA

### Google reCAPTCHA v3

Add to `pom.xml`:
```xml
<dependency>
    <groupId>com.google.api-client</groupId>
    <artifactId>google-api-client</artifactId>
    <version>2.0.0</version>
</dependency>
```

**Get API keys**: https://www.google.com/recaptcha/admin

Create `RecaptchaService.java`:

```java
@Service
public class RecaptchaService {

    @Value("${recaptcha.secret-key}")
    private String secretKey;

    private static final String VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

    public boolean verify(String token, String action) {
        RestTemplate restTemplate = new RestTemplate();

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("secret", secretKey);
        params.add("response", token);

        RecaptchaResponse response = restTemplate.postForObject(
            VERIFY_URL,
            params,
            RecaptchaResponse.class
        );

        return response != null
            && response.isSuccess()
            && response.getScore() >= 0.5  // Threshold: 0.0 (bot) to 1.0 (human)
            && action.equals(response.getAction());
    }
}
```

**Frontend**:
```html
<script src="https://www.google.com/recaptcha/api.js?render=YOUR_SITE_KEY"></script>
<script>
grecaptcha.ready(function() {
    grecaptcha.execute('YOUR_SITE_KEY', {action: 'login'}).then(function(token) {
        document.getElementById('recaptcha-token').value = token;
        document.getElementById('login-form').submit();
    });
});
</script>
```

**Validate on login**:
```java
@PostMapping("/login")
public String login(@RequestParam String recaptchaToken, ...) {
    if (!recaptchaService.verify(recaptchaToken, "login")) {
        throw new BotDetectedException("Bot activity detected");
    }
    // ... proceed with authentication
}
```

---

## Step 3: Device Fingerprinting

### FingerprintJS Integration

Frontend library to identify devices:

```html
<script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"></script>
<script>
  FingerprintJS.load().then(fp => {
    fp.get().then(result => {
      const visitorId = result.visitorId;
      document.getElementById('device-fingerprint').value = visitorId;
    });
  });
</script>
```

**Backend tracking**:
```java
@Entity
public class UserDevice {
    @Id
    private Long id;
    private Long userId;
    private String deviceFingerprint;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime lastSeen;
    private boolean trusted;
}
```

**Detect new device**:
```java
public boolean isNewDevice(User user, String deviceFingerprint) {
    return !userDeviceRepository.existsByUserIdAndDeviceFingerprint(
        user.getId(), deviceFingerprint
    );
}
```

**Trigger step-up authentication** for new devices:
```java
if (isNewDevice(user, deviceFingerprint)) {
    // Require MFA
    // Or send email verification link
    return "redirect:/verify-device";
}
```

---

## Step 4: Impossible Travel Detection

### Geo-Location Based Security

Use IP geolocation API (MaxMind GeoIP2):

```xml
<dependency>
    <groupId>com.maxmind.geoip2</groupId>
    <artifactId>geoip2</artifactId>
    <version>4.0.0</version>
</dependency>
```

```java
@Service
public class GeoLocationService {

    private final DatabaseReader reader;

    public GeoLocationService() throws IOException {
        File database = new File("/path/to/GeoLite2-City.mmdb");
        this.reader = new DatabaseReader.Builder(database).build();
    }

    public Location getLocation(String ipAddress) throws Exception {
        InetAddress ip = InetAddress.getByName(ipAddress);
        CityResponse response = reader.city(ip);

        return new Location(
            response.getCity().getName(),
            response.getCountry().getName(),
            response.getLocation().getLatitude(),
            response.getLocation().getLongitude()
        );
    }
}
```

**Impossible travel check**:
```java
public boolean isImpossibleTravel(LoginAttempt previous, LoginAttempt current) {
    Location loc1 = geoLocationService.getLocation(previous.getIpAddress());
    Location loc2 = geoLocationService.getLocation(current.getIpAddress());

    // Calculate distance between locations
    double distance = calculateDistance(loc1.getLatitude(), loc1.getLongitude(),
                                       loc2.getLatitude(), loc2.getLongitude());

    // Calculate time difference
    long minutesBetween = Duration.between(previous.getTimestamp(), current.getTimestamp()).toMinutes();

    // Average speed in km/h
    double speed = (distance / minutesBetween) * 60;

    // Impossible if faster than 900 km/h (faster than commercial aircraft)
    return speed > 900;
}
```

**Alert on detection**:
```java
if (isImpossibleTravel(lastLogin, currentLogin)) {
    alertService.sendSecurityAlert(user, "Impossible travel detected");
    // Lock account temporarily
    // Require additional verification
}
```

**Learn More**: https://dev.maxmind.com/geoip/

---

## Step 5: Security Headers

### Configure Security Headers

Create `SecurityHeadersConfig.java`:

```java
@Configuration
public class SecurityHeadersConfig {

    @Bean
    public FilterRegistrationBean<SecurityHeadersFilter> securityHeadersFilter() {
        FilterRegistrationBean<SecurityHeadersFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SecurityHeadersFilter());
        registration.addUrlPatterns("/*");
        return registration;
    }
}

public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Prevent clickjacking
        httpResponse.setHeader("X-Frame-Options", "DENY");

        // XSS Protection
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");

        // Prevent MIME sniffing
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");

        // HSTS (force HTTPS)
        httpResponse.setHeader("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload");

        // Content Security Policy
        httpResponse.setHeader("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'");

        // Referrer Policy
        httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions Policy (formerly Feature-Policy)
        httpResponse.setHeader("Permissions-Policy",
            "geolocation=(), microphone=(), camera=()");

        chain.doFilter(request, response);
    }
}
```

**Test headers**: https://securityheaders.com/

---

## Step 6: Rate Limiting per IP/User

### Advanced Rate Limiting

```java
@Service
public class AdvancedRateLimiter {

    private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> userBuckets = new ConcurrentHashMap<>();

    // IP-based: 10 requests per minute
    public boolean allowByIp(String ipAddress) {
        Bucket bucket = ipBuckets.computeIfAbsent(ipAddress, k ->
            Bucket.builder()
                .addLimit(Limit.of(10, Duration.ofMinutes(1)))
                .build()
        );
        return bucket.tryConsume(1);
    }

    // User-based: 100 requests per hour
    public boolean allowByUser(String username) {
        Bucket bucket = userBuckets.computeIfAbsent(username, k ->
            Bucket.builder()
                .addLimit(Limit.of(100, Duration.ofHours(1)))
                .build()
        );
        return bucket.tryConsume(1);
    }

    // Failed login attempts: 5 per 15 minutes
    public boolean allowFailedLogin(String username) {
        String key = "failed_" + username;
        Bucket bucket = userBuckets.computeIfAbsent(key, k ->
            Bucket.builder()
                .addLimit(Limit.of(5, Duration.ofMinutes(15)))
                .build()
        );
        return bucket.tryConsume(1);
    }
}
```

**Apply to login**:
```java
@PostMapping("/login")
public String login(@RequestParam String username, HttpServletRequest request) {
    String ipAddress = getClientIp(request);

    if (!rateLimiter.allowByIp(ipAddress)) {
        throw new TooManyRequestsException("Too many requests from this IP");
    }

    // ... authentication logic

    // On failure
    if (!rateLimiter.allowFailedLogin(username)) {
        accountLockService.lockAccount(username, Duration.ofHours(1));
        throw new AccountLockedException("Account locked due to too many failed attempts");
    }
}
```

---

## Step 7: Secrets Management with Vault

### HashiCorp Vault Integration

Add dependency:
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-vault-config</artifactId>
</dependency>
```

**Configure** `bootstrap.yml`:
```yaml
spring:
  cloud:
    vault:
      uri: http://localhost:8200
      token: ${VAULT_TOKEN}
      kv:
        enabled: true
        backend: secret
```

**Store secrets in Vault**:
```bash
vault kv put secret/oauth-idp \
  jwt-secret="super-secret-key" \
  db-password="db-password-here" \
  client-secret="oauth-client-secret"
```

**Access in code**:
```java
@Value("${jwt-secret}")
private String jwtSecret;

@Value("${db-password}")
private String dbPassword;
```

**Learn More**: https://www.vaultproject.io/

---

## Step 8: WAF Integration

### AWS WAF Configuration

Create WAF rules (via AWS Console or Terraform):

```hcl
# terraform/waf.tf
resource "aws_wafv2_web_acl" "oauth_idp" {
  name  = "oauth-idp-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    action {
      block {}
    }
  }

  # Block known bad IPs
  rule {
    name     = "IPReputationList"
    priority = 2

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    override_action {
      none {}
    }
  }

  # SQL injection protection
  rule {
    name     = "SQLiProtection"
    priority = 3

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    override_action {
      none {}
    }
  }
}
```

**Cloudflare WAF** (Alternative):
- Enable under Security → WAF
- Configure rulesets: OWASP Core Ruleset, Cloudflare Managed Ruleset
- Custom rules for your IdP

---

## Step 9: Account Takeover Prevention

### Multi-Layer Defense

**1. Login Notification Emails**:
```java
@EventListener
public void onSuccessfulLogin(LoginSuccessEvent event) {
    User user = event.getUser();
    String ipAddress = event.getIpAddress();
    String location = geoLocationService.getLocation(ipAddress).getCity();

    if (isNewDevice(user, event.getDeviceFingerprint())) {
        emailService.sendLoginNotification(user, location, event.getTimestamp());
    }
}
```

**2. Session Invalidation on Password Change**:
```java
@PostMapping("/change-password")
public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
    User user = getCurrentUser();

    // Change password
    userService.changePassword(user, request.getNewPassword());

    // Invalidate all existing sessions
    sessionRegistry.getAllSessions(user, false)
        .forEach(SessionInformation::expireNow);

    // Revoke all refresh tokens
    refreshTokenService.revokeAllForUser(user.getId());

    return ResponseEntity.ok().build();
}
```

**3. Require Re-Authentication for Sensitive Actions**:
```java
@PostMapping("/delete-account")
@PreAuthorize("hasRecentAuthentication()")  // Custom annotation
public ResponseEntity<?> deleteAccount() {
    User user = getCurrentUser();
    userService.deleteAccount(user);
    return ResponseEntity.ok().build();
}
```

---

## Step 10: Security Monitoring & Alerting

### Security Event Dashboard

Create security metrics:

```java
@Service
public class SecurityMetricsService {

    private final MeterRegistry meterRegistry;

    public void recordFailedLogin(String reason) {
        meterRegistry.counter("security.failed_logins",
            "reason", reason).increment();
    }

    public void recordAccountLocked() {
        meterRegistry.counter("security.accounts_locked").increment();
    }

    public void recordImpossibleTravel() {
        meterRegistry.counter("security.impossible_travel").increment();
    }

    public void recordBreachedPasswordAttempt() {
        meterRegistry.counter("security.breached_password").increment();
    }
}
```

**Alert on thresholds**:
```java
@Scheduled(fixedRate = 60000)  // Every minute
public void checkSecurityThresholds() {
    long failedLogins = getCounterValue("security.failed_logins");

    if (failedLogins > 100) {  // More than 100 failed logins/minute
        alertService.sendAlert("High rate of failed logins detected");
    }
}
```

**Grafana Dashboard**: Visualize security metrics

---

## Common Issues

### False Positives in Bot Detection

**Problem**: Legitimate users flagged as bots

**Solution**:
- Lower reCAPTCHA threshold (0.3 instead of 0.5)
- Whitelist known good IPs
- Use reCAPTCHA v3 for invisible challenges

### Geo-IP Accuracy

**Problem**: VPN users trigger impossible travel alerts

**Solution**:
- Allow users to mark devices as trusted
- Increase speed threshold (consider VPN relocation)
- Send notification instead of blocking

### Vault Connection Failures

**Problem**: App fails to start if Vault unavailable

**Solution**:
```yaml
spring:
  cloud:
    vault:
      fail-fast: false  # Don't fail on Vault connection error
```

---

## What You've Accomplished

✅ Integrated breached password checking
✅ Added bot detection with reCAPTCHA
✅ Implemented device fingerprinting
✅ Created impossible travel detection
✅ Configured security headers
✅ Set up secrets management with Vault
✅ Integrated WAF for protection
✅ Built account takeover prevention
✅ Created security monitoring dashboard

---

## Next Steps

**Proceed to Guide 40**: Monitoring and Observability

Before moving on:
- [ ] Breached password detection working
- [ ] reCAPTCHA integrated on login/registration
- [ ] Device fingerprinting tracking new devices
- [ ] Security headers passing securityheaders.com scan
- [ ] Secrets managed in Vault (or equivalent)
- [ ] Security metrics being collected

---

## Key Concepts Learned

### Defense in Depth

Multiple layers of security:
1. Network (WAF, DDoS protection)
2. Application (Input validation, security headers)
3. Authentication (MFA, breached passwords)
4. Authorization (Principle of least privilege)
5. Monitoring (Anomaly detection, alerts)

### Zero Trust Principles

- Never trust, always verify
- Assume breach has already occurred
- Verify explicitly (device, location, behavior)
- Least-privilege access

---

## Additional Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Have I Been Pwned API**: https://haveibeenpwned.com/API/v3
- **reCAPTCHA**: https://www.google.com/recaptcha/
- **HashiCorp Vault**: https://www.vaultproject.io/docs
- **AWS WAF**: https://docs.aws.amazon.com/waf/
- **Cloudflare WAF**: https://developers.cloudflare.com/waf/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
