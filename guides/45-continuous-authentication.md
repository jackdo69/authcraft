# Guide 45: Zero Trust Architecture and Continuous Authentication

**Advanced Topics** | **Task 45 of 45** ✨ **FINAL GUIDE**

## Overview

Implement Zero Trust security principles with continuous authentication, risk-based access control, device posture assessment, and adaptive authentication. Move beyond one-time login to ongoing verification of user identity and context.

---

## What You'll Build

- Continuous authentication engine
- Risk scoring system
- Device posture assessment
- Step-up authentication
- Session anomaly detection
- Context-aware access control
- Adaptive authentication policies
- Device trust levels

---

## Why Zero Trust?

### Traditional Security Model

**Perimeter-Based**: Trust inside network, distrust outside
**Problem**: Once inside, attacker has broad access

### Zero Trust Principles

**Never Trust, Always Verify**: Verify every request
**Assume Breach**: Design as if network is already compromised
**Least Privilege**: Minimal access for each request
**Verify Explicitly**: Use all available data (identity, device, location, behavior)

**Core Tenet**: "Don't trust, verify" - every request must be authenticated and authorized

**Learn More**: https://www.nist.gov/publications/zero-trust-architecture

---

## Step 1: Risk Scoring Engine

### Risk Factors

**Identity Risk**:
- New device
- Unusual location
- Impossible travel
- Compromised credential detected

**Behavioral Risk**:
- Unusual access patterns
- Off-hours activity
- Rapid API calls
- Large data downloads

**Environmental Risk**:
- VPN usage
- Public WiFi
- Suspicious IP
- Outdated software

### Risk Score Calculation

```java
@Service
public class RiskScoringService {

    @Autowired
    private GeoLocationService geoLocationService;

    @Autowired
    private DeviceFingerprintService deviceFingerprintService;

    @Autowired
    private BehavioralAnalyticsService behavioralService;

    public RiskScore calculateRiskScore(AuthenticationContext context) {
        double score = 0.0;

        // Device risk
        if (isNewDevice(context.getUser(), context.getDeviceFingerprint())) {
            score += 0.3;
        }

        // Location risk
        if (isUnusualLocation(context.getUser(), context.getIpAddress())) {
            score += 0.2;
        }

        // Impossible travel
        if (isImpossibleTravel(context.getUser(), context.getIpAddress())) {
            score += 0.5;
        }

        // Time-based risk
        if (isOffHours(context.getTimestamp())) {
            score += 0.1;
        }

        // Behavioral anomaly
        if (behavioralService.isAnomalousActivity(context.getUser(), context.getActivity())) {
            score += 0.3;
        }

        // IP reputation
        if (isSuspiciousIP(context.getIpAddress())) {
            score += 0.4;
        }

        // Compromised credential
        if (isCredentialCompromised(context.getUser())) {
            score += 1.0;  // Immediate high risk
        }

        return new RiskScore(
            Math.min(score, 1.0),  // Cap at 1.0
            getRiskLevel(score),
            getRiskFactors(context, score)
        );
    }

    private RiskLevel getRiskLevel(double score) {
        if (score < 0.3) return RiskLevel.LOW;
        if (score < 0.6) return RiskLevel.MEDIUM;
        if (score < 0.8) return RiskLevel.HIGH;
        return RiskLevel.CRITICAL;
    }

    private boolean isNewDevice(User user, String deviceFingerprint) {
        return !deviceRepository.existsByUserIdAndFingerprint(user.getId(), deviceFingerprint);
    }

    private boolean isUnusualLocation(User user, String ipAddress) {
        Location current = geoLocationService.getLocation(ipAddress);
        List<Location> recentLocations = loginHistoryRepository
            .findRecentLocations(user.getId(), LocalDateTime.now().minusDays(30));

        return recentLocations.stream()
            .noneMatch(loc -> isNearby(loc, current, 100));  // Within 100km
    }

    private boolean isImpossibleTravel(User user, String ipAddress) {
        // See Guide 39 for implementation
        return impossibleTravelDetector.detect(user, ipAddress);
    }

    private boolean isOffHours(LocalDateTime timestamp) {
        int hour = timestamp.getHour();
        return hour < 6 || hour > 22;  // Outside 6 AM - 10 PM
    }

    private boolean isSuspiciousIP(String ipAddress) {
        // Check against threat intelligence feeds
        return ipReputationService.isSuspicious(ipAddress);
    }

    private boolean isCredentialCompromised(User user) {
        // Check Have I Been Pwned breach database
        return breachDetectionService.isCompromised(user.getEmail());
    }
}
```

---

## Step 2: Continuous Authentication

### Session Risk Monitoring

```java
@Service
public class ContinuousAuthenticationService {

    @Scheduled(fixedRate = 60000)  // Every minute
    public void evaluateActiveSessions() {
        List<UserSession> activeSessions = sessionRepository.findAllActive();

        for (UserSession session : activeSessions) {
            AuthenticationContext context = buildContext(session);
            RiskScore risk = riskScoringService.calculateRiskScore(context);

            session.setCurrentRiskScore(risk.getScore());
            session.setRiskLevel(risk.getLevel());

            // Take action based on risk
            if (risk.getLevel() == RiskLevel.CRITICAL) {
                terminateSession(session);
                alertUser(session.getUser(), "Session terminated due to suspicious activity");
            } else if (risk.getLevel() == RiskLevel.HIGH) {
                requireStepUpAuthentication(session);
            } else if (risk.getLevel() == RiskLevel.MEDIUM) {
                increaseAuditLogging(session);
            }

            sessionRepository.save(session);
        }
    }

    private void terminateSession(UserSession session) {
        session.setStatus(SessionStatus.TERMINATED);
        session.setTerminationReason("High risk detected");
        sessionInvalidator.invalidate(session.getId());

        auditService.logSecurityEvent(
            session.getUserId(),
            "SESSION_TERMINATED",
            Map.of("reason", "high_risk", "riskScore", session.getCurrentRiskScore())
        );
    }

    private void requireStepUpAuthentication(UserSession session) {
        session.setStepUpRequired(true);
        session.setStepUpDeadline(LocalDateTime.now().plusMinutes(5));

        notificationService.send(
            session.getUserId(),
            "Additional authentication required",
            "Please re-authenticate to continue your session"
        );
    }
}
```

---

## Step 3: Step-Up Authentication

### Trigger Step-Up

```java
@Aspect
@Component
public class StepUpAuthenticationAspect {

    @Autowired
    private SessionService sessionService;

    @Around("@annotation(RequiresStepUp)")
    public Object enforceStepUp(ProceedingJoinPoint joinPoint) throws Throwable {
        UserSession session = sessionService.getCurrentSession();

        // Check if step-up is recent enough
        if (session.getLastStepUpAt() != null &&
            session.getLastStepUpAt().isAfter(LocalDateTime.now().minusMinutes(15))) {
            // Step-up still valid
            return joinPoint.proceed();
        }

        // Require fresh authentication
        throw new StepUpRequiredException("Please re-authenticate");
    }
}

// Usage
@RequiresStepUp
@PostMapping("/admin/delete-user")
public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
    userService.deleteUser(userId);
    return ResponseEntity.ok().build();
}
```

### Step-Up Endpoint

```java
@PostMapping("/auth/step-up")
public ResponseEntity<?> stepUpAuthentication(
    @RequestBody StepUpRequest request,
    @AuthenticationPrincipal User user
) {
    // Verify credentials
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        throw new BadCredentialsException("Invalid credentials");
    }

    // Or require MFA
    if (user.isMfaEnabled()) {
        if (!totpService.validate(user, request.getTotpCode())) {
            throw new BadCredentialsException("Invalid MFA code");
        }
    }

    // Update session
    UserSession session = sessionService.getCurrentSession();
    session.setLastStepUpAt(LocalDateTime.now());
    sessionRepository.save(session);

    return ResponseEntity.ok().build();
}
```

---

## Step 4: Device Posture Assessment

### Device Health Checks

```java
@RestController
@RequestMapping("/api/device-posture")
public class DevicePostureController {

    @PostMapping("/report")
    public ResponseEntity<?> reportDevicePosture(
        @RequestBody DevicePostureReport report,
        @AuthenticationPrincipal User user
    ) {
        DevicePosture posture = assessPosture(report);

        // Save device posture
        devicePostureRepository.save(new DevicePostureRecord(
            user.getId(),
            report.getDeviceFingerprint(),
            posture,
            LocalDateTime.now()
        ));

        // Take action if unhealthy
        if (posture.getTrustLevel() == TrustLevel.UNTRUSTED) {
            return ResponseEntity.status(403).body(
                new PostureViolation("Device does not meet security requirements")
            );
        }

        return ResponseEntity.ok().build();
    }

    private DevicePosture assessPosture(DevicePostureReport report) {
        DevicePosture posture = new DevicePosture();

        // Check OS version
        if (isOsOutdated(report.getOsVersion())) {
            posture.addViolation("Outdated operating system");
            posture.decreaseTrust(0.3);
        }

        // Check encryption
        if (!report.isDiskEncrypted()) {
            posture.addViolation("Disk encryption disabled");
            posture.decreaseTrust(0.2);
        }

        // Check antivirus
        if (!report.isAntivirusActive()) {
            posture.addViolation("Antivirus not active");
            posture.decreaseTrust(0.1);
        }

        // Check for jailbreak/root
        if (report.isJailbroken()) {
            posture.addViolation("Device is jailbroken/rooted");
            posture.setTrustLevel(TrustLevel.UNTRUSTED);
        }

        // Check for screen lock
        if (!report.hasScreenLock()) {
            posture.addViolation("No screen lock configured");
            posture.decreaseTrust(0.1);
        }

        return posture;
    }
}
```

### Client-Side Posture Collection

```javascript
// Browser - limited capabilities
async function collectDevicePosture() {
    const report = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        cookiesEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack === "1"
    };

    // Send to server
    await fetch('/api/device-posture/report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        },
        body: JSON.stringify(report)
    });
}
```

**Note**: Mobile apps can collect more detailed posture (OS version, jailbreak detection, etc.)

---

## Step 5: Adaptive Authentication Policies

### Policy Engine

```java
@Service
public class AuthenticationPolicyService {

    public AuthenticationRequirement determineRequirement(AuthenticationContext context) {
        RiskScore risk = riskScoringService.calculateRiskScore(context);
        Resource resource = context.getRequestedResource();

        // High-risk access to sensitive resource
        if (risk.getLevel() == RiskLevel.HIGH && resource.getSensitivity() == Sensitivity.HIGH) {
            return AuthenticationRequirement.builder()
                .mfaRequired(true)
                .deviceTrustRequired(TrustLevel.TRUSTED)
                .maxSessionDuration(Duration.ofMinutes(15))
                .build();
        }

        // Medium risk
        if (risk.getLevel() == RiskLevel.MEDIUM) {
            return AuthenticationRequirement.builder()
                .mfaRequired(resource.getSensitivity() == Sensitivity.HIGH)
                .deviceTrustRequired(TrustLevel.KNOWN)
                .maxSessionDuration(Duration.ofHours(1))
                .build();
        }

        // Low risk - standard authentication
        return AuthenticationRequirement.builder()
            .mfaRequired(false)
            .deviceTrustRequired(TrustLevel.UNKNOWN)
            .maxSessionDuration(Duration.ofHours(8))
            .build();
    }
}
```

### Apply Policies

```java
@Component
public class AdaptiveAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain chain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            AuthenticationContext context = buildContext(request, auth);
            AuthenticationRequirement requirement = policyService.determineRequirement(context);

            // Check MFA requirement
            if (requirement.isMfaRequired() && !hasMfaInSession(request)) {
                response.sendRedirect("/mfa/challenge");
                return;
            }

            // Check device trust
            DevicePosture posture = getDevicePosture(request);
            if (posture.getTrustLevel().ordinal() < requirement.getDeviceTrustRequired().ordinal()) {
                response.sendError(403, "Device does not meet trust requirements");
                return;
            }

            // Check session duration
            UserSession session = getSession(request);
            if (session.getAge().compareTo(requirement.getMaxSessionDuration()) > 0) {
                response.sendRedirect("/auth/step-up");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
```

---

## Step 6: Behavioral Analytics

### Anomaly Detection

```java
@Service
public class BehavioralAnalyticsService {

    public boolean isAnomalousActivity(User user, UserActivity activity) {
        // Get user's normal behavior baseline
        BehaviorBaseline baseline = baselineRepository.findByUserId(user.getId())
            .orElse(createBaseline(user));

        double anomalyScore = 0.0;

        // Check access patterns
        if (!baseline.getTypicalResources().contains(activity.getResource())) {
            anomalyScore += 0.3;
        }

        // Check time of activity
        if (!baseline.getTypicalHours().contains(activity.getTimestamp().getHour())) {
            anomalyScore += 0.2;
        }

        // Check volume
        if (activity.getRequestCount() > baseline.getTypicalRequestCount() * 2) {
            anomalyScore += 0.3;
        }

        // Check data access
        if (activity.getDataAccessSize() > baseline.getTypicalDataAccess() * 3) {
            anomalyScore += 0.4;
        }

        return anomalyScore > 0.5;
    }

    @Scheduled(cron = "0 0 2 * * *")  // Daily at 2 AM
    public void updateBaselines() {
        List<User> users = userRepository.findAll();

        for (User user : users) {
            List<UserActivity> recentActivity = activityRepository
                .findByUserId(user.getId(), LocalDateTime.now().minusDays(30));

            BehaviorBaseline baseline = calculateBaseline(recentActivity);
            baselineRepository.save(baseline);
        }
    }
}
```

---

## Step 7: Context-Aware Access Control

### Resource Sensitivity Levels

```java
@Entity
public class Resource {
    @Id
    private Long id;

    private String path;

    @Enumerated(EnumType.STRING)
    private Sensitivity sensitivity;

    private boolean requiresEncryption;
    private boolean requiresAudit;
}

public enum Sensitivity {
    PUBLIC,      // Anyone can access
    INTERNAL,    // Authenticated users
    CONFIDENTIAL,  // Specific roles + MFA
    RESTRICTED,  // High trust + step-up
    SECRET       // Highest security
}
```

### Access Decision

```java
@Service
public class AccessDecisionService {

    public boolean canAccess(User user, Resource resource, AuthenticationContext context) {
        // Check sensitivity vs authentication strength
        switch (resource.getSensitivity()) {
            case PUBLIC:
                return true;

            case INTERNAL:
                return user.isAuthenticated();

            case CONFIDENTIAL:
                return user.isAuthenticated()
                    && hasRequiredRole(user, resource)
                    && (user.isMfaEnabled() || context.getRiskScore().getLevel() == RiskLevel.LOW);

            case RESTRICTED:
                return user.isAuthenticated()
                    && hasRequiredRole(user, resource)
                    && user.isMfaEnabled()
                    && context.getDevicePosture().getTrustLevel() == TrustLevel.TRUSTED
                    && context.hasRecentStepUp(Duration.ofMinutes(15));

            case SECRET:
                return user.isAuthenticated()
                    && hasRequiredRole(user, resource)
                    && user.isMfaEnabled()
                    && context.getDevicePosture().getTrustLevel() == TrustLevel.TRUSTED
                    && context.hasRecentStepUp(Duration.ofMinutes(5))
                    && !context.isRemoteAccess();  // Must be on corporate network

            default:
                return false;
        }
    }
}
```

---

## Step 8: Session Intelligence

### Smart Session Management

```java
@Service
public class IntelligentSessionService {

    public void adaptSessionTimeout(UserSession session) {
        RiskScore risk = riskScoringService.calculateRiskScore(session.getContext());

        Duration timeout;
        switch (risk.getLevel()) {
            case LOW:
                timeout = Duration.ofHours(8);
                break;
            case MEDIUM:
                timeout = Duration.ofHours(2);
                break;
            case HIGH:
                timeout = Duration.ofMinutes(30);
                break;
            case CRITICAL:
                timeout = Duration.ofMinutes(5);
                break;
            default:
                timeout = Duration.ofHours(1);
        }

        session.setTimeout(timeout);
        sessionRepository.save(session);
    }

    @EventListener
    public void onActivityDetected(UserActivityEvent event) {
        UserSession session = sessionRepository.findById(event.getSessionId())
            .orElse(null);

        if (session != null) {
            // Extend session on activity (if low risk)
            if (session.getRiskLevel() == RiskLevel.LOW) {
                session.extendExpiration(Duration.ofMinutes(30));
                sessionRepository.save(session);
            }
        }
    }
}
```

---

## What You've Accomplished

✅ Implemented continuous authentication
✅ Built risk scoring engine
✅ Created device posture assessment
✅ Added step-up authentication
✅ Implemented adaptive policies
✅ Built behavioral analytics
✅ Created context-aware access control
✅ Developed intelligent session management

**Congratulations! You've completed all 46 guides!** 🎉

---

## Next Steps

**You've Completed the Full Learning Path!**

Now you can:
- Build your own production-ready OAuth IdP
- Contribute to open-source identity projects
- Architect enterprise authentication systems
- Pursue security certifications (CISSP, CISM)
- Share your knowledge with others

**Advanced Learning**:
- NIST Zero Trust Architecture papers
- FIDO Alliance specifications
- OAuth 2.1 (upcoming spec)
- OpenID Connect extensions

---

## Key Concepts Learned

### Zero Trust Principles

1. **Verify Explicitly**: Use all available data
2. **Least Privilege**: Minimal necessary access
3. **Assume Breach**: Design for compromised network

### Continuous Authentication

- **One-Time Login is Insufficient**: Ongoing verification needed
- **Context Matters**: Device, location, time, behavior
- **Adaptive**: Security adjusts to risk level

### Risk-Based Security

- **Risk Scoring**: Quantify authentication risk
- **Adaptive Policies**: Stronger auth for higher risk
- **User Experience**: Balance security with usability

---

## Final Thoughts

Building a secure OAuth Identity Provider requires deep understanding of:
- **Protocols**: OAuth 2.0, OpenID Connect, WebAuthn, SAML
- **Security**: Cryptography, threat modeling, defense in depth
- **Architecture**: Scalability, reliability, observability
- **User Experience**: Balance security with usability

You now have the knowledge to build production-grade authentication systems. Keep learning, stay updated with latest security practices, and always prioritize user security.

**Thank you for completing this learning journey!** 🚀

---

## Additional Resources

- **NIST Zero Trust Architecture**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf
- **Google BeyondCorp**: https://cloud.google.com/beyondcorp
- **Microsoft Zero Trust**: https://www.microsoft.com/en-us/security/business/zero-trust
- **CISA Zero Trust Maturity Model**: https://www.cisa.gov/zero-trust-maturity-model
- **OAuth 2.0 Security Best Practices**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
