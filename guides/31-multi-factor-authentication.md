# Guide 31: Multi-Factor Authentication (MFA)

**Advanced Topics** | **Task 31 of 45**

## Overview

Add multi-factor authentication to enhance security with TOTP (Time-Based One-Time Password) support using authenticator apps.

---

## What You'll Build

- MFA enrollment flow
- TOTP generation and verification
- QR code generation for setup
- Backup codes
- MFA enforcement policies

---

## Step 1: Add Dependencies

```xml
<dependency>
    <groupId>dev.samstevens.totp</groupId>
    <artifactId>totp</artifactId>
    <version>1.7.1</version>
</dependency>
<dependency>
    <groupId>com.google.zxing</groupId>
    <artifactId>javase</artifactId>
    <version>3.5.1</version>
</dependency>
```

---

## Step 2: Update User Entity

```java
@Column(name = "mfa_enabled")
private boolean mfaEnabled = false;

@Column(name = "mfa_secret", length = 32)
private String mfaSecret;  // Encrypted

@Column(name = "backup_codes", length = 500)
private String backupCodes;  // Encrypted, comma-separated
```

---

## Step 3: Implement MFA Service

```java
@Service
public class MfaService {
    
    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    
    public String generateSecret() {
        return secretGenerator.generate();
    }
    
    public String generateQrCodeUri(String secret, String username) {
        return "otpauth://totp/MyApp:" + username + "?secret=" + secret + "&issuer=MyApp";
    }
    
    public boolean verifyCode(String secret, String code) {
        return codeVerifier.isValidCode(secret, code);
    }
    
    public List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();
        
        for (int i = 0; i < 10; i++) {
            codes.add(String.format("%08d", random.nextInt(100000000)));
        }
        
        return codes;
    }
}
```

---

## Step 4: MFA Enrollment Endpoint

```java
@PostMapping("/api/mfa/enable")
public ResponseEntity<MfaEnrollmentResponse> enableMfa(Principal principal) {
    User user = getUserFromPrincipal(principal);
    
    String secret = mfaService.generateSecret();
    String qrUri = mfaService.generateQrCodeUri(secret, user.getUsername());
    List<String> backupCodes = mfaService.generateBackupCodes();
    
    // Store encrypted
    user.setMfaSecret(encrypt(secret));
    user.setBackupCodes(encrypt(String.join(",", backupCodes)));
    user.setMfaEnabled(false);  // Not enabled until verified
    userRepository.save(user);
    
    return ResponseEntity.ok(MfaEnrollmentResponse.builder()
        .qrCode(generateQrCodeImage(qrUri))
        .manualEntryKey(secret)
        .backupCodes(backupCodes)
        .build());
}

@PostMapping("/api/mfa/verify")
public ResponseEntity<Void> verifyMfa(@RequestParam String code, Principal principal) {
    User user = getUserFromPrincipal(principal);
    String secret = decrypt(user.getMfaSecret());
    
    if (mfaService.verifyCode(secret, code)) {
        user.setMfaEnabled(true);
        userRepository.save(user);
        return ResponseEntity.ok().build();
    }
    
    return ResponseEntity.status(400).build();
}
```

---

## Step 5: MFA Login Flow

```java
@Component
public class MfaAuthenticationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response,
                                   FilterChain filterChain) {
        
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        if (auth != null && auth.isAuthenticated()) {
            User user = getUserFromAuth(auth);
            
            if (user.isMfaEnabled() && !isMfaVerified(request.getSession())) {
                // Redirect to MFA verification page
                response.sendRedirect("/mfa-verify");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

---

## Key Concepts

- **TOTP**: RFC 6238 time-based one-time passwords
- **QR Code**: Easy enrollment via authenticator apps
- **Backup Codes**: Recovery when device unavailable
- **Verification**: Prove possession before enabling

---

## Resources

- **RFC 6238 (TOTP)**: https://datatracker.ietf.org/doc/html/rfc6238
- **Google Authenticator**: Compatible TOTP implementation
- **TOTP Java Library**: https://github.com/samdjstevens/java-totp
