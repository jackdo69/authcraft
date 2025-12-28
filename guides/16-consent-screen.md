# Guide 16: Build Consent Screen

**Phase 4: User Experience** | **Week 7-8** | **Task 16 of 30**

## Overview

Create a professional, user-friendly consent screen that clearly communicates what permissions an application is requesting. Implement consent storage to remember user decisions and provide granular control over granted permissions.

---

## What You'll Build

- Enhanced consent UI with clear scope descriptions
- Consent persistence in database
- Remember consent functionality
- Granular scope selection
- Consent management page

---

## Why Consent Screens Matter?

### User Trust

**Users need to understand**:
- What application is requesting access
- What data will be accessed
- What actions the app can perform
- How to revoke access later

### Legal Requirements

**GDPR, CCPA, privacy laws** require:
- Informed consent
- Clear purpose statements
- Ability to withdraw consent
- Granular permission control

### Security

**Well-designed consent** prevents:
- Over-permissioned applications
- User confusion and errors
- Phishing attempts (users recognize legitimate consent screens)

**Learn More**: https://www.oauth.com/oauth2-servers/authorization/the-authorization-interface/

---

## Step 1: Design Consent Data Model

### UserConsent Entity

Location: `src/main/java/com/learning/idp/model/UserConsent.java`

```java
@Entity
@Table(name = "user_consents")
@Data
@NoArgsConstructor
public class UserConsent {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "user_id", nullable = false)
    private Long userId;
    
    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @Column(name = "scopes", length = 500, nullable = false)
    private String scopes;  // Granted scopes
    
    @Column(name = "granted_at", nullable = false)
    private LocalDateTime grantedAt;
    
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;  // Optional: consent expiration
    
    @Column(name = "remember_consent", nullable = false)
    private boolean rememberConsent = true;
}
```

### Create Migration

`V14__create_user_consents_table.sql`:

```sql
CREATE TABLE user_consents (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes VARCHAR(500) NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    remember_consent BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    UNIQUE(user_id, client_id)
);

CREATE INDEX idx_user_consents_user_client ON user_consents(user_id, client_id);
```

---

## Step 2: Create Scope Registry

### Define Standard Scopes

Create `Scope` entity for human-readable descriptions:

```java
@Entity
@Table(name = "scopes")
@Data
public class Scope {
    
    @Id
    private String name;  // e.g., "openid"
    
    @Column(nullable = false)
    private String displayName;  // e.g., "OpenID Connect"
    
    @Column(length = 500)
    private String description;  // User-friendly explanation
    
    @Column
    private String category;  // "identity", "profile", "api"
    
    @Column(nullable = false)
    private boolean userConsent required = true;  // Require explicit consent
}
```

### Migration with Seed Data

`V15__create_scopes_table.sql`:

```sql
CREATE TABLE scopes (
    name VARCHAR(100) PRIMARY KEY,
    display_name VARCHAR(200) NOT NULL,
    description VARCHAR(500),
    category VARCHAR(50),
    user_consent_required BOOLEAN NOT NULL DEFAULT TRUE
);

-- Seed standard OIDC scopes
INSERT INTO scopes (name, display_name, description, category, user_consent_required) VALUES
('openid', 'OpenID Connect', 'Verify your identity', 'identity', TRUE),
('profile', 'Profile Information', 'Access your profile (name, picture, etc.)', 'profile', TRUE),
('email', 'Email Address', 'Access your email address', 'profile', TRUE),
('address', 'Address', 'Access your postal address', 'profile', TRUE),
('phone', 'Phone Number', 'Access your phone number', 'profile', TRUE);

-- Add custom API scopes
INSERT INTO scopes (name, display_name, description, category) VALUES
('api.read', 'Read API Access', 'Read data from APIs', 'api'),
('api.write', 'Write API Access', 'Create or modify data via APIs', 'api');
```

---

## Step 3: Create Consent Service

### ConsentService.java

```java
@Service
@RequiredArgsConstructor
public class ConsentService {
    
    private final UserConsentRepository userConsentRepository;
    private final ScopeRepository scopeRepository;
    
    /**
     * Check if user has previously consented to these exact scopes
     */
    public Optional<UserConsent> findExistingConsent(
            Long userId, 
            String clientId,
            Set<String> requestedScopes) {
        
        Optional<UserConsent> consent = userConsentRepository
            .findByUserIdAndClientId(userId, clientId);
        
        if (consent.isPresent()) {
            Set<String> grantedScopes = Set.of(
                consent.get().getScopes().split("\\s+")
            );
            
            // Check if granted scopes cover requested scopes
            if (grantedScopes.containsAll(requestedScopes)) {
                // Check expiration
                if (consent.get().getExpiresAt() == null ||
                    consent.get().getExpiresAt().isAfter(LocalDateTime.now())) {
                    return consent;
                }
            }
        }
        
        return Optional.empty();
    }
    
    /**
     * Save user's consent decision
     */
    public void saveConsent(Long userId, String clientId, 
                           Set<String> scopes, boolean rememberConsent) {
        
        UserConsent consent = userConsentRepository
            .findByUserIdAndClientId(userId, clientId)
            .orElse(new UserConsent());
        
        consent.setUserId(userId);
        consent.setClientId(clientId);
        consent.setScopes(String.join(" ", scopes));
        consent.setGrantedAt(LocalDateTime.now());
        consent.setRememberConsent(rememberConsent);
        
        // Optional: Set expiration (e.g., 1 year)
        if (rememberConsent) {
            consent.setExpiresAt(LocalDateTime.now().plusYears(1));
        }
        
        userConsentRepository.save(consent);
    }
    
    /**
     * Revoke consent
     */
    public void revokeConsent(Long userId, String clientId) {
        userConsentRepository.deleteByUserIdAndClientId(userId, clientId);
    }
    
    /**
     * Get scope details for display
     */
    public List<ScopeDisplay> getScopeDisplayInfo(Set<String> scopes) {
        return scopes.stream()
            .map(scopeName -> {
                Scope scope = scopeRepository.findById(scopeName)
                    .orElse(createDefaultScope(scopeName));
                    
                return new ScopeDisplay(
                    scope.getName(),
                    scope.getDisplayName(),
                    scope.getDescription()
                );
            })
            .collect(Collectors.toList());
    }
    
    private Scope createDefaultScope(String scopeName) {
        // Fallback for unregistered scopes
        Scope scope = new Scope();
        scope.setName(scopeName);
        scope.setDisplayName(scopeName);
        scope.setDescription("Access to " + scopeName);
        return scope;
    }
}
```

---

## Step 4: Update Authorization Endpoint

### Check Existing Consent

In `AuthorizationController`, before showing consent screen:

```java
@GetMapping("/oauth2/authorize")
public String authorize(@Valid @ModelAttribute AuthorizationRequest request,
                       Principal principal,
                       Model model) {
    
    // ... existing validation ...
    
    // Check if user already consented
    Long userId = getUserId(principal);
    Set<String> requestedScopes = request.getScopes();
    
    Optional<UserConsent> existingConsent = consentService.findExistingConsent(
        userId,
        request.getClientId(),
        requestedScopes
    );
    
    if (existingConsent.isPresent() && existingConsent.get().isRememberConsent()) {
        // Skip consent screen - auto-approve
        return handleConsentApproval(request, requestedScopes, principal);
    }
    
    // Show consent screen
    return showConsentScreen(request, model);
}
```

### Prepare Consent Screen Data

```java
private String showConsentScreen(AuthorizationRequest request, Model model) {
    
    Client client = clientService.findByClientId(request.getClientId());
    List<ScopeDisplay> scopes = consentService.getScopeDisplayInfo(
        request.getScopes()
    );
    
    model.addAttribute("client", client);
    model.addAttribute("scopes", scopes);
    model.addAttribute("authRequest", request);
    
    return "consent";
}
```

---

## Step 5: Create Enhanced Consent Template

### consent.html

Location: `src/main/resources/templates/consent.html`

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Authorization Request</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
        }
        .app-info {
            text-align: center;
            margin-bottom: 30px;
        }
        .app-logo {
            width: 64px;
            height: 64px;
            border-radius: 12px;
        }
        .app-name {
            font-size: 24px;
            font-weight: 600;
            margin: 10px 0;
        }
        .permissions-header {
            font-size: 16px;
            font-weight: 500;
            margin: 20px 0 10px 0;
        }
        .permission-item {
            display: flex;
            align-items: start;
            padding: 12px;
            margin: 8px 0;
            background: #f5f5f5;
            border-radius: 8px;
        }
        .permission-icon {
            margin-right: 12px;
            font-size: 20px;
        }
        .permission-details {
            flex: 1;
        }
        .permission-name {
            font-weight: 500;
            margin-bottom: 4px;
        }
        .permission-description {
            font-size: 14px;
            color: #666;
        }
        .checkbox-container {
            margin: 20px 0;
        }
        .button-container {
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }
        .btn {
            flex: 1;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
        }
        .btn-approve {
            background: #007aff;
            color: white;
        }
        .btn-deny {
            background: #f0f0f0;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="app-info">
        <img th:src="@{${client.logoUrl}}" 
             th:alt="${client.clientName}"
             class="app-logo"
             onerror="this.style.display='none'"/>
        <div class="app-name" th:text="${client.clientName}">Application Name</div>
        <p style="color: #666;">wants to access your account</p>
    </div>

    <div class="permissions-header">This will allow the app to:</div>

    <div th:each="scope : ${scopes}" class="permission-item">
        <div class="permission-icon">✓</div>
        <div class="permission-details">
            <div class="permission-name" th:text="${scope.displayName}">Permission Name</div>
            <div class="permission-description" th:text="${scope.description}">
                Permission description
            </div>
        </div>
    </div>

    <form method="post" th:action="@{/oauth2/authorize/consent}">
        <!-- Hidden fields to preserve authorization request -->
        <input type="hidden" name="client_id" th:value="${authRequest.clientId}"/>
        <input type="hidden" name="redirect_uri" th:value="${authRequest.redirectUri}"/>
        <input type="hidden" name="scope" th:value="${authRequest.scope}"/>
        <input type="hidden" name="state" th:value="${authRequest.state}"/>
        <input type="hidden" name="response_type" th:value="${authRequest.responseType}"/>
        <input type="hidden" name="code_challenge" th:value="${authRequest.codeChallenge}"/>
        <input type="hidden" name="code_challenge_method" 
               th:value="${authRequest.codeChallengeMethod}"/>

        <div class="checkbox-container">
            <label>
                <input type="checkbox" name="remember_consent" value="true" checked/>
                Don't ask again for this app
            </label>
        </div>

        <div class="button-container">
            <button type="submit" name="action" value="deny" class="btn btn-deny">
                Cancel
            </button>
            <button type="submit" name="action" value="approve" class="btn btn-approve">
                Allow
            </button>
        </div>
    </form>

    <div style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
        <p>By clicking Allow, you allow this app to use your information in 
           accordance with their terms of service and privacy policy.</p>
        <a href="/oauth2/consents" style="color: #007aff;">Manage your consents</a>
    </div>
</body>
</html>
```

---

## Step 6: Handle Consent Decision

### Process Approval/Denial

```java
@PostMapping("/oauth2/authorize/consent")
public String handleConsent(@Valid @ModelAttribute AuthorizationRequest request,
                           @RequestParam String action,
                           @RequestParam(required = false) boolean rememberConsent,
                           Principal principal) {
    
    if ("deny".equals(action)) {
        // User denied - redirect with error
        return redirectWithError(
            request.getRedirectUri(),
            "access_denied",
            "User denied authorization",
            request.getState()
        );
    }
    
    // User approved
    Long userId = getUserId(principal);
    Set<String> scopes = request.getScopes();
    
    // Save consent if remember checked
    if (rememberConsent) {
        consentService.saveConsent(
            userId,
            request.getClientId(),
            scopes,
            true
        );
    }
    
    // Generate authorization code and redirect
    return handleConsentApproval(request, scopes, principal);
}
```

---

## Step 7: Create Consent Management Page

### List User's Consents

`ConsentsController.java`:

```java
@Controller
@RequestMapping("/oauth2/consents")
@RequiredArgsConstructor
public class ConsentsController {
    
    private final ConsentService consentService;
    private final ClientService clientService;
    
    @GetMapping
    public String listConsents(Principal principal, Model model) {
        Long userId = getUserId(principal);
        
        List<UserConsent> consents = consentService.findByUserId(userId);
        
        // Enrich with client details
        List<ConsentDisplay> displayConsents = consents.stream()
            .map(consent -> {
                Client client = clientService.findByClientId(consent.getClientId());
                return new ConsentDisplay(
                    consent.getId(),
                    client.getClientName(),
                    consent.getScopes(),
                    consent.getGrantedAt()
                );
            })
            .collect(Collectors.toList());
        
        model.addAttribute("consents", displayConsents);
        return "consents";
    }
    
    @PostMapping("/{id}/revoke")
    public String revokeConsent(@PathVariable Long id, Principal principal) {
        Long userId = getUserId(principal);
        
        UserConsent consent = consentService.findById(id);
        if (consent.getUserId().equals(userId)) {
            consentService.revokeConsent(userId, consent.getClientId());
            
            // Also revoke associated tokens
            tokenRevocationService.revokeAllTokens(userId, consent.getClientId());
        }
        
        return "redirect:/oauth2/consents";
    }
}
```

### consents.html Template

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Manage Consents</title>
</head>
<body>
    <h1>Apps with Access to Your Account</h1>
    
    <div th:if="${#lists.isEmpty(consents)}">
        <p>You haven't authorized any apps yet.</p>
    </div>
    
    <div th:each="consent : ${consents}" class="consent-item">
        <h3 th:text="${consent.clientName}">App Name</h3>
        <p>Permissions: <span th:text="${consent.scopes}">scopes</span></p>
        <p>Granted: <span th:text="${#temporals.format(consent.grantedAt, 'yyyy-MM-dd HH:mm')}">date</span></p>
        
        <form method="post" th:action="@{/oauth2/consents/{id}/revoke(id=${consent.id})}">
            <button type="submit">Revoke Access</button>
        </form>
    </div>
</body>
</html>
```

---

## Step 8: Testing Consent Flow

### Test Case 1: First-Time Consent

**1. Start authorization**: Navigate to authorization URL
**2. Login**: Complete authentication
**3. Consent screen**: Should show scope descriptions
**4. Approve**: Check "remember" and click Allow
**5. Verify database**:
```sql
SELECT * FROM user_consents WHERE user_id = X AND client_id = 'demo-client';
```

### Test Case 2: Skip Consent on Second Request

**1. Repeat authorization** with same client and scopes
**2. Expected**: No consent screen, direct redirect with code

### Test Case 3: New Scopes Require Consent

**1. Authorization with additional scope**
**2. Expected**: Consent screen shows again (new permissions)

### Test Case 4: Revoke Consent

**1. Visit** `/oauth2/consents`
**2. Click "Revoke Access"** for a client
**3. Verify**: Consent removed from database
**4. Next authorization**: Shows consent screen again

---

## Common Issues

### Consent not remembered

**Cause**: checkbox not checked or data not saved

**Solution**: Verify form submission includes `remember_consent` parameter

### Consent screen shows every time

**Cause**: Scopes don't match exactly

**Solution**: Ensure scope comparison uses sets (order doesn't matter)

### Layout broken on mobile

**Solution**: Add responsive CSS with media queries

---

## What You've Accomplished

✅ Created professional consent screen UI
✅ Implemented consent persistence
✅ Added remember consent functionality
✅ Built scope registry with descriptions
✅ Created consent management page
✅ Implemented consent revocation

---

## Next Steps

**Proceed to Guide 17**: Scope Management

Before moving on:
- [ ] Consent screen displays clearly
- [ ] Scopes have user-friendly descriptions
- [ ] Consent is saved when remembered
- [ ] Subsequent authorizations skip consent
- [ ] Users can view and revoke consents

---

## Key Concepts Learned

### User Consent
- Informed authorization required
- Clear communication of permissions
- User control over access

### Consent Persistence
- Remember user decisions
- Skip consent for known grants
- Expiration and renewal

### Scope Descriptions
- Technical scopes → user-friendly language
- Categorization for clarity
- Transparency in permissions

---

## Additional Resources

- **OAuth Consent Best Practices**: https://www.oauth.com/oauth2-servers/authorization/the-authorization-interface/
- **GDPR Consent Requirements**: https://gdpr-info.eu/art-7-gdpr/
- **Google Consent Screen**: https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
