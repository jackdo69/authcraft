# Guide 44: Passwordless Authentication with WebAuthn and Passkeys

**Advanced Topics** | **Task 44 of 45**

## Overview

Implement passwordless authentication using WebAuthn (FIDO2) and Passkeys. Allow users to log in with biometrics (Face ID, Touch ID, Windows Hello) or hardware security keys (YubiKey) instead of passwords. The future of authentication.

---

## What You'll Build

- WebAuthn registration flow
- WebAuthn authentication flow
- Passkey support (synced across devices)
- Fallback to password
- Credential management UI
- Attestation validation
- Resident credentials (discoverable credentials)

---

## Why Passwordless?

### Problems with Passwords

**Forgotten**: Users forget passwords
**Weak**: Users choose weak passwords
**Reused**: Same password across sites (credential stuffing)
**Phishable**: Can be stolen via phishing

### WebAuthn Benefits

**Phishing-Resistant**: Cryptographic challenge tied to domain
**No Shared Secrets**: Private key never leaves device
**Biometric**: Face ID, Touch ID, fingerprint
**Hardware Keys**: YubiKey, Titan Key
**Synced Passkeys**: iCloud Keychain, Google Password Manager

**Learn More**: https://webauthn.guide/

---

## Step 1: Add WebAuthn Dependencies

### Maven Dependencies

```xml
<dependencies>
    <!-- Yubico WebAuthn library -->
    <dependency>
        <groupId>com.yubico</groupId>
        <artifactId>webauthn-server-core</artifactId>
        <version>2.5.0</version>
    </dependency>
    <dependency>
        <groupId>com.yubico</groupId>
        <artifactId>webauthn-server-attestation</artifactId>
        <version>2.5.0</version>
    </dependency>
</dependencies>
```

---

## Step 2: Database Schema for Credentials

### Create Migration

`V17__create_webauthn_credentials.sql`:

```sql
CREATE TABLE webauthn_credentials (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key_cose BYTEA NOT NULL,
    signature_count BIGINT NOT NULL DEFAULT 0,
    credential_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    attestation_statement JSONB,
    user_handle BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    device_name VARCHAR(255),
    is_resident_key BOOLEAN DEFAULT FALSE,
    transports TEXT[],

    CONSTRAINT fk_credential_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_credentials_user ON webauthn_credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX idx_credentials_user_handle ON webauthn_credentials(user_handle);
```

**credential_id**: Unique identifier for the credential
**public_key_cose**: Public key in COSE format
**signature_count**: Counter to detect cloned authenticators
**user_handle**: User identifier (for resident keys)

---

## Step 3: Implement Registration (Creating Passkey)

### Backend - Start Registration

```java
@RestController
@RequestMapping("/api/webauthn")
public class WebAuthnController {

    @Autowired
    private WebAuthnService webAuthnService;

    @PostMapping("/register/start")
    public PublicKeyCredentialCreationOptions startRegistration(
        @AuthenticationPrincipal User user
    ) {
        return webAuthnService.startRegistration(user);
    }

    @PostMapping("/register/finish")
    public ResponseEntity<?> finishRegistration(
        @AuthenticationPrincipal User user,
        @RequestBody RegistrationResponse response
    ) {
        webAuthnService.finishRegistration(user, response);
        return ResponseEntity.ok().build();
    }
}
```

### WebAuthn Service

```java
@Service
public class WebAuthnService {

    private final RelyingParty relyingParty;
    private final CredentialRepository credentialRepository;
    private final Map<ByteArray, PublicKeyCredentialCreationOptions> registrationsByUserHandle = new ConcurrentHashMap<>();

    public WebAuthnService(CredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;

        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
            .id("idp.example.com")  // Domain
            .name("My OAuth IdP")
            .build();

        this.relyingParty = RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(credentialRepository)
            .allowOriginPort(false)  // Production: must match exactly
            .build();
    }

    public PublicKeyCredentialCreationOptions startRegistration(User user) {
        ByteArray userHandle = ByteArray.fromBase64(user.getWebAuthnUserHandle());

        PublicKeyCredentialCreationOptions request = relyingParty.startRegistration(
            StartRegistrationOptions.builder()
                .user(UserIdentity.builder()
                    .name(user.getEmail())
                    .displayName(user.getFirstName() + " " + user.getLastName())
                    .id(userHandle)
                    .build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                    .userVerification(UserVerificationRequirement.PREFERRED)
                    .residentKey(ResidentKeyRequirement.PREFERRED)  // Enable passkeys
                    .build())
                .build()
        );

        // Store temporarily for verification
        registrationsByUserHandle.put(userHandle, request);

        return request;
    }

    public void finishRegistration(User user, RegistrationResponse response) {
        ByteArray userHandle = ByteArray.fromBase64(user.getWebAuthnUserHandle());

        PublicKeyCredentialCreationOptions request = registrationsByUserHandle.get(userHandle);

        if (request == null) {
            throw new IllegalStateException("Registration not started");
        }

        try {
            RegistrationResult result = relyingParty.finishRegistration(
                FinishRegistrationOptions.builder()
                    .request(request)
                    .response(parseRegistrationResponse(response))
                    .build()
            );

            // Save credential
            WebAuthnCredential credential = new WebAuthnCredential();
            credential.setUserId(user.getId());
            credential.setCredentialId(result.getKeyId().getId().getBytes());
            credential.setPublicKeyCose(result.getPublicKeyCose().getBytes());
            credential.setSignatureCount(result.getSignatureCount());
            credential.setUserHandle(userHandle.getBytes());
            credential.setIsResidentKey(result.isResidentKey());

            credentialRepository.save(credential);

        } finally {
            registrationsByUserHandle.remove(userHandle);
        }
    }
}
```

### Frontend - Registration

```html
<button id="register-passkey">Register Passkey</button>

<script>
document.getElementById('register-passkey').addEventListener('click', async () => {
    // Step 1: Get challenge from server
    const optionsResponse = await fetch('/api/webauthn/register/start', {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + accessToken
        }
    });
    const options = await optionsResponse.json();

    // Convert base64url to Uint8Array
    options.challenge = base64urlToUint8Array(options.challenge);
    options.user.id = base64urlToUint8Array(options.user.id);

    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(cred => ({
            ...cred,
            id: base64urlToUint8Array(cred.id)
        }));
    }

    // Step 2: Create credential
    const credential = await navigator.credentials.create({
        publicKey: options
    });

    // Step 3: Send to server
    const finishResponse = await fetch('/api/webauthn/register/finish', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + accessToken
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            response: {
                attestationObject: uint8ArrayToBase64url(new Uint8Array(credential.response.attestationObject)),
                clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON))
            },
            type: credential.type
        })
    });

    if (finishResponse.ok) {
        alert('Passkey registered successfully!');
    }
});

function base64urlToUint8Array(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function uint8ArrayToBase64url(array) {
    const binary = String.fromCharCode(...array);
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
</script>
```

---

## Step 4: Implement Authentication (Login with Passkey)

### Backend - Start Authentication

```java
@PostMapping("/authenticate/start")
public PublicKeyCredentialRequestOptions startAuthentication() {
    return webAuthnService.startAuthentication();
}

@PostMapping("/authenticate/finish")
public ResponseEntity<?> finishAuthentication(
    @RequestBody AuthenticationResponse response
) {
    User user = webAuthnService.finishAuthentication(response);

    // Generate OAuth tokens
    String accessToken = tokenService.generateAccessToken(user);
    String refreshToken = tokenService.generateRefreshToken(user);

    return ResponseEntity.ok(new TokenResponse(accessToken, refreshToken));
}
```

### WebAuthn Service - Authentication

```java
public PublicKeyCredentialRequestOptions startAuthentication() {
    AssertionRequest request = relyingParty.startAssertion(
        StartAssertionOptions.builder()
            .userVerification(UserVerificationRequirement.PREFERRED)
            .build()
    );

    // Store temporarily
    String requestId = UUID.randomUUID().toString();
    assertionRequests.put(requestId, request);

    return request.getPublicKeyCredentialRequestOptions();
}

public User finishAuthentication(AuthenticationResponse response) {
    AssertionRequest request = assertionRequests.get(response.getRequestId());

    if (request == null) {
        throw new IllegalStateException("Authentication not started");
    }

    try {
        AssertionResult result = relyingParty.finishAssertion(
            FinishAssertionOptions.builder()
                .request(request)
                .response(parseAuthenticationResponse(response))
                .build()
        );

        if (!result.isSuccess()) {
            throw new AuthenticationException("Authentication failed");
        }

        // Get user from credential
        WebAuthnCredential credential = credentialRepository
            .findByCredentialId(result.getCredentialId())
            .orElseThrow(() -> new CredentialNotFoundException());

        // Update signature counter (detect cloning)
        if (result.getSignatureCount() <= credential.getSignatureCount()) {
            throw new SecurityException("Cloned authenticator detected");
        }

        credential.setSignatureCount(result.getSignatureCount());
        credential.setLastUsedAt(LocalDateTime.now());
        credentialRepository.save(credential);

        return userService.findById(credential.getUserId())
            .orElseThrow(() -> new UserNotFoundException());

    } finally {
        assertionRequests.remove(response.getRequestId());
    }
}
```

### Frontend - Authentication

```html
<button id="login-passkey">Sign in with Passkey</button>

<script>
document.getElementById('login-passkey').addEventListener('click', async () => {
    // Step 1: Get challenge
    const optionsResponse = await fetch('/api/webauthn/authenticate/start', {
        method: 'POST'
    });
    const options = await optionsResponse.json();

    // Convert base64url to Uint8Array
    options.challenge = base64urlToUint8Array(options.challenge);

    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(cred => ({
            ...cred,
            id: base64urlToUint8Array(cred.id)
        }));
    }

    // Step 2: Get credential
    const credential = await navigator.credentials.get({
        publicKey: options
    });

    // Step 3: Send to server
    const finishResponse = await fetch('/api/webauthn/authenticate/finish', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            response: {
                authenticatorData: uint8ArrayToBase64url(new Uint8Array(credential.response.authenticatorData)),
                clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
                signature: uint8ArrayToBase64url(new Uint8Array(credential.response.signature)),
                userHandle: credential.response.userHandle ? uint8ArrayToBase64url(new Uint8Array(credential.response.userHandle)) : null
            },
            type: credential.type
        })
    });

    const tokens = await finishResponse.json();
    localStorage.setItem('access_token', tokens.access_token);

    alert('Logged in successfully!');
    window.location.href = '/dashboard';
});
</script>
```

---

## Step 5: Conditional UI (AutoFill)

### Passkey AutoFill

```html
<form>
    <input type="text" id="username" autocomplete="username webauthn" />
    <input type="password" id="password" autocomplete="current-password" />
    <button type="submit">Sign In</button>
</form>

<script>
// Conditional mediation - show passkey in autofill
const options = await fetch('/api/webauthn/authenticate/start').then(r => r.json());

options.challenge = base64urlToUint8Array(options.challenge);
options.mediation = 'conditional';  // Enable autofill

const credential = await navigator.credentials.get({
    publicKey: options
}).catch(err => {
    // User dismissed or no passkey available
    console.log('Passkey autofill not used');
});

if (credential) {
    // Authenticate with passkey
    // ... send to server
}
</script>
```

**User Experience**: Passkeys appear in autofill dropdown alongside saved passwords

---

## Step 6: Credential Management

### List User Credentials

```java
@GetMapping("/credentials")
public List<CredentialInfo> listCredentials(@AuthenticationPrincipal User user) {
    return credentialRepository.findByUserId(user.getId())
        .stream()
        .map(cred -> new CredentialInfo(
            cred.getId(),
            cred.getDeviceName(),
            cred.getCreatedAt(),
            cred.getLastUsedAt(),
            cred.getIsResidentKey()
        ))
        .collect(Collectors.toList());
}

@DeleteMapping("/credentials/{id}")
public ResponseEntity<?> deleteCredential(
    @AuthenticationPrincipal User user,
    @PathVariable Long id
) {
    WebAuthnCredential credential = credentialRepository.findById(id)
        .orElseThrow(() -> new CredentialNotFoundException());

    if (!credential.getUserId().equals(user.getId())) {
        throw new UnauthorizedException();
    }

    credentialRepository.delete(credential);
    return ResponseEntity.ok().build();
}
```

### Frontend - Credential List

```html
<h3>Your Passkeys</h3>
<ul id="credential-list"></ul>

<script>
async function loadCredentials() {
    const response = await fetch('/api/webauthn/credentials', {
        headers: {
            'Authorization': 'Bearer ' + accessToken
        }
    });
    const credentials = await response.json();

    const list = document.getElementById('credential-list');
    list.innerHTML = '';

    credentials.forEach(cred => {
        const li = document.createElement('li');
        li.innerHTML = `
            ${cred.deviceName || 'Unnamed Device'}
            <span>Created: ${new Date(cred.createdAt).toLocaleDateString()}</span>
            <button onclick="deleteCredential(${cred.id})">Remove</button>
        `;
        list.appendChild(li);
    });
}

async function deleteCredential(id) {
    if (!confirm('Remove this passkey?')) return;

    await fetch(`/api/webauthn/credentials/${id}`, {
        method: 'DELETE',
        headers: {
            'Authorization': 'Bearer ' + accessToken
        }
    });

    loadCredentials();
}

loadCredentials();
</script>
```

---

## Step 7: Platform vs Cross-Platform Authenticators

### Platform Authenticators

**Definition**: Built into device (Face ID, Touch ID, Windows Hello)
**Pros**: Convenient, always available
**Cons**: Tied to single device (unless using passkeys)

### Cross-Platform Authenticators

**Definition**: External hardware (YubiKey, Titan Key)
**Pros**: Portable across devices
**Cons**: User must carry key

### Configuration

```java
AuthenticatorSelectionCriteria.builder()
    .authenticatorAttachment(AuthenticatorAttachment.PLATFORM)  // Face ID, Touch ID
    // or
    .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)  // YubiKey
    .build()
```

---

## Common Issues

### Browser Compatibility

**Problem**: WebAuthn not supported in old browsers

**Solution**: Check support and provide fallback:
```javascript
if (!window.PublicKeyCredential) {
    alert('Passkeys not supported. Please use password login.');
    // Show password form
}
```

### User Cancelled

**Problem**: User dismisses biometric prompt

**Solution**: Handle DOMException:
```javascript
try {
    const credential = await navigator.credentials.get({publicKey: options});
} catch (err) {
    if (err.name === 'NotAllowedError') {
        console.log('User cancelled');
    }
}
```

### Signature Counter Mismatch

**Problem**: Counter decreased (cloned authenticator)

**Solution**: Lock account and alert user
```java
if (result.getSignatureCount() <= credential.getSignatureCount()) {
    alertService.sendSecurityAlert(user, "Cloned authenticator detected");
    accountLockService.lockAccount(user.getId());
    throw new SecurityException("Cloned authenticator");
}
```

---

## What You've Accomplished

✅ Implemented WebAuthn registration
✅ Built passwordless authentication
✅ Added passkey support (synced credentials)
✅ Created credential management UI
✅ Implemented autofill integration
✅ Added fallback to password
✅ Detected cloned authenticators

---

## Next Steps

**Proceed to Guide 45**: Zero Trust Architecture (Final Guide!)

Before moving on:
- [ ] Users can register passkeys
- [ ] Passwordless login working
- [ ] Passkey autofill functional
- [ ] Credential management UI complete
- [ ] Tested on multiple devices/browsers

---

## Key Concepts Learned

### WebAuthn Flow

1. **Registration**: Create keypair, store public key on server
2. **Authentication**: Sign challenge with private key, verify signature
3. **No Shared Secrets**: Private key never leaves device

### Passkeys vs Traditional WebAuthn

**Traditional**: Credential bound to device
**Passkeys**: Synced via iCloud Keychain / Google Password Manager
**Benefit**: Same passkey works on all your devices

### Security Benefits

- **Phishing-Resistant**: Domain-bound challenge
- **No Password Database**: Nothing to steal
- **Hardware-Backed**: TPM, Secure Enclave

---

## Additional Resources

- **WebAuthn Guide**: https://webauthn.guide/
- **W3C WebAuthn Spec**: https://www.w3.org/TR/webauthn-2/
- **Yubico WebAuthn Library**: https://github.com/Yubico/java-webauthn-server
- **Passkeys.dev**: https://passkeys.dev/
- **FIDO Alliance**: https://fidoalliance.org/
