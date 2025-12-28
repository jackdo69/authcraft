# Guide 37: Device Authorization Flow (RFC 8628)

**Advanced Topics** | **Task 37 of 45**

## Overview

Implement OAuth 2.0 Device Authorization Grant (Device Flow) for input-constrained devices like Smart TVs, streaming devices, IoT devices, and CLI tools. Enable users to authenticate on a secondary device (phone/computer) while granting access to a device with limited input capabilities.

---

## What You'll Build

- Device authorization endpoint (`/device/code`)
- User verification endpoint (`/device/verify`)
- Token endpoint extension for device flow
- Device code storage and validation
- User code generation and verification UI
- Polling mechanism for devices
- Rate limiting for polling requests
- User approval flow

---

## Why Device Flow?

### The Problem

**Scenario**: User wants to log into Netflix on Smart TV
**Challenge**: Entering email/password with TV remote is painful
**Solution**: Show code on TV, user enters code on phone to authorize

### Use Cases

- **Smart TVs**: Netflix, YouTube, Spotify
- **Game Consoles**: PlayStation, Xbox
- **IoT Devices**: Smart speakers, home automation
- **CLI Tools**: GitHub CLI, AWS CLI, Azure CLI
- **Streaming Devices**: Roku, Apple TV, Chromecast

**Learn More**: RFC 8628 - https://datatracker.ietf.org/doc/html/rfc8628

---

## Device Flow Step-by-Step

### The Flow

```
1. Device → IdP: POST /device/code with client_id
2. IdP → Device: Return device_code, user_code, verification_uri
3. Device: Display "Go to https://example.com/device and enter code: ABCD-1234"
4. Device → IdP: Start polling POST /token with device_code
5. User (on phone): Navigate to https://example.com/device
6. User: Enter code "ABCD-1234"
7. IdP: Verify code, show consent screen
8. User: Approve access
9. IdP: Mark device_code as approved
10. Device (polling): Receive access_token
```

---

## Step 1: Create Database Schema

### Device Code Table

Create `src/main/resources/db/migration/V15__create_device_flow.sql`:

```sql
CREATE TABLE device_codes (
    id BIGSERIAL PRIMARY KEY,
    device_code VARCHAR(255) UNIQUE NOT NULL,
    user_code VARCHAR(20) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    scope TEXT,
    user_id BIGINT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_polled_at TIMESTAMP,
    poll_count INTEGER DEFAULT 0,

    CONSTRAINT fk_device_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_device_client FOREIGN KEY (client_id)
        REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_device_code ON device_codes(device_code);
CREATE INDEX idx_user_code ON device_codes(user_code);
CREATE INDEX idx_device_status ON device_codes(status);
CREATE INDEX idx_device_expires ON device_codes(expires_at);
```

**Status values**: PENDING, APPROVED, DENIED, EXPIRED

---

## Step 2: Implement Device Code Entity

### Device Code Model

Create `DeviceCode.java`:

**Fields**:
- `id`: Primary key
- `deviceCode`: Secret code for device to poll (long, random)
- `userCode`: Short code user enters (readable, e.g., "ABCD-1234")
- `clientId`: OAuth client requesting authorization
- `scope`: Requested scopes
- `userId`: User who approved (null until approved)
- `status`: PENDING | APPROVED | DENIED | EXPIRED
- `expiresAt`: When device_code expires (typically 15 minutes)
- `createdAt`: When code generated
- `lastPolledAt`: Last time device polled
- `pollCount`: Number of poll attempts (for rate limiting)

### Device Code Repository

```java
public interface DeviceCodeRepository extends JpaRepository<DeviceCode, Long> {
    Optional<DeviceCode> findByDeviceCode(String deviceCode);
    Optional<DeviceCode> findByUserCode(String userCode);
    List<DeviceCode> findByExpiresAtBefore(LocalDateTime now);
}
```

---

## Step 3: Create Device Authorization Endpoint

### Device Code Request

Create `DeviceAuthorizationController.java`:

```java
@RestController
@RequestMapping("/device")
public class DeviceAuthorizationController {

    @Autowired
    private DeviceCodeService deviceCodeService;

    @PostMapping("/code")
    public ResponseEntity<DeviceAuthorizationResponse> authorize(
        @RequestParam("client_id") String clientId,
        @RequestParam(value = "scope", required = false) String scope
    ) {
        // Validate client
        OAuth2Client client = clientService.findByClientId(clientId)
            .orElseThrow(() -> new InvalidClientException("Invalid client_id"));

        // Generate codes
        String deviceCode = generateSecureDeviceCode(); // e.g., 64 random chars
        String userCode = generateUserCode(); // e.g., "ABCD-1234"

        // Save to database
        DeviceCode deviceCodeEntity = new DeviceCode();
        deviceCodeEntity.setDeviceCode(deviceCode);
        deviceCodeEntity.setUserCode(userCode);
        deviceCodeEntity.setClientId(clientId);
        deviceCodeEntity.setScope(scope);
        deviceCodeEntity.setStatus(DeviceCodeStatus.PENDING);
        deviceCodeEntity.setExpiresAt(LocalDateTime.now().plusMinutes(15));
        deviceCodeRepository.save(deviceCodeEntity);

        // Build response
        DeviceAuthorizationResponse response = new DeviceAuthorizationResponse();
        response.setDeviceCode(deviceCode);
        response.setUserCode(userCode);
        response.setVerificationUri("https://idp.example.com/device/verify");
        response.setVerificationUriComplete("https://idp.example.com/device/verify?user_code=" + userCode);
        response.setExpiresIn(900); // 15 minutes
        response.setInterval(5); // Poll every 5 seconds

        return ResponseEntity.ok(response);
    }

    private String generateSecureDeviceCode() {
        return RandomStringUtils.randomAlphanumeric(64);
    }

    private String generateUserCode() {
        // Generate readable code like "ABCD-1234"
        String part1 = RandomStringUtils.randomAlphabetic(4).toUpperCase();
        String part2 = RandomStringUtils.randomNumeric(4);
        return part1 + "-" + part2;
    }
}
```

**Response format** (per RFC 8628):
```json
{
  "device_code": "NGU5OWFiNjQ5YmQwNGY3YTdmZTEyNzQ3YzQ1YTgzYmE",
  "user_code": "ABCD-1234",
  "verification_uri": "https://idp.example.com/device/verify",
  "verification_uri_complete": "https://idp.example.com/device/verify?user_code=ABCD-1234",
  "expires_in": 900,
  "interval": 5
}
```

**Why two codes?**:
- `device_code`: Secret for the device to poll
- `user_code`: Short code for human to type

---

## Step 4: Build User Verification UI

### Verification Page

Create `device-verify.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Device Verification</title>
    <style>
        .code-input {
            font-size: 2em;
            letter-spacing: 0.5em;
            text-align: center;
            text-transform: uppercase;
            width: 300px;
            padding: 20px;
        }
        .device-info {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>Device Verification</h1>

    <!-- Step 1: Enter code -->
    <div id="enter-code-step">
        <p>Enter the code displayed on your device:</p>
        <input type="text" id="user-code" class="code-input"
               placeholder="ABCD-1234" maxlength="9"
               pattern="[A-Z]{4}-[0-9]{4}">
        <button onclick="verifyCode()">Continue</button>
    </div>

    <!-- Step 2: Confirm device -->
    <div id="confirm-step" style="display:none;">
        <div class="device-info">
            <h3>Confirm Device</h3>
            <p><strong>Device:</strong> <span id="device-name"></span></p>
            <p><strong>Requesting:</strong> <span id="scopes"></span></p>
        </div>
        <button onclick="approve()">Approve</button>
        <button onclick="deny()">Deny</button>
    </div>

    <!-- Step 3: Success -->
    <div id="success-step" style="display:none;">
        <h2>✓ Device Authorized</h2>
        <p>You can close this window and return to your device.</p>
    </div>

    <script>
        let currentUserCode = null;

        function verifyCode() {
            const userCode = document.getElementById('user-code').value.toUpperCase();

            fetch('/api/device/verify', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({userCode: userCode})
            })
            .then(res => res.json())
            .then(data => {
                if (data.valid) {
                    currentUserCode = userCode;
                    document.getElementById('device-name').textContent = data.clientName;
                    document.getElementById('scopes').textContent = data.scope;
                    document.getElementById('enter-code-step').style.display = 'none';
                    document.getElementById('confirm-step').style.display = 'block';
                } else {
                    alert('Invalid code. Please try again.');
                }
            });
        }

        function approve() {
            fetch('/api/device/approve', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({userCode: currentUserCode})
            })
            .then(() => {
                document.getElementById('confirm-step').style.display = 'none';
                document.getElementById('success-step').style.display = 'block';
            });
        }

        function deny() {
            fetch('/api/device/deny', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({userCode: currentUserCode})
            })
            .then(() => {
                alert('Device denied');
                location.reload();
            });
        }
    </script>
</body>
</html>
```

**Auto-fill from URL**: If `verification_uri_complete` used, pre-fill code

---

## Step 5: Implement Verification Endpoints

### Verify User Code

```java
@PostMapping("/verify")
public ResponseEntity<DeviceVerificationResponse> verifyUserCode(
    @RequestBody DeviceVerificationRequest request
) {
    Optional<DeviceCode> deviceCode = deviceCodeRepository.findByUserCode(request.getUserCode());

    if (deviceCode.isEmpty() || deviceCode.get().isExpired()) {
        return ResponseEntity.ok(new DeviceVerificationResponse(false));
    }

    DeviceVerificationResponse response = new DeviceVerificationResponse(true);
    response.setClientName(deviceCode.get().getClient().getName());
    response.setScope(deviceCode.get().getScope());

    return ResponseEntity.ok(response);
}
```

### Approve Device

```java
@PostMapping("/approve")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<Void> approveDevice(
    @RequestBody DeviceApprovalRequest request,
    Authentication authentication
) {
    User user = (User) authentication.getPrincipal();

    DeviceCode deviceCode = deviceCodeRepository.findByUserCode(request.getUserCode())
        .orElseThrow(() -> new InvalidRequestException("Invalid user code"));

    if (deviceCode.isExpired()) {
        throw new ExpiredCodeException("Device code expired");
    }

    // Mark as approved
    deviceCode.setStatus(DeviceCodeStatus.APPROVED);
    deviceCode.setUserId(user.getId());
    deviceCodeRepository.save(deviceCode);

    // Log approval
    auditService.logDeviceApproval(user, deviceCode.getClientId());

    return ResponseEntity.ok().build();
}
```

### Deny Device

```java
@PostMapping("/deny")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<Void> denyDevice(@RequestBody DeviceApprovalRequest request) {
    DeviceCode deviceCode = deviceCodeRepository.findByUserCode(request.getUserCode())
        .orElseThrow(() -> new InvalidRequestException("Invalid user code"));

    deviceCode.setStatus(DeviceCodeStatus.DENIED);
    deviceCodeRepository.save(deviceCode);

    return ResponseEntity.ok().build();
}
```

---

## Step 6: Extend Token Endpoint for Device Flow

### Handle Device Grant Type

Update `TokenController.java`:

```java
@PostMapping("/oauth2/token")
public ResponseEntity<?> token(@RequestParam Map<String, String> params) {
    String grantType = params.get("grant_type");

    switch (grantType) {
        case "authorization_code":
            return handleAuthorizationCodeGrant(params);
        case "refresh_token":
            return handleRefreshTokenGrant(params);
        case "client_credentials":
            return handleClientCredentialsGrant(params);
        case "urn:ietf:params:oauth:grant-type:device_code":
            return handleDeviceCodeGrant(params);
        default:
            throw new UnsupportedGrantTypeException(grantType);
    }
}

private ResponseEntity<?> handleDeviceCodeGrant(Map<String, String> params) {
    String deviceCode = params.get("device_code");
    String clientId = params.get("client_id");

    // Validate client
    OAuth2Client client = clientService.findByClientId(clientId)
        .orElseThrow(() -> new InvalidClientException());

    // Find device code
    DeviceCode code = deviceCodeRepository.findByDeviceCode(deviceCode)
        .orElseThrow(() -> new InvalidGrantException("Invalid device_code"));

    // Check expiration
    if (code.isExpired()) {
        deviceCodeRepository.delete(code);
        return ResponseEntity.status(400).body(
            new OAuth2Error("expired_token", "Device code has expired")
        );
    }

    // Update poll tracking
    code.setLastPolledAt(LocalDateTime.now());
    code.setPollCount(code.getPollCount() + 1);

    // Check rate limiting (RFC 8628 Section 3.5)
    if (isPollingTooFast(code)) {
        return ResponseEntity.status(400).body(
            new OAuth2Error("slow_down", "Polling too frequently")
        );
    }

    // Check status
    switch (code.getStatus()) {
        case PENDING:
            // User hasn't approved yet
            return ResponseEntity.status(400).body(
                new OAuth2Error("authorization_pending", "User has not approved yet")
            );

        case DENIED:
            deviceCodeRepository.delete(code);
            return ResponseEntity.status(400).body(
                new OAuth2Error("access_denied", "User denied authorization")
            );

        case APPROVED:
            // Generate tokens
            User user = userRepository.findById(code.getUserId()).get();
            String accessToken = tokenService.generateAccessToken(user, code.getClientId(), code.getScope());
            String refreshToken = tokenService.generateRefreshToken(user, code.getClientId());

            // Delete device code (one-time use)
            deviceCodeRepository.delete(code);

            // Return tokens
            OAuth2TokenResponse response = new OAuth2TokenResponse();
            response.setAccessToken(accessToken);
            response.setRefreshToken(refreshToken);
            response.setTokenType("Bearer");
            response.setExpiresIn(3600);
            return ResponseEntity.ok(response);

        default:
            throw new IllegalStateException("Unknown device code status");
    }
}

private boolean isPollingTooFast(DeviceCode code) {
    if (code.getLastPolledAt() == null) {
        return false;
    }
    Duration timeSinceLastPoll = Duration.between(code.getLastPolledAt(), LocalDateTime.now());
    return timeSinceLastPoll.getSeconds() < 5; // RFC recommends 5 second minimum
}
```

**Error codes** (per RFC 8628):
- `authorization_pending`: User hasn't approved yet (device should keep polling)
- `slow_down`: Device polling too fast (increase interval by 5 seconds)
- `expired_token`: Device code expired
- `access_denied`: User denied access

---

## Step 7: Implement Rate Limiting

### Slow Down Mechanism

```java
@Service
public class DeviceFlowRateLimiter {

    private static final int DEFAULT_INTERVAL = 5; // seconds
    private static final int SLOW_DOWN_PENALTY = 5; // add 5 seconds

    private final Map<String, Integer> clientIntervals = new ConcurrentHashMap<>();

    public boolean shouldSlowDown(DeviceCode code) {
        if (code.getLastPolledAt() == null) {
            return false;
        }

        int requiredInterval = clientIntervals.getOrDefault(code.getClientId(), DEFAULT_INTERVAL);
        long actualInterval = Duration.between(code.getLastPolledAt(), LocalDateTime.now()).getSeconds();

        if (actualInterval < requiredInterval) {
            // Increase interval for this client
            clientIntervals.put(code.getClientId(), requiredInterval + SLOW_DOWN_PENALTY);
            return true;
        }

        return false;
    }

    public void resetInterval(String clientId) {
        clientIntervals.remove(clientId);
    }
}
```

**Why rate limiting?**: Prevent devices from overwhelming the server with polling requests

---

## Step 8: Clean Up Expired Codes

### Scheduled Cleanup

```java
@Service
public class DeviceCodeCleanupService {

    @Autowired
    private DeviceCodeRepository deviceCodeRepository;

    @Scheduled(fixedRate = 300000) // Every 5 minutes
    public void cleanupExpiredCodes() {
        List<DeviceCode> expiredCodes = deviceCodeRepository.findByExpiresAtBefore(LocalDateTime.now());
        deviceCodeRepository.deleteAll(expiredCodes);
        log.info("Cleaned up {} expired device codes", expiredCodes.size());
    }
}
```

---

## Step 9: Build Device Client Example

### Python CLI Example

```python
import requests
import time

# Step 1: Request device code
response = requests.post('https://idp.example.com/device/code', data={
    'client_id': 'cli-app'
})
data = response.json()

device_code = data['device_code']
user_code = data['user_code']
verification_uri = data['verification_uri']
interval = data['interval']

# Step 2: Show instructions to user
print(f"Please visit: {verification_uri}")
print(f"And enter code: {user_code}")

# Step 3: Poll for token
while True:
    time.sleep(interval)

    token_response = requests.post('https://idp.example.com/oauth2/token', data={
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
        'device_code': device_code,
        'client_id': 'cli-app'
    })

    if token_response.status_code == 200:
        token_data = token_response.json()
        access_token = token_data['access_token']
        print(f"Success! Access token: {access_token}")
        break
    elif token_response.status_code == 400:
        error = token_response.json()['error']

        if error == 'authorization_pending':
            print("Waiting for user approval...")
            continue
        elif error == 'slow_down':
            print("Polling too fast, slowing down...")
            interval += 5
            continue
        elif error == 'expired_token':
            print("Code expired. Please restart.")
            break
        elif error == 'access_denied':
            print("User denied access.")
            break
        else:
            print(f"Error: {error}")
            break
```

**Output**:
```
Please visit: https://idp.example.com/device/verify
And enter code: ABCD-1234
Waiting for user approval...
Waiting for user approval...
Success! Access token: eyJhbGciOiJSUzI1NiIs...
```

---

## Testing Device Flow

### Test Full Flow

```bash
# Step 1: Request device code
curl -X POST http://localhost:8080/device/code \
  -d "client_id=cli-app"

# Response:
# {
#   "device_code": "NGU5OWFiNjQ5...",
#   "user_code": "ABCD-1234",
#   "verification_uri": "http://localhost:8080/device/verify",
#   "expires_in": 900,
#   "interval": 5
# }

# Step 2: User navigates to verification_uri and enters code

# Step 3: Device polls for token
curl -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=NGU5OWFiNjQ5..." \
  -d "client_id=cli-app"

# Before approval:
# {"error": "authorization_pending"}

# After approval:
# {
#   "access_token": "eyJhbGciOiJSUz...",
#   "token_type": "Bearer",
#   "expires_in": 3600,
#   "refresh_token": "def50200..."
# }
```

---

## Common Issues

### Code Not Found

**Problem**: "Invalid user code" error

**Solution**:
- Verify code is stored in database
- Check code hasn't expired
- Ensure exact match (case-sensitive)

### Polling Too Fast

**Problem**: "slow_down" error even with correct interval

**Solution**:
- Check server time synchronization
- Implement exponential backoff
- Log polling intervals for debugging

### Expired Code

**Problem**: Code expires before user approves

**Solution**:
- Increase expiration time (default 15 minutes)
- Show countdown timer on device
- Allow user to regenerate code

### User Not Authenticated

**Problem**: Verification endpoint requires login, but user isn't logged in

**Solution**:
- Store redirect URL in session
- After login, redirect to verification page with code pre-filled
- Support social login for faster authentication

---

## What You've Accomplished

✅ Implemented device authorization endpoint
✅ Created user verification UI
✅ Extended token endpoint for device flow
✅ Built polling mechanism with rate limiting
✅ Added approval/denial flows
✅ Implemented expired code cleanup
✅ Created device client example
✅ Tested complete device flow

---

## Next Steps

**Proceed to Guide 38**: Performance Testing

Before moving on:
- [ ] Device authorization endpoint working
- [ ] User verification UI functional
- [ ] Polling returns correct errors
- [ ] Rate limiting prevents abuse
- [ ] Approved codes return tokens
- [ ] Tested with CLI or test device

---

## Key Concepts Learned

### Device Flow Mechanics

- **Decoupled Authentication**: User authenticates on different device
- **Polling**: Device continuously checks for approval
- **User Codes**: Short, human-readable codes
- **Rate Limiting**: Prevent server overload from polling

### Security Considerations

- **Device Code Secrecy**: Treat like authorization code
- **Expiration**: Limit time window for approval
- **One-Time Use**: Consume device code after token issuance
- **Rate Limiting**: Enforce minimum polling interval

### User Experience

- **Clear Instructions**: Show verification URI prominently
- **QR Codes**: Optionally display QR code for easy mobile scanning
- **Auto-fill**: Use `verification_uri_complete` to pre-fill code
- **Feedback**: Show status on both device and verification page

---

## Additional Resources

- **RFC 8628 - Device Authorization Grant**: https://datatracker.ietf.org/doc/html/rfc8628
- **OAuth 2.0 for TV and Limited-Input Device Applications**: https://oauth.net/2/device-flow/
- **Google Device Flow**: https://developers.google.com/identity/protocols/oauth2/limited-input-device
- **GitHub Device Flow**: https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#device-flow
- **Spring Authorization Server - Device Flow**: https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-device-authorization-endpoint
