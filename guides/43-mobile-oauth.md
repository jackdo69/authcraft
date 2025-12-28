# Guide 43: Mobile App OAuth Integration

**Advanced Topics** | **Task 43 of 45**

## Overview

Implement OAuth 2.0 for native mobile applications (iOS and Android) using Authorization Code Flow with PKCE and AppAuth libraries. Handle deep linking, secure token storage, and biometric authentication.

---

## What You'll Build

- AppAuth iOS integration
- AppAuth Android integration
- Deep linking configuration
- Secure token storage (Keychain/Keystore)
- Biometric authentication
- Token refresh handling
- Logout and token revocation

---

## Why Mobile OAuth is Different?

### Security Challenges

**No Client Secret**: Native apps can't securely store secrets (decompilation risk)
**Custom URI Schemes**: Deep linking for redirect after login
**Token Storage**: Secure storage on device
**App Switching**: Browser/app context switching

### Solutions

**PKCE**: Replaces client secret with code challenge
**System Browser**: Use ASWebAuthenticationSession (iOS) or Custom Tabs (Android)
**Secure Storage**: Keychain (iOS), Keystore (Android)
**Universal Links / App Links**: Claimed HTTPS URLs for deep linking

**Learn More**: https://oauth.net/2/native-apps/

---

## Step 1: Configure IdP for Mobile Apps

### Register Mobile Client

```java
OAuth2Client mobileClient = new OAuth2Client();
mobileClient.setClientId("mobile-app");
mobileClient.setClientSecret(null);  // No secret for native apps
mobileClient.setGrantTypes(List.of("authorization_code", "refresh_token"));
mobileClient.setRedirectUris(List.of(
    "com.example.app:/oauth/callback",  // Custom scheme
    "https://app.example.com/oauth/callback"  // Universal Link
));
mobileClient.setScopes(List.of("openid", "profile", "email", "offline_access"));
mobileClient.setPublicClient(true);  // Mark as public (PKCE required)
```

### Enforce PKCE for Public Clients

```java
@Service
public class AuthorizationCodeService {

    public AuthorizationCode validateAuthorizationRequest(AuthorizationRequest request) {
        OAuth2Client client = getClient(request.getClientId());

        // Enforce PKCE for public clients
        if (client.isPublicClient() && request.getCodeChallenge() == null) {
            throw new InvalidRequestException("code_challenge required for public clients");
        }

        // ... rest of validation
    }
}
```

---

## Step 2: iOS Integration with AppAuth

### Install AppAuth iOS

`Podfile`:
```ruby
platform :ios, '13.0'
use_frameworks!

target 'YourApp' do
  pod 'AppAuth', '~> 1.6'
end
```

```bash
pod install
```

### Configure Info.plist

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>com.example.app</string>
        </array>
    </dict>
</array>
```

### Implement OAuth Flow (Swift)

```swift
import AppAuth

class AuthManager {
    var authState: OIDAuthState?

    func login(viewController: UIViewController, completion: @escaping (Bool, Error?) -> Void) {
        // Configuration
        let issuer = URL(string: "https://idp.example.com")!
        let redirectURI = URL(string: "com.example.app:/oauth/callback")!
        let clientID = "mobile-app"

        // Discover endpoints
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in
            guard let config = configuration else {
                completion(false, error)
                return
            }

            // Build authorization request
            let request = OIDAuthorizationRequest(
                configuration: config,
                clientId: clientID,
                clientSecret: nil,  // No secret for native apps
                scopes: ["openid", "profile", "email", "offline_access"],
                redirectURL: redirectURI,
                responseType: OIDResponseTypeCode,
                additionalParameters: nil
            )

            // Present authorization UI
            let appDelegate = UIApplication.shared.delegate as! AppDelegate

            appDelegate.currentAuthorizationFlow = OIDAuthState.authState(
                byPresenting: request,
                presenting: viewController
            ) { authState, error in
                if let authState = authState {
                    self.authState = authState
                    self.saveAuthState(authState)
                    completion(true, nil)
                } else {
                    completion(false, error)
                }
            }
        }
    }

    // Get valid access token (refreshes if needed)
    func getAccessToken(completion: @escaping (String?, Error?) -> Void) {
        authState?.performAction { accessToken, idToken, error in
            completion(accessToken, error)
        }
    }

    // Make API request
    func fetchUserInfo(completion: @escaping (UserInfo?, Error?) -> Void) {
        getAccessToken { accessToken, error in
            guard let token = access Token else {
                completion(nil, error)
                return
            }

            var request = URLRequest(url: URL(string: "https://idp.example.com/oauth2/userinfo")!)
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

            URLSession.shared.dataTask(with: request) { data, response, error in
                // Parse JSON response
                if let data = data {
                    let userInfo = try? JSONDecoder().decode(UserInfo.self, from: data)
                    completion(userInfo, nil)
                } else {
                    completion(nil, error)
                }
            }.resume()
        }
    }

    // Save auth state securely
    func saveAuthState(_ authState: OIDAuthState) {
        let data = NSKeyedArchiver.archivedData(withRootObject: authState)
        KeychainHelper.save(key: "authState", data: data)
    }

    // Load auth state
    func loadAuthState() {
        if let data = KeychainHelper.load(key: "authState") {
            authState = NSKeyedUnarchiver.unarchiveObject(with: data) as? OIDAuthState
        }
    }

    // Logout
    func logout() {
        guard let authState = authState else { return }

        // Revoke tokens
        let revokeURL = URL(string: "https://idp.example.com/oauth2/revoke")!
        var request = URLRequest(url: revokeURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let body = "token=\(authState.refreshToken ?? "")&token_type_hint=refresh_token"
        request.httpBody = body.data(using: .utf8)

        URLSession.shared.dataTask(with: request).resume()

        // Clear local state
        authState = nil
        KeychainHelper.delete(key: "authState")
    }
}
```

### Keychain Helper

```swift
class KeychainHelper {
    static func save(key: String, data: Data) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ] as [String: Any]

        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as [String: Any]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == noErr {
            return dataTypeRef as? Data
        }
        return nil
    }

    static func delete(key: String) {
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ] as [String: Any]

        SecItemDelete(query as CFDictionary)
    }
}
```

---

## Step 3: Android Integration with AppAuth

### Add Dependencies

`build.gradle`:
```groovy
dependencies {
    implementation 'net.openid:appauth:0.11.1'
    implementation 'androidx.browser:browser:1.5.0'
}
```

### Configure Redirect URI

`AndroidManifest.xml`:
```xml
<activity
    android:name="net.openid.appauth.RedirectUriReceiverActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="com.example.app"
            android:host="oauth"
            android:path="/callback"/>
    </intent-filter>
</activity>
```

### Implement OAuth Flow (Kotlin)

```kotlin
class AuthManager(private val context: Context) {

    private val SHARED_PREFS = "AuthStatePrefs"
    private val AUTH_STATE = "authState"

    private var authState: AuthState? = null
    private val authService = AuthorizationService(context)

    fun login(activity: Activity) {
        val issuerUri = Uri.parse("https://idp.example.com")
        val redirectUri = Uri.parse("com.example.app:/oauth/callback")
        val clientId = "mobile-app"

        // Discover configuration
        AuthorizationServiceConfiguration.fetchFromIssuer(issuerUri) { serviceConfig, ex ->
            if (ex != null) {
                Log.e("AuthManager", "Failed to fetch configuration", ex)
                return@fetchFromIssuer
            }

            // Build authorization request
            val authRequest = AuthorizationRequest.Builder(
                serviceConfig!!,
                clientId,
                ResponseTypeValues.CODE,
                redirectUri
            )
                .setScopes("openid", "profile", "email", "offline_access")
                .build()

            // Launch browser for authorization
            val authIntent = authService.getAuthorizationRequestIntent(authRequest)
            activity.startActivityForResult(authIntent, RC_AUTH)
        }
    }

    fun handleAuthorizationResponse(
        data: Intent?,
        onSuccess: (String) -> Unit,
        onError: (Exception) -> Unit
    ) {
        val response = AuthorizationResponse.fromIntent(data!!)
        val ex = AuthorizationException.fromIntent(data)

        if (response != null) {
            // Exchange authorization code for tokens
            authService.performTokenRequest(response.createTokenExchangeRequest()) { tokenResponse, exception ->
                if (tokenResponse != null) {
                    authState = AuthState(response, tokenResponse, exception)
                    saveAuthState()
                    onSuccess(tokenResponse.accessToken!!)
                } else {
                    onError(exception ?: Exception("Unknown error"))
                }
            }
        } else {
            onError(ex ?: Exception("Authorization failed"))
        }
    }

    fun getAccessToken(callback: (String?) -> Unit) {
        authState?.performActionWithFreshTokens(authService) { accessToken, idToken, ex ->
            callback(accessToken)
        }
    }

    fun fetchUserInfo(callback: (UserInfo?) -> Unit) {
        getAccessToken { accessToken ->
            if (accessToken == null) {
                callback(null)
                return@getAccessToken
            }

            // Make API request
            val url = URL("https://idp.example.com/oauth2/userinfo")
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.setRequestProperty("Authorization", "Bearer $accessToken")

            val response = connection.inputStream.bufferedReader().readText()
            val userInfo = Gson().fromJson(response, UserInfo::class.java)
            callback(userInfo)
        }
    }

    fun logout() {
        authState?.let { state ->
            // Revoke tokens
            val revokeRequest = state.refreshToken?.let { token ->
                TokenRevocationRequest.Builder(
                    state.authorizationServiceConfiguration!!,
                    token
                ).build()
            }

            revokeRequest?.let {
                authService.performTokenRevocation(it) { ex ->
                    if (ex != null) {
                        Log.e("AuthManager", "Token revocation failed", ex)
                    }
                }
            }
        }

        // Clear local state
        authState = null
        clearAuthState()
    }

    private fun saveAuthState() {
        val json = authState?.jsonSerializeString()
        context.getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(AUTH_STATE, json)
            .apply()
    }

    private fun loadAuthState() {
        val json = context.getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
            .getString(AUTH_STATE, null)

        authState = json?.let { AuthState.jsonDeserialize(it) }
    }

    private fun clearAuthState() {
        context.getSharedPreferences(SHARED_PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(AUTH_STATE)
            .apply()
    }

    companion object {
        const val RC_AUTH = 100
    }
}
```

### Activity Usage

```kotlin
class LoginActivity : AppCompatActivity() {

    private lateinit var authManager: AuthManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        authManager = AuthManager(this)

        loginButton.setOnClickListener {
            authManager.login(this)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == AuthManager.RC_AUTH) {
            authManager.handleAuthorizationResponse(
                data,
                onSuccess = { accessToken ->
                    // Login successful
                    startActivity(Intent(this, HomeActivity::class.java))
                },
                onError = { exception ->
                    Toast.makeText(this, "Login failed: ${exception.message}", Toast.LENGTH_LONG).show()
                }
            )
        }
    }
}
```

---

## Step 4: Add Biometric Authentication

### iOS - Face ID / Touch ID

```swift
import LocalAuthentication

class BiometricAuth {

    func authenticateWithBiometrics(completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "Authenticate to access your account"

            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, authError in
                DispatchQueue.main.async {
                    completion(success, authError)
                }
            }
        } else {
            completion(false, error)
        }
    }

    func loginWithBiometrics(authManager: AuthManager, completion: @escaping (Bool) -> Void) {
        authenticateWithBiometrics { success, error in
            if success {
                authManager.loadAuthState()
                authManager.getAccessToken { token, error in
                    completion(token != nil)
                }
            } else {
                completion(false)
            }
        }
    }
}
```

### Android - Biometric Prompt

```kotlin
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

class BiometricAuth(private val activity: FragmentActivity) {

    fun authenticateWithBiometrics(
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)

        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    onError("Authentication failed")
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to access your account")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    fun loginWithBiometrics(authManager: AuthManager, callback: (Boolean) -> Unit) {
        authenticateWithBiometrics(
            onSuccess = {
                authManager.loadAuthState()
                authManager.getAccessToken { token ->
                    callback(token != null)
                }
            },
            onError = {
                callback(false)
            }
        )
    }
}
```

---

## Step 5: Universal Links / App Links

### iOS - Universal Links

**Configure Associated Domains**:

In Xcode, enable "Associated Domains" capability and add:
```
applinks:app.example.com
```

**Host apple-app-site-association**:

Serve at: `https://app.example.com/.well-known/apple-app-site-association`

```json
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appID": "TEAM_ID.com.example.app",
        "paths": ["/oauth/callback"]
      }
    ]
  }
}
```

**Handle Universal Link**:

```swift
func application(_ application: UIApplication,
                 continue userActivity: NSUserActivity,
                 restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
    if userActivity.activityType == NSUserActivityTypeBrowsingWeb {
        if let url = userActivity.webpageURL {
            // Handle OAuth callback
            return OIDAuthorizationService.resumeExternalUserAgentFlow(with: url)
        }
    }
    return false
}
```

### Android - App Links

**Configure Intent Filter**:

`AndroidManifest.xml`:
```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data
        android:scheme="https"
        android:host="app.example.com"
        android:path="/oauth/callback"/>
</intent-filter>
```

**Host assetlinks.json**:

Serve at: `https://app.example.com/.well-known/assetlinks.json`

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.example.app",
    "sha256_cert_fingerprints": [
      "SHA256_FINGERPRINT_HERE"
    ]
  }
}]
```

---

## Common Issues

### Deep Link Not Working

**Problem**: App doesn't open after login

**Solutions**:
- Verify URL scheme registered in Info.plist (iOS) or AndroidManifest.xml
- Check Universal Link / App Link association file is accessible
- Test with `xcrun simctl openurl booted "com.example.app:/oauth/callback?code=abc"` (iOS)

### Tokens Not Persisting

**Problem**: User logged out after app restart

**Solution**: Ensure tokens saved to Keychain (iOS) or SharedPreferences (Android)

### Token Refresh Failing

**Problem**: Access token expires, refresh fails

**Solution**: AppAuth handles automatic refresh. Ensure refresh_token scope requested and refresh token stored

---

## What You've Accomplished

✅ Integrated AppAuth for iOS and Android
✅ Implemented OAuth with PKCE
✅ Configured deep linking
✅ Secured token storage (Keychain/Keystore)
✅ Added biometric authentication
✅ Handled token refresh automatically
✅ Implemented logout and revocation

---

## Next Steps

**Proceed to Guide 44**: Passwordless Authentication (WebAuthn/Passkeys)

Before moving on:
- [ ] Mobile client registered in IdP
- [ ] iOS app can login and fetch user info
- [ ] Android app can login and fetch user info
- [ ] Deep linking working
- [ ] Tokens persisting across app restarts
- [ ] Biometric auth functional

---

## Key Concepts Learned

### Native App OAuth Best Practices

- Use system browser (not WebView)
- Always use PKCE (never use client secret)
- Secure token storage (Keychain/Keystore)
- Universal Links / App Links for seamless UX

### Security

- No hardcoded secrets in app binary
- PKCE protects against authorization code interception
- Biometric auth for convenience without compromising security

---

## Additional Resources

- **RFC 8252 - OAuth for Native Apps**: https://datatracker.ietf.org/doc/html/rfc8252
- **AppAuth iOS**: https://github.com/openid/AppAuth-iOS
- **AppAuth Android**: https://github.com/openid/AppAuth-Android
- **iOS Universal Links**: https://developer.apple.com/ios/universal-links/
- **Android App Links**: https://developer.android.com/training/app-links
