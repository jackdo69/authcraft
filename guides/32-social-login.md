# Guide 32: Social Login Integration

**Advanced Topics** | **Task 32 of 45**

## Overview

Integrate OAuth login with social providers (Google, GitHub, Facebook, Microsoft) to allow users to authenticate using their existing accounts from these platforms.

---

## What You'll Build

- OAuth client configuration for multiple providers
- Social account linking to local users
- Provider-specific user data handling
- Account conflict resolution
- Provider management UI

---

## Why Social Login?

### User Benefits

**Convenience**: No new password to remember
**Speed**: Faster registration and login
**Trust**: Leverage existing trusted accounts
**Security**: Providers handle 2FA, breach detection

### Developer Benefits

**Reduced friction**: Higher conversion rates
**Less maintenance**: No password reset emails
**Better security**: Delegate to experts
**User data**: Access to profile information with consent

**Learn More**: https://developers.google.com/identity/protocols/oauth2

---

## Step 1: Register OAuth Applications

### Google OAuth Setup

1. **Visit**: https://console.cloud.google.com/
2. **Create project**: "OAuth IdP Learning"
3. **Enable API**: Google+ API
4. **Create credentials**: OAuth 2.0 Client ID
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:8080/login/oauth2/code/google`
5. **Copy**: Client ID and Client Secret

### GitHub OAuth Setup

1. **Visit**: https://github.com/settings/developers
2. **New OAuth App**
3. **Configure**:
   - Application name: Your IdP
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL: `http://localhost:8080/login/oauth2/code/github`
4. **Copy**: Client ID and Client Secret

### Facebook OAuth Setup

1. **Visit**: https://developers.facebook.com/
2. **Create App**: Consumer
3. **Add Facebook Login** product
4. **Settings → Basic**: Copy App ID and App Secret
5. **Facebook Login Settings**:
   - Valid OAuth Redirect URIs: `http://localhost:8080/login/oauth2/code/facebook`

### Microsoft OAuth Setup

1. **Visit**: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps
2. **New registration**
3. **Configure**:
   - Supported account types: Personal Microsoft accounts
   - Redirect URI: `http://localhost:8080/login/oauth2/code/microsoft`
4. **Copy**: Application (client) ID
5. **Certificates & secrets**: New client secret

---

## Step 2: Configure Spring Security OAuth2 Client

### Add Dependency

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```

### Configure Providers

application.yml:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope:
              - openid
              - profile
              - email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            
          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope:
              - read:user
              - user:email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            
          facebook:
            client-id: ${FACEBOOK_APP_ID}
            client-secret: ${FACEBOOK_APP_SECRET}
            scope:
              - public_profile
              - email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            
          microsoft:
            client-id: ${MICROSOFT_CLIENT_ID}
            client-secret: ${MICROSOFT_CLIENT_SECRET}
            scope:
              - openid
              - profile
              - email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            authorization-grant-type: authorization_code
            
        provider:
          microsoft:
            authorization-uri: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
            token-uri: https://login.microsoftonline.com/common/oauth2/v2.0/token
            user-info-uri: https://graph.microsoft.com/oidc/userinfo
            jwk-set-uri: https://login.microsoftonline.com/common/discovery/v2.0/keys
            user-name-attribute: sub
```

### Environment Variables

Create `.env` file:
```bash
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
```

---

## Step 3: Update User Entity

### Add Provider Fields

```java
@Entity
@Table(name = "users")
public class User {
    
    // Existing fields...
    
    @Column(name = "auth_provider", length = 20)
    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider = AuthProvider.LOCAL;
    
    @Column(name = "provider_user_id", length = 255)
    private String providerUserId;  // Unique ID from provider
    
    @Column(name = "provider_username", length = 255)
    private String providerUsername;  // Username from provider
    
    @Column(name = "picture_url", length = 500)
    private String pictureUrl;  // Profile picture from provider
}
```

### AuthProvider Enum

```java
public enum AuthProvider {
    LOCAL,      // Regular username/password
    GOOGLE,
    GITHUB,
    FACEBOOK,
    MICROSOFT
}
```

### Migration

Create `V16__add_provider_fields_to_users.sql`:

```sql
ALTER TABLE users
ADD COLUMN auth_provider VARCHAR(20) DEFAULT 'LOCAL',
ADD COLUMN provider_user_id VARCHAR(255),
ADD COLUMN provider_username VARCHAR(255),
ADD COLUMN picture_url VARCHAR(500);

CREATE INDEX idx_users_provider ON users(auth_provider, provider_user_id);
```

---

## Step 4: Implement OAuth2 User Service

### Create OAuth2UserService

```java
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        
        // Get user info from provider
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // Extract provider info
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = AuthProvider.valueOf(registrationId.toUpperCase());
        
        // Process and save user
        User user = processOAuth2User(userRequest, oauth2User, provider);
        
        // Return custom principal
        return new CustomOAuth2User(user, oauth2User.getAttributes());
    }
    
    private User processOAuth2User(OAuth2UserRequest userRequest, 
                                   OAuth2User oauth2User,
                                   AuthProvider provider) {
        
        // Extract user info based on provider
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
            provider, 
            oauth2User.getAttributes()
        );
        
        // Check if user exists by provider ID
        Optional<User> userOptional = userRepository
            .findByAuthProviderAndProviderUserId(provider, userInfo.getId());
        
        User user;
        if (userOptional.isPresent()) {
            // Update existing user
            user = userOptional.get();
            user = updateExistingUser(user, userInfo);
        } else {
            // Check if user exists by email
            userOptional = userRepository.findByEmail(userInfo.getEmail());
            
            if (userOptional.isPresent()) {
                // Link provider to existing account
                user = userOptional.get();
                user = linkProviderToExistingUser(user, provider, userInfo);
            } else {
                // Create new user
                user = createNewUser(provider, userInfo);
            }
        }
        
        return userRepository.save(user);
    }
    
    private User createNewUser(AuthProvider provider, OAuth2UserInfo userInfo) {
        User user = new User();
        user.setAuthProvider(provider);
        user.setProviderUserId(userInfo.getId());
        user.setProviderUsername(userInfo.getName());
        user.setEmail(userInfo.getEmail());
        user.setUsername(generateUniqueUsername(userInfo));
        user.setEmailVerified(true);  // Provider verified
        user.setPictureUrl(userInfo.getImageUrl());
        user.setEnabled(true);
        // No password for social login users
        
        return user;
    }
    
    private User updateExistingUser(User user, OAuth2UserInfo userInfo) {
        user.setProviderUsername(userInfo.getName());
        user.setEmail(userInfo.getEmail());
        user.setPictureUrl(userInfo.getImageUrl());
        return user;
    }
    
    private User linkProviderToExistingUser(User user, AuthProvider provider, OAuth2UserInfo userInfo) {
        if (user.getAuthProvider() == AuthProvider.LOCAL) {
            // Allow linking social account to local account
            user.setAuthProvider(provider);
            user.setProviderUserId(userInfo.getId());
            user.setProviderUsername(userInfo.getName());
            user.setPictureUrl(userInfo.getImageUrl());
        } else {
            throw new OAuth2AuthenticationProcessingException(
                "Email already linked to " + user.getAuthProvider() + " account"
            );
        }
        return user;
    }
    
    private String generateUniqueUsername(OAuth2UserInfo userInfo) {
        String baseUsername = userInfo.getName().replaceAll("\\s+", "").toLowerCase();
        String username = baseUsername;
        int suffix = 1;
        
        while (userRepository.existsByUsername(username)) {
            username = baseUsername + suffix++;
        }
        
        return username;
    }
}
```

---

## Step 5: Create Provider-Specific User Info Classes

### OAuth2UserInfo Interface

```java
public interface OAuth2UserInfo {
    String getId();
    String getName();
    String getEmail();
    String getImageUrl();
}
```

### GoogleOAuth2UserInfo

```java
public class GoogleOAuth2UserInfo implements OAuth2UserInfo {
    
    private Map<String, Object> attributes;
    
    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    
    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }
    
    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
    
    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
    
    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
```

### GitHubOAuth2UserInfo

```java
public class GitHubOAuth2UserInfo implements OAuth2UserInfo {
    
    private Map<String, Object> attributes;
    
    public GitHubOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    
    @Override
    public String getId() {
        return ((Integer) attributes.get("id")).toString();
    }
    
    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
    
    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
    
    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
```

### FacebookOAuth2UserInfo

```java
public class FacebookOAuth2UserInfo implements OAuth2UserInfo {
    
    private Map<String, Object> attributes;
    
    public FacebookOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    
    @Override
    public String getId() {
        return (String) attributes.get("id");
    }
    
    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
    
    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
    
    @Override
    public String getImageUrl() {
        Map<String, Object> picture = (Map<String, Object>) attributes.get("picture");
        if (picture != null) {
            Map<String, Object> data = (Map<String, Object>) picture.get("data");
            if (data != null) {
                return (String) data.get("url");
            }
        }
        return null;
    }
}
```

### OAuth2UserInfoFactory

```java
public class OAuth2UserInfoFactory {
    
    public static OAuth2UserInfo getOAuth2UserInfo(AuthProvider provider, 
                                                    Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> new GoogleOAuth2UserInfo(attributes);
            case GITHUB -> new GitHubOAuth2UserInfo(attributes);
            case FACEBOOK -> new FacebookOAuth2UserInfo(attributes);
            case MICROSOFT -> new MicrosoftOAuth2UserInfo(attributes);
            default -> throw new OAuth2AuthenticationProcessingException(
                "Login with " + provider + " is not supported"
            );
        };
    }
}
```

---

## Step 6: Update Security Configuration

### Configure OAuth2 Login

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;
    
    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    
    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login/**", "/oauth2/**", "/error").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                )
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
            );
        
        return http.build();
    }
}
```

---

## Step 7: Handle OAuth2 Success

### Create Success Handler

```java
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    
    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) throws IOException {
        
        String targetUrl = determineTargetUrl(request, response, authentication);
        
        if (response.isCommitted()) {
            logger.debug("Response already committed. Unable to redirect to " + targetUrl);
            return;
        }
        
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
    
    protected String determineTargetUrl(HttpServletRequest request,
                                       HttpServletResponse response,
                                       Authentication authentication) {
        
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
            .map(Cookie::getValue);
        
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());
        
        // If continuing OAuth flow (from /oauth2/authorize)
        // Generate authorization code and redirect to client
        
        return targetUrl;
    }
    
    protected void clearAuthenticationAttributes(HttpServletRequest request, 
                                                 HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}
```

---

## Step 8: Update Login Page

### Add Social Login Buttons

login.html:

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login</title>
    <style>
        .social-login {
            margin-top: 20px;
        }
        .social-button {
            display: block;
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            text-align: center;
        }
        .google { background: #4285f4; color: white; }
        .github { background: #24292e; color: white; }
        .facebook { background: #1877f2; color: white; }
        .microsoft { background: #2f2f2f; color: white; }
        .divider {
            margin: 20px 0;
            text-align: center;
            position: relative;
        }
        .divider::before {
            content: '';
            position: absolute;
            left: 0;
            top: 50%;
            width: 45%;
            height: 1px;
            background: #ccc;
        }
        .divider::after {
            content: '';
            position: absolute;
            right: 0;
            top: 50%;
            width: 45%;
            height: 1px;
            background: #ccc;
        }
    </style>
</head>
<body>
    <h2>Login</h2>
    
    <!-- Traditional login form -->
    <form method="post" th:action="@{/login}">
        <input type="text" name="username" placeholder="Username" required/>
        <input type="password" name="password" placeholder="Password" required/>
        <button type="submit">Login</button>
    </form>
    
    <div class="divider">OR</div>
    
    <!-- Social login buttons -->
    <div class="social-login">
        <a href="/oauth2/authorization/google" class="social-button google">
            Continue with Google
        </a>
        <a href="/oauth2/authorization/github" class="social-button github">
            Continue with GitHub
        </a>
        <a href="/oauth2/authorization/facebook" class="social-button facebook">
            Continue with Facebook
        </a>
        <a href="/oauth2/authorization/microsoft" class="social-button microsoft">
            Continue with Microsoft
        </a>
    </div>
    
    <p>Don't have an account? <a href="/register">Register</a></p>
</body>
</html>
```

---

## Step 9: Handle Account Linking

### Account Linking Flow

When user with email `john@example.com`:
1. Registers locally with password
2. Later tries to login with Google using same email
3. System detects existing email
4. Prompts: "Link Google account to existing account?"
5. User enters password to confirm
6. Accounts are linked

### Implement Linking Endpoint

```java
@PostMapping("/api/account/link")
public ResponseEntity<Void> linkAccount(@RequestParam AuthProvider provider,
                                       @RequestParam String password,
                                       Principal principal) {
    
    User user = getUserFromPrincipal(principal);
    
    // Verify password
    if (!passwordEncoder.matches(password, user.getPassword())) {
        throw new BadCredentialsException("Invalid password");
    }
    
    // Link provider (stored in session from OAuth flow)
    OAuth2UserInfo providerInfo = getProviderInfoFromSession();
    
    user.setAuthProvider(provider);
    user.setProviderUserId(providerInfo.getId());
    user.setProviderUsername(providerInfo.getName());
    user.setPictureUrl(providerInfo.getImageUrl());
    
    userRepository.save(user);
    
    return ResponseEntity.ok().build();
}
```

---

## Step 10: Testing Social Login

### Test Google Login

1. **Click** "Continue with Google"
2. **Redirected** to Google login
3. **Login** with Google account
4. **Consent** to share profile and email
5. **Redirected** back to your app
6. **Check database**:
```sql
SELECT username, email, auth_provider, provider_user_id FROM users;
```

### Verify User Creation

- User created with email from Google
- `auth_provider` = "GOOGLE"
- `provider_user_id` = Google's user ID
- `picture_url` = Profile picture URL
- No password set (null)

### Test Account Linking

1. **Register** local account with email
2. **Logout**
3. **Login** with Google using same email
4. **Prompted** to link accounts
5. **Enter** local password
6. **Accounts linked** - can login either way

---

## Common Issues

### Email not provided by provider

**Cause**: User didn't consent to email scope

**Solution**: Make email scope mandatory, handle missing email gracefully

### Redirect URI mismatch

**Error**: "redirect_uri_mismatch"

**Solution**: Ensure exact match between configured and registered URIs (including http vs https, trailing slash)

### User info endpoint fails

**Cause**: Insufficient scopes or expired token

**Solution**: Request correct scopes, handle token refresh

### Duplicate usernames

**Cause**: Multiple users with same name from different providers

**Solution**: Append provider suffix or number (john.doe.google, john.doe1)

---

## What You've Accomplished

✅ Configured OAuth clients for major providers
✅ Implemented social login flow
✅ Created provider-specific user info extraction
✅ Built account linking functionality
✅ Updated UI with social login buttons
✅ Handled account conflicts and edge cases

---

## Next Steps

**Proceed to Guide 33**: Docker Deployment with HTTPS

Before moving on:
- [ ] Social login works for all providers
- [ ] User data extracted correctly
- [ ] Account linking functions properly
- [ ] Email conflicts handled gracefully
- [ ] Profile pictures displayed

---

## Key Concepts Learned

### OAuth as Client
- Your IdP acts as OAuth client to other providers
- Standard OAuth flow: redirect → consent → callback
- Provider-specific attribute mapping required

### Account Linking
- Multiple authentication methods for one user
- Email as common identifier
- Verification required before linking

### Provider Differences
- Each provider returns different attribute structure
- Scope names vary by provider
- User ID formats differ

### Security Considerations
- Validate email from provider
- Don't auto-trust social accounts
- Allow users to unlink providers
- Maintain local password as fallback

---

## Additional Resources

- **Spring OAuth2 Client**: https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html
- **Google OAuth**: https://developers.google.com/identity/protocols/oauth2
- **GitHub OAuth**: https://docs.github.com/en/developers/apps/building-oauth-apps
- **Facebook Login**: https://developers.facebook.com/docs/facebook-login/
- **Microsoft Identity**: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
- **OAuth.net Providers**: https://oauth.net/code/
