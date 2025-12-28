# Guide 10: Create a Simple Client App to Test

**Phase 2: Basic OAuth** | **Week 3-4** | **Task 10 of 10**

## Overview

Build a simple Spring Boot client application that demonstrates the complete OAuth 2.0 authorization code flow. This client will redirect users to your IdP, handle callbacks, exchange codes for tokens, and call protected resources.

---

## What You'll Build

- Spring Boot OAuth 2.0 client application
- Login with OAuth button
- Callback endpoint to receive authorization code
- Token exchange implementation
- Display user profile information
- Simple dashboard showing OAuth flow results

---

## Why Build a Client?

Testing OAuth with Postman only validates individual endpoints. A real client application demonstrates:
- Complete flow integration
- Redirect handling
- Session management
- How third-party apps consume your IdP

---

## Step 1: Create Client Project

### Using Spring Initializr

Visit https://start.spring.io/ and configure:

**Project Settings**:
- **Project**: Maven
- **Language**: Java
- **Spring Boot**: 3.2.x
- **Group**: `com.learning`
- **Artifact**: `oauth-client`
- **Java**: 17

**Dependencies**:
- Spring Web
- Thymeleaf
- Spring Security
- OAuth2 Client
- Lombok

### Extract and Open

1. **Download** and extract to `authcraft/client-app/`
2. **Open** in IntelliJ IDEA
3. **Wait** for Maven dependencies to download

---

## Step 2: Configure OAuth Client

### Update application.yml

Location: `src/main/resources/application.yml`

```yaml
server:
  port: 3000  # Different from IdP (8080)

spring:
  application:
    name: oauth-client

  security:
    oauth2:
      client:
        registration:
          custom-idp:  # Registration ID
            client-id: demo-client
            client-secret: demo-secret
            authorization-grant-type: authorization_code
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: openid,profile,email
            client-name: Demo OAuth Client

        provider:
          custom-idp:  # Provider ID (must match registration)
            authorization-uri: http://localhost:8080/oauth2/authorize
            token-uri: http://localhost:8080/oauth2/token
            user-info-uri: http://localhost:8080/oauth2/userinfo  # Phase 5
            user-name-attribute: username  # Which claim to use as principal name
```

### Configuration Explained

**Registration**: Defines your client credentials and OAuth settings
- **client-id/secret**: Must match what's registered in IdP's clients table
- **redirect-uri**: Where IdP sends authorization code
  - `{baseUrl}` = http://localhost:3000
  - `{registrationId}` = custom-idp
  - Full URI = http://localhost:3000/login/oauth2/code/custom-idp

**Provider**: Defines IdP endpoints
- **authorization-uri**: Where to send users for login
- **token-uri**: Where to exchange code for tokens

*Why two sections?*: Registration = client config, Provider = server config. Allows multiple clients to share same provider.

**Learn More**: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html

---

## Step 3: Create Security Configuration

### Create SecurityConfig.java

Location: `src/main/java/com/learning/client/config/SecurityConfig.java`

### Configure OAuth2 Login

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/error").permitAll()  // Public pages
                .anyRequest().authenticated()  // Everything else requires auth
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/custom-idp")  // Where to redirect for login
                .defaultSuccessUrl("/dashboard", true)  // After login, go here
            );

        return http.build();
    }
}
```

### What This Does

- **authorizeHttpRequests**: Defines which URLs need authentication
- **oauth2Login**: Enables OAuth 2.0 login
  - Spring automatically creates OAuth endpoints
  - `/oauth2/authorization/{registrationId}` redirects to IdP
  - `/login/oauth2/code/{registrationId}` receives callback

*Why Spring does this?*: OAuth 2.0 Login is a common pattern, Spring provides auto-configuration.

---

## Step 4: Create Home Page

### Create HomeController.java

Location: `src/main/java/com/learning/client/controller/HomeController.java`

```java
@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "index";  // Returns index.html template
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            model.addAttribute("username", principal.getAttribute("username"));
            model.addAttribute("email", principal.getAttribute("email"));
            model.addAttribute("attributes", principal.getAttributes());
        }
        return "dashboard";
    }
}
```

### @AuthenticationPrincipal

Injects the authenticated OAuth2 user:
- Contains claims from UserInfo endpoint (Phase 5)
- For now, will contain data from token introspection
- Null if user not authenticated

---

## Step 5: Create Templates

### Create index.html

Location: `src/main/resources/templates/index.html`

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>OAuth Client Demo</title>
</head>
<body>
    <h1>OAuth 2.0 Client Application</h1>

    <p>This is a demo client that uses OAuth 2.0 to authenticate with a custom Identity Provider.</p>

    <h2>Login Options:</h2>
    <ul>
        <li>
            <a th:href="@{/oauth2/authorization/custom-idp}">
                Login with Custom IdP
            </a>
        </li>
    </ul>

    <p><small>Click to start the OAuth 2.0 authorization code flow</small></p>
</body>
</html>
```

### What Happens When Clicked

1. Browser redirects to `/oauth2/authorization/custom-idp`
2. Spring redirects to IdP's authorization endpoint
3. User logs in at IdP
4. User approves consent
5. IdP redirects back to `/login/oauth2/code/custom-idp?code=...`
6. Spring automatically exchanges code for tokens
7. Spring creates authentication session
8. User redirected to `/dashboard`

---

## Step 6: Create Dashboard Page

### Create dashboard.html

Location: `src/main/resources/templates/dashboard.html`

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Dashboard</h1>

    <h2>Welcome, <span th:text="${username}">User</span>!</h2>

    <h3>Your Information:</h3>
    <ul>
        <li><strong>Username:</strong> <span th:text="${username}">N/A</span></li>
        <li><strong>Email:</strong> <span th:text="${email}">N/A</span></li>
    </ul>

    <h3>All Attributes:</h3>
    <pre th:text="${attributes}"></pre>

    <hr>

    <form th:action="@{/logout}" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
```

---

## Step 7: Test the Complete Flow

### Prerequisites

1. **IdP running**: `identity-provider` on port 8080
2. **Database running**: PostgreSQL and Redis via Docker
3. **Test user exists**: Created via registration or seeded
4. **Test client registered**: In clients table with:
   - client_id: `demo-client`
   - client_secret: `demo-secret` (hashed)
   - redirect_uris: `http://localhost:3000/login/oauth2/code/custom-idp`
   - grant_types: `authorization_code`
   - scopes: `openid,profile,email`

### Testing Steps

1. **Start client app**: Run `OauthClientApplication`
2. **Open browser**: Navigate to http://localhost:3000
3. **Click "Login with Custom IdP"**
4. **Observe redirect**: Browser goes to http://localhost:8080/oauth2/authorize?...
5. **Login**: Enter credentials on IdP login page
6. **Consent**: Approve requested scopes
7. **Callback**: Browser returns to http://localhost:3000/login/oauth2/code/custom-idp?code=...
8. **Dashboard**: See user information displayed

### What to Verify

- [ ] Redirect to IdP works
- [ ] Login page appears
- [ ] Consent screen shows scopes
- [ ] Callback URL receives authorization code
- [ ] Spring exchanges code automatically
- [ ] Dashboard shows user data
- [ ] Logout works

---

## Step 8: Debug Common Issues

### Issue: Redirect URI Mismatch

**Error**: OAuth error "redirect_uri" mismatch

**Cause**: Client's redirect_uri doesn't match IdP's registered URI

**Solution**:
- Check `application.yml`: `redirect-uri` value
- Check IdP database: `clients.redirect_uris` column
- Must be **exact match** (including trailing slash, protocol, port)

### Issue: Client Authentication Failed

**Error**: "invalid_client"

**Cause**: client_id or client_secret doesn't match

**Solution**:
- Check `application.yml` values
- Check IdP database for correct client_id
- Verify client_secret is hashed in database (should start with `$2a$`)

### Issue: UserInfo Endpoint Not Found

**Error**: 404 when fetching user info

**Cause**: UserInfo endpoint doesn't exist yet (Phase 5)

**Workaround**:
- Remove `user-info-uri` from configuration for now
- Or implement basic UserInfo endpoint (returns username/email from token)

### Issue: Infinite Redirect Loop

**Cause**: Spring can't establish authenticated session

**Solution**:
- Check Spring Security configuration
- Verify token endpoint returns valid tokens
- Check logs for token validation errors

---

## Step 9: Understand Spring OAuth2 Client

### What Spring Does Automatically

When you click "Login with Custom IdP":

1. **Generates authorization URL**:
   - Adds client_id, redirect_uri, scope, state
   - State is random for CSRF protection

2. **Handles callback**:
   - Validates state parameter
   - Extracts authorization code
   - Exchanges code for tokens (POST to token endpoint)

3. **Stores tokens**:
   - Saves access token, refresh token
   - Creates authenticated session

4. **Loads user info** (if UserInfo endpoint configured):
   - Calls UserInfo endpoint with access token
   - Creates OAuth2User object

5. **Creates authentication**:
   - Stores OAuth2User in SecurityContext
   - Session cookie maintains authentication

### Accessing Tokens Programmatically

```java
@GetMapping("/token-info")
public String tokenInfo(@RegisteredOAuth2AuthorizedClient("custom-idp")
                        OAuth2AuthorizedClient authorizedClient) {
    OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
    // Use token to call resource server APIs
}
```

**Learn More**: https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html

---

## Step 10: Call Protected Resource Server (Preview)

### Add RestTemplate

```java
@Bean
public RestTemplate restTemplate() {
    return new RestTemplate();
}
```

### Call Resource Server

```java
@GetMapping("/api/call")
public String callResourceServer(
        @RegisteredOAuth2AuthorizedClient("custom-idp") OAuth2AuthorizedClient client) {

    String accessToken = client.getAccessToken().getTokenValue();

    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(accessToken);
    HttpEntity<String> entity = new HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate.exchange(
        "http://localhost:8081/api/protected",
        HttpMethod.GET,
        entity,
        String.class
    );

    return response.getBody();
}
```

This previews Phase 6 (Resource Server) - the resource server validates the access token and returns protected data.

---

## What You've Accomplished

✅ Created OAuth 2.0 client application
✅ Configured Spring Security OAuth2 Login
✅ Implemented login flow with IdP
✅ Handled OAuth callback automatically
✅ Displayed user information from tokens
✅ Tested complete authorization code flow end-to-end

**Phase 2 Complete!** 🎉

---

## Next Steps

**Proceed to Phase 3 - Guide 11**: Add PKCE Support

Before moving on:
- [ ] Client app redirects to IdP for login
- [ ] User can login and consent at IdP
- [ ] Client receives and exchanges authorization code
- [ ] Dashboard shows user information
- [ ] Complete flow works end-to-end

---

## Key Concepts Learned

### OAuth 2.0 Client
- Delegates authentication to IdP
- Receives authorization code via redirect
- Exchanges code for tokens
- Uses tokens to access protected resources

### Spring Security OAuth2 Login
- Auto-configuration reduces boilerplate
- Handles OAuth flow automatically
- Manages token storage
- Integrates with Spring Security session

### Authorization Code Flow Recap
1. User clicks login → redirect to IdP
2. User authenticates at IdP
3. User consents to scopes
4. IdP redirects with authorization code
5. Client exchanges code for tokens
6. Client uses tokens to access resources

---

## Additional Resources

- **Spring Security OAuth2 Login**: https://docs.spring.io/spring-security/reference/servlet/oauth2/login/core.html
- **OAuth2AuthorizedClient**: https://docs.spring.io/spring-security/reference/servlet/oauth2/client/authorized-clients.html
- **Testing OAuth2 Applications**: https://www.baeldung.com/spring-security-oauth2-testing
- **OAuth 2.0 Simplified**: https://www.oauth.com/
