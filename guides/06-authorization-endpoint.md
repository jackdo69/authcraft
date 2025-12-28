# Guide 06: Implement Authorization Endpoint

**Phase 2: Basic OAuth** | **Week 3-4** | **Task 6 of 10**

## Overview

Build the OAuth 2.0 authorization endpoint - the entry point for the authorization code flow. This is where users grant permission to client applications to access their resources.

---

## What You'll Build

- Authorization endpoint (`/oauth2/authorize`)
- Request parameter validation (client_id, redirect_uri, scope, state, response_type)
- User authentication check
- Redirect to login if not authenticated
- Authorization consent screen logic

---

## Understanding the Authorization Endpoint

### What It Does

The authorization endpoint is where the OAuth flow begins:

1. **Client redirects user** to IdP with authorization request
2. **IdP checks** if user is logged in
3. **If not logged in** → redirect to login page
4. **If logged in** → show consent screen (or auto-approve)
5. **User approves** → generate authorization code
6. **Redirect back** to client with authorization code

### Why This Endpoint Matters

This is the **user-facing** part of OAuth - where users understand what they're authorizing. The consent screen should clearly show:
- Which application is requesting access
- What permissions (scopes) they're requesting
- Options to approve or deny

---

## Step 1: Understand the Authorization Request

### Request Parameters

A client initiates OAuth by redirecting the user to:

```
GET /oauth2/authorize?
  response_type=code&
  client_id=demo-client&
  redirect_uri=http://localhost:3000/callback&
  scope=openid%20profile%20email&
  state=xyz123
```

### Required Parameters

| Parameter | Purpose | Validation |
|-----------|---------|------------|
| **response_type** | What client expects back | Must be "code" (for authorization code flow) |
| **client_id** | Identifies the client app | Must exist in clients table |
| **redirect_uri** | Where to send user after authorization | Must match registered URI for this client |
| **scope** | Permissions being requested | Must be subset of client's allowed scopes |
| **state** | CSRF protection token | Opaque string, returned unchanged to client |

*Why state?*: Prevents CSRF attacks. Client generates random value, stores it, then verifies it matches when user returns.

### Optional Parameters

| Parameter | Purpose |
|-----------|---------|
| **code_challenge** | PKCE challenge (covered in Phase 3) |
| **code_challenge_method** | PKCE method (S256 or plain) |
| **prompt** | Whether to show consent screen (none, consent, login) |

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1

---

## Step 2: Create Authorization Request DTO

### Create AuthorizationRequest.java

Location: `src/main/java/com/learning/idp/dto/AuthorizationRequest.java`

### Fields to Include

All request parameters as fields:
- `responseType` (String)
- `clientId` (String)
- `redirectUri` (String)
- `scope` (String) - space-separated scopes
- `state` (String)
- `codeChallenge` (String, optional for now)
- `codeChallengeMethod` (String, optional for now)

### Validation Annotations

- **@NotBlank**: On required fields (responseType, clientId, redirectUri, scope)
- **@Pattern**: Validate response_type is "code"
  - Example: `@Pattern(regexp = "code", message = "Only authorization code flow is supported")`

### Parse Scopes Helper

Add a helper method to split scope string into a Set:
```java
public Set<String> getScopes() {
    return Set.of(scope.split("\\s+"));
}
```

*Why?*: Makes it easier to work with individual scopes for validation and storage.

---

## Step 3: Create Authorization Controller

### Create AuthorizationController.java

Location: `src/main/java/com/learning/idp/controller/AuthorizationController.java`

### Endpoint Mapping

**Method**: GET
**Path**: `/oauth2/authorize`

*Why GET?*: OAuth spec requires GET for authorization endpoint because it's a redirect from the client application.

### Method Signature

Needs access to:
- **Request parameters**: Use `AuthorizationRequest` with `@ModelAttribute` (for URL query parameters)
  - *Note*: Use `@ModelAttribute` instead of `@RequestBody` for GET requests
- **Current authentication**: Inject `Principal` or use `SecurityContextHolder`
- **Model**: For passing data to view (consent screen)

### Annotations

- **@Controller**: Not `@RestController` - returns views (HTML), not JSON
- **@GetMapping("/oauth2/authorize")**

---

## Step 4: Implement Request Validation

### Validation Steps

In your authorization endpoint handler method:

#### 1. Validate Client

```java
// Pseudo-code
Client client = clientService.findByClientId(request.getClientId());
if (client == null) {
    throw new InvalidClientException("Unknown client");
}
```

*Why validate client first?*: If client is invalid, we can't trust the redirect_uri, so we can't safely redirect user back.

#### 2. Validate Redirect URI

```java
if (!client.getRedirectUris().contains(request.getRedirectUri())) {
    throw new InvalidRedirectUriException("Redirect URI not registered");
}
```

*Why critical?*: Prevents authorization code from being sent to attacker's server (open redirect vulnerability).

#### 3. Validate Scopes

```java
Set<String> requestedScopes = request.getScopes();
Set<String> allowedScopes = client.getAllowedScopes();

if (!allowedScopes.containsAll(requestedScopes)) {
    return redirectWithError(request.getRedirectUri(), "invalid_scope", request.getState());
}
```

*Why?*: Prevent clients from requesting scopes they're not authorized for.

#### 4. Validate Response Type

```java
if (!"code".equals(request.getResponseType())) {
    return redirectWithError(request.getRedirectUri(), "unsupported_response_type", request.getState());
}
```

---

## Step 5: Check User Authentication

### Detect Authentication Status

```java
Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

if (authentication == null || !authentication.isAuthenticated() ||
    authentication instanceof AnonymousAuthenticationToken) {
    // User not logged in - redirect to login
    return redirectToLogin(request);
}
```

### Redirect to Login

If user not authenticated:
1. **Save authorization request** in session (so we can resume after login)
2. **Redirect to login page** with return URL
3. **After login** → resume authorization flow

### Session Attribute

Store the authorization request:
```java
session.setAttribute("PENDING_AUTHORIZATION_REQUEST", request);
return "redirect:/login";
```

*Why?*: When user completes login, you need to know where they were trying to go.

---

## Step 6: Create Login Page

### Create login.html

Location: `src/main/resources/templates/login.html`

### What to Include

A basic Thymeleaf template with:
- **Form action**: `/login` (Spring Security default)
- **Method**: POST
- **Fields**:
  - Username input (`name="username"`)
  - Password input (`name="password"`)
  - Submit button
- **Error display**: Show error message if login fails
- **CSRF token**: Thymeleaf automatically includes this

### Thymeleaf Basics

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>

    <div th:if="${param.error}">
        Invalid username or password
    </div>

    <form method="post" th:action="@{/login}">
        <!-- Form fields here -->
    </form>
</body>
</html>
```

**Learn More**: https://www.thymeleaf.org/doc/tutorials/3.1/thymeleafspring.html

---

## Step 7: Configure Login in Spring Security

### Update SecurityConfig

In your `SecurityFilterChain` bean:

#### Configure Form Login

```java
http
    .formLogin(form -> form
        .loginPage("/login")  // Custom login page
        .loginProcessingUrl("/login")  // Where to submit credentials
        .defaultSuccessUrl("/oauth2/authorize", true)  // Where to go after login
        .permitAll()
    )
```

### Why This Configuration?

- **loginPage**: Tells Spring to use your custom login page (not the default)
- **loginProcessingUrl**: POST endpoint for credential submission
- **defaultSuccessUrl**: After successful login, redirect back to authorization endpoint
  - The saved `PENDING_AUTHORIZATION_REQUEST` will be loaded from session
- **permitAll**: Login page must be accessible without authentication

---

## Step 8: Handle Authorization Request After Login

### Resume Flow

After user logs in successfully:

1. **Load saved request** from session:
```java
AuthorizationRequest savedRequest = (AuthorizationRequest) session.getAttribute("PENDING_AUTHORIZATION_REQUEST");
```

2. **Re-validate** the request (client, redirect_uri, scopes)
   - *Why re-validate?*: Session could have been tampered with

3. **Proceed to consent screen** or auto-approve

### Clear Session Attribute

After loading, remove it:
```java
session.removeAttribute("PENDING_AUTHORIZATION_REQUEST");
```

---

## Step 9: Create Consent Screen Logic

### Check if Consent Required

Some scenarios where consent can be skipped:
- **First-party apps**: If your IdP and client app are owned by same company
- **Previously approved**: User already consented to these exact scopes for this client
- **prompt=none**: Client explicitly requests no UI (advanced)

### For Learning Project

**Always show consent** for now - makes the flow visible and educational.

### Consent Data Model

Store user consent in database:

**Table**: `user_consents`
- `user_id`
- `client_id`
- `scopes` (granted scopes)
- `granted_at` (timestamp)

### Migration

Create: `V8__create_user_consents_table.sql`

---

## Step 10: Build Consent Screen

### Create consent.html

Location: `src/main/resources/templates/consent.html`

### What to Display

- **Client name**: "App XYZ is requesting access to:"
- **Scopes**: List of permissions with user-friendly descriptions
  - `openid` → "Verify your identity"
  - `profile` → "Access your profile information (name, picture)"
  - `email` → "Access your email address"
- **Actions**:
  - **Approve** button (submits form)
  - **Deny** button (cancels flow)

### Form Submission

**Action**: POST `/oauth2/authorize/consent`
**Hidden fields**:
- All original authorization request parameters
- User's decision (approve/deny)

---

## Step 11: Handle Consent Decision

### Create Consent Endpoint

**Method**: POST
**Path**: `/oauth2/authorize/consent`

### If User Approves

1. **Record consent** in `user_consents` table
2. **Generate authorization code** (covered in Guide 07)
3. **Build redirect URL**:
   ```
   {redirect_uri}?code={authorization_code}&state={state}
   ```
4. **Redirect user** to client application

### If User Denies

**Build error redirect**:
```
{redirect_uri}?error=access_denied&error_description=User%20denied%20access&state={state}
```

### Error Response Format

According to OAuth spec, errors should include:
- **error**: Error code (`access_denied`, `invalid_request`, `invalid_scope`, etc.)
- **error_description**: Human-readable description (optional)
- **state**: Original state parameter (for CSRF protection)

**Learn More**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1

---

## Understanding the Complete Flow

### Sequence Diagram

```
Client App                 IdP                      User
    |                       |                         |
    |-- Redirect to ------->|                         |
    |   /oauth2/authorize   |                         |
    |                       |                         |
    |                       |<------ Not logged in ---|
    |                       |                         |
    |                       |--- Show login form ---->|
    |                       |                         |
    |                       |<---- Submit creds ------|
    |                       |                         |
    |                       |--- Show consent form -->|
    |                       |                         |
    |                       |<------ Approve ---------|
    |                       |                         |
    |<-- Redirect with -----|                         |
    |    authorization code |                         |
```

---

## Testing the Authorization Endpoint

### Manual Test Steps

1. **Start your app**: Ensure user is created in database
2. **Open browser**: Navigate to:
   ```
   http://localhost:8080/oauth2/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile&state=abc123
   ```
3. **Should redirect** to login page
4. **Login** with test credentials
5. **Should show** consent screen
6. **Approve** consent
7. **Check redirect**: URL should be:
   ```
   http://localhost:3000/callback?code=SOME_CODE&state=abc123
   ```
   *(Will show error since client app doesn't exist yet - that's OK for now!)*

### What to Verify

- [ ] Invalid client_id returns error
- [ ] Invalid redirect_uri returns error
- [ ] Unauthenticated user redirects to login
- [ ] Login success resumes authorization flow
- [ ] Consent screen shows client name and scopes
- [ ] Approval generates authorization code
- [ ] Denial redirects with error=access_denied
- [ ] State parameter is preserved throughout

---

## Common Issues

### "Circular view path" error

**Cause**: Returning view name same as mapping path

**Solution**: Return different view name than endpoint path

### State parameter missing in redirect

**Cause**: Not preserving state through the flow

**Solution**: Include state in session attributes or hidden form fields

### Redirect URI validation too strict

**Cause**: Exact string match including trailing slashes, query parameters

**Solution**: Normalize URIs before comparison (remove trailing slash, ignore query params for comparison)

---

## What You've Accomplished

✅ Built OAuth 2.0 authorization endpoint
✅ Implemented request parameter validation
✅ Integrated user authentication check
✅ Created login page with Thymeleaf
✅ Built consent screen flow
✅ Handled approval and denial scenarios
✅ Understood complete authorization flow

---

## Next Steps

**Proceed to Guide 07**: Generate and Validate Authorization Codes

Before moving on:
- [ ] Authorization endpoint validates all parameters
- [ ] Login flow works and resumes authorization
- [ ] Consent screen displays correctly
- [ ] Approval flow (mostly) works (code generation covered next)
- [ ] Error handling returns proper OAuth error responses

---

## Key Concepts Learned

### OAuth Authorization Request
- Client initiates flow by redirecting user
- Parameters define what client wants
- State parameter prevents CSRF attacks

### Redirect URI Validation
- Critical security check
- Prevents authorization code theft
- Must be exact match with registered URI

### User Consent
- Explicit user permission required
- Scopes define granularity of access
- Consent can be remembered

### Error Handling in OAuth
- Errors redirect back to client
- Standard error codes defined by spec
- Never expose internal errors to user

---

## Additional Resources

- **OAuth 2.0 Authorization Endpoint**: https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
- **Authorization Request**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
- **Error Responses**: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
- **Thymeleaf Spring Security**: https://www.thymeleaf.org/doc/articles/springsecurity.html
- **Spring Security Form Login**: https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html
