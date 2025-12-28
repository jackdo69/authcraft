# Guide 36: SAML 2.0 Federation

**Advanced Topics** | **Task 36 of 45**

## Overview

Implement SAML 2.0 federation to enable Enterprise Single Sign-On (SSO). Allow your IdP to act as both SAML Service Provider (SP) and Identity Provider (IdP), enabling integration with corporate identity systems like Okta, Azure AD, and Google Workspace.

---

## What You'll Build

- SAML 2.0 Service Provider (SP) implementation
- SAML 2.0 Identity Provider (IdP) implementation
- Metadata endpoints and configuration
- Assertion Consumer Service (ACS)
- Single Logout (SLO) support
- Attribute mapping
- Certificate management
- Integration with Azure AD / Okta / Google

---

## Why SAML?

### Enterprise SSO Standard

**Legacy but Essential**: While OAuth 2.0/OIDC is modern, many enterprises still use SAML
**Wide Adoption**: Azure AD, Okta, Google Workspace, Salesforce all support SAML
**Zero-Trust SSO**: Employees log in once to access all applications

### Use Cases

- **As SP**: Your app accepts SAML logins from corporate IdP (Okta, Azure AD)
- **As IdP**: Your IdP provides SAML SSO to third-party SaaS apps
- **Federation**: Trust relationships between organizations

**Learn More**:
- SAML 2.0 Spec: https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html
- SAML vs OAuth: https://www.okta.com/identity-101/saml-vs-oauth/

---

## SAML Concepts

### Key Components

**Service Provider (SP)**: Application requesting authentication (your app)
**Identity Provider (IdP)**: System that authenticates users (Azure AD, Okta, your IdP)
**SAML Assertion**: XML document containing user identity and attributes
**Metadata**: XML describing SP/IdP configuration (endpoints, certificates)

### SAML Flow (SP-Initiated)

```
1. User → SP: Access protected resource
2. SP → Browser: Redirect to IdP with SAMLRequest
3. Browser → IdP: Forward SAMLRequest
4. IdP: Authenticate user
5. IdP → Browser: Redirect to SP with SAMLResponse
6. Browser → SP: POST SAMLResponse to Assertion Consumer Service (ACS)
7. SP: Validate signature, extract user info, create session
8. SP → User: Grant access
```

---

## Step 1: Add SAML Dependencies

### Maven Dependencies

Add to `pom.xml`:

```xml
<dependencies>
    <!-- Spring Security SAML -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-saml2-service-provider</artifactId>
    </dependency>

    <!-- For IdP functionality -->
    <dependency>
        <groupId>org.opensaml</groupId>
        <artifactId>opensaml-core</artifactId>
        <version>4.3.0</version>
    </dependency>
    <dependency>
        <groupId>org.opensaml</groupId>
        <artifactId>opensaml-saml-api</artifactId>
        <version>4.3.0</version>
    </dependency>
    <dependency>
        <groupId>org.opensaml</groupId>
        <artifactId>opensaml-saml-impl</artifactId>
        <version>4.3.0</version>
    </dependency>

    <!-- XML Security -->
    <dependency>
        <groupId>org.apache.santuario</groupId>
        <artifactId>xmlsec</artifactId>
        <version>2.3.3</version>
    </dependency>
</dependencies>
```

**Why OpenSAML?**: Industry-standard library for SAML processing
**Why xmlsec?**: XML digital signature validation

---

## Step 2: Generate SAML Certificates

### Create Keystore

```bash
# Generate keystore with RSA key pair
keytool -genkeypair -alias saml-signing \
  -keyalg RSA -keysize 2048 \
  -validity 3650 \
  -keystore saml-keystore.jks \
  -storepass changeit \
  -keypass changeit \
  -dname "CN=idp.example.com, OU=IT, O=Example Corp, L=San Francisco, ST=CA, C=US"

# Export public certificate
keytool -export -alias saml-signing \
  -keystore saml-keystore.jks \
  -file saml-cert.crt \
  -storepass changeit
```

Move `saml-keystore.jks` to `src/main/resources/saml/`

**Why keystore?**: SAML assertions must be digitally signed
**Validity**: 10 years (3650 days) - rotation is complex in enterprise

---

## Step 3: Implement SAML Service Provider

### Configure Spring Security SAML SP

Create `Saml2SecurityConfig.java`:

```java
@Configuration
@EnableWebSecurity
public class Saml2SecurityConfig {

    @Bean
    public SecurityFilterChain samlSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/saml/**").permitAll()
                .requestMatchers("/login/saml2/**").permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .loginProcessingUrl("/login/saml2/sso/{registrationId}")
            )
            .saml2Logout(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrations() {
        // Configure SAML IdP connections
        RelyingPartyRegistration okta = RelyingPartyRegistrations
            .fromMetadataLocation("https://dev-12345.okta.com/app/metadata")
            .registrationId("okta")
            .build();

        return new InMemoryRelyingPartyRegistrationRepository(okta);
    }
}
```

**What this does**:
- `/login/saml2/sso/{registrationId}`: Assertion Consumer Service (ACS)
- `RelyingPartyRegistration`: Configuration for each external IdP
- Metadata URL: Automatically fetches IdP configuration

### Application Configuration

`application.yml`:

```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          okta:
            signing:
              credentials:
                - certificate-location: classpath:saml/saml-cert.crt
                  private-key-location: classpath:saml/saml-private-key.pem
            assertingparty:
              metadata-uri: https://dev-12345.okta.com/app/metadata
              entity-id: http://www.okta.com/exk12345
              singlesignon:
                url: https://dev-12345.okta.com/app/sso/saml
                sign-request: false
```

**Configuration explained**:
- `signing.credentials`: Your SP's signing certificate
- `metadata-uri`: IdP's metadata endpoint (auto-configures IdP)
- `sign-request`: Whether to sign SAMLRequest (optional for most IdPs)

---

## Step 4: Extract SAML User Attributes

### Custom User Details Service

Create `SamlUserDetailsService.java`:

```java
@Service
public class SamlUserDetailsService implements Saml2AuthenticatedPrincipalConverter {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication convert(Saml2AuthenticatedPrincipal principal) {
        String email = principal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        String firstName = principal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
        String lastName = principal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");

        // Find or create user
        User user = userRepository.findByEmail(email)
            .orElseGet(() -> createUserFromSaml(email, firstName, lastName));

        return new UsernamePasswordAuthenticationToken(
            user,
            null,
            List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    private User createUserFromSaml(String email, String firstName, String lastName) {
        User user = new User();
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(true);
        return userRepository.save(user);
    }
}
```

**SAML Attribute Names**: Vary by IdP
- **Okta**: Uses standard SAML attribute names
- **Azure AD**: Custom format (`http://schemas.microsoft.com/...`)
- **Google**: Different format

**Auto-provisioning**: Create user on first SAML login (Just-In-Time provisioning)

---

## Step 5: Implement SAML Identity Provider

### Create SAML Assertion Builder

Create `SamlAssertionBuilder.java`:

```java
@Service
public class SamlAssertionBuilder {

    private final KeyStore keyStore;
    private final String keyAlias = "saml-signing";
    private final String keyPassword = "changeit";

    public Response buildAuthNResponse(
        User user,
        String audienceURI,
        String recipientURL,
        String inResponseTo
    ) {
        // Build Assertion
        Assertion assertion = buildAssertion(user, audienceURI, recipientURL);

        // Build Response
        Response response = buildResponse(assertion, recipientURL, inResponseTo);

        // Sign assertion
        signAssertion(assertion);

        return response;
    }

    private Assertion buildAssertion(User user, String audienceURI, String recipientURL) {
        Assertion assertion = create(Assertion.class);
        assertion.setID(generateID());
        assertion.setIssueInstant(Instant.now());
        assertion.setIssuer(buildIssuer("https://idp.example.com"));

        // Subject
        Subject subject = create(Subject.class);
        NameID nameID = create(NameID.class);
        nameID.setFormat(NameID.EMAIL);
        nameID.setValue(user.getEmail());
        subject.setNameID(nameID);

        // Subject Confirmation
        SubjectConfirmation confirmation = create(SubjectConfirmation.class);
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData confirmationData = create(SubjectConfirmationData.class);
        confirmationData.setRecipient(recipientURL);
        confirmationData.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
        confirmationData.setInResponseTo(inResponseTo);
        confirmation.setSubjectConfirmationData(confirmationData);
        subject.getSubjectConfirmations().add(confirmation);

        assertion.setSubject(subject);

        // Conditions
        Conditions conditions = create(Conditions.class);
        conditions.setNotBefore(Instant.now());
        conditions.setNotOnOrAfter(Instant.now().plus(5, ChronoUnit.MINUTES));
        AudienceRestriction audienceRestriction = create(AudienceRestriction.class);
        Audience audience = create(Audience.class);
        audience.setURI(audienceURI);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        // AuthnStatement
        AuthnStatement authnStatement = create(AuthnStatement.class);
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setSessionIndex(generateID());
        AuthnContext authnContext = create(AuthnContext.class);
        AuthnContextClassRef classRef = create(AuthnContextClassRef.class);
        classRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(classRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);

        // Attributes
        assertion.getAttributeStatements().add(buildAttributeStatement(user));

        return assertion;
    }

    private AttributeStatement buildAttributeStatement(User user) {
        AttributeStatement statement = create(AttributeStatement.class);

        // Email attribute
        Attribute emailAttr = create(Attribute.class);
        emailAttr.setName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
        emailAttr.setNameFormat(Attribute.URI_REFERENCE);
        XSString emailValue = createXSString(user.getEmail());
        emailAttr.getAttributeValues().add(emailValue);
        statement.getAttributes().add(emailAttr);

        // First name
        Attribute firstNameAttr = create(Attribute.class);
        firstNameAttr.setName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname");
        firstNameAttr.setNameFormat(Attribute.URI_REFERENCE);
        firstNameAttr.getAttributeValues().add(createXSString(user.getFirstName()));
        statement.getAttributes().add(firstNameAttr);

        // Last name
        Attribute lastNameAttr = create(Attribute.class);
        lastNameAttr.setName("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname");
        lastNameAttr.setNameFormat(Attribute.URI_REFERENCE);
        lastNameAttr.getAttributeValues().add(createXSString(user.getLastName()));
        statement.getAttributes().add(lastNameAttr);

        return statement;
    }

    private void signAssertion(Assertion assertion) {
        Signature signature = create(Signature.class);
        signature.setSigningCredential(getSigningCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        // Marshall and sign
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
            marshaller.marshall(assertion);
            Signer.signObject(signature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign SAML assertion", e);
        }
    }

    private String generateID() {
        return "_" + UUID.randomUUID().toString();
    }
}
```

**Complex but necessary**: SAML assertions have strict structure and signing requirements

---

## Step 6: Create SAML Metadata Endpoint

### IdP Metadata Controller

Create `SamlMetadataController.java`:

```java
@RestController
@RequestMapping("/saml")
public class SamlMetadataController {

    @GetMapping("/metadata")
    public ResponseEntity<String> getIdPMetadata() {
        EntityDescriptor entityDescriptor = buildEntityDescriptor();
        String metadataXml = marshallToXml(entityDescriptor);

        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_XML)
            .body(metadataXml);
    }

    private EntityDescriptor buildEntityDescriptor() {
        EntityDescriptor descriptor = create(EntityDescriptor.class);
        descriptor.setEntityID("https://idp.example.com");

        IDPSSODescriptor idpDescriptor = create(IDPSSODescriptor.class);
        idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // Key Descriptor (signing)
        KeyDescriptor signingKey = create(KeyDescriptor.class);
        signingKey.setUse(UsageType.SIGNING);
        signingKey.setKeyInfo(buildKeyInfo());
        idpDescriptor.getKeyDescriptors().add(signingKey);

        // Single Sign-On Service
        SingleSignOnService ssoService = create(SingleSignOnService.class);
        ssoService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        ssoService.setLocation("https://idp.example.com/saml/sso");
        idpDescriptor.getSingleSignOnServices().add(ssoService);

        // Single Logout Service
        SingleLogoutService sloService = create(SingleLogoutService.class);
        sloService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        sloService.setLocation("https://idp.example.com/saml/logout");
        idpDescriptor.getSingleLogoutServices().add(sloService);

        // Name ID Formats
        NameIDFormat emailFormat = create(NameIDFormat.class);
        emailFormat.setURI(NameID.EMAIL);
        idpDescriptor.getNameIDFormats().add(emailFormat);

        descriptor.getRoleDescriptors().add(idpDescriptor);

        return descriptor;
    }
}
```

**Metadata Purpose**: SP consumes this to configure SAML integration

**URLs in metadata**:
- SSO Service: Where SP sends SAMLRequest
- SLO Service: For logout
- Certificates: SP validates assertion signatures

---

## Step 7: Configure Azure AD Integration

### Register App in Azure AD

1. Go to Azure Portal → Azure Active Directory → Enterprise Applications
2. Click "New Application" → "Create your own application"
3. Name: "My OAuth IdP"
4. Select "Integrate any other application you don't find in the gallery (Non-gallery)"
5. Click "Create"

### Configure SAML

1. Go to "Single sign-on" → Select "SAML"
2. Basic SAML Configuration:
   - **Identifier (Entity ID)**: `https://your-idp.com/saml/metadata`
   - **Reply URL (ACS)**: `https://your-idp.com/login/saml2/sso/azuread`
3. Attributes & Claims:
   - **email**: `user.mail`
   - **givenname**: `user.givenname`
   - **surname**: `user.surname`
4. Download:
   - **Certificate (Base64)**: Upload to your IdP
   - **Login URL**: Use in configuration

### Update Your Configuration

```yaml
spring:
  security:
    saml2:
      relyingparty:
        registration:
          azuread:
            signing:
              credentials:
                - certificate-location: classpath:saml/saml-cert.crt
                  private-key-location: classpath:saml/saml-private-key.pem
            assertingparty:
              metadata-uri: https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml
```

**Test**: Users from Azure AD can now log into your app via SAML

---

## Step 8: Implement Single Logout (SLO)

### Logout Controller

Create `SamlLogoutController.java`:

```java
@Controller
public class SamlLogoutController {

    @PostMapping("/saml/logout")
    public String processSingleLogout(@RequestParam("SAMLRequest") String samlRequest,
                                     HttpServletRequest request) {
        // Decode and validate SAMLRequest
        LogoutRequest logoutRequest = decodeLogoutRequest(samlRequest);

        // Find session by NameID
        String nameID = logoutRequest.getNameID().getValue();
        invalidateSession(nameID);

        // Build LogoutResponse
        LogoutResponse response = buildLogoutResponse(logoutRequest.getID());

        // Redirect back to IdP with LogoutResponse
        String encodedResponse = encodeResponse(response);
        String idpLogoutURL = getIdPLogoutURL(logoutRequest.getIssuer());

        return "redirect:" + idpLogoutURL + "?SAMLResponse=" + encodedResponse;
    }
}
```

**Why SLO?**: When user logs out of one app, log out of all SAML-connected apps

---

## Step 9: Attribute Mapping

### Flexible Attribute Configuration

Create `SamlAttributeMapper.java`:

```java
@Service
public class SamlAttributeMapper {

    private static final Map<String, String> ATTRIBUTE_MAPPING = Map.of(
        "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "lastName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    );

    public Map<String, String> extractAttributes(Saml2AuthenticatedPrincipal principal) {
        Map<String, String> attributes = new HashMap<>();

        ATTRIBUTE_MAPPING.forEach((key, samlAttrName) -> {
            String value = principal.getFirstAttribute(samlAttrName);
            if (value != null) {
                attributes.put(key, value);
            }
        });

        return attributes;
    }
}
```

**Why mapping?**: Different IdPs use different attribute names

---

## Step 10: Testing SAML Integration

### Test with SAML Test Tool

**Use SAMLtest.id**:
1. Go to https://samltest.id/
2. Upload your IdP metadata
3. Click "Test SAML Login"
4. Complete authentication flow
5. Verify assertion received

### Test with Real IdP

```bash
# Test with Okta
1. Navigate to https://your-app.com/saml/login/okta
2. Should redirect to Okta login
3. Enter Okta credentials
4. Should redirect back with SAML assertion
5. Verify user logged in
```

### Validate SAML Response

Use browser devtools:
1. Open Network tab
2. Complete SAML login
3. Find POST to ACS endpoint
4. View Form Data → SAMLResponse
5. Decode Base64
6. Verify XML structure and signature

**Decoder**: https://www.samltool.com/decode.php

---

## Common Issues

### Signature Validation Failed

**Problem**: "SAML assertion signature validation failed"

**Solutions**:
- Verify certificate matches between IdP and SP
- Check clock skew (time must be synchronized)
- Ensure using correct signature algorithm

### Attribute Not Found

**Problem**: `principal.getFirstAttribute("email")` returns null

**Solution**: Check attribute name in SAML response
```xml
<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
```
Use exact attribute name from XML

### Redirect Loop

**Problem**: Continuously redirecting between SP and IdP

**Solution**:
- Check ACS URL matches exactly in both configs
- Verify InResponseTo ID matches SAMLRequest ID
- Check session cookie is being set

### Certificate Expired

**Problem**: "Certificate has expired"

**Solution**:
- Generate new certificate
- Update IdP metadata
- Notify all connected SPs to update

---

## What You've Accomplished

✅ Implemented SAML Service Provider
✅ Built SAML Identity Provider
✅ Generated and managed SAML certificates
✅ Created metadata endpoints
✅ Integrated with Azure AD / Okta
✅ Implemented attribute mapping
✅ Added Single Logout support
✅ Tested SAML flows

---

## Next Steps

**Proceed to Guide 37**: Device Authorization Flow

Before moving on:
- [ ] SAML SP integration working with external IdP
- [ ] SAML IdP metadata generated
- [ ] Attribute mapping configured
- [ ] Tested with at least one enterprise IdP (Azure AD or Okta)
- [ ] Single Logout tested

---

## Key Concepts Learned

### SAML vs OAuth/OIDC

**SAML**:
- XML-based
- Enterprise SSO focus
- Supports attribute exchange
- Complex but mature

**OAuth/OIDC**:
- JSON-based (JWT)
- Modern, mobile-friendly
- Simpler to implement
- Gaining enterprise adoption

### SAML Security

- **Assertion Signing**: Prevent tampering
- **Time Validation**: NotBefore/NotOnOrAfter
- **Audience Restriction**: Prevent assertion replay
- **Recipient Check**: Ensure ACS URL matches

### Enterprise Integration

- **Just-In-Time Provisioning**: Create user on first login
- **Attribute Mapping**: Sync user profile from IdP
- **Group/Role Mapping**: Assign roles based on SAML attributes
- **Audit Logging**: Track SAML logins

---

## Additional Resources

- **SAML 2.0 Technical Overview**: https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html
- **Spring Security SAML**: https://docs.spring.io/spring-security/reference/servlet/saml2/index.html
- **OneLogin SAML Toolkits**: https://developers.onelogin.com/saml
- **SAML Debugger**: https://www.samltool.com/
- **SAMLtest.id**: https://samltest.id/
- **Azure AD SAML**: https://learn.microsoft.com/en-us/azure/active-directory/develop/single-sign-on-saml-protocol
- **Okta SAML**: https://developer.okta.com/docs/concepts/saml/
